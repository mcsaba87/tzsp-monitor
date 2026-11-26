"""Run a shell command when one of the stack's detectors finds something.

Six sources, all read back out of InfluxDB rather than hooked into the
services that produce them, so a stopped or misconfigured alerter changes
nothing anywhere else:

    suricata    suricata_alert      severity 1-4 from the rule
    dns         dns_block           graded by the dns-filter list that refused
                                    the name (dns-filter /which)
    arp         arp_alert           severity 1-4 from arp-watch
    wids        wids_alert          severity 1-4 from wids
    scan        port_scan           internal scanner 2, external 4
    reputation  ip_reputation_hit   outbound to a C2 feed 1, other outbound 2,
                                    inbound 4

What each source does -- on/off, the lowest severity that alerts, and the
command -- is owned by the Alerting dashboard, the same Infinity
control-surface trick as rule-control/dns-filter/wids:

    GET /apply?enable=<src>&disable=<src>&severity=<src>:<1-4>
              &command_for=<src|default>&command=<text>
              &confirm=<code>&cancel=<code>&test=<src>:<token>&site=<uid>
        -> the rules table
    GET /rules    GET /status    GET /pending

Things that are easy to get wrong, and why it is built this way:

* **A dashboard that sets a shell command is remote code execution for every
  Grafana login.** Infinity calls this service with the datasource's
  identity, not the viewer's, so Grafana's roles do not gate it. Two things
  narrow it:
  - A command typed into the dashboard is only *staged*. It takes effect when
    a Confirm link carrying a server-generated one-time code is followed.
    Without that, a crafted dashboard URL (`/d/alerting?var-command=...`)
    sent to anyone logged in would be enough: the panels apply whatever the
    URL says as soon as they render. The code is not in any URL until the
    stage exists, so such a link cannot carry it.
  - The command runs as `nobody`, in its own process group, with an
    environment built from scratch (no InfluxDB token, nothing inherited), on
    a read-only filesystem where only /tmp is writable, and the container
    mounts no secrets -- suricata.properties, which holds the router
    passwords, is deliberately NOT mounted here; this service is configured
    through its environment instead. Webhook tokens go in the git-ignored
    `alerting.env` as ALERT_SECRET_*, and are handed to every command, so
    they never have to be typed into a dashboard that every viewer can read.
  ALERTING_CONTROL=ro makes the whole surface read-only.

* **Polling, not pushing.** Every source already writes its findings to
  InfluxDB, so each poll asks for the last `lookback` seconds and remembers
  what it has seen (by measurement, time and tags). Late writes are the
  normal case -- arp-watch and wids write when a window closes, dns-monitor
  every 30 s -- which is why the window looks back rather than starting where
  the previous poll stopped. The seen set and the cooldowns persist, so a
  restart neither repeats nor drops anything inside the look-back.

* **Enabling a source must not fire its history.** Turning a source on (or
  lowering its threshold) marks it to be *primed*: the next poll records
  everything already in the window as seen and runs nothing. Only what
  arrives after the click alerts.

* **One alert per thing, not per packet.** A cooldown per key (signature +
  endpoints, ARP alert + address, scanner, ...) holds repeats for
  ALERTING_REPEAT_SECONDS; the next command that does run carries how many
  were held back (ALERT_REPEATS). Behind that, a global per-minute cap and a
  bounded queue: an alert storm must not become a fork bomb or a webhook
  ban.

* **Syslog is a second sink, not a command.** With ALERTING_SYSLOG set
  (`host`, `host:port`, `[v6]:port`; 514/udp by default) every alert that
  passes the severity threshold and the cooldown is also sent there as one
  RFC 5424 datagram whose message is the alert's JSON (the same as
  $ALERT_JSON). It goes whether or not a command is set, and the per-minute
  cap does not apply: that cap protects the fork table and webhook quotas,
  and a datagram costs neither. It is sent from a thread of its own behind a
  bounded queue, so a name that will not resolve never stalls a poll. UDP
  syslog is fire-and-forget: "sent" means handed to the kernel, nothing
  more.

* **Tests must not repeat.** Grafana re-sends every box on every refresh, so
  a "test" box would fire once a minute for as long as it stayed filled. A
  test link carries a per-source token that is rotated when it is used; the
  re-sent request no longer matches and does nothing.
"""
import hashlib
import hmac
import io
import csv
import json
import os
import queue
import re
import secrets
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def env_int(name, default):
    try:
        return int(os.getenv(name, "") or default)
    except ValueError:
        return default


INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")
DNS_FILTER_URL = os.getenv("DNS_FILTER_URL", "http://dns-filter:8040")

STATE_DIR = os.getenv("STATE_DIR", "/var/lib/alerter")
STATE_FILE = os.path.join(STATE_DIR, "state.json")
LISTEN_PORT = env_int("LISTEN_PORT", 8090)              # control, not published
CONTROL = os.getenv("ALERTING_CONTROL", "rw").strip().lower() not in ("ro", "false", "off", "0")
POLL_SECONDS = max(5, env_int("ALERTING_POLL_SECONDS", 30))
LOOKBACK = max(120, env_int("ALERTING_LOOKBACK_SECONDS", 600))
REPEAT_SECONDS = max(0, env_int("ALERTING_REPEAT_SECONDS", 3600))
MAX_PER_MINUTE = max(1, env_int("ALERTING_MAX_PER_MINUTE", 20))
COMMAND_TIMEOUT = max(1, env_int("ALERTING_COMMAND_TIMEOUT", 20))
PARALLEL = max(1, env_int("ALERTING_PARALLEL", 4))
MAX_EVENTS = max(10, env_int("ALERTING_MAX_EVENTS_PER_POLL", 500))
MAX_COMMAND = 4000
PENDING_TTL = 900
SITE = os.getenv("ALERTING_SITE", "local")
GRAFANA_URL = os.getenv("ALERTING_GRAFANA_URL", "").rstrip("/")
LOCAL_SITE_UID = "InfluxDB_Flux"
# Commands drop to this uid/gid when the service runs as root (it does in the
# container). Outside a container -- the selftest -- there is nobody to drop to.
RUN_UID = env_int("ALERTING_RUN_UID", 65534)
RUN_GID = env_int("ALERTING_RUN_GID", 65534)

SEVERITY_NAMES = {1: "critical", 2: "high", 3: "medium", 4: "info"}

# Syslog: empty = off. host, host:port or [v6addr]:port; 514/udp by default.
SYSLOG_TARGET = os.getenv("ALERTING_SYSLOG", "").strip()
SYSLOG_FACILITY = os.getenv("ALERTING_SYSLOG_FACILITY", "local0").strip().lower()
FACILITIES = {"kern": 0, "user": 1, "daemon": 3, "auth": 4, "syslog": 5,
              "authpriv": 10, "security": 13, **{f"local{i}": 16 + i for i in range(8)}}
# Our 1-4 onto syslog's severities: crit, err, warning, info.
SYSLOG_SEVERITY = {1: 2, 2: 3, 3: 4, 4: 6}
# One datagram. RFC 5424 receivers SHOULD take 2048 bytes; rsyslog takes 8k.
# A longer alert has its detail values shortened rather than being cut, so the
# message always stays valid JSON.
SYSLOG_MAX_BYTES = max(480, env_int("ALERTING_SYSLOG_MAX_BYTES", 2048))


def parse_map(text, default):
    """`a=1,b=2` -> {a: 1, b: 2}, over a copy of `default`. Bad items are skipped."""
    out = dict(default)
    for item in (text or "").split(","):
        key, sep, value = item.strip().partition("=")
        if sep and key.strip():
            try:
                out[key.strip().lower()] = min(4, max(1, int(value)))
            except ValueError:
                pass
    return out


# Which dns-filter list refused a name decides how serious the lookup is. A
# name the IDS itself put on the blacklist (an alert named it as C2/phishing)
# is the strongest signal this stack has that a host is compromised; ads or
# gambling is policy, not an incident. `*` covers every other category, and a
# name on no list at all (blocked by some other resolver, or a list that has
# changed since) gets `?`.
DNS_SEVERITY = parse_map(os.getenv("ALERTING_DNS_SEVERITY", ""), {
    "_automatic": 1, "_blacklist": 3, "malware": 2, "phishing": 2,
    "cryptojacking": 2, "stalkerware": 2, "ddos": 2, "*": 4, "?": 4})
SCAN_SEVERITY = parse_map(os.getenv("ALERTING_SCAN_SEVERITY", ""),
                          {"internal": 2, "external": 4})
# Talking *to* a botnet C2 is a compromised host; talking to the rest of the
# lists is suspicious; being contacted *by* them is the internet's background.
REP_CRITICAL_FEEDS = {f.strip().lower() for f in
                      os.getenv("ALERTING_REPUTATION_CRITICAL_FEEDS", "feodo").split(",")
                      if f.strip()}
REP_SEVERITY = parse_map(os.getenv("ALERTING_REPUTATION_SEVERITY", ""),
                         {"critical": 1, "outbound": 2, "inbound": 4})

SOURCES = {
    "suricata": {"name": "Suricata IDS", "dashboard": "suricata-alerts",
                 "about": "Every Suricata alert, at the rule's own severity."},
    "dns": {"name": "Blocked DNS lookups", "dashboard": "dns-activity",
            "about": "A host asked for a name the router refused; severity from "
                     "the list that refused it (automatic C2 blacklist 1, "
                     "malware/phishing 2, hand-made blacklist 3, others 4)."},
    "arp": {"name": "ARP watch", "dashboard": "ethernet-attacks",
            "about": "ARP spoofing, poisoning, conflicts and floods, at "
                     "arp-watch's severity."},
    "wids": {"name": "Wireless IDS", "dashboard": "wireless-ids",
             "about": "Evil twins, spoofing, floods, handshake harvesting, at "
                      "wids' severity."},
    "scan": {"name": "Port scanners", "dashboard": "port-scanners",
             "about": "A source the flow verdict calls SCAN: internal 2, "
                      "external 4."},
    "reputation": {"name": "IP reputation", "dashboard": "ip-reputation",
                   "about": "A host talked to an address on an enabled "
                            "blocklist: outbound to a C2 feed 1, other "
                            "outbound 2, inbound 4."},
}
ORDER = list(SOURCES)

_state_lock = threading.Lock()


def log(msg):
    print(f"{datetime.now().strftime('%H:%M:%S')} {msg}", flush=True)


def now_iso(ts=None):
    return datetime.fromtimestamp(ts if ts is not None else time.time(),
                                  timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text):
    """Flux RFC3339 (nanoseconds, Z) -> epoch seconds."""
    text = (text or "").strip()
    if not text:
        return 0.0
    main, _, frac = text.rstrip("Z").partition(".")
    try:
        base = datetime.strptime(main, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return 0.0
    return base.timestamp() + (float("0." + frac) if frac.isdigit() else 0.0)


# ---------------------------------------------------------------------------
# InfluxDB
def esc_tag(value):
    return re.sub(r"([,= ])", r"\\\1", str(value)) or "none"


def esc_str(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def influx_write(lines):
    if not lines:
        return
    url = (f"{INFLUX_URL.rstrip('/')}/api/v2/write?org={urllib.parse.quote(INFLUX_ORG)}"
           f"&bucket={urllib.parse.quote(INFLUX_BUCKET)}&precision=ns")
    req = urllib.request.Request(url, data="\n".join(lines).encode(), method="POST",
                                 headers={"Authorization": f"Token {INFLUX_TOKEN}",
                                          "Content-Type": "text/plain; charset=utf-8"})
    try:
        urllib.request.urlopen(req, timeout=10).close()
    except (urllib.error.URLError, OSError) as exc:
        log(f"influx write error: {exc}")


def point(measurement, tags, fields, ts_ns=None):
    tag_text = "".join(f",{k}={esc_tag(v)}" for k, v in sorted(tags.items()))
    field_text = ",".join(f"{k}={v}" for k, v in fields.items())
    return f"{measurement}{tag_text} {field_text} {ts_ns or time.time_ns()}"


def parse_flux_csv(text):
    """Plain CSV: a header per table, a blank line between tables (the
    responder's reader; Flux's answer has a leading empty column)."""
    rows, header = [], None
    for record in csv.reader(io.StringIO(text)):
        if not record or not any(record):
            header = None
            continue
        if header is None:
            header = record
            continue
        rows.append(dict(zip(header, record)))
    return rows


def flux_rows(query, timeout=30):
    body = json.dumps({"query": query, "type": "flux",
                       "dialect": {"header": True, "annotations": []}}).encode()
    req = urllib.request.Request(
        f"{INFLUX_URL.rstrip('/')}/api/v2/query?org={urllib.parse.quote(INFLUX_ORG)}",
        data=body, method="POST",
        headers={"Authorization": f"Token {INFLUX_TOKEN}",
                 "Content-Type": "application/json", "Accept": "application/csv"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return parse_flux_csv(resp.read().decode("utf-8", "replace"))


# ---------------------------------------------------------------------------
# Sources: one query and one row -> event conversion each
def sev_regex(min_sev):
    return f"/^[1-{min(4, max(1, int(min_sev)))}]$/"


def query_for(source, lookback, min_sev, limit):
    """The Flux for one source. Tag-filtered severity and field selection both
    push down, so only the handful of rows that can alert are pivoted."""
    def q(measurement, fields, extra=""):
        field_filter = " or ".join(f'r._field == "{f}"' for f in fields)
        return (f'from(bucket: "{INFLUX_BUCKET}")\n'
                f'  |> range(start: -{int(lookback)}s)\n'
                f'  |> filter(fn: (r) => r._measurement == "{measurement}"{extra})\n'
                f'  |> filter(fn: (r) => {field_filter})\n'
                f'  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")\n'
                f'  |> group()\n'
                f'  |> sort(columns: ["_time"])\n'
                f'  |> limit(n: {int(limit)})\n')
    sev = f" and r.severity =~ {sev_regex(min_sev)}"
    if source == "suricata":
        return q("suricata_alert", ["count", "signature_id", "details", "src_port",
                                    "dst_port"], sev)
    if source == "arp":
        return q("arp_alert", ["count", "mac", "vendor", "other_mac", "other_vendor",
                               "detail"], sev)
    if source == "wids":
        return q("wids_alert", ["count", "detail", "ssid", "source"], sev)
    if source == "dns":
        return q("dns_block", ["count", "rrtype", "resolver"])
    if source == "scan":
        return q("port_scan", ["count", "attempts", "targets", "services", "completion"])
    if source == "reputation":
        return q("ip_reputation_hit", ["count", "flows", "bytes", "listed"])
    raise ValueError(source)


# Tags that identify a point, per measurement, for the seen-set id. Fields are
# not part of it: a point is its series and its time.
ID_TAGS = {
    "suricata": ("src_ip", "dst_ip", "signature", "severity", "proto"),
    "arp": ("alert", "ip", "vlan", "severity"),
    "wids": ("alert", "bssid", "severity"),
    "dns": ("src_ip", "qname"),
    "scan": ("src_ip", "scope", "outcome"),
    "reputation": ("internal_ip", "remote_ip", "direction", "feed"),
}


def event_id(source, row):
    raw = "|".join([source, row.get("_time", "")] + [row.get(t, "") for t in ID_TAGS[source]])
    return hashlib.sha1(raw.encode()).hexdigest()[:20]


def as_int(value, default=0):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def make_event(source, row, dns_lists=None):
    """A row of the source's query -> event dict, or None if it cannot be
    graded yet (a DNS name whose list is not known)."""
    ev = {"source": source, "id": event_id(source, row),
          "time": parse_time(row.get("_time")), "details": {}}
    d = ev["details"]
    if source == "suricata":
        sev = as_int(row.get("severity"), 4)
        sig = row.get("signature", "")
        d.update(signature=sig, sid=row.get("signature_id", ""),
                 category=row.get("category", ""), src_ip=row.get("src_ip", ""),
                 src_port=row.get("src_port", ""), dst_ip=row.get("dst_ip", ""),
                 dst_port=row.get("dst_port", ""), proto=row.get("proto", ""),
                 app_proto=row.get("app_proto", ""), action=row.get("action", ""),
                 decision=row.get("decision", ""), info=row.get("details", ""))
        ev.update(type="suricata.alert", severity=sev,
                  key=f"{d['sid'] or sig}|{d['src_ip']}|{d['dst_ip']}",
                  title=f"{sig} ({d['src_ip']}:{d['src_port']} -> "
                        f"{d['dst_ip']}:{d['dst_port']} {d['proto']})")
    elif source == "arp":
        sev = as_int(row.get("severity"), 4)
        kind = row.get("alert", "unknown")
        d.update(alert=kind, ip=row.get("ip", ""), vlan=row.get("vlan", ""),
                 mac=row.get("mac", ""), vendor=row.get("vendor", ""),
                 other_mac=row.get("other_mac", ""),
                 other_vendor=row.get("other_vendor", ""),
                 detail=row.get("detail", ""), count=row.get("count", ""))
        ev.update(type=f"arp.{kind}", severity=sev, key=f"{kind}|{d['ip']}|{d['vlan']}",
                  title=f"ARP {kind} {d['ip']}: {d['detail']}"[:300])
    elif source == "wids":
        sev = as_int(row.get("severity"), 4)
        kind = row.get("alert", "unknown")
        d.update(alert=kind, bssid=row.get("bssid", ""), ssid=row.get("ssid", ""),
                 transmitter=row.get("source", ""), detail=row.get("detail", ""),
                 count=row.get("count", ""))
        ev.update(type=f"wids.{kind}", severity=sev, key=f"{kind}|{d['bssid']}",
                  title=f"Wi-Fi {kind} {d['bssid']}: {d['detail']}"[:300])
    elif source == "dns":
        qname = row.get("qname", "")
        hit = (dns_lists or {}).get(qname)
        if hit is None:
            return None
        lst, origin = hit.get("list", ""), hit.get("source", "")
        if lst == "_blacklist":
            grade = "_automatic" if origin == "automatic" else "_blacklist"
        else:
            grade = lst or "?"
        sev = DNS_SEVERITY.get(grade, DNS_SEVERITY.get("*" if lst else "?", 4))
        listed = ("blacklist (automatic, from an IDS alert)" if grade == "_automatic"
                  else "blacklist" if grade == "_blacklist" else lst or "no known list")
        d.update(src_ip=row.get("src_ip", ""), qname=qname, list=lst or "",
                 list_source=origin, list_note=hit.get("note", ""),
                 rrtype=row.get("rrtype", ""), resolver=row.get("resolver", ""),
                 count=row.get("count", ""))
        ev.update(type="dns.blocked", severity=sev, key=f"{d['src_ip']}|{qname}",
                  title=f"{d['src_ip']} looked up {qname}, blocked by {listed}")
    elif source == "scan":
        scope = row.get("scope", "external")
        sev = SCAN_SEVERITY.get(scope, 4)
        d.update(src_ip=row.get("src_ip", ""), scope=scope,
                 outcome=row.get("outcome", ""), attempts=row.get("attempts", ""),
                 targets=row.get("targets", ""), services=row.get("services", ""),
                 completion=row.get("completion", ""))
        ev.update(type=f"scan.{scope}", severity=sev, key=d["src_ip"],
                  title=f"{scope} port scan from {d['src_ip']}: {d['attempts']} "
                        f"attempts, {d['targets']} targets, {d['services']} services "
                        f"({d['outcome']})")
    elif source == "reputation":
        direction = row.get("direction", "")
        feed = row.get("feed", "")
        if direction == "outbound":
            sev = REP_SEVERITY["critical" if feed.lower() in REP_CRITICAL_FEEDS else "outbound"]
        else:
            sev = REP_SEVERITY["inbound"]
        d.update(internal_ip=row.get("internal_ip", ""), remote_ip=row.get("remote_ip", ""),
                 direction=direction, feed=feed, listed=row.get("listed", ""),
                 flows=row.get("flows", ""), bytes=row.get("bytes", ""))
        arrow = "->" if direction == "outbound" else "<-"
        ev.update(type=f"reputation.{direction or 'unknown'}", severity=sev,
                  key=f"{d['internal_ip']}|{d['remote_ip']}|{direction}",
                  title=f"{d['internal_ip']} {arrow} {d['remote_ip']} "
                        f"(listed by {feed}, {d['flows']} flows)")
    else:
        return None
    ev["severity"] = min(4, max(1, ev["severity"]))
    return ev


def dns_which(names, timeout=10):
    """{name: {list, source, note}} from dns-filter, or raises."""
    out = {}
    names = sorted(set(n for n in names if n))
    for i in range(0, len(names), 100):
        chunk = names[i:i + 100]
        url = f"{DNS_FILTER_URL.rstrip('/')}/which?names=" + urllib.parse.quote(",".join(chunk))
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            for item in json.loads(resp.read().decode()):
                out[item.get("name", "")] = item
        for name in chunk:   # the reply normalises; keep the asked form too
            out.setdefault(name, out.get(name.lower().rstrip("."), {"list": "", "source": ""}))
    return out


# ---------------------------------------------------------------------------
# State
def default_state():
    return {"rules": {s: {"enabled": False, "min_severity": 2, "command": ""}
                      for s in ORDER},
            "default_command": "", "seen": {}, "cooldown": {},
            "primed": False}


def load_state(path=None):
    path = path or STATE_FILE
    state = default_state()
    try:
        with open(path) as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        return state, False
    for s in ORDER:
        rule = (saved.get("rules") or {}).get(s) or {}
        state["rules"][s].update({k: rule[k] for k in ("enabled", "min_severity", "command")
                                  if k in rule})
    state["default_command"] = saved.get("default_command", "")
    state["seen"] = dict(saved.get("seen") or {})
    state["cooldown"] = dict(saved.get("cooldown") or {})
    state["primed"] = bool(saved.get("primed"))
    return state, True


def save_state(state, path=None):
    path = path or STATE_FILE
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.chmod(tmp, 0o600)   # commands may hold webhook URLs
    os.replace(tmp, path)


# ---------------------------------------------------------------------------
# What an alert is, to the outside: $ALERT_JSON and the syslog message
def alert_payload(ev, test=False):
    sev = ev["severity"]
    dash = SOURCES.get(ev["source"], {}).get("dashboard", "")
    url = f"{GRAFANA_URL}/d/{dash}" if GRAFANA_URL and dash else ""
    return {"source": ev["source"],
            "source_name": SOURCES.get(ev["source"], {}).get("name", ev["source"]),
            "type": ev["type"], "severity": sev, "severity_name": SEVERITY_NAMES[sev],
            "title": ev["title"], "details": ev["details"], "time": now_iso(ev["time"]),
            "site": SITE, "id": ev["id"], "repeats": ev.get("repeats", 0),
            "test": bool(test), "url": url}


def parse_syslog_target(text):
    """`host`, `host:port`, `[v6]:port`, a bare v6 address -> (host, port)."""
    text = text.strip()
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        port = rest.lstrip(":")
    elif text.count(":") == 1:
        host, _, port = text.partition(":")
    else:
        host, port = text, ""
    return host, int(port) if port else 514


def syslog_token(text, limit):
    """RFC 5424 header fields: printable US-ASCII, no spaces, '-' if empty."""
    out = "".join(c for c in str(text) if 33 <= ord(c) <= 126)[:limit]
    return out or "-"


def syslog_message(ev, test=False, facility=None, hostname=None, max_bytes=None):
    """One RFC 5424 datagram: <PRI>1 TIMESTAMP HOST tzsp-monitor - MSGID - JSON.
    MSGID is the alert type; the message is the alert's JSON, shortened by
    detail value (never cut) to fit max_bytes."""
    facility = FACILITIES.get(facility or SYSLOG_FACILITY, 16)
    max_bytes = max_bytes or SYSLOG_MAX_BYTES
    pri = facility * 8 + SYSLOG_SEVERITY.get(ev["severity"], 6)
    ts = datetime.fromtimestamp(time.time(), timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    head = (f"<{pri}>1 {ts} {syslog_token(hostname or SITE, 255)} tzsp-monitor - "
            f"{syslog_token(ev['type'], 32)} - ").encode()
    payload = alert_payload(ev, test)
    for cap in (None, 256, 64, 0):
        if cap is not None:
            payload["details"] = {k: str(v)[:cap] for k, v in ev["details"].items()} if cap else {}
            payload["title"] = ev["title"][:max(cap, 200)]
        # BOM: RFC 5424 says the MSG is UTF-8 only when it starts with one.
        body = b"\xef\xbb\xbf" + json.dumps(payload, ensure_ascii=False).encode()
        if len(head) + len(body) <= max_bytes:
            break
    return (head + body)[:max_bytes]


class Syslog:
    """Sends alerts to one syslog server over UDP, from a thread of its own.
    The name is re-resolved at most once a minute, so a server that moves is
    followed and a resolver that hangs costs this thread, never a poll."""

    def __init__(self, target, start=True):
        self.target = target
        self.host, self.port = parse_syslog_target(target)
        self.queue = queue.Queue(maxsize=1000)
        self.counts = {"syslog_sent": 0, "syslog_failed": 0}
        self.count_lock = threading.Lock()
        self.addr, self.sock, self.resolved_at = None, None, 0.0
        self.last_error = ""
        if start:
            threading.Thread(target=self.run, daemon=True).start()

    def send(self, ev, test=False):
        try:
            self.queue.put_nowait(syslog_message(ev, test))
            return True
        except queue.Full:
            self.bump("syslog_failed")
            return False

    def bump(self, key):
        with self.count_lock:
            self.counts[key] += 1

    def take_counts(self):
        with self.count_lock:
            out = dict(self.counts)
            for k in self.counts:
                self.counts[k] = 0
        return out

    def resolve(self):
        if self.addr and time.monotonic() - self.resolved_at < 60:
            return
        family, _, _, _, addr = socket.getaddrinfo(self.host, self.port, 0,
                                                   socket.SOCK_DGRAM)[0]
        if self.sock is None or self.sock.family != family:
            if self.sock:
                self.sock.close()
            self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.addr, self.resolved_at = addr, time.monotonic()

    def deliver(self, data):
        try:
            self.resolve()
            self.sock.sendto(data, self.addr)
            self.bump("syslog_sent")
            self.last_error = ""
        except OSError as exc:
            self.bump("syslog_failed")
            self.addr = None             # resolve again next time
            if str(exc) != self.last_error:
                log(f"syslog: cannot send to {self.target}: {exc}")
            self.last_error = str(exc)

    def run(self):
        while True:
            self.deliver(self.queue.get())


# ---------------------------------------------------------------------------
# Running a command
def command_env(ev, test=False):
    """The command's whole environment. Built from nothing, on purpose: the
    service's own environment holds the InfluxDB token."""
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp", "LANG": "C.UTF-8",
           "TMPDIR": "/tmp"}
    env.update({k: v for k, v in os.environ.items() if k.startswith("ALERT_SECRET_")})
    sev = ev["severity"]
    lines = [f"{k}: {v}" for k, v in ev["details"].items() if v not in ("", None)]
    payload = alert_payload(ev, test)
    url = payload["url"]
    env.update({
        "ALERT_SOURCE": ev["source"],
        "ALERT_SOURCE_NAME": payload["source_name"],
        "ALERT_TYPE": ev["type"],
        "ALERT_SEVERITY": str(sev),
        "ALERT_SEVERITY_NAME": SEVERITY_NAMES[sev],
        "ALERT_TITLE": ev["title"],
        "ALERT_DETAILS": "\n".join(lines),
        "ALERT_JSON": json.dumps(payload, ensure_ascii=False),
        "ALERT_TIME": payload["time"],
        "ALERT_EPOCH": str(int(ev["time"])),
        "ALERT_SITE": SITE,
        "ALERT_ID": ev["id"],
        "ALERT_REPEATS": str(ev.get("repeats", 0)),
        "ALERT_TEST": "1" if test else "0",
        "ALERT_URL": url,
    })
    reserved = set(env)
    for key, value in ev["details"].items():
        name = "ALERT_" + re.sub(r"[^A-Z0-9_]", "_", str(key).upper())
        if name not in reserved:
            env[name] = "" if value is None else str(value)
    # Environment strings cannot carry NUL; anything else is the command's
    # business to quote ("$ALERT_TITLE").
    return {k: str(v).replace("\0", "") for k, v in env.items()}


def run_command(command, env, timeout=None):
    """(result, exit_code, output, duration_ms). Kills the whole process
    group on timeout and once the shell exits, so a backgrounded child cannot
    outlive the alert; output is kept to its first 2000 bytes and the rest is
    read and dropped, so `yes` cannot fill memory."""
    timeout = timeout or COMMAND_TIMEOUT
    kwargs = {}
    if os.geteuid() == 0 and RUN_UID >= 0:
        kwargs.update(user=RUN_UID, group=RUN_GID, extra_groups=[])
    started = time.monotonic()
    try:
        proc = subprocess.Popen(["/bin/sh", "-c", command], env=env, cwd="/tmp"
                                if os.path.isdir("/tmp") else None,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True,
                                close_fds=True, **kwargs)
    except OSError as exc:
        return "error", -1, f"could not start: {exc}", 0.0
    kept = bytearray()

    def drain():
        while True:
            chunk = proc.stdout.read1(4096) if hasattr(proc.stdout, "read1") else proc.stdout.read(4096)
            if not chunk:
                return
            if len(kept) < 2000:
                kept.extend(chunk[:2000 - len(kept)])

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    result = "ok"
    try:
        code = proc.wait(timeout=timeout)
        if code != 0:
            result = "failed"
    except subprocess.TimeoutExpired:
        result, code = "timeout", -9
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    reader.join(timeout=2)
    try:
        proc.stdout.close()
    except OSError:
        pass
    duration = (time.monotonic() - started) * 1000.0
    return result, code, kept.decode("utf-8", "replace"), duration


# ---------------------------------------------------------------------------
class Alerter:
    def __init__(self, state_path=None, write=influx_write, query=flux_rows,
                 which=dns_which, start_workers=True, syslog="env"):
        # "env": from ALERTING_SYSLOG (None when unset). Tests pass their own.
        self.syslog = (Syslog(SYSLOG_TARGET) if SYSLOG_TARGET else None) \
            if syslog == "env" else syslog
        self.state_path = state_path or STATE_FILE
        self.lookback = LOOKBACK
        self.write, self.query, self.which = write, query, which
        self.state, existed = load_state(self.state_path)
        # First start ever: nothing in the window may fire. Afterwards the
        # persisted seen-set makes a restart catch up on exactly what it missed.
        self.prime = set(ORDER) if not existed or not self.state.get("primed") else set()
        self.pending = None                     # {source, command, code, at}
        self.tokens = {s: secrets.token_hex(8) for s in ORDER + ["default"]}
        self.last = {s: {"at": "", "result": "", "title": ""} for s in ORDER + ["default"]}
        self.message = ""
        self.lock = threading.Lock()
        self.queue = queue.Queue(maxsize=200)
        self.sent_times = []                    # monotonic, for the per-minute cap
        self.counters = {"events": 0, "fired": 0, "suppressed": 0, "rate_limited": 0,
                         "dropped": 0, "no_command": 0, "failed": 0, "truncated": 0}
        self.query_error = ""
        self.query_ms = 0.0
        self.dns_cache = {}                     # qname -> (hit, expiry)
        if start_workers:
            for _ in range(PARALLEL):
                threading.Thread(target=self.worker, daemon=True).start()

    # ---- rules ----------------------------------------------------------
    def effective(self, source):
        if source == "default":
            return self.state["default_command"], "default"
        own = self.state["rules"][source]["command"]
        if own:
            return own, "own"
        if self.state["default_command"]:
            return self.state["default_command"], "default"
        return "", "none"

    def rows(self):
        out = []
        for s in ORDER:
            rule = self.state["rules"][s]
            command, origin = self.effective(s)
            ms = int(rule["min_severity"])
            out.append({
                "source": s, "name": SOURCES[s]["name"], "about": SOURCES[s]["about"],
                "enabled": 1 if rule["enabled"] else 0,
                "min_severity": ms,
                "severity_text": f"{ms} {SEVERITY_NAMES[ms]}" + (" and above" if ms > 1 else " only"),
                "command": rule["command"],
                "effective_command": command or "(none: nothing will run)",
                "command_origin": origin,
                "test_token": self.tokens[s],
                "last_at": self.last[s]["at"], "last_result": self.last[s]["result"],
                "last_title": self.last[s]["title"],
            })
        out.append({
            "source": "default", "name": "Default command",
            "about": "Runs for every enabled source that has no command of its own.",
            "enabled": -1, "min_severity": -1, "severity_text": "",
            "command": self.state["default_command"],
            "effective_command": self.state["default_command"] or "(none)",
            "command_origin": "default", "test_token": self.tokens["default"],
            "last_at": self.last["default"]["at"],
            "last_result": self.last["default"]["result"],
            "last_title": self.last["default"]["title"]})
        return out

    def state_code(self):
        enabled = [s for s in ORDER if self.state["rules"][s]["enabled"]]
        if self.query_error:
            return 0
        if not enabled:
            return 1
        if not self.syslog and not any(self.effective(s)[0] for s in enabled):
            return 2                     # syslog alone is somewhere for alerts to go
        return 3

    def status(self):
        p = self.pending
        return {"control": 1 if CONTROL else 0, "state_code": self.state_code(),
                "enabled": sum(1 for s in ORDER if self.state["rules"][s]["enabled"]),
                "pending": 1 if p else 0, "message": self.message or "-",
                "error": self.query_error or "", "query_ms": round(self.query_ms, 1),
                "syslog": self.syslog.target if self.syslog else "-",
                "secrets": ",".join(sorted(k[len("ALERT_SECRET_"):] for k in os.environ
                                           if k.startswith("ALERT_SECRET_"))) or "-"}

    def pending_rows(self):
        p = self.pending
        if not p or time.time() - p["at"] > PENDING_TTL:
            self.pending = None
            return []
        current, _ = (self.effective(p["source"]) if p["source"] == "default"
                      else (self.state["rules"][p["source"]]["command"], ""))
        return [{"source": p["source"],
                 "name": "Default command" if p["source"] == "default"
                 else SOURCES[p["source"]]["name"],
                 "current": current or "(none)", "new": p["command"] or "(none: clear it)",
                 "code": p["code"], "expires": now_iso(p["at"] + PENDING_TTL),
                 "confirm": "Confirm", "cancel": "Cancel"}]

    def audit(self, action, source, detail):
        self.write([point("alerting_control", {"action": action, "source": source},
                          {"count": "1i", "detail": esc_str(detail[:500])})])

    def apply(self, q):
        """Every box of the dashboard, every refresh. Idempotent: only a real
        change is saved, audited and reported."""
        def vals(name):
            return [v.strip() for raw in q.get(name, []) for v in raw.split(",") if v.strip()]

        changes, problems = [], []
        with self.lock:
            wants_change = any(vals(n) for n in ("enable", "disable", "severity", "confirm",
                                                 "cancel", "test")) or (
                q.get("command_for", [""])[0].strip() and "command" in q)
            if wants_change and not CONTROL:
                problems.append("ALERTING_CONTROL=ro: alerting is read-only")
            elif wants_change:
                if "default" in vals("enable") + vals("disable") + [
                        v.partition(":")[0] for v in vals("severity")]:
                    problems.append("the default command has no on/off or severity: "
                                    "it runs for every enabled source without its own")
                for s in vals("enable"):
                    if s == "default":
                        continue
                    if s not in SOURCES:
                        problems.append(f"no such source '{s}'")
                    elif not self.state["rules"][s]["enabled"]:
                        self.state["rules"][s]["enabled"] = True
                        self.prime.add(s)
                        changes.append(("enable", s, "on"))
                for s in vals("disable"):    # after enable: a stale enable box loses
                    if s in SOURCES and self.state["rules"][s]["enabled"]:
                        self.state["rules"][s]["enabled"] = False
                        changes.append(("disable", s, "off"))
                for item in vals("severity"):
                    s, _, level = item.partition(":")
                    if s == "default":
                        continue
                    if s not in SOURCES or level not in ("1", "2", "3", "4"):
                        problems.append(f"severity '{item}' is not <source>:<1-4>")
                        continue
                    old = int(self.state["rules"][s]["min_severity"])
                    if old != int(level):
                        self.state["rules"][s]["min_severity"] = int(level)
                        if int(level) > old:
                            self.prime.add(s)   # newly eligible history must not fire
                        changes.append(("severity", s, f"{old} -> {level}"))
                self._stage(q, changes, problems)
                for code in vals("confirm"):
                    self._confirm(code, changes, problems)
                for code in vals("cancel"):
                    p = self.pending
                    if p and hmac.compare_digest(p["code"], code):
                        self.pending = None
                        changes.append(("cancel", p["source"], "staged command discarded"))
                for item in vals("test"):
                    s, _, token = item.partition(":")
                    if s in self.tokens and token and hmac.compare_digest(self.tokens[s], token):
                        self.tokens[s] = secrets.token_hex(8)
                        self.enqueue_test(s, changes, problems)
            if changes:
                if any(a in ("enable", "disable", "severity", "command") for a, _, _ in changes):
                    self.save()
                for action, source, detail in changes:
                    if action != "stage":
                        self.audit(action, source, detail)
                    log(f"control: {action} {source}: {detail}")
            if problems or changes:
                self.message = "; ".join(problems) if problems else (
                    now_iso()[11:19] + " UTC: " + "; ".join(
                        f"{a} {s}" + (f" ({d})" if a in ("severity", "stage", "test") else "")
                        for a, s, d in changes))
                for why in problems:
                    log(f"control: refused: {why}")
        return self.rows()

    def _stage(self, q, changes, problems):
        target = q.get("command_for", [""])[0].strip()
        if not target or "command" not in q:
            return
        if target != "default" and target not in SOURCES:
            problems.append(f"no such source '{target}'")
            return
        command = q.get("command", [""])[0].strip()
        if len(command) > MAX_COMMAND or "\0" in command:
            problems.append(f"command longer than {MAX_COMMAND} characters or not text")
            return
        current = (self.state["default_command"] if target == "default"
                   else self.state["rules"][target]["command"])
        p = self.pending
        if command == current:
            return                       # the edit link pre-fills what is there
        if p and p["source"] == target and p["command"] == command \
                and time.time() - p["at"] <= PENDING_TTL:
            return                       # the same stage, re-sent by a refresh
        self.pending = {"source": target, "command": command,
                        "code": secrets.token_hex(12), "at": time.time()}
        changes.append(("stage", target, "confirm it in Pending Command Change"))

    def _confirm(self, code, changes, problems):
        p = self.pending
        if not p or not hmac.compare_digest(p["code"], code):
            return                       # consumed already: the URL keeps it
        if time.time() - p["at"] > PENDING_TTL:
            self.pending = None
            problems.append("the staged command expired; type it again")
            return
        if p["source"] == "default":
            self.state["default_command"] = p["command"]
        else:
            self.state["rules"][p["source"]]["command"] = p["command"]
        self.pending = None
        changes.append(("command", p["source"], p["command"] or "(cleared)"))

    def save(self):
        with _state_lock:
            save_state(self.state, self.state_path)

    # ---- firing ---------------------------------------------------------
    def enqueue_test(self, source, changes, problems):
        command, origin = self.effective(source)
        if not command and not self.syslog:
            problems.append(f"test {source}: no command to run (set one, or a default)")
            return
        rule = self.state["rules"].get(source, {"min_severity": 1})
        sev = int(rule["min_severity"])
        name = SOURCES.get(source, {}).get("name", "Default command")
        ev = {"source": source if source in SOURCES else "test", "id": secrets.token_hex(10),
              "time": time.time(), "type": f"{source}.test", "severity": sev,
              "title": f"Test alert from tzsp-monitor alerting ({name})",
              "key": "", "details": {"note": "sent from the Alerting dashboard's Test link"}}
        if self.syslog:
            self.syslog.send(ev, test=True)
        if not command:
            changes.append(("test", source, f"sent to syslog {self.syslog.target} only, "
                                            "no command to run"))
            return
        try:
            self.queue.put_nowait((ev, command, origin, True, source))
            changes.append(("test", source, f"queued, {origin} command"))
        except queue.Full:
            problems.append("the command queue is full; try again in a minute")

    def admit(self, ev, now=None):
        """Cooldown per key. Returns True to fire (with ev['repeats'] set)."""
        now = now or time.time()
        if not REPEAT_SECONDS or not ev.get("key"):
            ev["repeats"] = 0
            return True
        key = f"{ev['source']}|{ev['key']}"
        last, held = self.state["cooldown"].get(key, [0, 0])
        if now - last < REPEAT_SECONDS:
            self.state["cooldown"][key] = [last, held + 1]
            return False
        self.state["cooldown"][key] = [now, 0]
        ev["repeats"] = held
        return True

    def rate_ok(self):
        now = time.monotonic()
        self.sent_times = [t for t in self.sent_times if now - t < 60]
        if len(self.sent_times) >= MAX_PER_MINUTE:
            return False
        self.sent_times.append(now)
        return True

    def fire(self, ev):
        # Syslog first and regardless of the command: it is a sink of its own,
        # and the per-minute cap below is about forks and webhooks, not datagrams.
        if self.syslog:
            self.syslog.send(ev)
        command, origin = self.effective(ev["source"])
        if not command:
            self.counters["no_command"] += 1
            return
        if not self.rate_ok():
            self.counters["rate_limited"] += 1
            self.record(ev, "rate-limited", None, "", 0.0, origin)
            return
        try:
            self.queue.put_nowait((ev, command, origin, False, ev["source"]))
            self.counters["fired"] += 1
        except queue.Full:
            self.counters["dropped"] += 1
            self.record(ev, "queue-full", None, "", 0.0, origin)

    def worker(self):
        while True:
            ev, command, origin, test, row = self.queue.get()
            try:
                result, code, output, ms = run_command(command, command_env(ev, test))
            except Exception as exc:          # never lose the worker
                result, code, output, ms = "error", -1, str(exc), 0.0
            if result != "ok":
                self.counters["failed"] += 1
            label = f"test-{result}" if test else result
            self.last[row] = {"at": now_iso(), "result": label, "title": ev["title"][:200]}
            log(f"[ALERT] {ev['type']} sev {ev['severity']} {label} (exit {code}, "
                f"{ms:.0f} ms): {ev['title'][:160]}"
                + (f" | {output.strip()[:200]}" if result != "ok" and output.strip() else ""))
            self.record(ev, label, code, output, ms, origin)

    def record(self, ev, result, code, output, ms, origin):
        fields = {"count": "1i", "title": esc_str(ev["title"][:500]),
                  "duration_ms": f"{ms:.1f}", "repeats": f"{int(ev.get('repeats', 0))}i",
                  "output": esc_str(output.strip()[:1000]), "command": esc_str(origin),
                  "alert_id": esc_str(ev["id"])}
        if code is not None:
            fields["exit_code"] = f"{int(code)}i"
        self.write([point("alert_dispatch", {"source": ev["source"], "type": ev["type"],
                                             "severity": str(ev["severity"]),
                                             "result": result}, fields)])

    # ---- polling --------------------------------------------------------
    def poll_source(self, source, now):
        rule = self.state["rules"][source]
        min_sev = int(rule["min_severity"])
        priming = source in self.prime
        rows = self.query(query_for(source, self.lookback, min_sev, MAX_EVENTS))
        if len(rows) >= MAX_EVENTS:
            self.counters["truncated"] += 1
            log(f"{source}: {len(rows)} rows in {self.lookback}s, the per-poll limit "
                "(ALERTING_MAX_EVENTS_PER_POLL); older ones beyond it are not seen")
        seen = self.state["seen"]
        fresh = [r for r in rows if event_id(source, r) not in seen]
        dns_lists = {}
        if source == "dns" and fresh and not priming:
            dns_lists = self.dns_lookup({r.get("qname", "") for r in fresh}, now)
        fired = 0
        for row in fresh:
            ev = make_event(source, row, dns_lists)
            if ev is None:
                # Not gradable yet (dns-filter unreachable). Retried next poll
                # until half the look-back has passed, then graded unknown.
                if now - parse_time(row.get("_time")) < self.lookback / 2:
                    continue
                ev = make_event(source, row, {row.get("qname", ""): {"list": "", "source": ""}})
            seen[ev["id"]] = max(ev["time"], now) + self.lookback * 2
            if priming or ev["severity"] > min_sev:
                continue
            self.counters["events"] += 1
            if not self.admit(ev, now):
                self.counters["suppressed"] += 1
                continue
            self.fire(ev)
            fired += 1
        if priming:
            self.prime.discard(source)
            log(f"{source}: primed -- {len(fresh)} point(s) already in the window "
                "are history, not alerts")
        return fired

    def dns_lookup(self, names, now):
        out, ask = {}, []
        for name in names:
            hit = self.dns_cache.get(name)
            if hit and hit[1] > now:
                out[name] = hit[0]
            elif name:
                ask.append(name)
        if ask:
            try:
                got = self.which(ask)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                log(f"dns: dns-filter /which failed ({exc}); grading those lookups later")
                return out
            for name in ask:
                hit = got.get(name, {"list": "", "source": ""})
                self.dns_cache[name] = (hit, now + 600)
                out[name] = hit
        if len(self.dns_cache) > 20000:
            self.dns_cache.clear()
        return out

    def poll(self, now=None):
        now = now or time.time()
        started = time.monotonic()
        errors = []
        with self.lock:
            enabled = [s for s in ORDER if self.state["rules"][s]["enabled"]]
        for source in enabled:
            try:
                with self.lock:
                    self.poll_source(source, now)
            except (urllib.error.URLError, OSError, ValueError) as exc:
                errors.append(f"{source}: {exc}"[:200])
                log(f"{source}: query failed: {exc}")
        with self.lock:
            # Prune: seen ids past their expiry, cooldowns long over.
            self.state["seen"] = {k: v for k, v in self.state["seen"].items() if v > now}
            if len(self.state["seen"]) > 50000:
                keep = sorted(self.state["seen"].items(), key=lambda kv: kv[1])[-50000:]
                self.state["seen"] = dict(keep)
            horizon = max(REPEAT_SECONDS, 60) * 2
            self.state["cooldown"] = {k: v for k, v in self.state["cooldown"].items()
                                      if now - v[0] < horizon}
            # Sources that are off are primed when they come back on; nothing
            # else needs the first-start flag after one full pass.
            self.prime &= set(enabled)
            self.state["primed"] = True
            self.query_error = "; ".join(errors)
            self.query_ms = (time.monotonic() - started) * 1000.0
            self.save()
            c = dict(self.counters)
            for k in self.counters:
                self.counters[k] = 0
            code = self.state_code()
            enabled_n = len(enabled)
        if self.syslog:
            c.update(self.syslog.take_counts())
        fields = {k: f"{v}i" for k, v in c.items()}
        fields.update(up="1i", state_code=f"{code}i", enabled=f"{enabled_n}i",
                      queue=f"{self.queue.qsize()}i", query_ms=f"{self.query_ms:.1f}",
                      error=esc_str(self.query_error))
        self.write([point("alerter", {}, fields)])
        if c["fired"] or c["suppressed"] or c["rate_limited"] or c["dropped"]:
            log(f"[POLL] {c['events']} event(s): {c['fired']} fired, {c['suppressed']} held "
                f"by cooldown, {c['rate_limited']} over the per-minute cap, "
                f"{c['dropped']} dropped (queue full), {c['no_command']} without a command")


# ---------------------------------------------------------------------------
def is_local(q):
    return q.get("site", [LOCAL_SITE_UID])[0] in ("", LOCAL_SITE_UID)


def serve(alerter, port):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            local = is_local(q)
            if parsed.path in ("/apply", "/rules"):
                # Another site's rules shown as this one's would mislead, and a
                # click there must not change this instance.
                body = (alerter.apply(q) if parsed.path == "/apply" else alerter.rows()) \
                    if local else []
            elif parsed.path == "/pending":
                if local and parsed.query:
                    alerter.apply(q)     # whichever panel renders first acts
                body = alerter.pending_rows() if local else []
            elif parsed.path == "/status":
                if local and parsed.query:
                    alerter.apply(q)
                body = [alerter.status() if local else
                        {"control": 2, "state_code": -2, "enabled": -1, "pending": 0,
                         "message": "another site: alerting acts on this instance only",
                         "error": "", "query_ms": 0, "secrets": "-", "syslog": "-"}]
            else:
                self.send_response(404)
                self.end_headers()
                return
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def main():
    os.makedirs(STATE_DIR, exist_ok=True)
    alerter = Alerter()
    serve(alerter, LISTEN_PORT)
    on = [s for s in ORDER if alerter.state["rules"][s]["enabled"]]
    secrets_found = alerter.status()["secrets"]
    log(f"alerter: poll {POLL_SECONDS}s, look-back {LOOKBACK}s, cooldown {REPEAT_SECONDS}s, "
        f"max {MAX_PER_MINUTE}/min, {PARALLEL} parallel, timeout {COMMAND_TIMEOUT}s; "
        f"control {'read-write' if CONTROL else 'READ-ONLY'}; enabled: {', '.join(on) or 'none'}; "
        f"secrets: {secrets_found}; syslog: "
        f"{alerter.syslog.target + ' (udp, ' + SYSLOG_FACILITY + ')' if alerter.syslog else 'off'}; "
        f"commands run as "
        f"{'uid %d' % RUN_UID if os.geteuid() == 0 else 'this user (not root)'}")
    if alerter.syslog and SYSLOG_FACILITY not in FACILITIES:
        log(f"syslog: unknown facility '{SYSLOG_FACILITY}', using local0 "
            f"(one of: {', '.join(FACILITIES)})")
    while True:
        try:
            alerter.poll()
        except Exception as exc:                 # keep polling whatever happens
            log(f"poll failed: {exc!r}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
