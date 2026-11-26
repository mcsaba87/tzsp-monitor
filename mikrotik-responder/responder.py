r"""Turn Suricata alerts into Mikrotik address-list entries and InfluxDB points.

    suricata eve.json --> [this service] --> InfluxDB   (the alerts dashboard)
                                        \-> RouterOS REST API (address lists)
                                        \-> dns-filter        (DNS blacklist)

Three responses, each with its own gates, all off the tailing thread:

* **block** -- the *external* end of a severe, repeated alert goes on
  `mikrotik.address_list` (the original response);
* **quarantine** -- an *internal* host that trips a compromise signature
  (C2, trojan, miner) goes on `quarantine.list`, so a hand-made firewall rule
  can cut it off from everything but DNS and the helpdesk;
* **domain** -- a domain such an alert names (TLS SNI, HTTP Host, DNS query)
  goes on dns-filter's blacklist with an expiry, so the C2 is unreachable by
  name for every client, not just by today's IP;
* **scanners** -- a source the Port Scanners dashboard's flow verdict calls
  SCAN, or that keeps tripping ET SCAN signatures, goes on `scanners.list`.

Everything configurable lives in a property file (see suricata.properties.example),
not in the environment, because the router credentials and the never-block list
are site data that must not end up in `docker inspect` output or in Grafana's
environment.

The two rules that shape the whole design:

* **Blocking is the dangerous half.** Every path that ends in a router write is
  gated: the whitelist is checked before anything else, non-global addresses are
  refused outright, an address must alert `block.min_alerts` times inside
  `block.window_seconds`, alerts older than `block.max_age_seconds` never block
  (so a restart cannot replay yesterday onto the firewall), and entries are
  written with a RouterOS-side timeout so the block fails open if this stack
  dies. Shipping an alert to the dashboard, by contrast, is free of consequence
  and is done unconditionally.

* **The decision and the outcome are different facts.** `suricata_alert` records
  what we decided to do with an alert; `suricata_block` records what the router
  actually said. Router calls happen on a worker thread, so tailing eve.json
  never stalls on an unreachable router -- which means the outcome is simply not
  known yet when the alert point is written.
"""
import base64
import collections
import csv
import io
import ipaddress
import json
import os
import queue
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

PROPERTIES_FILE = os.getenv("PROPERTIES_FILE", "/etc/tzsp-monitor/suricata.properties")
EVE_FILE = os.getenv("EVE_FILE", "/var/log/suricata/eve.json")
DNS_FILTER_URL = os.getenv("DNS_FILTER_URL", "http://dns-filter:8040")
STATE_FILE = os.getenv("STATE_FILE", "/var/lib/responder/position.json")

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

IDLE_POLL = 0.5  # seconds to wait when eve.json has nothing new
MAINTENANCE_INTERVAL = 60


_log_lock = threading.Lock()


def log(msg):
    # One write per line under a lock: `print` emits the text and the newline
    # separately, so the tailing thread and the router worker interleave
    # mid-line without this.
    with _log_lock:
        sys.stdout.write(f"{datetime.now().strftime('%H:%M:%S')} {msg}\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Property file
# ---------------------------------------------------------------------------
class Config:
    """`key = value` property file with typed access and defaults.

    `#` only starts a comment at the start of a line: passwords contain `#`
    often enough that stripping trailing comments would be a support call.
    """

    def __init__(self, path):
        self.path = path
        self.values = {}
        self.present = os.path.isfile(path)
        if not self.present:
            log(f"no property file at {path}: alerts will be shipped to InfluxDB, "
                f"but nothing will be sent to a router. Copy "
                f"suricata.properties.example to enable blocking.")
            return
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("!"):
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                self.values[key.strip()] = value.strip()

    def get(self, key, default=""):
        return self.values.get(key, default)

    def get_int(self, key, default):
        try:
            return int(self.get(key, "") or default)
        except ValueError:
            log(f"{key}: not an integer, using {default}")
            return default

    def get_bool(self, key, default):
        value = self.get(key, "").lower()
        if value in ("true", "yes", "1", "on"):
            return True
        if value in ("false", "no", "0", "off"):
            return False
        return default

    def get_list(self, key):
        return [item.strip() for item in self.get(key).split(",") if item.strip()]


# ---------------------------------------------------------------------------
# Several routers. The same block in responder.py, dns-filter/filter.py and
# ip-reputation/reputation.py (each service is its own build context, and they
# are stdlib-only single files) -- keep them in step.
# ---------------------------------------------------------------------------
ROLES = ("block", "quarantine", "dns_filter", "ip_reputation", "scanners")
_warned = set()


def warn_once(msg):
    """Config complaints are found on every lookup; say each one once."""
    if msg not in _warned:
        _warned.add(msg)
        log(msg)


class RouterConfig(Config):
    """One router's view of the property file.

    The unprefixed `mikrotik.*` keys are the first router (named by
    `mikrotik.name`, default `main`), exactly as before there was more than
    one. `mikrotik.routers` names the rest; each reads `mikrotik.<name>.<key>`
    first and falls back to the unprefixed key, so a second router usually
    needs only a host and a password. `host` and `roles` are never inherited:
    a router nobody named must not be reached by accident, and narrowing the
    first router's roles must not narrow everyone's.
    """

    NOT_INHERITED = ("host", "roles")

    def __init__(self, base, name, primary):          # noqa: super not called
        self.path = getattr(base, "path", "")
        self.values, self.present = base.values, base.present
        self.name, self.primary = name, primary

    def get(self, key, default=""):
        if key.startswith("mikrotik.") and not self.primary:
            sub = key[len("mikrotik."):]
            own = self.values.get(f"mikrotik.{self.name}.{sub}")
            if own is not None:
                return own
            if sub in self.NOT_INHERITED:
                return default
        return self.values.get(key, default)

    @property
    def roles(self):
        """`mikrotik[.<name>].roles`; empty means every role."""
        listed = {r.strip().lower() for r in self.get("mikrotik.roles").split(",")
                  if r.strip()}
        unknown = listed - set(ROLES)
        if unknown:
            warn_once(f"router {self.name}: unknown role(s) {', '.join(sorted(unknown))} "
                f"ignored (known: {', '.join(ROLES)})")
        return (listed & set(ROLES)) or set(ROLES)


def router_hosts(cfg):
    """The address of every router, whatever its roles -- never to be blocked
    or quarantined by anything here."""
    hosts = []
    for role in ROLES:
        for rc in router_configs(cfg, role):
            host = rc.get("mikrotik.host")
            if host and host not in hosts:
                hosts.append(host)
    return hosts


def router_configs(cfg, role):
    """Every router that has `role`, the first router first. The first one is
    left out only when it has no host and others are listed -- a setup that
    names its routers explicitly does not need the unprefixed ones."""
    names = [(cfg.get("mikrotik.name", "main").strip().lower() or "main")]
    for name in cfg.get_list("mikrotik.routers"):
        name = name.lower()
        if not re.fullmatch(r"[a-z0-9_\-]{1,32}", name) or name in names:
            warn_once(f"mikrotik.routers: ignoring {name!r} (bad or duplicate name)")
            continue
        names.append(name)
    routers = [RouterConfig(cfg, name, i == 0) for i, name in enumerate(names)]
    if len(routers) > 1 and not routers[0].get("mikrotik.host"):
        routers = routers[1:]
    return [rc for rc in routers if role in rc.roles]


# ---------------------------------------------------------------------------
# InfluxDB
# ---------------------------------------------------------------------------
def esc_tag(value):
    return (str(value).replace("\\", "\\\\").replace(" ", "\\ ")
            .replace(",", "\\,").replace("=", "\\="))


def esc_str(value):
    flat = str(value).replace("\r", " ").replace("\n", " ")
    return '"' + flat.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Influx:
    """Buffered InfluxDB v2 line-protocol writer, stdlib only.

    Batched because a burst of alerts arrives as fast as eve.json can be read,
    and one HTTP round trip per alert would make the tail fall behind.
    """

    def __init__(self, url, token, org, bucket, batch=200, interval=2.0):
        self.endpoint = (f"{url.rstrip('/')}/api/v2/write"
                         f"?org={urllib.parse.quote(org)}"
                         f"&bucket={urllib.parse.quote(bucket)}&precision=ns")
        self.headers = {"Authorization": f"Token {token}",
                        "Content-Type": "text/plain; charset=utf-8"}
        self.batch = batch
        self.interval = interval
        self.lock = threading.Lock()
        self.buffer = []
        threading.Thread(target=self._flush_forever, daemon=True).start()

    def point(self, measurement, tags, fields, timestamp_ns=None):
        parts = [measurement]
        for key, value in tags.items():
            if value in (None, ""):
                value = "unknown"  # InfluxDB silently drops empty tag values
            parts.append(f"{esc_tag(key)}={esc_tag(value)}")
        line = ",".join(parts) + " " + ",".join(
            f"{esc_tag(k)}={v}" for k, v in fields.items())
        if timestamp_ns:
            line += f" {timestamp_ns}"
        with self.lock:
            self.buffer.append(line)
            due = len(self.buffer) >= self.batch
        if due:
            self.flush()

    def flush(self):
        with self.lock:
            if not self.buffer:
                return
            body = "\n".join(self.buffer).encode()
            self.buffer = []
        req = urllib.request.Request(self.endpoint, data=body,
                                     headers=self.headers, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10).close()
        except urllib.error.HTTPError as exc:
            log(f"influx write rejected ({exc.code}): {exc.read()[:300]!r}")
        except (urllib.error.URLError, OSError) as exc:
            log(f"influx write failed: {exc}")

    def _flush_forever(self):
        while True:
            time.sleep(self.interval)
            self.flush()


# ---------------------------------------------------------------------------
# RouterOS REST client
# ---------------------------------------------------------------------------
class RouterError(Exception):
    pass


class ListTarget:
    """Which address list a write goes to, with its own expiry and comment."""

    def __init__(self, list_name, timeout, comment_prefix):
        self.list_name = list_name
        self.timeout = timeout
        self.comment_prefix = comment_prefix


class Mikrotik:
    """Just enough of the RouterOS v7 REST API to maintain one address list.

    RouterOS maps REST verbs onto its own CLI: PUT on a collection adds a row,
    PATCH on `/collection/<.id>` edits one. Re-adding an address that is already
    listed is an error rather than a no-op, so a repeat offender is handled by
    looking the row up and patching its timeout -- that refreshes the block
    instead of failing.
    """

    def __init__(self, cfg):
        self.name = getattr(cfg, "name", "main")
        self.host = cfg.get("mikrotik.host")
        self.user = cfg.get("mikrotik.user")
        self.password = cfg.get("mikrotik.password")
        self.list_name = cfg.get("mikrotik.address_list", "suricata-blocked")
        self.timeout_value = cfg.get("mikrotik.timeout", "1h")
        self.comment_prefix = cfg.get("mikrotik.comment_prefix", "suricata")
        self.request_timeout = cfg.get_int("mikrotik.request_timeout", 5)
        self.dry_run = cfg.get_bool("mikrotik.dry_run", False)

        scheme = cfg.get("mikrotik.scheme", "https")
        port = cfg.get_int("mikrotik.port", 443 if scheme == "https" else 80)
        self.base = f"{scheme}://{self.host}:{port}/rest"

        if scheme == "https" and not cfg.get_bool("mikrotik.verify_tls", False):
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context))
        token = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}",
                        "Content-Type": "application/json"}
        self.default_target = ListTarget(self.list_name, self.timeout_value,
                                         self.comment_prefix)

    def _call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data,
                                     headers=self.headers, method=method)
        try:
            with self.opener.open(req, timeout=self.request_timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise RouterError(f"HTTP {exc.code} {detail}") from exc
        except (urllib.error.URLError, OSError, ssl.SSLError) as exc:
            raise RouterError(str(exc)) from exc
        return json.loads(raw) if raw.strip() else None

    def block(self, ip, signature, target=None):
        """Add or refresh `ip` on an address list. Returns a result label.

        `target` is a ListTarget; without one it is the block list itself."""
        target = target or self.default_target
        comment = f"{target.comment_prefix}: {signature}"[:255]
        entry = {"list": target.list_name, "address": ip, "comment": comment}
        if target.timeout:
            entry["timeout"] = target.timeout

        if self.dry_run:
            log(f"[dry-run] would add {ip} to '{target.list_name}' "
                f"timeout={target.timeout or 'none'} ({signature})")
            return "dry-run"

        try:
            self._call("PUT", "/ip/firewall/address-list", entry)
            return "added"
        except RouterError as exc:
            if "already have such entry" not in str(exc):
                raise
        return self._refresh(ip, entry)

    def _refresh(self, ip, entry):
        query = urllib.parse.urlencode({"list": entry["list"], "address": ip})
        rows = self._call("GET", f"/ip/firewall/address-list?{query}") or []
        if not rows:
            # Listed a moment ago, gone now (manual removal, or a timeout that
            # expired between the two calls). Nothing left to refresh.
            return "vanished"
        row_id = urllib.parse.quote(rows[0].get(".id", ""), safe="*")
        patch = {k: v for k, v in entry.items() if k in ("timeout", "comment")}
        self._call("PATCH", f"/ip/firewall/address-list/{row_id}", patch)
        return "refreshed"

    def probe(self):
        """Router reachability + credentials, for the dashboard tile."""
        started = time.monotonic()
        info = self._call("GET", "/system/resource")
        latency_ms = (time.monotonic() - started) * 1000.0
        version = (info or {}).get("version", "unknown")
        return latency_ms, version


# ---------------------------------------------------------------------------
# Block policy
# ---------------------------------------------------------------------------
class Policy:
    """Decides whether an alert may reach the router, and for which address."""

    def __init__(self, cfg):
        self.networks = []
        for item in cfg.get_list("whitelist.networks") + cfg.get_list("whitelist.ips"):
            try:
                self.networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                log(f"whitelist: ignoring unparseable entry {item!r}")
        self.max_severity = cfg.get_int("block.max_severity", 2)
        self.min_alerts = cfg.get_int("block.min_alerts", 3)
        self.window = cfg.get_int("block.window_seconds", 300)
        self.refresh = cfg.get_int("mikrotik.refresh_seconds", 300)
        self.direction = cfg.get("block.direction", "external").lower()
        self.max_age = cfg.get_int("block.max_age_seconds", 300)
        self.ignore_sids = {s for s in cfg.get_list("block.ignore_sids")}
        patterns = cfg.get_list("block.ignore_signatures")
        self.ignore_re = re.compile("|".join(patterns), re.I) if patterns else None

        self.recent = collections.defaultdict(collections.deque)  # ip -> alert times
        self.last_sent = {}  # ip -> monotonic time of the last router call

    def whitelisted(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True  # unparseable: refuse rather than guess
        # Refused regardless of the configured list: blocking any of these on a
        # router is either useless or actively harmful.
        if (addr.is_loopback or addr.is_multicast or addr.is_unspecified
                or addr.is_reserved or addr.is_link_local):
            return True
        return any(addr in net for net in self.networks)

    def candidates(self, src, dst):
        """Which endpoints this alert could justify blocking."""
        if self.direction == "src":
            pool = [src]
        elif self.direction == "dst":
            pool = [dst]
        elif self.direction == "both":
            pool = [src, dst]
        else:  # external
            pool = [src, dst]
        allowed = [ip for ip in pool if ip and not self.whitelisted(ip)]
        if self.direction == "external" and len(allowed) > 1:
            # Neither side is ours; the source is the one acting.
            allowed = allowed[:1]
        return allowed

    def ignored(self, alert):
        """`block.ignore_*` apply to every response, not only the block: a sid
        someone told us never to act on must not quarantine a host either."""
        if str(alert.get("signature_id", "")) in self.ignore_sids:
            return "ignored-sid"
        if self.ignore_re and self.ignore_re.search(alert.get("signature", "")):
            return "ignored-signature"
        return None

    def decide(self, alert, src, dst, age_seconds):
        """Return (ips_to_block, decision_label). `ips` is empty unless we act."""
        severity = alert.get("severity", 3)

        ignored = self.ignored(alert)
        if ignored:
            return [], ignored
        if severity > self.max_severity:
            return [], "below-severity"
        if age_seconds > self.max_age:
            # Backlog from a restart. Recorded, never acted on.
            return [], "stale"

        targets = self.candidates(src, dst)
        if not targets:
            return [], "whitelisted"

        now = time.monotonic()
        ready = []
        for ip in targets:
            seen = self.recent[ip]
            seen.append(now)
            while seen and now - seen[0] > self.window:
                seen.popleft()
            if len(seen) < self.min_alerts:
                continue
            if now - self.last_sent.get(ip, -1e9) < self.refresh:
                continue
            self.last_sent[ip] = now
            ready.append(ip)

        if ready:
            return ready, "blocking"
        # Distinguishing these two keeps the dashboard honest about why an
        # obvious attacker is not on the address list yet.
        if any(now - self.last_sent.get(ip, -1e9) < self.refresh for ip in targets):
            return [], "already-listed"
        return [], "below-threshold"

    def prune(self):
        """Drop bookkeeping for addresses that went quiet, so the dicts on a
        long-running responder stay proportional to recent activity."""
        now = time.monotonic()
        for ip in [ip for ip, seen in self.recent.items()
                   if not seen or now - seen[-1] > self.window * 4]:
            del self.recent[ip]
        for ip in [ip for ip, sent in self.last_sent.items()
                   if now - sent > max(self.refresh, 3600) * 4]:
            del self.last_sent[ip]


# ---------------------------------------------------------------------------
# Shared helpers for the quarantine and domain responses
# ---------------------------------------------------------------------------
def parse_networks(items, label):
    nets = []
    for item in items:
        item = item.strip().strip("[]").strip()
        if not item or item.startswith(("!", "$")):
            continue        # Suricata negations and variables: not an address
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            log(f"{label}: ignoring unparseable entry {item!r}")
    return nets


def home_networks(cfg):
    """`suricata.home_net` is `[a,b,c]` Suricata syntax; the networks only."""
    return parse_networks(cfg.get("suricata.home_net").strip("[]").split(","),
                          "suricata.home_net")


def duration_seconds(text, default):
    """RouterOS duration (`4h`, `1d12h`, `30m`, `90s`, `00:30:00`) -> seconds."""
    text = (text or "").strip().lower()
    if not text:
        return default
    if re.fullmatch(r"\d+:\d\d:\d\d", text):
        h, m, sec = (int(x) for x in text.split(":"))
        return h * 3600 + m * 60 + sec
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    parts = re.findall(r"(\d+)([wdhms]?)", text)
    if not parts or "".join(n + u for n, u in parts) != text:
        return default
    return sum(int(n) * units[u or "s"] for n, u in parts)


def match_gate(alert, max_severity, categories, signature_re):
    """Severity, classtype and signature, ALL of which must pass. Each of the
    two text gates is skipped when it is configured empty; both are on by
    default, because each alone lets through a family of alerts it should not:
    `ET MALWARE` includes PUP/adware rules, and the trojan classtype is
    carried by the odd `ET INFO` rule."""
    if alert.get("severity", 3) > max_severity:
        return "below-severity"
    if categories and alert.get("category", "").lower() not in categories:
        return "wrong-category"
    if signature_re and not signature_re.search(alert.get("signature", "")):
        return "wrong-signature"
    return None


class HourlyCap:
    """At most `limit` new actions per rolling hour -- the backstop against a
    misfiring rule quarantining an office or blacklisting half the web."""

    def __init__(self, limit):
        self.limit = limit
        self.times = collections.deque()

    def full(self):
        now = time.monotonic()
        while self.times and now - self.times[0] > 3600:
            self.times.popleft()
        return self.limit > 0 and len(self.times) >= self.limit

    def take(self):
        self.times.append(time.monotonic())


class Repeats:
    """`min_alerts` within `window`, per key, plus a per-key refresh throttle."""

    def __init__(self, min_alerts, window, refresh):
        self.min_alerts, self.window, self.refresh = min_alerts, window, refresh
        self.recent = collections.defaultdict(collections.deque)
        self.last_sent = {}

    def count(self, key):
        now = time.monotonic()
        seen = self.recent[key]
        seen.append(now)
        while seen and now - seen[0] > self.window:
            seen.popleft()
        return len(seen) >= self.min_alerts

    def recently_sent(self, key, within=None):
        within = self.refresh if within is None else within
        return time.monotonic() - self.last_sent.get(key, -1e9) < within

    def sent(self, key):
        self.last_sent[key] = time.monotonic()

    def prune(self, keep_sent):
        now = time.monotonic()
        for key in [k for k, seen in self.recent.items()
                    if not seen or now - seen[-1] > self.window * 4]:
            del self.recent[key]
        for key in [k for k, t in self.last_sent.items() if now - t > keep_sent]:
            del self.last_sent[key]


DEFAULT_COMPROMISE_CATEGORIES = (
    "A Network Trojan was detected, Malware Command and Control Activity "
    "Detected, Domain Observed Used for C2 Detected, Crypto Currency Mining "
    "Activity Detected")
DEFAULT_COMPROMISE_SIGNATURES = r"^ET (MALWARE|CNC|TROJAN|MOBILE_MALWARE|COINMINER)\b"


# ---------------------------------------------------------------------------
# Quarantine: an internal host that looks compromised
# ---------------------------------------------------------------------------
class Quarantine:
    """Puts an internal host on `quarantine.list` when it trips a compromise
    signature.

    The block list is for the outside; this is the other half -- the laptop
    beaconing to a C2 is the likelier problem than a scanner on the internet,
    and `whitelist.networks` (rightly) keeps every internal address off the
    block list. Gates, in order: the shared ignore lists, `max_age`, the
    compromise gate (severity AND classtype AND signature), the host has to be
    inside `quarantine.networks` and outside `quarantine.never`,
    `min_alerts` within `window_seconds`, and a hard `max_per_hour` cap on
    *new* quarantines. Like the block list it does nothing by itself: the
    router rule that gives the list its teeth is made by hand.
    """

    def __init__(self, cfg, policy):
        self.policy = policy
        self.enabled = cfg.get_bool("quarantine.enabled", True)
        self.target = ListTarget(
            cfg.get("quarantine.list", "suricata-quarantine"),
            cfg.get("quarantine.timeout", "4h"),
            cfg.get("quarantine.comment_prefix", "suricata-quarantine"))
        self.timeout_s = duration_seconds(self.target.timeout, 4 * 3600)
        self.networks = (parse_networks(cfg.get_list("quarantine.networks"),
                                        "quarantine.networks")
                         or home_networks(cfg))
        # Every router and the individually whitelisted addresses (an
        # upstream resolver, a scanner of ours) are never quarantined: cutting
        # off the gateway or the DNS server is cutting off everyone.
        never = (cfg.get_list("quarantine.never") + cfg.get_list("whitelist.ips")
                 + router_hosts(cfg))
        self.never = parse_networks([n for n in never if n], "quarantine.never")
        self.max_severity = cfg.get_int("quarantine.max_severity", 2)
        self.categories = {c.lower() for c in cfg.get_list("quarantine.categories")
                           or DEFAULT_COMPROMISE_CATEGORIES.split(", ")}
        pattern = cfg.get("quarantine.signatures", DEFAULT_COMPROMISE_SIGNATURES)
        self.signature_re = re.compile(pattern, re.I) if pattern else None
        self.repeats = Repeats(cfg.get_int("quarantine.min_alerts", 2),
                               cfg.get_int("quarantine.window_seconds", 3600),
                               cfg.get_int("mikrotik.refresh_seconds", 300))
        self.cap = HourlyCap(cfg.get_int("quarantine.max_per_hour", 3))

    def internal(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return False
        if (addr.is_loopback or addr.is_multicast or addr.is_unspecified
                or addr.is_link_local or str(addr) == "255.255.255.255"):
            return False
        return any(addr in net for net in self.networks)

    def exempt(self, ip):
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self.never)

    def host(self, event):
        """The internal endpoint that looks infected, or None.

        If both ends are internal (a C2 lookup sent to the router's resolver)
        it is the flow's initiator: `flow.src_ip` in Suricata 8, which stays
        the initiator even when the alert itself fired on the reply."""
        ends = [ip for ip in (event.get("src_ip"), event.get("dest_ip"))
                if self.internal(ip)]
        if not ends:
            return None
        initiator = (event.get("flow") or {}).get("src_ip") or event.get("src_ip")
        return initiator if initiator in ends else ends[0]

    def decide(self, event, age_seconds):
        """(ip or None, label). The label is only interesting when it acts or
        when the cap stopped it; otherwise the block decision speaks."""
        if not self.enabled:
            return None, None
        alert = event.get("alert") or {}
        if self.policy.ignored(alert) or age_seconds > self.policy.max_age:
            return None, None
        if match_gate(alert, self.max_severity, self.categories, self.signature_re):
            return None, None
        ip = self.host(event)
        if not ip:
            return None, None
        if self.exempt(ip):
            return None, "quarantine-exempt"
        if not self.repeats.count(ip) or self.repeats.recently_sent(ip):
            return None, None
        # A host still inside its last quarantine is a refresh, which the cap
        # does not count: the cap is about how many hosts, not how many alerts.
        fresh = not self.repeats.recently_sent(ip, self.timeout_s)
        if fresh and self.cap.full():
            return None, "quarantine-capped"
        if fresh:
            self.cap.take()
        self.repeats.sent(ip)
        return ip, "quarantining"

    def prune(self):
        self.repeats.prune(max(self.timeout_s, 3600) * 2)


# ---------------------------------------------------------------------------
# Domain blocking: the name a compromise alert points at
# ---------------------------------------------------------------------------
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-_]*[a-z0-9])?"
                       r"(\.[a-z0-9]([a-z0-9\-_]*[a-z0-9])?)+$")

# Shared platforms that malware *abuses* rather than owns. An alert for C2 over
# drive.google.com is real, and blocking drive.google.com for a day would be
# an outage. Suffix match; `domain_block.never` replaces this list.
DEFAULT_NEVER_DOMAINS = (
    "google.com, googleapis.com, gstatic.com, googleusercontent.com, "
    "youtube.com, microsoft.com, microsoftonline.com, live.com, office.com, "
    "office365.com, outlook.com, sharepoint.com, onedrive.com, windows.com, "
    "windowsupdate.com, apple.com, icloud.com, amazon.com, github.com, "
    "githubusercontent.com, dropbox.com, telegram.org, discord.com, "
    "discordapp.com, slack.com, zoom.us, cloudflare.com, akamai.net, "
    "facebook.com, whatsapp.net")


def alert_domains(event, internal):
    """The domain names an alert points at, normalised.

    DNS: every queried name -- `dns.queries[].rrname` in Suricata 8 (measured,
    version 3 records), `dns.rrname`/`dns.query[]` in older formats.
    TLS SNI and HTTP Host: only when the *server* is external, because an
    inbound attack on our own web server names our own domain.
    """
    names = []
    dns = event.get("dns") or {}
    for item in (dns.get("queries") or dns.get("query") or []):
        if isinstance(item, dict) and item.get("rrname"):
            names.append(item["rrname"])
    if dns.get("rrname"):
        names.append(dns["rrname"])
    flow = event.get("flow") or {}
    server = flow.get("dest_ip") or event.get("dest_ip")
    if not internal(server):
        tls = event.get("tls") or {}
        if tls.get("sni"):
            names.append(tls["sni"])
        http = event.get("http") or {}
        if http.get("hostname"):
            names.append(http["hostname"])
    out = []
    for name in names:
        name = str(name).strip().lower().rstrip(".")
        name = re.sub(r":\d+$", "", name)
        try:
            ipaddress.ip_address(name.strip("[]"))
            continue                         # an IP literal is the block list's job
        except ValueError:
            pass
        if len(name) <= 253 and DOMAIN_RE.match(name) and name not in out:
            out.append(name)
    return out


class DomainPolicy:
    """Decides which alert-named domains go on dns-filter's blacklist.

    Same compromise gate as the quarantine (plus phishing by default), its own
    `min_alerts` per *domain* across all hosts, a never-list of shared
    platforms, and a cap on new domains per hour. Entries carry a ttl and
    dns-filter expires them; a repeat inside `refresh_seconds` is not re-sent,
    one after it extends the expiry. dns-filter adds two gates of its own: it
    refuses anything its whitelist covers, and a hand-made entry is never
    touched.
    """

    def __init__(self, cfg, policy, internal):
        self.policy = policy
        self.internal = internal
        self.enabled = cfg.get_bool("domain_block.enabled", True)
        self.ttl = duration_seconds(cfg.get("domain_block.ttl", "1d"), 86400)
        self.max_severity = cfg.get_int("domain_block.max_severity", 2)
        default_categories = (DEFAULT_COMPROMISE_CATEGORIES
                              + ", Possible Social Engineering Attempted")
        self.categories = {c.lower() for c in cfg.get_list("domain_block.categories")
                           or default_categories.split(", ")}
        pattern = cfg.get("domain_block.signatures",
                          r"^ET (MALWARE|CNC|TROJAN|MOBILE_MALWARE|COINMINER|PHISHING)\b")
        self.signature_re = re.compile(pattern, re.I) if pattern else None
        never = cfg.get_list("domain_block.never") or DEFAULT_NEVER_DOMAINS.split(", ")
        self.never = {d.lower().lstrip("*.").rstrip(".") for d in never}
        self.repeats = Repeats(cfg.get_int("domain_block.min_alerts", 2),
                               cfg.get_int("domain_block.window_seconds", 3600),
                               cfg.get_int("domain_block.refresh_seconds", 3600))
        self.cap = HourlyCap(cfg.get_int("domain_block.max_per_hour", 20))

    def shared(self, name):
        labels = name.split(".")
        return any(".".join(labels[i:]) in self.never for i in range(len(labels)))

    def decide(self, event, age_seconds):
        """([domains], label-or-None)."""
        if not self.enabled:
            return [], None
        alert = event.get("alert") or {}
        if self.policy.ignored(alert) or age_seconds > self.policy.max_age:
            return [], None
        if match_gate(alert, self.max_severity, self.categories, self.signature_re):
            return [], None
        ready, capped = [], False
        for name in alert_domains(event, self.internal):
            if self.shared(name):
                continue
            if not self.repeats.count(name) or self.repeats.recently_sent(name):
                continue
            fresh = not self.repeats.recently_sent(name, self.ttl)
            if fresh and self.cap.full():
                capped = True
                continue
            if fresh:
                self.cap.take()
            self.repeats.sent(name)
            ready.append(name)
        if ready:
            return ready, "domain-blocking"
        return [], ("domain-capped" if capped else None)

    def prune(self):
        self.repeats.prune(max(self.ttl, 3600) * 2)


# ---------------------------------------------------------------------------
# Port scanners: the flow verdict of the Port Scanners dashboard, and ET SCAN
# ---------------------------------------------------------------------------
# The candidates query of port_scanners.json, without the cidr box and without
# its top-25 cut, filtered to the SCAN verdict. Keep the two in step: what the
# dashboard calls SCAN is what goes on the router. An attempt is a flow that
# carried a SYN (a SYN-less flow is a 5s chunk of a longer one), reach is 20+
# targets or 5+ services, and SCAN is under 20% of connections finishing.
SCAN_QUERY = """
opens = from(bucket: "{bucket}")
  |> range(start: -{window}m)
  |> filter(fn: (r) => r._measurement == "network_flow" and r.protocol == "6" and r._field == "syn_packets" and r._value > 0)
  |> group(columns: ["src_ip", "dst_ip", "service"])
  |> count()

flags = from(bucket: "{bucket}")
  |> range(start: -{window}m)
  |> filter(fn: (r) => r._measurement == "network_flow" and r.protocol == "6" and (r._field == "syn_packets" or r._field == "fin_packets" or r._field == "rst_packets"))
  |> group(columns: ["src_ip", "_field"])
  |> sum()
  |> map(fn: (r) => ({{src_ip: r.src_ip, k: r._field, v: r._value}}))

union(tables: [
  opens |> group(columns: ["src_ip"]) |> sum()
        |> map(fn: (r) => ({{src_ip: r.src_ip, k: "attempts", v: r._value}})),
  opens |> group(columns: ["src_ip", "dst_ip"]) |> sum() |> group(columns: ["src_ip"]) |> count()
        |> map(fn: (r) => ({{src_ip: r.src_ip, k: "targets", v: r._value}})),
  opens |> group(columns: ["src_ip", "service"]) |> sum() |> group(columns: ["src_ip"]) |> count()
        |> map(fn: (r) => ({{src_ip: r.src_ip, k: "services", v: r._value}})),
  flags,
])
  |> group()
  |> pivot(rowKey: ["src_ip"], columnKey: ["k"], valueColumn: "v")
  |> filter(fn: (r) => exists r.attempts and r.attempts >= {min_attempts})
  |> filter(fn: (r) => r.targets >= 20 or r.services >= 5)
  |> filter(fn: (r) => exists r.syn_packets and exists r.fin_packets)
  |> map(fn: (r) => ({{r with
      completion: if r.syn_packets > 0 then float(v: r.fin_packets) / float(v: r.syn_packets) * 100.0 else 0.0}}))
  |> filter(fn: (r) => r.completion < 20.0)
  |> sort(columns: ["attempts"], desc: true)
  |> limit(n: {limit})
  |> keep(columns: ["src_ip", "attempts", "targets", "services", "completion"])
"""


def flux_rows(query, timeout=60):
    """Run a Flux query, return its rows as dicts (strings). Plain CSV with a
    header per table and a blank line between tables -- no annotations."""
    body = json.dumps({"query": query, "type": "flux",
                       "dialect": {"header": True, "annotations": []}}).encode()
    req = urllib.request.Request(
        f"{INFLUX_URL.rstrip('/')}/api/v2/query?org={urllib.parse.quote(INFLUX_ORG)}",
        data=body, method="POST",
        headers={"Authorization": f"Token {INFLUX_TOKEN}",
                 "Content-Type": "application/json", "Accept": "application/csv"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return parse_flux_csv(resp.read().decode("utf-8", "replace"))


def parse_flux_csv(text):
    rows, header = [], None
    for record in csv.reader(io.StringIO(text)):
        if not record or not any(record):
            header = None                    # the next table brings its own header
            continue
        if header is None:
            header = record
            continue
        rows.append(dict(zip(header, record)))
    return rows


class ScanPolicy:
    """Who goes on the scanner list, from either source.

    The two sources answer the same question differently: the flow verdict
    sees scans no signature covers (and is what the dashboard shows), ET SCAN
    sees the ones too slow or too narrow for the verdict's thresholds. Both
    share the gates: external sources only by default (`scanners.scope`), never
    a router, `whitelist.ips` or `scanners.never`, never a reserved address,
    and one hourly cap on *new* listings -- the internet's background scanning
    is hundreds of sources a day, and a list that grows without bound is a
    router's memory, not a defence.
    """

    def __init__(self, cfg, policy, internal):
        self.policy = policy
        self.internal = internal
        self.enabled = cfg.get_bool("scanners.enabled", True)
        self.target = ListTarget(cfg.get("scanners.list", "port-scanners"),
                                 cfg.get("scanners.timeout", "1d"),
                                 cfg.get("scanners.comment_prefix", "scanner"))
        self.timeout_s = duration_seconds(self.target.timeout, 86400)
        self.scope = cfg.get("scanners.scope", "external").lower()
        if self.scope not in ("external", "all"):
            log(f"scanners.scope: {self.scope!r} is not external/all, using external")
            self.scope = "external"
        never = (cfg.get_list("scanners.never") + cfg.get_list("whitelist.ips")
                 + router_hosts(cfg))
        self.never = parse_networks([n for n in never if n], "scanners.never")
        self.window = cfg.get_int("scanners.window_minutes", 15)
        self.interval = cfg.get_int("scanners.interval_seconds", 300)
        self.min_attempts = cfg.get_int("scanners.min_attempts", 50)
        self.max_candidates = cfg.get_int("scanners.max_candidates", 200)
        pattern = cfg.get("scanners.alert_signatures", r"^(ET|GPL) SCAN\b")
        self.alert_re = re.compile(pattern, re.I) if pattern else None
        self.repeats = Repeats(cfg.get_int("scanners.alert_min_alerts", 2),
                               cfg.get_int("scanners.alert_window_seconds", 600),
                               cfg.get_int("scanners.refresh_seconds", 3600))
        self.cap = HourlyCap(cfg.get_int("scanners.max_per_hour", 100))

    def ineligible(self, ip):
        """Why `ip` must not be listed, or None."""
        try:
            addr = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return "unparseable"
        if (addr.is_loopback or addr.is_multicast or addr.is_unspecified
                or addr.is_link_local or addr.is_reserved):
            return "reserved"
        if any(addr in net for net in self.never):
            return "never"
        if self.scope == "external" and self.ours(ip):
            return "internal"
        return None

    def ours(self, ip):
        """Is the scanning host one of ours? The same networks the scope gate
        skips (quarantine's internal set, plus `whitelist.networks`), but asked
        whatever `scanners.scope` says: the port_scan point records who
        scanned, not whether the router may list them. Not `whitelisted()`
        on its own, because that also answers yes for reserved addresses."""
        try:
            addr = ipaddress.ip_address(ip)
        except (TypeError, ValueError):
            return False
        return self.internal(ip) or any(addr in net for net in self.policy.networks)

    def admit(self, ip):
        """'scanner-listing', 'scanner-capped', or None (listed recently)."""
        if self.repeats.recently_sent(ip):
            return None
        fresh = not self.repeats.recently_sent(ip, self.timeout_s)
        if fresh and self.cap.full():
            return "scanner-capped"
        if fresh:
            self.cap.take()
        self.repeats.sent(ip)
        return "scanner-listing"

    def decide_alert(self, event, age_seconds):
        """(ip or None, label-or-None) for an ET SCAN alert's source."""
        if not (self.enabled and self.alert_re):
            return None, None
        alert = event.get("alert") or {}
        if self.policy.ignored(alert) or age_seconds > self.policy.max_age:
            return None, None
        if not self.alert_re.search(alert.get("signature", "")):
            return None, None
        ip = event.get("src_ip")
        if self.ineligible(ip) or not self.repeats.count(ip):
            return None, None
        label = self.admit(ip)
        return (ip if label == "scanner-listing" else None), label

    def query(self):
        return SCAN_QUERY.format(bucket=INFLUX_BUCKET, window=int(self.window),
                                 min_attempts=int(self.min_attempts),
                                 limit=int(self.max_candidates))

    def prune(self):
        self.repeats.prune(max(self.timeout_s, 3600) * 2)


def scan_int(value):
    """A Flux CSV cell as an int: rows are strings, a column a table lacks is
    missing, and a pivot can hand back a float form ("312.0")."""
    try:
        return int(float(value))
    except (TypeError, ValueError, OverflowError):   # OverflowError: "inf"
        return 0


def write_port_scan(influx, scans, ip, outcome, source, row=None, timestamp_ns=None):
    """One `port_scan` point per detected scanner, whatever happened to it.

    `suricata_block` only ever sees the sources that were listed and
    `scan_watch` only counts the rest, so an internal host scanning -- the
    more alarming case, and one the default scope never lists -- left no
    per-host record at all. Cardinality is bounded by the query's
    `max_candidates` (and, for alerts, by the listing gates)."""
    row = row or {}
    try:
        completion = float(row.get("completion") or 0)
    except (TypeError, ValueError):
        completion = 0.0
    if completion != completion or completion in (float("inf"), float("-inf")):
        completion = 0.0                     # line protocol has no NaN/inf
    influx.point("port_scan",
                 {"src_ip": ip, "scope": "internal" if scans.ours(ip) else "external",
                  "outcome": outcome},
                 {"count": "1i",
                  "attempts": f"{scan_int(row.get('attempts'))}i",
                  "targets": f"{scan_int(row.get('targets'))}i",
                  "services": f"{scan_int(row.get('services'))}i",
                  "completion": f"{completion:.2f}",
                  "source": esc_str(source)},
                 timestamp_ns)


class ScanWatcher(threading.Thread):
    """Runs the flow verdict every `scanners.interval_seconds` and hands each
    SCAN source to the routers with the `scanners` role. Writes `scan_watch`
    every run, so the dashboard can tell "nobody scanned" from "not running"
    and from "the query fails" -- the query is the one piece whose cost on a
    busy mirror is not measured, which is why its duration is recorded too."""

    def __init__(self, scans, workers, influx, lock):
        super().__init__(daemon=True)
        self.scans, self.workers, self.influx, self.lock = scans, workers, influx, lock

    def run_once(self):
        started = time.monotonic()
        counts = {"candidates": 0, "listed": 0, "capped": 0, "already": 0,
                  "internal": 0, "never": 0, "reserved": 0, "detected": 0}
        error = ""
        try:
            rows = flux_rows(self.scans.query())
        except (urllib.error.URLError, OSError, ValueError) as exc:
            rows, error = [], str(exc)[:200]
            log(f"scanners: verdict query failed: {exc}")
        query_ms = (time.monotonic() - started) * 1000.0
        now_ns = time.time_ns()
        for row in rows:
            ip = row.get("src_ip", "")
            if not ip:
                continue
            counts["candidates"] += 1
            reason = self.scans.ineligible(ip)
            if reason:
                counts[reason if reason in counts else "reserved"] += 1
                write_port_scan(self.influx, self.scans, ip, reason, "flow", row, now_ns)
                continue
            if not self.workers:
                # No router takes the list: detect only. The point is still
                # written -- it is what the alerter reads -- but nothing is
                # admitted, so neither the hourly cap nor the refresh clock is
                # spent on a listing that is never made.
                counts["detected"] += 1
                write_port_scan(self.influx, self.scans, ip, "detected", "flow", row, now_ns)
                continue
            with self.lock:                  # the tail thread admits alerts too
                label = self.scans.admit(ip)
            if label is None:
                counts["already"] += 1
                write_port_scan(self.influx, self.scans, ip, "already", "flow", row, now_ns)
                continue
            if label == "scanner-capped":
                counts["capped"] += 1
                write_port_scan(self.influx, self.scans, ip, "capped", "flow", row, now_ns)
                continue
            counts["listed"] += 1
            write_port_scan(self.influx, self.scans, ip, "listed", "flow", row, now_ns)
            why = (f"flow scan: {row.get('attempts')} attempts, {row.get('targets')} "
                   f"targets, {row.get('services')} services, "
                   f"{float(row.get('completion') or 0):.0f}% completed")
            log(f"[SCANNER] {ip}: {why}")
            for worker in self.workers:
                worker.submit(ip, why, now_ns, self.scans.target)
        if counts["capped"]:
            log(f"scanners: hourly cap (scanners.max_per_hour) held back "
                f"{counts['capped']} source(s)")
        fields = {k: f"{v}i" for k, v in counts.items()}
        fields.update(query_ms=f"{query_ms:.0f}", up="1i",
                      state_code=f"{0 if error else 2 if self.workers else 1}i",
                      error=esc_str(error))
        self.influx.point("scan_watch", {}, fields)
        return counts, error

    def run(self):
        time.sleep(30)                       # let the collector's first flows land
        while True:
            self.run_once()
            time.sleep(max(30, self.scans.interval))


# ---------------------------------------------------------------------------
# eve.json tail
# ---------------------------------------------------------------------------
class EveTail:
    """Follow eve.json across a rotation and across our restarts.

    A rotation is disk-guard renaming the file and asking Suricata to reopen it;
    the check below is by inode, and it only runs once the current file has been
    read to EOF, so nothing is lost in the handover. The new file appears on
    Suricata's next write rather than immediately, which is why _open() waits
    for it instead of treating its absence as an error.

    The read position is persisted so a responder restart does not lose the
    alerts written while it was down; `block.max_age_seconds` is what stops that
    catch-up from acting on old events.
    """

    def __init__(self, path, state_path):
        self.path = path
        self.state_path = state_path
        self.fh = None
        self.inode = None
        self.dirty = False

    def _load_state(self):
        try:
            with open(self.state_path) as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _save_state(self):
        if not self.fh or not self.dirty:
            return
        try:
            os.makedirs(os.path.dirname(self.state_path), exist_ok=True)
            tmp = self.state_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump({"inode": self.inode, "offset": self.fh.tell()}, fh)
            os.replace(tmp, self.state_path)
            self.dirty = False
        except OSError as exc:
            log(f"could not save read position: {exc}")

    def _open(self):
        while not os.path.exists(self.path):
            log(f"waiting for {self.path} (is suricata running?)")
            time.sleep(2)
        # Binary, not text: a text file's tell() is an opaque cookie that may not
        # be a byte offset, so neither the rewind below nor the persisted
        # position would be well defined.
        self.fh = open(self.path, "rb")
        self.inode = os.fstat(self.fh.fileno()).st_ino

        state = self._load_state()
        if state.get("inode") == self.inode:
            self.fh.seek(min(state.get("offset", 0),
                             os.fstat(self.fh.fileno()).st_size))
            log(f"resuming {self.path} at offset {self.fh.tell()}")
        elif state:
            # Rotated while we were down: this file is entirely new to us.
            log(f"{self.path} was rotated; reading it from the start")
        else:
            self.fh.seek(0, os.SEEK_END)
            log(f"first start: following {self.path} from the end "
                f"({self.fh.tell()} B of history skipped)")
        self.dirty = True
        self._save_state()

    def follow(self):
        """Yield each JSON line; yield None whenever the file goes quiet."""
        self._open()
        while True:
            line = self.fh.readline()
            if line:
                if line.endswith(b"\n"):
                    self.dirty = True
                    yield line.decode("utf-8", "replace")
                    continue
                # A partial line: Suricata is mid-write. Rewind and retry.
                self.fh.seek(-len(line), os.SEEK_CUR)
            self._save_state()
            self._reopen_if_rotated()
            yield None
            time.sleep(IDLE_POLL)

    def _reopen_if_rotated(self):
        try:
            st = os.stat(self.path)
        except OSError:
            return
        if st.st_ino != self.inode:
            log("eve.json rotated, reopening")
            self.fh.close()
            self.fh = open(self.path, "rb")
            self.inode = st.st_ino
            self.dirty = True
        elif st.st_size < self.fh.tell():
            log("eve.json truncated, rereading from the start")
            self.fh.seek(0)
            self.dirty = True


# ---------------------------------------------------------------------------
# Alert -> InfluxDB
# ---------------------------------------------------------------------------
def event_time_ns(event):
    """Suricata's ISO-8601 timestamp as epoch nanoseconds, or now."""
    try:
        parsed = datetime.fromisoformat(event["timestamp"])
    except (KeyError, ValueError):
        return time.time_ns()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp() * 1_000_000_000)


def alert_details(event):
    """Flatten the app-layer context into one readable string for the table.

    Keeping this as a single field instead of a tag per protocol matters: it is
    high-cardinality forensic detail, useless to group by and expensive to index.
    """
    parts = []
    http = event.get("http") or {}
    if http:
        parts.append("http " + " ".join(str(v) for v in (
            http.get("http_method"), http.get("hostname"), http.get("url"),
            http.get("status")) if v))
    dns = event.get("dns") or {}
    # Suricata 8 (DNS record version 3) nests the name in `queries`; measured
    # on 8.0.6, and the flat `rrname` older versions wrote is simply absent.
    for query in (dns.get("queries") or dns.get("query") or [])[:3]:
        if isinstance(query, dict) and query.get("rrname"):
            parts.append(f"dns {query.get('rrtype', '')} {query['rrname']}".strip())
    if dns.get("rrname"):
        parts.append(f"dns {dns.get('rrtype', '')} {dns['rrname']}".strip())
    tls = event.get("tls") or {}
    if tls.get("sni") or tls.get("subject"):
        parts.append("tls " + (tls.get("sni") or tls.get("subject")))
    for key in ("ssh", "smb", "ftp", "smtp", "krb5", "dhcp"):
        section = event.get(key)
        if isinstance(section, dict) and section:
            parts.append(f"{key} " + json.dumps(section, separators=(",", ":"))[:120])
    flow = event.get("flow") or {}
    if flow:
        parts.append(f"flow pkts {flow.get('pkts_toserver', 0)}/"
                     f"{flow.get('pkts_toclient', 0)} bytes "
                     f"{flow.get('bytes_toserver', 0)}/{flow.get('bytes_toclient', 0)}")
    return " | ".join(parts)


SEVERITY_NAMES = {1: "critical", 2: "high", 3: "medium", 4: "info"}


def write_alert(influx, event, decision):
    alert = event.get("alert") or {}
    severity = alert.get("severity", 3)
    fields = {
        "count": "1i",
        "src_port": f"{int(event.get('src_port') or 0)}i",
        "dst_port": f"{int(event.get('dest_port') or 0)}i",
        "signature_id": f"{int(alert.get('signature_id') or 0)}i",
        "rev": f"{int(alert.get('rev') or 0)}i",
        "details": esc_str(alert_details(event)),
        "community_id": esc_str(event.get("community_id", "")),
    }
    payload = event.get("payload_printable")
    if payload:
        # Enough to recognise the traffic in the alert table, not a packet dump.
        fields["payload"] = esc_str(payload[:200])

    influx.point("suricata_alert", {
        "src_ip": event.get("src_ip"),
        "dst_ip": event.get("dest_ip"),
        "proto": event.get("proto"),
        "app_proto": event.get("app_proto", "none"),
        "category": alert.get("category", "uncategorised"),
        "signature": alert.get("signature", "unknown"),
        "severity": severity,
        "severity_name": SEVERITY_NAMES.get(severity, "unknown"),
        "action": alert.get("action", "allowed"),
        "decision": decision,
    }, fields, event_time_ns(event))


def stat(section, *path, default=0):
    node = section
    for key in path:
        if not isinstance(node, dict):
            return default
        node = node.get(key)
    return node if isinstance(node, (int, float)) else default


class StatsForwarder:
    """Suricata's own counters, as per-interval deltas.

    Deltas rather than raw totals because the totals reset to zero whenever
    Suricata restarts, which puts a cliff in every panel built on them.
    """

    def __init__(self, influx):
        self.influx = influx
        self.prev = {}

    def handle(self, event):
        stats = event.get("stats") or {}
        current = {
            "packets": stat(stats, "capture", "kernel_packets"),
            "drops": stat(stats, "capture", "kernel_drops"),
            "ifdrops": stat(stats, "capture", "kernel_ifdrops"),
            "decoded": stat(stats, "decoder", "pkts"),
            "bytes": stat(stats, "decoder", "bytes"),
            "invalid": stat(stats, "decoder", "invalid"),
            "alerts": stat(stats, "detect", "alert"),
        }
        fields = {}
        for key, total in current.items():
            previous = self.prev.get(key, 0)
            delta = total - previous if total >= previous else total
            fields[key] = f"{int(delta)}i"
            fields[key + "_total"] = f"{int(total)}i"
        self.prev = current

        seen = int(fields["packets"].rstrip("i")) + int(fields["drops"].rstrip("i"))
        fields["drop_percent"] = f"{(int(fields['drops'].rstrip('i')) / seen * 100.0) if seen else 0.0}"
        fields["uptime"] = f"{int(stat(stats, 'uptime'))}i"
        fields["flow_active"] = f"{int(stat(stats, 'flow', 'active'))}i"
        fields["flow_memuse"] = f"{int(stat(stats, 'flow', 'memuse'))}i"
        fields["tcp_reassembly_gap"] = f"{int(stat(stats, 'tcp', 'reassembly_gap'))}i"

        self.influx.point("suricata_stats", {"source": "suricata"}, fields,
                          event_time_ns(event))


# ---------------------------------------------------------------------------
# Router worker
# ---------------------------------------------------------------------------
class BlockWorker(threading.Thread):
    """Serialises one router's writes off the tailing thread.

    One per router, each with its own queue: an unreachable router fills its
    own queue and drops its own requests, and never delays the others.

    Bounded queue on purpose: if the router is unreachable during an alert
    storm, the right failure is to drop block requests (they are retried by the
    next alert anyway) rather than to grow without limit or stall the tail.
    """

    def __init__(self, router, influx):
        super().__init__(daemon=True)
        self.router = router
        self.influx = influx
        self.queue = queue.Queue(maxsize=1000)

    def submit(self, ip, signature, timestamp_ns, target=None):
        target = target or self.router.default_target
        try:
            self.queue.put_nowait((ip, signature, timestamp_ns, target))
        except queue.Full:
            log(f"router {self.router.name}: queue full, dropping request for {ip}")
            self._record(ip, signature, "dropped-queue-full", timestamp_ns, target)

    def _record(self, ip, signature, result, timestamp_ns, target, latency_ms=0.0):
        self.influx.point("suricata_block", {
            "ip": ip,
            "list": target.list_name,
            "result": result,
            "router": self.router.name,
        }, {
            "count": "1i",
            "latency_ms": f"{latency_ms:.1f}",
            "signature": esc_str(signature),
            "timeout": esc_str(target.timeout or "none"),
        }, timestamp_ns)

    def run(self):
        while True:
            ip, signature, timestamp_ns, target = self.queue.get()
            started = time.monotonic()
            try:
                result = self.router.block(ip, signature, target)
                log(f"router {self.router.name}: {result} {ip} on "
                    f"'{target.list_name}' ({signature})")
            except RouterError as exc:
                result = "error"
                log(f"router {self.router.name}: FAILED to add {ip} to "
                    f"'{target.list_name}': {exc}")
            self._record(ip, signature, result, timestamp_ns, target,
                         (time.monotonic() - started) * 1000.0)


class DomainWorker(threading.Thread):
    """Hands alert-named domains to dns-filter's control API, off the tail.

    The outcome is recorded as `suricata_block` with `list=dns-blacklist` and
    the domain in `ip`, so the dashboard's router-actions table shows it next
    to the address-list writes. dns-filter does the router side itself.
    """

    LIST = "dns-blacklist"

    def __init__(self, influx, ttl, dry_run):
        super().__init__(daemon=True)
        self.influx = influx
        self.ttl = ttl
        self.dry_run = dry_run
        self.queue = queue.Queue(maxsize=200)

    def submit(self, domain, alert, timestamp_ns):
        try:
            self.queue.put_nowait((domain, alert, timestamp_ns))
        except queue.Full:
            log(f"domain queue full, dropping {domain}")

    def call(self, domain, note):
        query = urllib.parse.urlencode({"block": domain, "ttl": self.ttl,
                                        "note": note})
        with urllib.request.urlopen(f"{DNS_FILTER_URL}/messages?{query}",
                                    timeout=15) as resp:
            messages = [m.get("message", "") for m in json.loads(resp.read())]
        text = " | ".join(messages)
        if any(m.startswith("added") for m in messages):
            return "added", text
        if any(m.startswith("extended") for m in messages) or text == "no change":
            return "refreshed", text
        if any(m.startswith("refused") for m in messages):
            return "refused", text
        if "read-only" in text:
            return "read-only", text
        return "unknown", text

    def run(self):
        while True:
            domain, alert, timestamp_ns = self.queue.get()
            signature = alert.get("signature", "unknown")
            note = f"auto: sid {alert.get('signature_id', '?')} {signature}"[:200]
            started = time.monotonic()
            if self.dry_run:
                result, text = "dry-run", "mikrotik.dry_run"
                log(f"[dry-run] would blacklist {domain} for {self.ttl}s ({signature})")
            else:
                try:
                    result, text = self.call(domain, note)
                    log(f"dns-filter: {result} {domain} ({text})")
                except (urllib.error.URLError, OSError, ValueError) as exc:
                    result, text = "error", str(exc)
                    log(f"dns-filter: FAILED to blacklist {domain}: {exc}")
            self.influx.point("suricata_block", {
                "ip": domain, "list": self.LIST, "result": result,
            }, {
                "count": "1i",
                "latency_ms": f"{(time.monotonic() - started) * 1000.0:.1f}",
                "signature": esc_str(signature),
                "timeout": esc_str(f"{self.ttl}s"),
                "detail": esc_str(text[:200]),
            }, timestamp_ns)


def health_forever(router, influx, interval):
    while True:
        try:
            latency_ms, version = router.probe()
            influx.point("mikrotik_api", {"host": router.host, "router": router.name},
                         {"up": "1i", "latency_ms": f"{latency_ms:.1f}",
                          "version": esc_str(version)})
        except RouterError as exc:
            influx.point("mikrotik_api", {"host": router.host, "router": router.name},
                         {"up": "0i", "latency_ms": "0.0", "version": esc_str("")})
            log(f"router {router.name}: health probe failed: {exc}")
        time.sleep(interval)


# ---------------------------------------------------------------------------
# Rotated eve.json copies used to be pruned here, on the maintenance tick. That
# moved to disk-guard, which owns the log volume outright: two services deleting
# the same files is how a race becomes "the alert was in there yesterday", and a
# retain window in *days* was never able to promise anything about a disk
# anyway. This service is only a reader of that directory now -- see EveTail,
# which drains a rotated file to EOF before it follows the new one.


def combine_decision(block, quarantine, domain, scanner=None):
    """One `decision` tag per alert. Actions taken are joined with `+`, the
    block first; when nothing acted, a capped response is the label (a cap
    stopping a quarantine is the one thing an operator must not miss), and
    otherwise the block decision says why nothing happened."""
    acted = [label for label in (block if block == "blocking" else None,
                                 quarantine if quarantine == "quarantining" else None,
                                 domain if domain == "domain-blocking" else None,
                                 scanner if scanner == "scanner-listing" else None)
             if label]
    if acted:
        return "+".join(acted)
    for label in (quarantine, domain, scanner):
        if label in ("quarantine-capped", "domain-capped", "scanner-capped"):
            return label
    return block


def main():
    cfg = Config(PROPERTIES_FILE)
    policy = Policy(cfg)
    influx = Influx(INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG, INFLUX_BUCKET)
    stats_forwarder = StatsForwarder(influx)

    quarantine = Quarantine(cfg, policy)
    domains = DomainPolicy(cfg, policy, quarantine.internal)

    domain_worker = None
    if domains.enabled:
        domain_worker = DomainWorker(influx, domains.ttl,
                                     cfg.get_bool("mikrotik.dry_run", False))
        domain_worker.start()

    # One worker and one health probe per router. A router takes the block
    # list, the quarantine list or both, by `roles`; the decisions are made
    # once and handed to every router that takes them.
    block_workers, quarantine_workers, scanner_workers = [], [], []
    seen = {}
    for role, into in (("block", block_workers), ("quarantine", quarantine_workers),
                       ("scanners", scanner_workers)):
        for rc in router_configs(cfg, role):
            if rc.name not in seen:
                # Named separately from the truth test so the log can say
                # *which* field is missing: "you copied the example and did not
                # fill it in" is by far the likeliest reason nothing is blocked.
                missing = [k for k in ("mikrotik.host", "mikrotik.user",
                                       "mikrotik.password") if not rc.get(k)]
                if missing:
                    log(f"router {rc.name}: disabled, {', '.join(missing)} not set "
                        f"in {PROPERTIES_FILE}. Alerts are still shipped to InfluxDB.")
                    seen[rc.name] = None
                elif not rc.get_bool("mikrotik.enabled", False):
                    log(f"router {rc.name}: disabled (mikrotik.enabled=false)")
                    seen[rc.name] = None
                else:
                    router = Mikrotik(rc)
                    worker = BlockWorker(router, influx)
                    worker.start()
                    seen[rc.name] = worker
                    log(f"router {rc.name}: {router.base} list='{router.list_name}' "
                        f"timeout={router.timeout_value or 'permanent'} "
                        f"roles={','.join(sorted(rc.roles & {'block', 'quarantine', 'scanners'}))} "
                        f"dry_run={router.dry_run}")
                    interval = rc.get_int("mikrotik.health_interval", 60)
                    if interval > 0:
                        threading.Thread(target=health_forever, daemon=True,
                                         args=(router, influx, interval)).start()
            if seen[rc.name]:
                into.append(seen[rc.name])
    if not block_workers:
        log("no router takes the block list: alerts are still shipped to InfluxDB")

    scans = ScanPolicy(cfg, policy, quarantine.internal)
    scan_lock = threading.Lock()
    if scans.enabled and not scanner_workers:
        # Still run the verdict: every SCAN source becomes a port_scan point
        # (outcome=detected), which the alerter reads -- an internal host
        # scanning matters whether or not a router takes the list.
        ScanWatcher(scans, [], influx, scan_lock).start()
        log(f"scanners: detect only (no router takes the scanner list): verdict "
            f"every {scans.interval}s over {scans.window}m, port_scan points only")
    elif scans.enabled and scanner_workers:
        ScanWatcher(scans, scanner_workers, influx, scan_lock).start()
        log(f"scanners: list='{scans.target.list_name}' timeout={scans.target.timeout} "
            f"scope={scans.scope} verdict every {scans.interval}s over "
            f"{scans.window}m (>= {scans.min_attempts} attempts), ET SCAN "
            f"{scans.repeats.min_alerts}/{scans.repeats.window}s, "
            f"cap={scans.cap.limit}/h routers="
            f"{','.join(w.router.name for w in scanner_workers)}")
    else:
        log("scanners: off (scanners.enabled = false)")

    log(f"policy: max_severity={policy.max_severity} "
        f"min_alerts={policy.min_alerts}/{policy.window}s "
        f"direction={policy.direction} whitelist={len(policy.networks)} networks")
    if quarantine.enabled and quarantine_workers:
        log(f"quarantine: list='{quarantine.target.list_name}' "
            f"timeout={quarantine.target.timeout} "
            f"networks={','.join(map(str, quarantine.networks)) or 'NONE'} "
            f"never={len(quarantine.never)} min_alerts="
            f"{quarantine.repeats.min_alerts}/{quarantine.repeats.window}s "
            f"cap={quarantine.cap.limit}/h routers="
            f"{','.join(w.router.name for w in quarantine_workers)}")
        if not quarantine.networks:
            log("quarantine: no internal networks (quarantine.networks and "
                "suricata.home_net both empty) -- nothing can be quarantined")
    else:
        log("quarantine: off (" + ("no router takes the quarantine list"
                                   if quarantine.enabled
                                   else "quarantine.enabled = false") + ")")
    if domain_worker:
        log(f"domain blocking: {DNS_FILTER_URL} ttl={domains.ttl}s min_alerts="
            f"{domains.repeats.min_alerts}/{domains.repeats.window}s "
            f"cap={domains.cap.limit}/h never={len(domains.never)} suffixes")
    else:
        log("domain blocking: off (domain_block.enabled = false)")

    next_maintenance = time.monotonic() + MAINTENANCE_INTERVAL
    tail = EveTail(EVE_FILE, STATE_FILE)

    for line in tail.follow():
        if line is None:
            if time.monotonic() >= next_maintenance:
                policy.prune()
                quarantine.prune()
                domains.prune()
                with scan_lock:
                    scans.prune()
                next_maintenance = time.monotonic() + MAINTENANCE_INTERVAL
            continue

        try:
            event = json.loads(line)
        except ValueError:
            continue

        kind = event.get("event_type")
        if kind == "stats":
            stats_forwarder.handle(event)
            continue
        if kind != "alert":
            continue

        alert = event.get("alert") or {}
        src, dst = event.get("src_ip"), event.get("dest_ip")
        timestamp_ns = event_time_ns(event)
        age = max(0.0, time.time() - timestamp_ns / 1e9)

        if block_workers:
            targets, decision = policy.decide(alert, src, dst, age)
        else:
            targets, decision = [], "no-router"
        infected, q_label = (quarantine.decide(event, age) if quarantine_workers
                             else (None, None))
        names, d_label = (domains.decide(event, age) if domain_worker
                          else ([], None))
        scanner, s_label = None, None
        if scanner_workers and scans.enabled:
            with scan_lock:
                scanner, s_label = scans.decide_alert(event, age)

        decision = combine_decision(decision, q_label, d_label, s_label)
        write_alert(influx, event, decision)
        log(f"[ALERT] sev{alert.get('severity')} {src}:{event.get('src_port')} -> "
            f"{dst}:{event.get('dest_port')} {alert.get('signature')} => {decision}")

        for ip in targets:
            for worker in block_workers:
                worker.submit(ip, alert.get("signature", "unknown"), timestamp_ns)
        if infected:
            log(f"[QUARANTINE] {infected}: {alert.get('signature')}")
            for worker in quarantine_workers:
                worker.submit(infected, alert.get("signature", "unknown"),
                              timestamp_ns, quarantine.target)
        for name in names:
            domain_worker.submit(name, alert, timestamp_ns)
        if scanner:
            log(f"[SCANNER] {scanner}: {alert.get('signature')}")
            # Only a listing is recorded from this side: a scan alert that
            # stays below `alert_min_alerts` is not yet a detected scanner.
            write_port_scan(influx, scans, scanner, "listed", "alert",
                            timestamp_ns=timestamp_ns)
            for worker in scanner_workers:
                worker.submit(scanner, alert.get("signature", "unknown"),
                              timestamp_ns, scans.target)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log(f"fatal: {exc}")
        sys.exit(1)
