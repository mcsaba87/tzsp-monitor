"""Disable and re-enable Suricata rules from the Grafana UI.

Grafana cannot write anything by itself, but it *can* be made to fetch a URL:
the Infinity datasource performs the request server-side on every panel refresh,
and a table data link can navigate the dashboard with a variable pre-filled. Put
those together and one click on a SID becomes one HTTP call to this service:

    click a SID in Grafana
      -> dashboard reloads with var-disable_sid=<sid>
      -> the Rule Control panel's Infinity query hits /apply?disable=<sid>
      -> this service rewrites threshold.config and asks Suricata to reload
      -> the panel renders the new list of disabled rules

    GET /apply?disable=<entry>&enable=<entry|all>&note=<text> -> [rules...]
        &site=<datasource uid>: anything but the local one is inert
    GET /rules                                                -> [rules...]

An <entry> is a bare sid (suppress everywhere) or a sid scoped to one address
or range, for the rule that is noise for one host and signal for the rest:

    2013028                       every alert of the sid
    2013028@src:10.1.2.3          only when 10.1.2.3 is the source
    2013028@dst:10.1.0.0/16       only when the destination is in 10.1.0.0/16
    2013028@either:2001:db8::/32  either endpoint in the range

which becomes `suppress gen_id 1, sig_id 2013028, track by_src, ip 10.1.2.3`.
The entry string is also the key a restore names, so the Suppressed Rules panel
carries it as a hidden column. A source *and* destination pair cannot be
expressed: Suricata's suppress tracks one side only (by_src, by_dst or
by_either), so a pair would have to be a rule edit, which this service does not
do on purpose (see below).

A rule is disabled with a `suppress` line in threshold.config rather than by
removing it from the ruleset. That choice matters:

  * it takes effect on a ruleset reload, so no restart and no gap in the capture
    (verified: threshold parsing happens inside SigLoadSignatures, so
    `reload-rules` re-reads the file);
  * `suricata-update` cannot undo it, whereas a disable.conf entry would need a
    ruleset regeneration -- and internet access -- to apply at all;
  * it is trivially reversible, which is the whole point of a UI control.

The rule still evaluates; only the alert is suppressed. That costs a little CPU
and buys a mechanism that cannot leave the ruleset in a state this service
cannot reason about.

**Anyone who can view the dashboard can call this.** Infinity queries run with
the datasource's identity, not the viewer's, so Grafana's own permissions do not
gate it -- see the security note in CLAUDE.md before exposing the dashboard
widely, and set `rule_control.enabled = false` to make the whole thing read-only.
"""
import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONTROL_DIR = os.getenv("CONTROL_DIR", "/var/lib/suricata-control")
THRESHOLD_FILE = os.path.join(CONTROL_DIR, "threshold.config")
SOCKET_PATH = os.path.join(CONTROL_DIR, "suricata-command.socket")
STATE_FILE = os.path.join(CONTROL_DIR, "disabled.json")
PROPERTIES_FILE = os.getenv("PROPERTIES_FILE", "/etc/tzsp-monitor/suricata.properties")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "8020"))

# Searched to turn a sid into its msg text, so the disabled list reads as
# something other than a column of numbers.
RULE_FILES = ["/var/lib/suricata/rules/suricata.rules",
              "/etc/suricata/tzsp/rules/local.rules"]

BEGIN = "# BEGIN rule-control"
END = "# END rule-control"

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

_lock = threading.Lock()


def log(msg):
    print(f"{datetime.now().strftime('%H:%M:%S')} {msg}", flush=True)


# ---------------------------------------------------------------------------
def load_properties(path):
    """Same `key = value` format the responder reads; `#` comments full lines."""
    values = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if line and not line.startswith(("#", "!")) and "=" in line:
                    key, _, value = line.partition("=")
                    values[key.strip()] = value.strip()
    except OSError:
        log(f"no property file at {path}; using defaults")
    return values


PROPS = load_properties(PROPERTIES_FILE)
ENABLED = PROPS.get("rule_control.enabled", "true").lower() in ("true", "yes", "1", "on")
try:
    MAX_DISABLED = int(PROPS.get("rule_control.max_disabled") or 200)
except ValueError:
    MAX_DISABLED = 200


# ---------------------------------------------------------------------------
def read_state():
    """{entry key: {signature, since, note}}. Keys from before scoped entries
    existed are bare sids, which is exactly what a global entry's key is."""
    try:
        with open(STATE_FILE) as fh:
            state = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(state, dict):
        return {}
    # Drop anything unparseable rather than render it into threshold.config:
    # one bad line there and Suricata rejects the whole file on reload.
    return {key: entry for key, entry in state.items()
            if parse_entry(key) is not None and isinstance(entry, dict)}


def write_state(state):
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh, indent=1, sort_keys=True)
    os.replace(tmp, STATE_FILE)  # atomic: a torn state file loses every exception


def rule_msg(sid):
    """The msg text of a sid, looked up once when it is disabled.

    Stored rather than resolved on every read, because the point of storing it is
    to still know what a rule was after `suricata-update` drops it.
    """
    pattern = re.compile(r"\bsid:\s*%d\s*;" % sid)
    msg = re.compile(r'msg:\s*"([^"]*)"')
    for path in RULE_FILES:
        try:
            with open(path, errors="replace") as fh:
                # A rule is not necessarily a line: suricata.rules keeps one rule
                # per line, but local.rules is hand-written and wraps with
                # trailing backslashes, so the line carrying `sid:` is usually
                # not the one carrying `msg:`. Join continuations before matching.
                rule = ""
                for line in fh:
                    text = line.rstrip("\n").rstrip()
                    if not rule and text.lstrip().startswith("#"):
                        continue  # commented-out rules are not in the ruleset
                    if text.endswith("\\"):
                        rule += text[:-1]
                        continue
                    rule += text
                    if pattern.search(rule):
                        found = msg.search(rule)
                        return found.group(1) if found else "(rule has no msg)"
                    rule = ""
        except OSError:
            continue
    return "(not in the current ruleset)"


def threshold_line(key):
    sid, track, net = parse_entry(key)
    if track is None:
        return f"suppress gen_id 1, sig_id {sid}"
    return f"suppress gen_id 1, sig_id {sid}, track by_{track}, ip {net}"


def render_threshold(state):
    """Rewrite only the managed block, preserving hand-written thresholds."""
    try:
        with open(THRESHOLD_FILE, errors="replace") as fh:
            existing = fh.read().splitlines()
    except OSError:
        existing = []

    if BEGIN in existing and END in existing:
        head = existing[:existing.index(BEGIN)]
        tail = existing[existing.index(END) + 1:]
    else:
        # Markers gone (hand-edited, or a file from before this service): keep
        # whatever is there and append a fresh block rather than discarding it.
        head, tail = existing, []

    body = [BEGIN,
            "# Rules disabled from the Grafana UI. Do not edit by hand -- this",
            "# block is regenerated on every change.",
            *(threshold_line(key) for key in sorted(state, key=entry_sort)),
            END]
    return "\n".join(head + body + tail) + "\n"


def suricata_reload():
    """Ask Suricata to reload its ruleset over the unix command socket.

    Same handshake suricatasc uses: send {"version": ...}, then the command.

    **Every message sent must end with a newline.** Suricata checks the last byte
    of what it read and drops the connection outright if it is not a newline; it
    logs "Unix socket: incomplete client message, closing connection" and this
    side sees nothing but a closed socket, which looks like anything except a
    framing problem. Replies are read the other way round, by accumulating until
    the bytes parse as JSON, because the server does not frame them reliably.
    """
    def recv_json(sock):
        buf = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                raise OSError("suricata closed the command socket")
            buf += chunk
            try:
                return json.loads(buf)
            except ValueError:
                continue

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(120)  # a reload of ~50k rules is not instant
    try:
        sock.connect(SOCKET_PATH)
        sock.sendall(json.dumps({"version": "0.2"}).encode() + b"\n")
        hello = recv_json(sock)
        if hello.get("return") != "OK":
            raise OSError(f"handshake refused: {hello}")
        sock.sendall(json.dumps({"command": "reload-rules"}).encode() + b"\n")
        answer = recv_json(sock)
        if answer.get("return") != "OK":
            raise OSError(f"reload-rules failed: {answer}")
        return answer.get("message", "done")
    finally:
        sock.close()


def influx_audit(key, action, msg):
    """Permanent record of every change; the container log rotates away, and
    "when did detection get turned down, and for what" is an audit question.

    `track` (all/src/dst/either) is a tag; the address is a field, being
    unbounded."""
    sid, track, net = parse_entry(key)
    escaped = str(msg)[:200].replace("\\", "\\\\").replace('"', '\\"')
    line = (f"suricata_rule_control,sid={sid},action={action},"
            f"track={track or 'all'} "
            f'count=1i,signature="{escaped}",ip="{net or ""}"')
    endpoint = (f"{INFLUX_URL.rstrip('/')}/api/v2/write"
                f"?org={urllib.parse.quote(INFLUX_ORG)}"
                f"&bucket={urllib.parse.quote(INFLUX_BUCKET)}&precision=s")
    req = urllib.request.Request(
        endpoint, data=line.encode(), method="POST",
        headers={"Authorization": f"Token {INFLUX_TOKEN}",
                 "Content-Type": "text/plain; charset=utf-8"})
    try:
        urllib.request.urlopen(req, timeout=5).close()
    except (urllib.error.URLError, OSError) as exc:
        log(f"influx audit write failed: {exc}")


# ---------------------------------------------------------------------------
def parse_sid(raw):
    """A sid, or None. Anything unparseable is None so a stray variable value
    from Grafana is a no-op rather than an error page."""
    raw = (raw or "").strip()
    if not raw or not raw.isdigit():
        return None
    sid = int(raw)
    return sid if 0 < sid < 2 ** 31 else None


TRACKS = {"src": "src", "by_src": "src", "dst": "dst", "by_dst": "dst",
          "either": "either", "by_either": "either", "any": "either"}


def parse_entry(raw):
    """(sid, track, network) from an entry string, or None.

    track is None for a global entry. The network is normalised (host bits
    cleared, /32 and /128 written as a bare address), so the same exception
    typed two ways is one key, and the returned key is canonical -- see
    entry_key. Unparseable means None, so a stray variable value from Grafana
    is a no-op rather than an error page.
    """
    raw = (raw or "").strip()
    sid_raw, sep, scope = raw.partition("@")
    sid = parse_sid(sid_raw)
    if sid is None:
        return None
    if not sep:
        return sid, None, None
    track_raw, _, addr = scope.partition(":")
    track = TRACKS.get(track_raw.strip().lower())
    try:
        net = ipaddress.ip_network(addr.strip(), strict=False)
    except ValueError:
        return None
    if track is None or net.prefixlen == 0:
        return None  # a /0 scope is a global suppression; say so by typing the sid
    text = (str(net.network_address) if net.prefixlen == net.max_prefixlen
            else str(net))
    return sid, track, text


def entry_key(parsed):
    sid, track, net = parsed
    return str(sid) if track is None else f"{sid}@{track}:{net}"


def entry_sort(key):
    sid, track, net = parse_entry(key)
    return (sid, track or "", net or "")


def apply_actions(disable_raw, enable_raw, note):
    """Apply at most one disable and one enable. Returns (rules, messages).

    Only touches the files and reloads Suricata when the set actually *changes*:
    Grafana re-runs this query on every panel refresh with the same variable
    still in the box, and reloading 50k rules once a minute would be a real cost.
    """
    messages = []
    with _lock:
        state = read_state()
        before = set(state)

        if not ENABLED and (disable_raw or enable_raw):
            return sorted_rules(state), ["rule_control.enabled = false: read-only"]

        if (enable_raw or "").strip().lower() == "all":
            if state:
                messages.append(f"re-enabled all {len(state)} suppression(s)")
                for key in list(state):
                    influx_audit(key, "enable", state[key].get("signature", ""))
                state = {}
        else:
            parsed = parse_entry(enable_raw)
            key = entry_key(parsed) if parsed else None
            if key in state:
                messages.append(f"re-enabled {key}")
                influx_audit(key, "enable", state[key].get("signature", ""))
                del state[key]

        parsed = parse_entry(disable_raw)
        key = entry_key(parsed) if parsed else None
        if key is not None and key not in state:
            if len(state) >= MAX_DISABLED:
                messages.append(f"refused: already {len(state)} suppressions "
                                f"(rule_control.max_disabled)")
            else:
                sid = parsed[0]
                # Another entry for the same sid already knows its text, and
                # may know it after suricata-update dropped the rule.
                signature = next(
                    (e.get("signature") for k, e in state.items()
                     if parse_entry(k)[0] == sid and e.get("signature")),
                    None) or rule_msg(sid)
                state[key] = {
                    "signature": signature,
                    "since": datetime.now(timezone.utc)
                             .strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "note": (note or "")[:200],
                }
                messages.append(f"disabled {key} ({signature})")
                influx_audit(key, "disable", signature)

        if set(state) == before:
            return sorted_rules(state), messages

        write_state(state)
        with open(THRESHOLD_FILE + ".tmp", "w") as fh:
            fh.write(render_threshold(state))
        os.replace(THRESHOLD_FILE + ".tmp", THRESHOLD_FILE)

        try:
            suricata_reload()
            messages.append("suricata reloaded its ruleset")
            log(" | ".join(messages))
        except (OSError, socket.timeout) as exc:
            # The file is already correct, so the change lands on the next
            # reload or restart -- say so instead of pretending it worked.
            messages.append(f"WARNING: suricata reload failed ({exc}); the "
                            f"change applies on its next restart")
            log(" | ".join(messages))
        return sorted_rules(state), messages


SCOPE_TEXT = {"src": "source", "dst": "destination", "either": "either end"}


def sorted_rules(state):
    rules = []
    for key in sorted(state, key=entry_sort):
        sid, track, net = parse_entry(key)
        entry = state[key]
        rules.append({"sid": sid,
                      "scope": (f"{SCOPE_TEXT[track]} {net}" if track
                                else "everywhere"),
                      "key": key,
                      "signature": entry.get("signature", ""),
                      "since": entry.get("since", ""),
                      "note": entry.get("note", "")})
    return rules


# The dashboards send the uid of the datasource their Site box points at. Only
# the local one may act: a central Grafana browsing another site still calls
# *this* rule-control, and a click on that site's alert would otherwise
# suppress the rule here. No parameter means a caller from before the Site box.
LOCAL_SITE_UID = "InfluxDB_Flux"


def is_local(query):
    return query.get("site", [LOCAL_SITE_UID])[0] in ("", LOCAL_SITE_UID)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.path in ("/apply", "/rules", "/") and not is_local(query):
            # Listing this site's suppressions next to another site's alerts
            # would read as that site's, so the list is empty as well.
            body = b"[]"
        elif parsed.path == "/status" and not is_local(query):
            body = json.dumps([{"disabled": -1, "control_enabled": 2,
                                "suricata_socket": -1}]).encode()
        elif parsed.path in ("/apply", "/rules", "/"):
            rules, messages = apply_actions(
                query.get("disable", [""])[0],
                query.get("enable", [""])[0],
                query.get("note", [""])[0])
            body = json.dumps(rules).encode()
        elif parsed.path == "/status":
            reachable = os.path.exists(SOCKET_PATH)
            body = json.dumps([{"disabled": len(read_state()),
                                "control_enabled": 1 if ENABLED else 0,
                                "suricata_socket": 1 if reachable else 0}]).encode()
        else:
            self.send_response(404)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Grafana must never serve a stale list after an action.
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # actions are logged by apply_actions; reads are noise


if __name__ == "__main__":
    os.makedirs(CONTROL_DIR, exist_ok=True)
    state = read_state()
    log(f"rule-control on :{LISTEN_PORT} | {len(state)} rule(s) disabled | "
        f"actions {'enabled' if ENABLED else 'DISABLED (read-only)'} | "
        f"max {MAX_DISABLED}")
    # threshold.config and the state file can drift apart if the volume is reset
    # or the file is hand-edited; re-render once at start so they agree.
    if state:
        with open(THRESHOLD_FILE + ".tmp", "w") as fh:
            fh.write(render_threshold(state))
        os.replace(THRESHOLD_FILE + ".tmp", THRESHOLD_FILE)
    ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
