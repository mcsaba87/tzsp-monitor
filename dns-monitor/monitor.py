r"""Count DNS lookups per client, and record the ones the router refused.

    suricata --(unix socket, DNS events only)--> [this service] --> InfluxDB

Two questions this answers that nothing else in the stack could:

* **which host asked for a blocked name.** `dns-filter` puts UT1 categories on
  the router's adlist and RouterOS answers `0.0.0.0` for every name on it, but
  the only evidence of a hit was the router's per-list `match-count` -- a
  number per category, with no idea who. A blocked lookup is identified here by
  its *answer*: an A/AAAA record whose rdata is 0.0.0.0 or ::. The queried name
  and the client are both in the same event.
* **how much DNS each host does, and how much of it fails.** NXDOMAIN storms and
  a host doing ten times everyone else's lookups are both visible in the
  per-client counts, and neither shows up in a flow record.

What this service deliberately does *not* do is record every query name per
host. It does not have to: the collector already tags every flow with
`server_name`, which nfstream fills from the DNS query as well as from TLS SNI,
so "who looked up what" is in `network_flow` already -- with full fidelity and
retroactively. Duplicating it here would double the cardinality to no end.

Three things about the transport, all measured on Suricata 8.0.6:

* **It is a unix socket, not a file, and that is the whole reason this is
  affordable.** eve.json is a file because an *alert* is evidence that has to
  survive a restart. DNS is a firehose -- on the production mirror it is on the
  order of gigabytes a day, some five hundred times what eve.json holds today --
  and it is telemetry, not evidence: losing a minute of counters while this
  service restarts costs nothing, whereas writing it to the log volume would
  push Suricata's alert history off the disk within the hour. Nothing is
  written to disk by this path at all.
* **Start order does not matter, in either direction.** With no listener at
  Suricata's start the output logs `will keep trying` and the engine starts
  normally; when this service later binds the socket, Suricata connects on its
  next DNS event. Kill this service with Suricata running and it logs `Broken
  pipe; reconnecting...` and reattaches the same way. So `suricata` needs no
  `depends_on` here, and rebuilding this service never touches the capture.
* **The client is `dest_ip`, not `src_ip`.** Only *responses* are logged
  (`requests: no` in suricata.yaml -- the response carries the query name as
  well, so logging both would double the stream for nothing), and in a response
  the source is the resolver and the destination is the host that asked.
"""
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

PROPERTIES_FILE = os.getenv("PROPERTIES_FILE", "/etc/tzsp-monitor/suricata.properties")
SOCKET_PATH = os.getenv("DNS_SOCKET", "/var/lib/suricata-dns/dns.socket")

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

# Bounds the buffer between newlines. A Suricata DNS record is a few hundred
# bytes; anything approaching this is a peer that is not Suricata.
MAX_LINE = 1 << 20

_log_lock = threading.Lock()


def log(msg):
    with _log_lock:
        sys.stdout.write(f"{datetime.now().strftime('%H:%M:%S')} {msg}\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Property file  (same shape as the responder's -- one file per host, not one
# per service, so site policy is written down in exactly one place)
# ---------------------------------------------------------------------------
class Config:
    """`key = value` property file with typed access and defaults.

    `#` only starts a comment at the start of a line, for the same reason as in
    the responder: values contain `#` often enough that stripping trailing
    comments would be a support call.
    """

    def __init__(self, path):
        self.values = {}
        self.present = os.path.isfile(path)
        if not self.present:
            log(f"no property file at {path}: using defaults")
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

    def get_list(self, key, default=""):
        return [item.strip() for item in self.get(key, default).split(",")
                if item.strip()]


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

    Same client as the responder's. Batched because a flush here emits one point
    per (client, result) pair plus one per blocked name, which on a busy pass is
    hundreds of lines that have no business being hundreds of round trips.
    """

    def __init__(self, url, token, org, bucket, batch=500, interval=5.0):
        self.endpoint = (f"{url.rstrip('/')}/api/v2/write"
                         f"?org={urllib.parse.quote(org)}"
                         f"&bucket={urllib.parse.quote(bucket)}&precision=ns")
        self.headers = {"Authorization": f"Token {token}",
                        "Content-Type": "text/plain; charset=utf-8"}
        self.batch = batch
        self.lock = threading.Lock()
        self.buffer = []
        threading.Thread(target=self._flush_forever, args=(interval,),
                         daemon=True).start()

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

    def _flush_forever(self, interval):
        while True:
            time.sleep(interval)
            self.flush()


# ---------------------------------------------------------------------------
# One eve DNS record -> (client, name, result)
# ---------------------------------------------------------------------------
CAPPED = "(capped)"

# What the dashboard's one tile means. Kept pure and separate because it is the
# reading that is easy to get wrong in the direction that matters: `connected`
# alone says WATCHING, and Suricata dials this socket when the *engine* starts,
# not when it has a DNS event to write. So a mirror that carries no DNS -- or
# carries only one direction of it, which with `requests: no` logs nothing at
# all -- looks exactly like a healthy pipeline over a quiet minute. The third
# state is the whole point: connected, and nothing has arrived for long enough
# that "quiet" is no longer the likely explanation.
STATE_DISCONNECTED = 0
STATE_SILENT = 1
STATE_WATCHING = 2


def monitor_state(connected, silent_for, silent_seconds):
    """0 nothing connected / 1 connected but nothing arriving / 2 watching.

    `silent_for` is measured from the last classified event *or* from the
    moment the current peer connected, whichever is later: a link that has only
    just come up has not had a chance to carry anything yet, and reporting it
    silent would make every Suricata restart look like a fault.
    """
    if not connected:
        return STATE_DISCONNECTED
    if silent_seconds > 0 and silent_for >= silent_seconds:
        return STATE_SILENT
    return STATE_WATCHING


def rrname(dns):
    """The queried name, whichever eve dns version produced the record.

    Lower-cased on purpose, and not only for tidiness: resolvers that implement
    0x20 encoding randomise the case of the name in the query and the answer
    echoes it back, so `WwW.ExAmPlE.CoM` and `www.example.com` are the same
    lookup arriving as two tag values. The trailing dot some records carry would
    split it a third way.
    """
    queries = dns.get("queries")
    if isinstance(queries, list) and queries:
        name = queries[0].get("rrname") or ""
    else:
        name = dns.get("rrname") or ""  # eve dns version 2
    return name.rstrip(".").lower()


def rrtype(dns):
    queries = dns.get("queries")
    if isinstance(queries, list) and queries:
        return queries[0].get("rrtype") or "unknown"
    return dns.get("rrtype") or "unknown"


def answers(dns):
    grouped = dns.get("answers")
    if isinstance(grouped, list):
        return [a.get("rdata") for a in grouped if isinstance(a, dict)]
    return []


class Classifier:
    """Turn one eve DNS event into what the dashboard needs, or None.

    Kept as its own object with no I/O in it because this is the part that
    decides what a "block" is, and getting it wrong is silent: a stack that
    counts nothing as blocked and a filter that is not working look identical
    from the dashboard.
    """

    def __init__(self, blocked_answers, resolvers):
        self.blocked_answers = set(blocked_answers)
        # Empty means "any resolver". Set it when clients can reach a resolver
        # that is not the router: a 0.0.0.0 answer from somebody else's
        # blocklist is a real block, but it is not *ours*, and counting it here
        # would credit the adlist with names that are not on it.
        self.resolvers = set(resolvers)

    def classify(self, event):
        dns = event.get("dns")
        if not isinstance(dns, dict):
            return None
        name = rrname(dns)
        if not name:
            return None

        # A response's source is the resolver and its destination is the host
        # that asked; a query is the other way round. Only responses are
        # configured, but a record without the marker is treated as a query so
        # a config change cannot silently swap every client for its resolver.
        if dns.get("type") == "response" or dns.get("qr") is True:
            client, resolver = event.get("dest_ip"), event.get("src_ip")
        else:
            client, resolver = event.get("src_ip"), event.get("dest_ip")
        if not client:
            return None

        rcode = (dns.get("rcode") or "").upper()
        ours = not self.resolvers or resolver in self.resolvers
        blocked = ours and bool(self.blocked_answers.intersection(answers(dns)))

        if blocked:
            result = "blocked"
        elif rcode == "NXDOMAIN":
            result = "nxdomain"
        elif rcode not in ("", "NOERROR"):
            result = "error"
        else:
            result = "ok"
        return client, resolver or "unknown", name, rrtype(dns), result


# ---------------------------------------------------------------------------
# Accumulate, then write one point per key per flush
# ---------------------------------------------------------------------------
class Aggregator:
    """Counts between flushes, so the write rate is independent of the query rate.

    A point per lookup would be one InfluxDB series write per DNS packet, which
    on the production mirror is ~170/s of data whose only use is being summed.
    Everything here is a count over the flush window instead, and the flush
    timestamp is the end of that window.
    """

    def __init__(self, influx, max_names):
        self.influx = influx
        self.max_names = max_names
        self.lock = threading.Lock()
        self.reset()

    def reset(self):
        self.per_client = {}   # (client, result) -> count
        self.per_block = {}    # (client, name)   -> [count, rrtype, resolver]
        self.events = 0
        self.blocked = 0
        self.capped = 0

    def add(self, client, resolver, name, qtype, result):
        with self.lock:
            self.events += 1
            key = (client, result)
            self.per_client[key] = self.per_client.get(key, 0) + 1
            if result != "blocked":
                return
            self.blocked += 1
            # `qname` is a tag because "which names are being blocked" has to be
            # groupable -- the same call as `signature` on suricata_alert. It is
            # affordable only because *blocked* names are a small set: a host
            # querying a thousand generated domains a minute is the shape that
            # would turn this into an unbounded tag, so past max_names the
            # overflow is counted under one name rather than dropped, and the
            # total stays right even when the detail is not.
            bkey = (client, name)
            if bkey not in self.per_block and len(self.per_block) >= self.max_names:
                self.capped += 1
                bkey = (client, CAPPED)
            row = self.per_block.setdefault(bkey, [0, qtype, resolver])
            row[0] += 1

    def flush(self, connected, state_code):
        with self.lock:
            per_client, per_block = self.per_client, self.per_block
            events, blocked, capped = self.events, self.blocked, self.capped
            self.reset()

        now_ns = time.time_ns()
        for (client, result), count in per_client.items():
            self.influx.point("dns_query", {"src_ip": client, "result": result},
                              {"count": f"{count}i"}, now_ns)
        for (client, name), (count, qtype, resolver) in per_block.items():
            self.influx.point("dns_block", {"src_ip": client, "qname": name},
                              {"count": f"{count}i", "rrtype": esc_str(qtype),
                               "resolver": esc_str(resolver)}, now_ns)

        # Written on every pass whether or not anything happened, so a quiet
        # network and a stopped service are different readings on the
        # dashboard rather than the same empty panel. `state_code` is the third
        # of those readings -- connected to Suricata and receiving nothing --
        # which `connected` on its own cannot express; see monitor_state.
        self.influx.point("dns_monitor", {}, {
            "up": "1i",
            "connected": f"{1 if connected else 0}i",
            "state_code": f"{state_code}i",
            "events": f"{events}i",
            "blocked": f"{blocked}i",
            "clients": f"{len({c for c, _ in per_client})}i",
            "names": f"{len(per_block)}i",
            "capped": f"{capped}i",
        }, now_ns)
        return events, blocked


# ---------------------------------------------------------------------------
# The socket Suricata connects to
# ---------------------------------------------------------------------------
def listener(path):
    """Bind the socket Suricata's eve `unix_stream` output dials into.

    Unlinked first: a unix socket is a filesystem object and it outlives the
    process that made it, so a restart would otherwise fail with EADDRINUSE on
    a socket nothing is listening to. The mode is permissive because Suricata
    runs as a different user in a different container; the socket only exists
    inside a volume shared by those two services, so nothing else can reach it.
    """
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    os.chmod(path, 0o666)
    srv.listen(1)
    srv.settimeout(1.0)
    return srv


def serve(srv, on_line, on_tick):
    """Read newline-delimited JSON from one peer at a time, forever.

    listen(1) and a single connection because there is exactly one writer. The
    timeouts are what make the flush tick independent of the traffic: with no
    DNS at all the loop still comes round once a second, which is how the health
    point gets written on a silent network.
    """
    conn = None
    buf = b""
    while True:
        if conn is None:
            try:
                conn, _ = srv.accept()
                conn.settimeout(1.0)
                log("suricata connected")
            except socket.timeout:
                pass
            except OSError as exc:
                log(f"accept failed: {exc}")
                time.sleep(1.0)
        else:
            try:
                data = conn.recv(65536)
                if data:
                    buf += data
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        on_line(line)
                    if len(buf) > MAX_LINE:
                        log(f"dropping {len(buf)} B with no newline in it")
                        buf = b""
                else:
                    log("suricata disconnected")
                    conn.close()
                    conn, buf = None, b""
            except socket.timeout:
                pass
            except OSError as exc:
                log(f"read failed: {exc}")
                conn.close()
                conn, buf = None, b""
        on_tick(conn is not None)


def main():
    cfg = Config(PROPERTIES_FILE)
    if not cfg.get_bool("dns_monitor.enabled", True):
        log("dns_monitor.enabled=false: nothing to do, idling")
        while True:
            time.sleep(3600)

    path = cfg.get("dns_monitor.socket", SOCKET_PATH)
    flush_seconds = max(5, cfg.get_int("dns_monitor.flush_seconds", 30))
    # How long a connected peer may send nothing before the dashboard stops
    # calling it healthy. Long enough that an ordinarily quiet network never
    # trips it -- a LAN with one host awake still resolves something every few
    # minutes -- and short enough to notice within one screen refresh. 0
    # disables the state, for a sensor that is genuinely idle for hours.
    silent_seconds = max(0, cfg.get_int("dns_monitor.silent_seconds", 600))
    classifier = Classifier(
        cfg.get_list("dns_monitor.blocked_answers", "0.0.0.0, ::"),
        cfg.get_list("dns_monitor.resolvers"))
    influx = Influx(INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG, INFLUX_BUCKET)
    agg = Aggregator(influx, cfg.get_int("dns_monitor.max_names", 500))

    srv = listener(path)
    log(f"listening on {path}; blocked answers="
        f"{sorted(classifier.blocked_answers)} "
        f"resolvers={sorted(classifier.resolvers) or 'any'} "
        f"flush={flush_seconds}s max_names={agg.max_names} "
        f"silent_after={silent_seconds or 'never'}s")

    # Single-threaded: serve() calls both of these from its own loop, so the
    # silence clock needs no lock.
    state = {"next": time.monotonic() + flush_seconds,
             "last_event": time.monotonic(),
             "connected": False,
             "code": STATE_DISCONNECTED}

    def on_line(raw):
        try:
            event = json.loads(raw)
        except ValueError:
            return
        if event.get("event_type") != "dns":
            return
        classified = classifier.classify(event)
        if classified:
            agg.add(*classified)
            state["last_event"] = time.monotonic()

    def on_tick(connected):
        now = time.monotonic()
        if connected and not state["connected"]:
            state["last_event"] = now  # a fresh link starts with a clean slate
        state["connected"] = connected
        if now < state["next"]:
            return
        state["next"] = now + flush_seconds
        code = monitor_state(connected, now - state["last_event"], silent_seconds)
        events, blocked = agg.flush(connected, code)
        if events or blocked:
            log(f"[DNS] {events} lookup(s), {blocked} blocked")
        # Logged on the change only: the interesting line is the one that says
        # when the stream stopped, and a message every 30s would bury it.
        if code != state["code"]:
            if code == STATE_SILENT:
                log(f"no DNS events for {silent_seconds}s although suricata "
                    "is connected: check that the mirror carries DNS in BOTH "
                    "directions (only responses are logged) and that "
                    "tzsp-decap is still receiving")
            elif code == STATE_WATCHING and state["code"] == STATE_SILENT:
                log("DNS events are arriving again")
            state["code"] = code

    serve(srv, on_line, on_tick)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log(f"fatal: {exc}")
        sys.exit(1)
