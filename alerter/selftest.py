"""Offline checks of every decision the alerter makes, and one live run.

    python selftest.py           # no InfluxDB, no dns-filter, no network
    python selftest.py --live    # also through the real InfluxDB (see live())

Offline, the queries, InfluxDB writes and dns-filter lookups are stubs and the
commands are real /bin/sh processes, so what is checked is exactly what runs:
grading per source, the first-start and on-enable priming, the cooldown, the
two-step command change, the one-shot test token, read-only mode, the
command's environment (and what is kept out of it), timeouts that kill
backgrounded children, and the output cap.
"""
import argparse
import json
import os
import socket
import sys
import tempfile
import time
import urllib.parse
import urllib.request

import alerter as A

FAILED = []


def check(name, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}" + (f"  -- {detail}" if detail and not ok else ""))
    if not ok:
        FAILED.append(name)
    return ok


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + f".{int((ts % 1) * 1e9):09d}Z"


class Stub:
    """Rows per measurement, recorded writes, a dns-filter answer table."""

    def __init__(self):
        self.rows = {}
        self.writes = []
        self.lists = {}
        self.which_fails = False
        self.queries = []

    def query(self, flux):
        self.queries.append(flux)
        for meas, rows in self.rows.items():
            if f'r._measurement == "{meas}"' in flux:
                # Honour the severity pushdown the way InfluxDB would.
                if "r.severity =~ /^[1-" in flux:
                    top = int(flux.split("r.severity =~ /^[1-")[1][0])
                    return [r for r in rows if int(r.get("severity", 4)) <= top]
                return list(rows)
        return []

    def write(self, lines):
        self.writes.extend(lines)

    def which(self, names):
        if self.which_fails:
            raise OSError("dns-filter down")
        return {n: self.lists.get(n, {"list": "", "source": ""}) for n in names}

    def points(self, measurement):
        return [w for w in self.writes if w.startswith(measurement + ",") or
                w.startswith(measurement + " ")]


def new_alerter(stub, path, syslog=None):
    return A.Alerter(state_path=path, write=stub.write, query=stub.query,
                     which=stub.which, start_workers=False, syslog=syslog)


def drain(al):
    out = []
    while not al.queue.empty():
        out.append(al.queue.get_nowait())
    return out


def q(**kw):
    return {k: [v] for k, v in kw.items()}


# ---------------------------------------------------------------------------
def grading():
    print("grading")
    t = iso(time.time())
    ev = A.make_event("suricata", {"_time": t, "severity": "1", "signature": "ET MALWARE x",
                                   "signature_id": "2000001", "src_ip": "10.0.0.5",
                                   "dst_ip": "203.0.113.9", "src_port": "5000",
                                   "dst_port": "443", "proto": "TCP"})
    check("suricata: rule severity, type, title with both ends",
          ev["severity"] == 1 and ev["type"] == "suricata.alert"
          and "10.0.0.5:5000 -> 203.0.113.9:443" in ev["title"], str(ev))
    hit = lambda lst, src="category": {"q.example": {"list": lst, "source": src}}
    row = {"_time": t, "src_ip": "10.0.0.7", "qname": "q.example"}
    grades = {
        "automatic blacklist entry -> 1": (hit("_blacklist", "automatic"), 1),
        "hand-made blacklist entry -> 3": (hit("_blacklist", "dashboard"), 3),
        "malware category -> 2": (hit("malware"), 2),
        "ads category -> 4": (hit("ads"), 4),
        "on no list -> 4": (hit(""), 4),
    }
    for name, (lists, want) in grades.items():
        ev = A.make_event("dns", row, lists)
        check(f"dns: {name}", ev["severity"] == want, f"got {ev['severity']}")
    check("dns: an unknown list is not graded (None, retried later)",
          A.make_event("dns", row, {}) is None)
    rep = {"_time": t, "internal_ip": "10.0.0.8", "remote_ip": "198.51.100.1",
           "feed": "feodo", "direction": "outbound", "flows": "3"}
    check("reputation: outbound to a C2 feed -> 1",
          A.make_event("reputation", rep)["severity"] == 1)
    check("reputation: outbound to another feed -> 2",
          A.make_event("reputation", dict(rep, feed="spamhaus_drop"))["severity"] == 2)
    check("reputation: inbound -> 4",
          A.make_event("reputation", dict(rep, direction="inbound"))["severity"] == 4)
    scan = {"_time": t, "src_ip": "10.0.0.9", "scope": "internal", "outcome": "internal"}
    check("scan: internal -> 2, external -> 4",
          A.make_event("scan", scan)["severity"] == 2
          and A.make_event("scan", dict(scan, scope="external"))["severity"] == 4)
    flux = A.query_for("suricata", 600, 2, 500)
    check("query: severity is a pushed-down tag regex", "r.severity =~ /^[1-2]$/" in flux, flux)
    check("query: computed-severity sources fetch every row",
          "severity" not in A.query_for("dns", 600, 2, 500))
    a = A.event_id("arp", {"_time": t, "alert": "x", "ip": "1.2.3.4"})
    b = A.event_id("arp", {"_time": t, "alert": "x", "ip": "1.2.3.5"})
    check("event id: series and time, so two addresses are two events", a != b)


def priming_and_firing(tmp):
    print("priming, severity, cooldown")
    stub, path = Stub(), os.path.join(tmp, "s1.json")
    now = time.time()
    old = {"_time": iso(now - 60), "alert": "ip_conflict", "severity": "3", "ip": "192.0.2.1",
           "vlan": "0", "detail": "old"}
    stub.rows["arp_alert"] = [old]
    al = new_alerter(stub, path)
    al.state["default_command"] = "true"
    al.apply(q(enable="arp", severity="arp:3"))
    al.poll(now)
    check("enabling a source fires nothing already in the window", not drain(al))
    check("...and says so in the alerter health point", bool(stub.points("alerter")))
    new = dict(old, _time=iso(now + 1), detail="new")
    stub.rows["arp_alert"].append(new)
    al.poll(now + 30)
    fired = drain(al)
    check("a new point after the prime fires once", len(fired) == 1, str(len(fired)))
    al.poll(now + 60)
    check("the same point is not fired again on the next poll", not drain(al))
    # Same key (alert + ip + vlan), new time: held by the cooldown.
    stub.rows["arp_alert"].append(dict(old, _time=iso(now + 70), detail="again"))
    al.poll(now + 90)
    check("a repeat of the same thing is held by the cooldown", not drain(al))
    check("...and counted as suppressed",
          al.state["cooldown"]["arp|ip_conflict|192.0.2.1|0"][1] == 1)
    later = now + A.REPEAT_SECONDS + 100
    stub.rows["arp_alert"].append(dict(old, _time=iso(later - 5), detail="much later"))
    al.lookback = A.REPEAT_SECONDS + 400
    al.poll(later)
    fired = drain(al)
    check("after the cooldown it fires, carrying the held-back count",
          len(fired) == 1 and fired[0][0]["repeats"] == 1,
          str([f[0].get("repeats") for f in fired]))
    al.lookback = A.LOOKBACK
    # Severity: a medium alert with the threshold at high stays quiet.
    stub.rows["arp_alert"] = [dict(old, _time=iso(later + 10), ip="192.0.2.2")]
    al.apply(q(severity="arp:2"))
    al.poll(later + 20)
    check("below the chosen severity: no command", not drain(al))
    # Restart: the persisted seen-set means nothing is repeated.
    al2 = new_alerter(stub, path)
    al2.poll(later + 30)
    check("a restart repeats nothing (seen-set persisted)", not drain(al2))
    check("a restart is not a first start (no prime)", not al2.prime)


def dns_retry(tmp):
    print("dns grading through dns-filter")
    stub, path = Stub(), os.path.join(tmp, "s2.json")
    now = time.time()
    al = new_alerter(stub, path)
    al.state["primed"] = True
    al.prime.clear()
    al.state["rules"]["dns"].update(enabled=True, min_severity=2)
    al.state["default_command"] = "true"
    stub.rows["dns_block"] = [{"_time": iso(now - 5), "src_ip": "10.0.0.7", "qname": "c2.example"},
                              {"_time": iso(now - 5), "src_ip": "10.0.0.7", "qname": "ads.example"}]
    stub.lists = {"c2.example": {"list": "_blacklist", "source": "automatic"},
                  "ads.example": {"list": "ads", "source": "category"}}
    stub.which_fails = True
    al.poll(now)
    check("dns-filter down: nothing fired, nothing marked seen", not drain(al)
          and not any(A.event_id("dns", r) in al.state["seen"] for r in stub.rows["dns_block"]))
    stub.which_fails = False
    al.poll(now + 30)
    fired = drain(al)
    check("dns-filter back: the C2 lookup fires, the ad lookup (info) does not",
          len(fired) == 1 and fired[0][0]["details"]["qname"] == "c2.example",
          str([f[0]["details"]["qname"] for f in fired]))


def control(tmp):
    print("control surface")
    stub, path = Stub(), os.path.join(tmp, "s3.json")
    al = new_alerter(stub, path)
    al.apply(q(command_for="suricata", command="curl -s https://example.invalid/x"))
    check("a typed command is only staged", al.state["rules"]["suricata"]["command"] == ""
          and al.pending is not None)
    code = al.pending["code"]
    al.apply(q(command_for="suricata", command="curl -s https://example.invalid/x"))
    check("the refresh re-sending the box keeps the same code", al.pending["code"] == code)
    al.apply(q(confirm="0" * 24))
    check("a wrong confirm code changes nothing", al.state["rules"]["suricata"]["command"] == "")
    al.apply(q(confirm=code))
    check("the right code applies it", al.state["rules"]["suricata"]["command"]
          == "curl -s https://example.invalid/x" and al.pending is None)
    check("...and audits it", any("alerting_control" in w and "action=command" in w
                                  for w in stub.writes))
    n = len(stub.writes)
    al.apply(q(confirm=code))
    check("the confirm re-sent by a refresh is a no-op", len(stub.writes) == n)
    al.apply(q(command_for="suricata", command="curl -s https://example.invalid/x"))
    check("the edit link pre-filling the current command stages nothing", al.pending is None)
    al.apply(q(command_for="default", command="echo hi"))
    c2 = al.pending["code"]
    al.apply(q(cancel=c2))
    check("cancel discards a staged change", al.pending is None and al.state["default_command"] == "")
    with open(path) as fh:
        saved = json.load(fh)
    check("the state file holds the command", saved["rules"]["suricata"]["command"].startswith("curl"))
    check("...and is private (0600)", (os.stat(path).st_mode & 0o777) == 0o600,
          oct(os.stat(path).st_mode & 0o777))
    # Test token: one shot.
    token = al.tokens["suricata"]
    al.apply(q(test=f"suricata:{token}"))
    first = drain(al)
    al.apply(q(test=f"suricata:{token}"))
    check("a test link runs once, not on every refresh",
          len(first) == 1 and first[0][3] is True and not drain(al))
    al.apply(q(test="suricata:deadbeef"))
    check("a guessed test token runs nothing", not drain(al))
    al.apply(q(enable="nope", severity="arp:9"))
    check("unknown source / bad severity are refused with a message",
          "no such source" in al.message and "not <source>:<1-4>" in al.message, al.message)
    al.apply(q(enable="wids", disable="wids"))
    check("disable after enable: a stale enable box loses", not al.state["rules"]["wids"]["enabled"])
    A.CONTROL = False
    try:
        al.apply(q(enable="suricata", command_for="default", command="id"))
        check("ALERTING_CONTROL=ro refuses every change",
              not al.state["rules"]["suricata"]["enabled"] and al.pending is None
              and "read-only" in al.message)
    finally:
        A.CONTROL = True
    check("another site's request is inert", not A.is_local({"site": ["site-other"]})
          and A.is_local({}) and A.is_local({"site": ["InfluxDB_Flux"]}))


def commands():
    print("commands")
    os.environ["ALERT_SECRET_HOOK"] = "s3cret"
    os.environ["INFLUXDB_TOKEN"] = "must-not-leak"
    ev = A.make_event("wids", {"_time": iso(time.time()), "alert": "evil_twin",
                               "severity": "1", "bssid": "02:00:5e:00:53:01",
                               "ssid": "corp", "detail": "a \"quoted\" & $(odd) detail"})
    ev["repeats"] = 2
    env = A.command_env(ev)
    check("env: type, severity, title, details, JSON",
          env["ALERT_TYPE"] == "wids.evil_twin" and env["ALERT_SEVERITY"] == "1"
          and env["ALERT_SEVERITY_NAME"] == "critical" and "evil_twin" in env["ALERT_TITLE"]
          and "ssid: corp" in env["ALERT_DETAILS"]
          and json.loads(env["ALERT_JSON"])["details"]["bssid"] == "02:00:5e:00:53:01"
          and env["ALERT_REPEATS"] == "2" and env["ALERT_BSSID"] == "02:00:5e:00:53:01")
    check("env: ALERT_SECRET_* is passed through", env.get("ALERT_SECRET_HOOK") == "s3cret")
    check("env: nothing else of the service's (no InfluxDB token)",
          "INFLUXDB_TOKEN" not in env and "must-not-leak" not in json.dumps(env))
    res, code, out, _ = A.run_command('printf %s "$ALERT_SECRET_HOOK|$ALERT_DETAILS" | head -c 40', env)
    check("a command reads the variables, quoting survives", res == "ok" and code == 0
          and out.startswith("s3cret|") , repr(out))
    res, code, out, _ = A.run_command("echo bad; exit 3", env)
    check("non-zero exit is 'failed' with its output", res == "failed" and code == 3
          and "bad" in out)
    marker = os.path.join(tempfile.gettempdir(), f"alerter-selftest-{os.getpid()}")
    started = time.monotonic()
    res, code, _, _ = A.run_command(f"(sleep 3; touch {marker}) & sleep 30", env, timeout=1)
    time.sleep(3.5)
    check("timeout: killed within its limit", res == "timeout"
          and time.monotonic() - started < 6)
    check("timeout: a backgrounded child dies with it", not os.path.exists(marker))
    res, code, out, _ = A.run_command("yes | head -c 5000000", env)
    check("output is capped at 2000 bytes", res == "ok" and len(out) <= 2000, str(len(out)))
    if os.geteuid() == 0:
        res, code, out, _ = A.run_command("id -u", env)
        check("as root the command runs as nobody", out.strip() == str(A.RUN_UID), out)


def syslog(tmp):
    print("syslog")
    check("target parsing: host, host:port, [v6]:port, bare v6",
          A.parse_syslog_target("log.example") == ("log.example", 514)
          and A.parse_syslog_target("10.0.0.1:1514") == ("10.0.0.1", 1514)
          and A.parse_syslog_target("[::1]:5514") == ("::1", 5514)
          and A.parse_syslog_target("fe80::1") == ("fe80::1", 514))
    ev = A.make_event("arp", {"_time": iso(time.time()), "alert": "gateway_spoof",
                              "severity": "1", "ip": "192.0.2.1", "vlan": "0",
                              "detail": "x" * 5000})
    msg = A.syslog_message(ev, facility="local0", hostname="my site", max_bytes=2048)
    head, _, body = msg.partition(b" - \xef\xbb\xbf")
    parts = head.split(b" ")
    check("RFC 5424 header: <PRI>1, crit on local0 (130), host without spaces, MSGID = type",
          parts[0] == b"<130>1" and parts[2] == b"mysite" and parts[3] == b"tzsp-monitor"
          and parts[5] == b"arp.gateway_spoof", repr(head))
    try:
        payload = json.loads(body)
    except ValueError:
        payload = {}
    check("an oversized alert is shortened, not cut: still JSON, still under the limit",
          len(msg) <= 2048 and payload.get("type") == "arp.gateway_spoof"
          and payload["details"].get("ip") == "192.0.2.1", str(len(msg)))
    check("severity map: 4 info -> syslog info (local0: 134)",
          A.syslog_message(dict(ev, severity=4), facility="local0").startswith(b"<134>1 "))
    # A real UDP round trip, through the Alerter.
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(3)
    sl = A.Syslog(f"127.0.0.1:{rx.getsockname()[1]}")
    stub, path = Stub(), os.path.join(tmp, "s5.json")
    al = new_alerter(stub, path, syslog=sl)
    al.state["primed"] = True
    al.prime.clear()
    al.state["rules"]["arp"].update(enabled=True, min_severity=2)  # no command at all
    now = time.time()
    stub.rows["arp_alert"] = [{"_time": iso(now - 5), "alert": "gateway_spoof", "severity": "1",
                               "ip": "192.0.2.1", "vlan": "0", "detail": "spoof"},
                              {"_time": iso(now - 5), "alert": "new_station", "severity": "4",
                               "ip": "192.0.2.9", "vlan": "0", "detail": "below threshold"}]
    al.poll(now)
    try:
        got = rx.recv(65535)
    except socket.timeout:
        got = b""
    check("an alert reaches syslog over UDP even with no command set",
          b"arp.gateway_spoof" in got and b'"192.0.2.1"' in got, repr(got[:120]))
    try:
        extra = rx.recv(65535)
    except socket.timeout:
        extra = b""
    check("below the threshold: nothing sent", not extra, repr(extra[:120]))
    stub.rows["arp_alert"].append({"_time": iso(now + 10), "alert": "gateway_spoof",
                                   "severity": "1", "ip": "192.0.2.1", "vlan": "0",
                                   "detail": "again"})
    al.poll(now + 20)
    rx.settimeout(1)
    try:
        extra = rx.recv(65535)
    except socket.timeout:
        extra = b""
    check("the cooldown holds syslog repeats too", not extra, repr(extra[:120]))
    check("the health point counts what was sent (by the next poll at the latest)",
          any("syslog_sent=1i" in w for w in stub.points("alerter")))
    al.apply(q(test=f"arp:{al.tokens['arp']}"))
    try:
        got = rx.recv(65535)
    except socket.timeout:
        got = b""
    check("a test link reaches syslog, marked as a test",
          b"arp.test" in got and b'"test": true' in got, repr(got[:120]))
    rx.close()


# ---------------------------------------------------------------------------
def live(tmp):
    """Through the real InfluxDB, without disturbing the running service.

    Writes one synthetic arp_alert on a TEST-NET address, timestamped *before*
    the running alerter's look-back window -- so the service never sees it
    and no real webhook fires -- then has a private Alerter (its own state, a
    longer look-back) prime, see the point, and run a command that writes a
    file. The point is deleted afterwards.
    """
    print("live (real InfluxDB)")
    stub = Stub()
    path = os.path.join(tmp, "live.json")
    al = A.Alerter(state_path=path, write=stub.write, which=stub.which, start_workers=False,
                   syslog=None)
    al.lookback = A.LOOKBACK + 900
    al.state["rules"]["arp"].update(enabled=True, min_severity=4)
    al.prime.add("arp")
    al.poll()
    check("live: query ran", not al.query_error, al.query_error)
    ts = time.time() - A.LOOKBACK - 300
    ip = f"192.0.2.{int(time.time()) % 200 + 20}"
    A.influx_write([A.point("arp_alert", {"alert": "alerter_selftest", "severity": "4",
                                          "severity_name": "info", "ip": ip, "vlan": "0"},
                            {"count": "1i", "detail": A.esc_str("alerter selftest")},
                            int(ts * 1e9))])
    marker = os.path.join(tempfile.gettempdir(), f"alerter-live-{os.getpid()}")
    al.state["default_command"] = f'printf %s "$ALERT_TYPE $ALERT_IP" > {marker}'
    found = []
    for _ in range(10):
        al.poll()
        found = drain(al)
        if found:
            break
        time.sleep(1)
    check("live: the new point became one alert", len(found) == 1, str(len(found)))
    if found:
        ev, command, origin, test, row = found[0]
        res, code, out, _ = A.run_command(command, A.command_env(ev))
        try:
            with open(marker) as fh:
                text = fh.read()
            os.remove(marker)
        except OSError:
            text = ""
        check("live: the command ran with the alert's variables",
              res == "ok" and text == f"arp.alerter_selftest {ip}", repr(text))
    # Delete the synthetic point (rewrites a shard; one point is nothing).
    body = json.dumps({"start": "1970-01-01T00:00:00Z", "stop": A.now_iso(time.time() + 60),
                       "predicate": '_measurement="arp_alert" AND alert="alerter_selftest"'})
    req = urllib.request.Request(
        f"{A.INFLUX_URL}/api/v2/delete?org={urllib.parse.quote(A.INFLUX_ORG)}"
        f"&bucket={urllib.parse.quote(A.INFLUX_BUCKET)}", data=body.encode(), method="POST",
        headers={"Authorization": f"Token {A.INFLUX_TOKEN}", "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=20).close()
        check("live: synthetic point deleted", True)
    except OSError as exc:
        check("live: synthetic point deleted", False, str(exc))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        grading()
        priming_and_firing(tmp)
        dns_retry(tmp)
        control(tmp)
        commands()
        syslog(tmp)
        if args.live:
            live(tmp)
    print()
    if FAILED:
        print(f"{len(FAILED)} FAILED: " + ", ".join(FAILED))
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
