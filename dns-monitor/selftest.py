"""Prove the DNS path without waiting for somebody to visit a blocked site.

    docker compose exec dns-monitor python selftest.py            # offline
    docker compose exec dns-monitor python selftest.py --live     # + real pipeline

The offline part needs nothing running: it builds the same eve records Suricata
emits (captured from 8.0.6, `version: 3`, `formats: [detailed]`) and runs them
through the real Classifier and the real socket server, with InfluxDB stubbed
out. What it covers is the part that is silent when it is wrong -- a stack that
never counts a block and a filter that is not working look identical on the
dashboard:

  * an A answer of 0.0.0.0 is a block, and `::` covers the AAAA form;
  * the client of a *response* is dest_ip, not src_ip -- getting this backwards
    would attribute every lookup on the network to the router;
  * 0x20-randomised case and a trailing dot are the same name, not three;
  * NXDOMAIN and SERVFAIL are their own results, not blocks;
  * `dns_monitor.resolvers`, when set, refuses to credit our adlist with a
    0.0.0.0 that came from somebody else's resolver;
  * past max_names the overflow is counted under one name, so the totals stay
    right when the detail cannot;
  * a whole record split across two recv() boundaries is still one event, and a
    peer that disconnects is followed by the next one;
  * a peer that is connected but has sent nothing for long enough is reported
    as such rather than as health -- Suricata dials this socket at engine
    start, so `connected` alone is true of a mirror carrying no DNS at all.

`--live` sends TZSP-encapsulated DNS through the real decapsulator, so Suricata,
the socket and the running dns-monitor all take part, then reads the point back
out of InfluxDB. It uses documentation-range addresses and a .invalid name, so
it cannot collide with anything real.
"""
import argparse
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import monitor  # noqa: E402

failures = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  -- {detail}" if detail else ""))
    if not ok:
        failures.append(label)
    return ok


class StubInflux:
    """Collects points instead of writing them, so a run touches no database."""

    def __init__(self):
        self.points = []

    def point(self, measurement, tags, fields, timestamp_ns=None):
        self.points.append((measurement, dict(tags), dict(fields)))

    def of(self, measurement):
        return [p for p in self.points if p[0] == measurement]


def response(name, rdata, client="192.0.2.50", resolver="198.51.100.53",
             rcode="NOERROR", rrtype="A"):
    """One eve dns record in the shape Suricata 8.0.6 actually emits."""
    answers = [] if rdata is None else [
        {"rrname": name, "rrtype": rrtype, "ttl": 60, "rdata": rdata}]
    return {
        "timestamp": "2026-09-22T07:47:51.168153+0000",
        "event_type": "dns", "src_ip": resolver, "src_port": 53,
        "dest_ip": client, "dest_port": 51000, "proto": "UDP",
        "dns": {"version": 3, "type": "response", "id": 4369, "qr": True,
                "rcode": rcode,
                "queries": [{"rrname": name, "rrtype": rrtype}],
                "answers": answers},
    }


def test_classify():
    print("classifying an eve dns record")
    c = monitor.Classifier(["0.0.0.0", "::"], [])

    client, resolver, name, qtype, result = c.classify(
        response("ads.example.test", "0.0.0.0"))
    check("an A answer of 0.0.0.0 is a block", result == "blocked")
    check("the client is the response's DESTINATION", client == "192.0.2.50",
          f"got {client}; src_ip would be the router, not the host that asked")
    check("the resolver is kept as evidence", resolver == "198.51.100.53")
    check("the queried name comes through", name == "ads.example.test")
    check("so does the record type", qtype == "A")

    check("`::` is the AAAA form of the same block",
          c.classify(response("ads.example.test", "::", rrtype="AAAA"))[4] == "blocked")
    check("a real address is not a block",
          c.classify(response("example.test", "93.184.216.34"))[4] == "ok")
    check("NXDOMAIN is its own result, not a block",
          c.classify(response("nope.example.test", None, rcode="NXDOMAIN"))[4] == "nxdomain")
    check("so is SERVFAIL",
          c.classify(response("nope.example.test", None, rcode="SERVFAIL"))[4] == "error")

    check("0x20-randomised case folds to one name",
          c.classify(response("AdS.ExAmPlE.TeSt", "0.0.0.0"))[2] == "ads.example.test",
          "otherwise one blocked domain is as many tag values as the resolver invents")
    check("and so does a trailing dot",
          c.classify(response("ads.example.test.", "0.0.0.0"))[2] == "ads.example.test")

    query = {"event_type": "dns", "src_ip": "192.0.2.50", "dest_ip": "198.51.100.53",
             "dns": {"type": "query", "rrname": "example.test", "rrtype": "A"}}
    got = c.classify(query)
    check("a version-2 query record still yields the asking host",
          got[0] == "192.0.2.50" and got[2] == "example.test")

    check("a record with no dns section is ignored",
          c.classify({"event_type": "dns"}) is None)
    check("and so is one with no name",
          c.classify(response("", "0.0.0.0")) is None)

    strict = monitor.Classifier(["0.0.0.0"], ["198.51.100.53"])
    check("dns_monitor.resolvers still counts our own resolver",
          strict.classify(response("ads.example.test", "0.0.0.0"))[4] == "blocked")
    check("but refuses to credit the adlist with somebody else's 0.0.0.0",
          strict.classify(response("ads.example.test", "0.0.0.0",
                                   resolver="9.9.9.9"))[4] == "ok",
          "a public blocklist resolver is a real block, but it is not ours")


def test_aggregate():
    print("\naccumulating between flushes")
    influx = StubInflux()
    agg = monitor.Aggregator(influx, max_names=2)
    for _ in range(3):
        agg.add("192.0.2.50", "198.51.100.53", "ads.example.test", "A", "blocked")
    agg.add("192.0.2.50", "198.51.100.53", "example.test", "A", "ok")
    agg.add("192.0.2.51", "198.51.100.53", "nope.example.test", "A", "nxdomain")
    events, blocked = agg.flush(connected=True, state_code=monitor.STATE_WATCHING)
    check("every lookup is counted once", events == 5, f"got {events}")
    check("and the blocked ones again", blocked == 3, f"got {blocked}")

    per_client = {(t["src_ip"], t["result"]): f["count"] for _, t, f in influx.of("dns_query")}
    check("three lookups by one host collapse to one point",
          per_client.get(("192.0.2.50", "blocked")) == "3i", str(per_client))
    check("results are kept apart", per_client.get(("192.0.2.50", "ok")) == "1i")
    check("and so are hosts", per_client.get(("192.0.2.51", "nxdomain")) == "1i")

    blocks = {t["qname"]: f for _, t, f in influx.of("dns_block")}
    check("only blocked names get a dns_block point", list(blocks) == ["ads.example.test"],
          str(list(blocks)))
    check("carrying the client, the count and the resolver",
          blocks["ads.example.test"]["count"] == "3i"
          and "198.51.100.53" in blocks["ads.example.test"]["resolver"])

    health = influx.of("dns_monitor")
    check("a health point is written even so", len(health) == 1)
    check("and it says the socket is connected", health[0][2]["connected"] == "1i")

    influx = StubInflux()
    agg = monitor.Aggregator(influx, max_names=2)
    for i in range(5):
        agg.add("192.0.2.50", "198.51.100.53", f"dga{i}.example.test", "A", "blocked")
    events, blocked = agg.flush(connected=True, state_code=monitor.STATE_WATCHING)
    names = {t["qname"] for _, t, _ in influx.of("dns_block")}
    check("max_names bounds the distinct names recorded", len(names) == 3, str(names))
    check("the overflow is named rather than dropped", monitor.CAPPED in names)
    total = sum(int(f["count"].rstrip("i")) for _, _, f in influx.of("dns_block"))
    check("so the total is still right", total == 5 and blocked == 5, f"{total}/{blocked}")
    check("and the pass says how much detail it lost",
          influx.of("dns_monitor")[0][2]["capped"] == "3i")

    influx = StubInflux()
    agg = monitor.Aggregator(influx, max_names=10)
    agg.flush(connected=False, state_code=monitor.STATE_DISCONNECTED)
    check("an idle pass still reports, so 'quiet' and 'stopped' differ",
          influx.of("dns_monitor")[0][2]["events"] == "0i")
    check("and says nothing is connected",
          influx.of("dns_monitor")[0][2]["connected"] == "0i")


def test_state():
    print("\nreporting what the tile is allowed to call healthy")
    # The failure this exists for: Suricata connects to this socket when the
    # *engine* starts, so `connected` is 1 from the moment it is up, whether or
    # not a single DNS record ever follows. A mirror that carries no DNS -- or
    # only one direction of it, which with `requests: no` logs nothing -- then
    # reads as WATCHING over an empty dashboard.
    check("nothing connected is nothing connected",
          monitor.monitor_state(False, 0, 600) == monitor.STATE_DISCONNECTED)
    check("and stays so however long it has been",
          monitor.monitor_state(False, 99999, 600) == monitor.STATE_DISCONNECTED)
    check("a connected peer that is sending is watching",
          monitor.monitor_state(True, 0, 600) == monitor.STATE_WATCHING)
    check("a quiet minute is not a fault",
          monitor.monitor_state(True, 599, 600) == monitor.STATE_WATCHING)
    check("but silence past the window is not health either",
          monitor.monitor_state(True, 600, 600) == monitor.STATE_SILENT,
          "this is the whole reason the state exists")
    check("0 disables it, for a sensor that is idle for hours",
          monitor.monitor_state(True, 99999, 0) == monitor.STATE_WATCHING)

    influx = StubInflux()
    agg = monitor.Aggregator(influx, max_names=10)
    agg.flush(connected=True, state_code=monitor.STATE_SILENT)
    fields = influx.of("dns_monitor")[0][2]
    check("the state reaches InfluxDB as its own field",
          fields["state_code"] == "1i", str(fields))
    check("and `connected` still says what it always said, for history",
          fields["connected"] == "1i")


def test_socket():
    print("\nreading the socket Suricata dials into")
    tmp = tempfile.mkdtemp(prefix="dns-monitor-selftest-")
    path = os.path.join(tmp, "dns.socket")
    influx = StubInflux()
    agg = monitor.Aggregator(influx, max_names=100)
    classifier = monitor.Classifier(["0.0.0.0"], [])
    ticks = {"connected": 0}

    def on_line(raw):
        try:
            event = json.loads(raw)
        except ValueError:
            return
        got = classifier.classify(event)
        if got:
            agg.add(*got)

    def on_tick(connected):
        ticks["connected"] += 1 if connected else 0

    srv = monitor.listener(path)
    check("the socket is created where Suricata will look for it",
          os.path.exists(path))
    check("rebinding over a stale socket works",
          bool(monitor.listener(path)) and os.path.exists(path),
          "a unix socket outlives its process, so a restart must unlink first")
    srv.close()
    srv = monitor.listener(path)

    threading.Thread(target=monitor.serve, args=(srv, on_line, on_tick),
                     daemon=True).start()

    blob = (json.dumps(response("ads.example.test", "0.0.0.0")) + "\n"
            + json.dumps(response("example.test", "93.184.216.34")) + "\n")
    encoded = blob.encode()
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.connect(path)
    # Split mid-record on purpose: a 300 B eve line has no reason to arrive in
    # one recv, and a reader that assumes it does loses every event it splits.
    peer.sendall(encoded[:len(encoded) // 3])
    time.sleep(0.2)
    peer.sendall(encoded[len(encoded) // 3:])
    time.sleep(1.5)
    events, blocked = agg.flush(connected=True, state_code=monitor.STATE_WATCHING)
    check("a record split across two writes is still one event", events == 2,
          f"got {events}")
    check("and the block in it was seen", blocked == 1)

    peer.close()
    time.sleep(1.5)
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    peer.connect(path)
    peer.sendall(json.dumps(response("ads.example.test", "0.0.0.0")).encode() + b"\n")
    time.sleep(1.5)
    events, _ = agg.flush(connected=True, state_code=monitor.STATE_WATCHING)
    check("a peer that goes away is followed by the next one", events == 1,
          "Suricata reconnects after a restart of this service; so must we")
    peer.close()
    check("the idle tick keeps running with no traffic", ticks["connected"] > 0)

    for name in os.listdir(tmp):
        os.unlink(os.path.join(tmp, name))
    os.rmdir(tmp)


# ---------------------------------------------------------------------------
# --live: the real pipeline, end to end
# ---------------------------------------------------------------------------
CLIENT, RESOLVER = "192.0.2.77", "198.51.100.53"
LIVE_NAME = "tzsp-monitor-selftest.invalid"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def labels(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_query(txid, name):
    return (struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
            + labels(name) + struct.pack("!HH", 1, 1))


def dns_response(txid, name, rdata):
    question = labels(name) + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(rdata)
    return struct.pack("!HHHHHH", txid, 0x8180, 1, 1, 0, 0) + question + answer


def tzsp_wrap(src_ip, dst_ip, sport, dport, payload):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0x4321, 0, 64, 17,
                         0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    ether = (b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"
             + struct.pack("!H", 0x0800))
    # TZSP: version 1, type 0 (received tag list), encap 1 (Ethernet), TAG_END.
    return struct.pack("!BBHB", 1, 0, 1, 1) + ether + header + udp


def influx_query(flux):
    url = f"{monitor.INFLUX_URL.rstrip('/')}/api/v2/query?org={monitor.INFLUX_ORG}"
    req = urllib.request.Request(url, data=flux.encode(), method="POST", headers={
        "Authorization": f"Token {monitor.INFLUX_TOKEN}",
        "Content-Type": "application/vnd.flux", "Accept": "application/csv"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", "replace")


def test_live(host, port, wait):
    print(f"\nthe real pipeline: TZSP -> {host}:{port} -> suricata -> dns-monitor")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for txid, rdata in ((0x7701, "0.0.0.0"), (0x7702, "93.184.216.34")):
        # The query goes first, and it is not optional: a flow whose first
        # packet comes from port 53 is one Suricata parses in the wrong
        # direction, and a lone response then produces no transaction and no
        # event at all. Verified -- packets reach the tap either way, and only
        # the pair is logged.
        sock.sendto(tzsp_wrap(CLIENT, RESOLVER, 51000, 53,
                              dns_query(txid, LIVE_NAME)), (host, port))
        sock.sendto(tzsp_wrap(RESOLVER, CLIENT, 53, 51000,
                              dns_response(txid, LIVE_NAME, rdata)), (host, port))
    print(f"  sent 2 lookups of {LIVE_NAME} from {CLIENT}, one answered "
          f"0.0.0.0; waiting up to {wait}s for a flush")

    flux = f'''from(bucket: "{monitor.INFLUX_BUCKET}")
  |> range(start: -10m)
  |> filter(fn: (r) => r._measurement == "dns_block" and r._field == "count")
  |> filter(fn: (r) => r.qname == "{LIVE_NAME}" and r.src_ip == "{CLIENT}")
  |> sum()'''
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(5)
        try:
            if LIVE_NAME in influx_query(flux):
                return check("the blocked lookup reached InfluxDB with its client",
                             True, f"dns_block qname={LIVE_NAME} src_ip={CLIENT}")
        except (urllib.error.URLError, OSError) as exc:
            print(f"  ...InfluxDB not answering yet ({exc})")
    check("the blocked lookup reached InfluxDB with its client", False,
          "nothing arrived. Check `docker compose logs dns-monitor` for "
          "'suricata connected', and that dns_monitor.enabled is not false")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true",
                    help="also drive the real decapsulator, Suricata and InfluxDB")
    ap.add_argument("--host", default="tzsp-decap", help="where tzsp-decap listens")
    ap.add_argument("--port", type=int, default=37008)
    ap.add_argument("--wait", type=int, default=90,
                    help="seconds to wait for a dns-monitor flush")
    args = ap.parse_args()

    test_classify()
    test_aggregate()
    test_state()
    test_socket()
    if args.live:
        test_live(args.host, args.port, args.wait)

    print()
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
