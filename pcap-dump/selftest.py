"""Prove the parts of pcap-dump that are dangerous to get wrong.

    docker compose exec pcap-dump python selftest.py          # offline
    docker compose exec pcap-dump python selftest.py --live   # + end to end

Offline, against a temporary directory and nothing else: the CIDR parsing and
the BPF expression built from it, which files the budget deletes (oldest closed
first, never the live one) and when capture has to pause instead, the renaming
of files tcpdump has closed, and reading a file's first-packet time. Then the
download path, with the real tcpdump on synthetic files: which files a host and
a time window select (and which a session's capture filter rules out), the
host filter including 802.1Q-tagged frames, trimming to the window, several
files merged under one pcap header, a bad BPF expression refused with
tcpdump's own message, and the text output.

--live drives the running service: it restricts capture to a TEST-NET range,
sends TZSP packets into tzsp-decap from inside the shared namespace (one inside
the range, one outside), puts the previous state back -- which closes the test
file -- and checks the file holds the first packet and not the second. The test
file is deleted afterwards. Before that, the same file is downloaded through
the extract listener (:8051), filtered to the one host, to prove the HTTP path. If capture was on, it is interrupted for the few
seconds this takes, and the switch appears in the audit table with the note
`selftest`.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

import dump

FAILED = []


def check(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}{' -- ' + detail if detail else ''}")
    if not ok:
        FAILED.append(name)


def offline():
    nets, err = dump.parse_cidrs("10.1.2.3/16, 192.168.1.5 2001:db8::/32,10.1.0.0/16")
    check("cidr: host bits dropped, bare IP is /32, duplicates merged",
          nets == ["10.1.0.0/16", "192.168.1.5/32", "2001:db8::/32"] and not err,
          str(nets))
    nets, err = dump.parse_cidrs("10.0.0.0/33")
    check("cidr: invalid prefix refused", not nets and err, err)
    nets, err = dump.parse_cidrs("10.0.0.0/8; rm -rf /")
    check("cidr: anything that is not an address is refused", not nets and err, err)
    expr = dump.bpf_filter(["10.0.0.0/20"])
    check("bpf: tagged frames covered, prefix kept exact",
          expr == "(net 10.0.0.0/20) or (vlan and (net 10.0.0.0/20))", expr)
    check("bpf: no networks = no filter", dump.bpf_filter([]) == "")

    M = dump.MIB
    # plan(closed, live_bytes, max_bytes, file_bytes, room)
    d, _, fits = dump.plan([100 * M] * 5, 10 * M, 1000 * M, 100 * M, 10 ** 12)
    check("budget: under it, nothing deleted", d == 0 and fits)
    d, _, fits = dump.plan([100 * M] * 10, 50 * M, 1000 * M, 100 * M, 10 ** 12)
    check("budget: over it, oldest closed go until a file's worth fits",
          d == 1 and fits, f"deleted {d}")
    d, _, fits = dump.plan([100 * M] * 5, 50 * M, 1000 * M, 100 * M, 150 * M)
    check("ceiling: little room left shrinks the budget", d == 0 and fits, f"deleted {d}")
    d, _, fits = dump.plan([100 * M] * 5, 50 * M, 1000 * M, 100 * M, -250 * M)
    check("ceiling: over it, deletes enough to get back under",
          d == 3 and fits, f"deleted {d}")
    d, _, fits = dump.plan([100 * M] * 2, 80 * M, 1000 * M, 100 * M, -10 ** 12)
    check("ceiling: nothing left to delete -> pause, live file untouched",
          d == 2 and not fits, f"deleted {d}")

    with tempfile.TemporaryDirectory() as tmp:
        for name in ("tzsp-20261014T100000Z.pcap", "tzsp-20261014T100000Z.pcap1",
                     "tzsp-20261014T110000Z.pcap", "tzsp-20261014T110000Z.pcap1",
                     "tzsp-20261014T110000Z.pcap2", "unrelated.txt"):
            open(os.path.join(tmp, name), "wb").close()
        files = dump.finalize(tmp, dump.scan(tmp), "20261014T110000Z")
        names = sorted(os.listdir(tmp))
        check("rename: closed files get their final name, live one is left",
              names == ["tzsp-20261014T100000Z-0000.pcap",
                        "tzsp-20261014T100000Z-0001.pcap",
                        "tzsp-20261014T110000Z-0000.pcap",
                        "tzsp-20261014T110000Z-0001.pcap",
                        "tzsp-20261014T110000Z.pcap2", "unrelated.txt"], str(names))
        check("scan: oldest first, unrelated files ignored",
              [f["name"] for f in files][0] == "tzsp-20261014T100000Z-0000.pcap"
              and len(files) == 5)
        dump.finalize(tmp, dump.scan(tmp), None)
        check("rename: with nothing running, every file is closed",
              "tzsp-20261014T110000Z-0002.pcap" in os.listdir(tmp))

        path = os.path.join(tmp, "x.pcap")
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
            fh.write(struct.pack("<IIII", 1760000000, 5, 0, 0))
        check("pcap: first packet time read from the header",
              dump.first_packet_time(path) == 1760000000)


# ---------------------------------------------------------------------------
def frame(src, dst, payload=b"x" * 32, vlan=None, sport=40000, dport=9999):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    macs = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01"
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    return macs + tag + b"\x08\x00" + ip + udp


def icmp_frame(src, dst, vlan=None):
    """An ICMP echo request, to tell the protocol box apart from UDP."""
    icmp = b"\x08\x00\x00\x00\x00\x01\x00\x01" + b"ping" * 8
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(icmp), 1, 0, 64, 1, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    macs = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01"
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    return macs + tag + b"\x08\x00" + ip + icmp


def write_pcap(path, packets):
    """packets: (epoch seconds, frame). mtime = the last packet, as tcpdump
    would leave it."""
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for ts, data in packets:
            fh.write(struct.pack("<IIII", int(ts), int(ts % 1 * 1e6), len(data), len(data)))
            fh.write(data)
    os.utime(path, (packets[-1][0], packets[-1][0]))


def records(blob):
    """(timestamps, frames) of a pcap stream; None if it is not exactly one
    global header followed by whole records."""
    if len(blob) < 24 or blob[:4] != b"\xd4\xc3\xb2\xa1":
        return None
    pos, stamps, frames = 24, [], []
    while pos < len(blob):
        if pos + 16 > len(blob):
            return None
        sec, usec, incl, _ = struct.unpack("<IIII", blob[pos:pos + 16])
        if pos + 16 + incl > len(blob):
            return None
        stamps.append(sec + usec / 1e6)
        frames.append(blob[pos + 16:pos + 16 + incl])
        pos += 16 + incl
    return stamps, frames


def extraction():
    T = 1760000000
    A, B, C = "10.0.0.1", "10.0.0.2", "192.0.2.5"
    expr = dump.bpf_filter(["10.0.0.1/32"], "udp port 53")
    check("bpf: extra expression ANDed, tagged frames still covered",
          expr == "((net 10.0.0.1/32) and (udp port 53)) or "
                  "(vlan and ((net 10.0.0.1/32) and (udp port 53)))", expr)
    expr = dump.bpf_filter(["10.0.0.1/32"], "vlan 100")
    check("bpf: an expression naming vlan is not wrapped in a second one",
          expr == "(vlan 100) and (net 10.0.0.1/32)", expr)

    def req(**kw):
        try:
            return dump.Request({k: [v] for k, v in kw.items()})
        except dump.ExtractError as exc:
            return exc

    # The Download protocol / port boxes.
    pp = dump.proto_port_filter
    check("proto: icmp covers IPv4 and IPv6", pp("icmp", "") == ("(icmp or icmp6)", ""), str(pp("icmp", "")))
    check("proto: any/empty is no filter", pp("any", "") == ("", "") and pp("", "") == ("", ""))
    check("proto: a port alone matches either end", pp("", "443") == ("port 443", ""))
    check("proto: tcp + a port range", pp("tcp", "8000-8100") == ("(tcp) and portrange 8000-8100", ""),
          str(pp("tcp", "8000-8100")))
    check("proto: unknown protocol refused", bool(pp("igmp", "")[1]))
    check("proto: a port with a portless protocol refused, not an empty file",
          bool(pp("icmp", "7")[1]) and bool(pp("gre", "7")[1]))
    check("proto: nonsense or out-of-range ports refused",
          all(pp("tcp", p)[1] for p in ("0", "65536", "80;id", "90-80", "x")))
    r = req(host="192.168.0.1", proto="icmp")
    check("request: host + protocol, the protocol inside the vlan doubling too",
          isinstance(r, dump.Request) and r.expr ==
          "((net 192.168.0.1/32) and (((icmp or icmp6)))) or "
          "(vlan and ((net 192.168.0.1/32) and (((icmp or icmp6)))))", str(getattr(r, "expr", r)))
    r = req(host="192.168.0.1", proto="tcp", port="443", bpf="vlan 100")
    check("request: the boxes follow a hand-written vlan expression, past the tag",
          isinstance(r, dump.Request) and r.expr ==
          "((vlan 100) and ((tcp) and port 443)) and (net 192.168.0.1/32)", str(getattr(r, "expr", r)))
    check("request: protocol/port end up in the file name",
          isinstance(r, dump.Request) and r.filename().startswith("192.168.0.1-tcp-port443-"))
    check("request: a bad port is a 400, not a silent full download",
          isinstance(req(host=A, proto="icmp", port="1"), dump.ExtractError))
    check("request: no host and no bpf is refused, not the whole ring",
          isinstance(req(), dump.ExtractError))
    check("request: a host that is not an address is refused",
          isinstance(req(host="10.0.0.1; rm"), dump.ExtractError))
    check("request: unknown format refused",
          isinstance(req(host=A, format="exe"), dump.ExtractError))
    r = req(host=A, **{"from": str(T * 1000), "to": str((T + 60) * 1000)})
    check("request: Grafana's epoch-ms window and a pcap by default",
          isinstance(r, dump.Request) and r.t0 == T and r.t1 == T + 60
          and r.format == "pcap" and r.filename().startswith("10.0.0.1-"),
          getattr(r, "filename", lambda: str(r))())

    with tempfile.TemporaryDirectory() as tmp:
        s1, s2 = "20261014T100000Z", "20261014T110000Z"
        f0 = os.path.join(tmp, f"tzsp-{s1}-0000.pcap")
        f1 = os.path.join(tmp, f"tzsp-{s1}-0001.pcap")
        f2 = os.path.join(tmp, f"tzsp-{s2}-0000.pcap")
        write_pcap(f0, [(T + i, frame(A if i % 2 == 0 else B, "10.0.0.9",
                                      vlan=100 if i == 4 else None)) for i in range(10)])
        write_pcap(f1, [(T + 10 + i, frame("10.0.0.9", A)) for i in range(5)])
        write_pcap(f2, [(T + 20 + i, frame(C, "10.0.0.9")) for i in range(5)])
        sessions = {s1: {"cidrs": []}, s2: {"cidrs": ["192.0.2.0/24"]}}

        listed = dump.select_files(tmp, sessions, ["10.0.0.1/32"], T, T + 100)
        use = [os.path.basename(f["name"]) for f in listed if f["use"]]
        skipped = [f["name"] for f in listed if not f["use"]]
        check("select: files of a session whose capture filter excludes the host "
              "are skipped unread", use == [os.path.basename(f0), os.path.basename(f1)]
              and skipped == [os.path.basename(f2)], f"{use} / {skipped}")
        listed = dump.select_files(tmp, sessions, ["10.0.0.1/32"], T + 11, T + 12)
        check("select: only files whose span touches the window",
              [f["name"] for f in listed] == [os.path.basename(f1)]
              and listed[0]["trim"], str([f["name"] for f in listed]))

        def run(t0, t1, host="10.0.0.1/32", extra=""):
            files = [f for f in dump.select_files(tmp, sessions, [host], t0, t1) if f["use"]]
            for f in files:
                f["path"] = os.path.join(tmp, f["name"])
            out = []
            counts = dump.stream_filtered(files, dump.bpf_filter([host], extra),
                                          t0, t1, out.append)
            return records(b"".join(out)), counts

        parsed, (packets, sent) = run(T, T + 100)
        ok = parsed is not None
        check("extract: two files merged under a single pcap header", ok)
        if ok:
            stamps, frames = parsed
            check("extract: only the host's frames, the 802.1Q-tagged one included",
                  len(frames) == 10 and any(f[12:14] == b"\x81\x00" for f in frames),
                  f"{len(frames)} frames")
            check("extract: byte count reported matches what was written",
                  sent == 24 + sum(16 + len(f) for f in frames))
        parsed, (packets, _) = run(T + 2, T + 6.5)
        check("extract: trimmed to the window, records counted",
              parsed is not None and [int(t) for t in parsed[0]] == [T + 2, T + 4, T + 6]
              and packets == 3, str(parsed and parsed[0]))
        parsed, _ = run(T, T + 100, extra="tcp")
        check("extract: nothing matching is still a valid, empty pcap",
              parsed is not None and parsed[0] == [])

        # Protocol box end to end with the real tcpdump: ICMP of one host,
        # tagged and untagged, out of a file that also holds its UDP.
        f3 = os.path.join(tmp, "proto.pcap")
        write_pcap(f3, [(T, frame(A, "10.0.0.9")), (T + 1, icmp_frame(A, "10.0.0.9")),
                        (T + 2, icmp_frame("10.0.0.9", A, vlan=100)),
                        (T + 3, icmp_frame(B, "10.0.0.9")), (T + 4, frame(A, "10.0.0.9", dport=53))])
        for name, (expr, _) in [(n, pp(n, "")) for n in dump.PROTOCOLS] + [("port", pp("udp", "53-60"))]:
            check(f"proto: tcpdump compiles the {name} filter",
                  dump.validate_expr(dump.bpf_filter(["10.0.0.1/32"], expr), f3) == "",
                  dump.validate_expr(dump.bpf_filter(["10.0.0.1/32"], expr), f3))

        def pick(proto, port=""):
            out = []
            dump.stream_filtered([{"path": f3, "name": "proto.pcap", "trim": False}],
                                 dump.bpf_filter(["10.0.0.1/32"], pp(proto, port)[0]),
                                 T, T + 100, out.append)
            got = records(b"".join(out))
            return [int(t) - T for t in got[0]] if got else None
        check("extract: icmp of one host -- both directions, the tagged one too",
              pick("icmp") == [1, 2], str(pick("icmp")))
        check("extract: udp port 53 of that host only", pick("udp", "53") == [4], str(pick("udp", "53")))
        check("extract: gre matches nothing here", pick("gre") == [], str(pick("gre")))

        problem = dump.validate_expr("net 10.0.0.1/32 and porrt 53", f0)
        check("extract: a bad BPF expression is refused with tcpdump's words",
              bool(problem), problem)
        check("extract: a good one passes", dump.validate_expr("udp port 9999", f0) == "")

        # The text path: the merged pcap through a second tcpdump.
        out = []
        files = [dict(f, path=os.path.join(tmp, f["name"]))
                 for f in dump.select_files(tmp, sessions, ["10.0.0.1/32"], T, T + 100)
                 if f["use"]]
        printer = subprocess.Popen([dump.TCPDUMP, "-r", "-", "-nn", "-tttt", "-e"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL)
        dump.stream_filtered(files, dump.bpf_filter(["10.0.0.1/32"]), T, T + 100,
                             printer.stdin.write)
        printer.stdin.close()
        lines = printer.stdout.read().decode().splitlines()
        printer.wait()
        check("text: one line per frame, absolute UTC time, VLAN tag shown",
              len(lines) == 10 and lines[0].startswith("2025-10-09 08:53:20")
              and any("vlan 100" in ln for ln in lines), f"{len(lines)} lines: {lines[:1]}")


# ---------------------------------------------------------------------------
API = f"http://127.0.0.1:{dump.LISTEN_PORT}"
TEST_NET = "203.0.113.0/24"
MAGIC_IN = b"PCAPDUMPSELFTEST-IN"
MAGIC_OUT = b"PCAPDUMPSELFTEST-OUT"


def call(path, **params):
    url = f"{API}{path}?{urllib.parse.urlencode(params)}"
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.load(resp)


def tzsp(src, dst, payload):
    udp = struct.pack("!HHHH", 40000, 9999, 8 + len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton(src), socket.inet_aton(dst))
    ether = b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
    return struct.pack("!BBHB", 1, 0, 1, 1) + ether + ip + udp


def wait_for(predicate, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.5)
    return None


def live():
    before = call("/status")[0]
    if not before["control_enabled"]:
        check("live: service is writable", False, "pcap_dump.control_enabled = false")
        return
    prev_on = "on" if before["enabled"] else "off"
    prev_filter = before["filter"] if before["filter"] != "all traffic" else "all"
    print(f"current state: capture {prev_on}, filter {before['filter']}")

    call("/messages", dump="on", cidr=TEST_NET, note="selftest")
    status = wait_for(lambda: (lambda s: s if s["state_code"] == 1 and s["session"]
                               and s["filter"] == TEST_NET else None)(call("/status")[0]))
    check("live: capture running with the test filter", bool(status),
          json.dumps(call("/status")[0]))
    if not status:
        call("/messages", dump=prev_on, cidr=prev_filter, note="selftest")
        return
    session = status["session"]
    time.sleep(1)    # tcpdump is listening once the file exists; be generous

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(5):
        sock.sendto(tzsp("203.0.113.66", "198.51.100.20", MAGIC_IN + b" " + b"x" * 64),
                    ("127.0.0.1", 37008))
        sock.sendto(tzsp("192.0.2.66", "198.51.100.20", MAGIC_OUT + b" " + b"x" * 64),
                    ("127.0.0.1", 37008))
    # libpcap hands frames to tcpdump in ring blocks, up to a second late, and
    # a stopped tcpdump does not drain the ring -- so wait that out first.
    time.sleep(2.5)

    # Putting the old state back stops or restarts tcpdump, which flushes and
    # closes the test file -- that is what makes its content checkable.
    call("/messages", dump=prev_on, cidr=prev_filter, note="selftest")

    def closed_files():
        names = [n for n in os.listdir(dump.SETTINGS.path) if session in n]
        if names and all(dump.FINISHED.match(n) for n in names):
            return names
        return None
    names = wait_for(closed_files, 30)
    check("live: test session closed and renamed", bool(names), str(names))
    if not names:
        return
    data = b"".join(open(os.path.join(dump.SETTINGS.path, n), "rb").read() for n in names)
    check("live: packet inside the CIDR was written", MAGIC_IN in data)
    check("live: packet outside the CIDR was filtered out", MAGIC_OUT not in data)
    url = (f"http://127.0.0.1:{dump.EXTRACT_PORT}/extract?host=203.0.113.66"
           f"&from={int((time.time() - 600) * 1000)}&to={int(time.time() * 1000)}")
    try:
        with urllib.request.urlopen(url, timeout=60) as resp:
            got, disposition = resp.read(), resp.headers.get("Content-Disposition", "")
    except OSError as exc:
        got, disposition = b"", str(exc)
    check("live: the host's packets download through the extract listener",
          MAGIC_IN in got and got[:4] == b"\xd4\xc3\xb2\xa1"
          and "attachment" in disposition, disposition)
    for n in names:
        os.unlink(os.path.join(dump.SETTINGS.path, n))
    after = call("/status")[0]
    check("live: previous state restored",
          after["enabled"] == before["enabled"] and after["filter"] == before["filter"],
          f"{after['enabled']} {after['filter']}")


def main():
    offline()
    extraction()
    if "--live" in sys.argv:
        dump.SETTINGS = dump.Settings(dump.Config(dump.PROPERTIES_FILE))
        live()
    print(f"\n{'ALL PASSED' if not FAILED else str(len(FAILED)) + ' FAILED'}")
    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
