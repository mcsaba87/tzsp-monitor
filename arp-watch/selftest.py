"""Prove the ARP watch without an attacker, and without a mirror.

    docker compose exec arp-watch python selftest.py            # offline
    docker compose exec arp-watch python selftest.py --live     # + the running service

The offline part needs nothing running: it builds the Ethernet/ARP frames a
mirror would carry, runs them through the real parser and the real Watcher with
a fake clock and InfluxDB stubbed out, and checks every detection in both
directions -- an ARP watch fails in two ways that both look like a working
dashboard: it never fires, or it fires on every DHCP renewal until somebody
stops reading it. So next to each attack is the ordinary shape that must stay
quiet:

  * a quiet LAN (requests, solicited replies, a gratuitous ARP at boot,
    RFC 5227 probes) raises nothing;
  * the gateway claimed by anyone else is critical on the first packet --
    learned or pinned -- but a VRRP (trusted) MAC on it is not, and a router
    really replaced is re-learned after relearn_seconds;
  * two MACs interleaving on one IP: poisoning when one of them is another
    host, a conflict when neither is; one clean change is mac_changed, info;
  * unsolicited replies, gratuitous floods and ARP sweeps above their
    thresholds, and the same traffic below them, or solicited, or from a
    router;
  * the same IP on two VLANs is two hosts, not a conflict;
  * the learning period, the restart (state round-trip), the repeat period;
  * the capture filter's BPF, run through a tiny cBPF interpreter, and the
    OUI reader against a synthetic registry;
  * random bytes never raise.

`--live` sends TZSP-wrapped ARP to tzsp-decap's 37008 (this container shares
its namespace, so that is 127.0.0.1) -- an IP conflict between two
documentation MACs (00:00:5e:00:53:xx, RFC 7042) on a TEST-NET address -- and
reads the `ip_conflict` point back out of InfluxDB once the window closes. So
it proves decap, the tap, the capture filter, the Watcher and the write in one
go. The two test MACs are then in the station table (and are new_station
alerts on the first run).
"""
import argparse
import os
import random
import socket
import struct
import sys
import tempfile
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arpwatch  # noqa: E402
from oui import OUI  # noqa: E402

failures = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  -- {detail}" if detail else ""))
    if not ok:
        failures.append(label)
    return ok


class StubInflux:
    def __init__(self):
        self.points = []

    def point(self, measurement, tags, fields, timestamp_ns=None):
        self.points.append((measurement, dict(tags), dict(fields)))

    def alerts(self, name=None):
        return [p for p in self.points if p[0] == "arp_alert"
                and (name is None or p[1]["alert"] == name)]

    def clear(self):
        self.points = []


def config(**values):
    cfg = arpwatch.Config.__new__(arpwatch.Config)  # no file, no log line
    cfg.present = True
    cfg.values = {k.replace("__", "."): str(v) for k, v in values.items()}
    return cfg


def settings(**values):
    base = {"arp_watch__learn_seconds": 0, "arp_watch__window_seconds": 60}
    base.update(values)
    return arpwatch.Settings(config(**base))


def mac(raw):
    return bytes(int(x, 16) for x in raw.split(":"))


def arp_frame(op, sha, spa, tha, tpa, eth_src=None, eth_dst=None, vlan=None):
    eth_dst = eth_dst or ("ff:ff:ff:ff:ff:ff" if op == 1 else tha)
    tag = struct.pack("!HH", 0x8100, vlan) if vlan is not None else b""
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + mac(sha) + socket.inet_aton(spa) \
        + mac(tha) + socket.inet_aton(tpa)
    frame = mac(eth_dst) + mac(eth_src or sha) + tag + struct.pack("!H", 0x0806) + body
    return frame + b"\x00" * max(0, 60 - len(frame))


GW, GW_IP = "48:a9:8a:00:00:01", "192.0.2.1"
H1, H1_IP = "dc:a6:32:00:00:10", "192.0.2.10"
H2, H2_IP = "00:00:0c:00:00:20", "192.0.2.20"
ATK, ATK_IP = "02:00:00:00:00:66", "192.0.2.66"
ZERO = "00:00:00:00:00:00"


class Rig:
    """A Watcher on a fake clock."""

    def __init__(self, oui=None, state=None, **cfg):
        cfg.setdefault("arp_watch__protected", GW_IP)
        self.s = settings(**cfg)
        self.influx = StubInflux()
        self.t = 1_000_000.0
        self.w = arpwatch.Watcher(self.s, self.influx, oui, state, now=self.t)

    def send(self, frame, aux_vlan=None, dt=0.01):
        self.t += dt
        pkt = arpwatch.parse_frame(frame, aux_vlan)
        assert pkt is not None, "test frame did not parse"
        self.w.observe(pkt, self.t)

    def ask(self, sha, spa, tpa, answer_mac=None, vlan=None):
        """A request and, if answer_mac, its solicited reply."""
        self.send(arp_frame(1, sha, spa, ZERO, tpa, vlan=vlan))
        if answer_mac:
            self.send(arp_frame(2, answer_mac, tpa, sha, spa, vlan=vlan))

    def close(self, advance=60):
        self.t += advance
        return self.w.close_window(self.t)

    def names(self):
        return sorted({p[1]["alert"] for p in self.influx.alerts()})


def quiet_lan(r, rounds=3):
    for _ in range(rounds):
        r.ask(H1, H1_IP, GW_IP, GW)
        r.ask(GW, GW_IP, H1_IP, H1)
        r.ask(H2, H2_IP, GW_IP, GW)
        r.ask(H1, H1_IP, H2_IP, H2)


def test_parse():
    print("parsing")
    f = arp_frame(2, H1, H1_IP, GW, GW_IP)
    p = arpwatch.parse_frame(f)
    check("untagged reply", p and (p.op, p.sha, p.spa, p.tha, p.tpa, p.vlan)
          == (2, H1, H1_IP, GW, GW_IP, 0))
    p = arpwatch.parse_frame(arp_frame(1, H1, H1_IP, ZERO, GW_IP, vlan=42))
    check("802.1Q tag in the frame", p and p.vlan == 42 and p.tpa == GW_IP)
    p = arpwatch.parse_frame(arp_frame(1, H1, H1_IP, ZERO, GW_IP), aux_vlan=7)
    check("tag from auxdata (stripped by the kernel)", p and p.vlan == 7)
    ip4 = mac(GW) + mac(H1) + b"\x08\x00" + b"\x45" + b"\x00" * 50
    check("IPv4 frame is not ARP", arpwatch.parse_frame(ip4) is None)
    check("truncated ARP", arpwatch.parse_frame(f[:30]) is None)
    rnd = random.Random(7)
    try:
        for _ in range(20000):
            n = rnd.randint(0, 80)
            buf = bytearray(rnd.getrandbits(8) for _ in range(n))
            if n > 13 and rnd.random() < 0.5:
                buf[12:14] = b"\x08\x06"
            pkt = arpwatch.parse_frame(bytes(buf))
            if pkt:
                arpwatch.bogus_sender(pkt)
        check("20,000 random frames never raise", True)
    except Exception as exc:  # noqa: BLE001
        check("20,000 random frames never raise", False, repr(exc))


def run_bpf(prog, frame):
    """Just enough classic BPF for ARP_FILTER: ldh abs, jeq k, ret k."""
    pc, a = 0, 0
    while True:
        code, jt, jf, k = prog[pc]
        if code == 0x28:
            if k + 2 > len(frame):
                return 0
            a = struct.unpack_from("!H", frame, k)[0]
            pc += 1
        elif code == 0x15:
            pc += 1 + (jt if a == k else jf)
        elif code == 0x06:
            return k
        else:
            raise ValueError(f"opcode {code:#x} not emulated")


def test_bpf():
    print("capture filter (cBPF)")
    prog = arpwatch.ARP_FILTER
    check("accepts untagged ARP", run_bpf(prog, arp_frame(1, H1, H1_IP, ZERO, GW_IP)) > 0)
    check("accepts 802.1Q ARP", run_bpf(prog, arp_frame(1, H1, H1_IP, ZERO, GW_IP, vlan=5)) > 0)
    qinq = mac(GW) + mac(H1) + struct.pack("!HHHH", 0x88A8, 5, 0x0806, 0) + b"\x00" * 40
    check("accepts 802.1ad-tagged ARP", run_bpf(prog, qinq) > 0)
    ip4 = mac(GW) + mac(H1) + b"\x08\x00" + b"\x00" * 46
    check("drops IPv4", run_bpf(prog, ip4) == 0)
    v_ip = mac(GW) + mac(H1) + struct.pack("!HHH", 0x8100, 5, 0x0800) + b"\x00" * 46
    check("drops tagged IPv4", run_bpf(prog, v_ip) == 0)
    check("drops a runt", run_bpf(prog, b"\x00" * 10) == 0)


def test_quiet():
    print("a quiet LAN raises nothing")
    r = Rig()
    quiet_lan(r)
    r.send(arp_frame(1, H2, "0.0.0.0", ZERO, H2_IP))           # RFC 5227 probe
    r.send(arp_frame(1, H2, H2_IP, ZERO, H2_IP))               # announcement
    r.close()
    quiet_lan(r)
    s = r.close()
    check("no alerts on the first-ever windows (learn=0 here)",
          r.names() == ["new_station"], str(r.names()))
    check("bindings written with vlan tag",
          any(p[0] == "arp_binding" and p[1]["ip"] == H1_IP and p[1]["vlan"] == "0"
              for p in r.influx.points))
    check("the probe bound nothing", "0.0.0.0" not in {p[1].get("ip") for p in r.influx.points
                                                         if p[0] == "arp_binding"})
    check("summary counts (3 rounds x 8 frames)", s["frames"] == 24 and s["requests"] == 12
          and s["unsolicited"] == 0, str(s))

    r = Rig(arp_watch__learn_seconds=3600)
    quiet_lan(r)
    r.close()
    check("learning period: not even new_station", r.names() == [], str(r.names()))


def test_gateway():
    print("gateway spoofing")
    r = Rig(arp_watch__learn_seconds=3600)
    quiet_lan(r)
    r.close()
    r.influx.clear()
    r.send(arp_frame(2, ATK, GW_IP, H1, H1_IP))                # one forged reply
    r.close()
    a = r.influx.alerts("gateway_spoof")
    check("one forged reply for the learned gateway is critical (even while learning)",
          len(a) == 1 and a[0][1]["severity"] == "1" and a[0][2]["mac"] == f'"{ATK}"',
          str(r.names()))
    check("the real gateway stays the binding",
          r.w.bindings["0|" + GW_IP]["mac"] == GW)

    r = Rig(arp_watch__protected=f"{GW_IP}={GW}")
    r.send(arp_frame(2, ATK, GW_IP, H1, H1_IP))                # attacker first
    r.close()
    check("pinned: the attacker is caught even if heard first",
          len(r.influx.alerts("gateway_spoof")) == 1)

    r = Rig(arp_watch__trusted_macs="00:00:5e:00:01:*")
    quiet_lan(r)
    r.send(arp_frame(2, "00:00:5e:00:01:01", GW_IP, H1, H1_IP))
    r.close()
    check("VRRP (trusted) MAC on the gateway is not an alert",
          not r.influx.alerts("gateway_spoof"))

    r = Rig(arp_watch__relearn_seconds=600)
    quiet_lan(r)
    r.close()
    new_gw = "48:a9:8a:00:00:99"
    for _ in range(12):                                         # 12 windows, old one silent
        r.ask(new_gw, GW_IP, H1_IP, H1)
        r.close()
    check("a replaced router is re-learned after relearn_seconds",
          r.w.gateways["0|" + GW_IP]["mac"] == new_gw
          and len(r.influx.alerts("mac_changed")) == 1)
    r.influx.clear()
    r.ask(new_gw, GW_IP, H1_IP, H1)
    r.close(advance=400)
    check("...and stops alerting", not r.influx.alerts("gateway_spoof"), str(r.names()))

    r = Rig(arp_watch__relearn_seconds=600)
    quiet_lan(r)
    r.close()
    for _ in range(15):                                         # poisoner, contradicted
        r.send(arp_frame(2, ATK, GW_IP, H1, H1_IP))
        r.ask(H2, H2_IP, GW_IP, GW)
        r.close()
    check("a poisoner the gateway keeps contradicting is never adopted",
          r.w.gateways["0|" + GW_IP]["mac"] == GW)


def test_poisoning():
    print("poisoning and conflicts")
    r = Rig(arp_watch__learn_seconds=3600)
    quiet_lan(r)
    r.ask(ATK, ATK_IP, GW_IP, GW)                               # attacker is a host too
    r.close()
    r.influx.clear()
    for _ in range(5):                                          # arpspoof -t gw victim
        r.send(arp_frame(2, ATK, H1_IP, GW, GW_IP))
        r.ask(GW, GW_IP, H1_IP, H1)
    r.close()
    a = r.influx.alerts("arp_poisoning")
    check("two MACs interleaving, one of them another host: arp_poisoning, high",
          len(a) == 1 and a[0][1]["severity"] == "2" and a[0][2]["mac"] == f'"{ATK}"',
          str(r.names()))
    check("detail names the impostor's own address", a and ATK_IP in a[0][2]["detail"])
    check("unsolicited replies counted, but below threshold", "unsolicited_replies"
          not in r.names())
    check("the victim keeps its binding", r.w.bindings["0|" + H1_IP]["mac"] == H1)

    r = Rig()
    for _ in range(4):
        r.ask("02:00:00:00:00:a1", "192.0.2.30", GW_IP, GW)
        r.ask("02:00:00:00:00:a2", "192.0.2.30", GW_IP, GW)
    r.close()
    a = r.influx.alerts("ip_conflict")
    check("two strangers alternating: ip_conflict, medium",
          len(a) == 1 and a[0][1]["severity"] == "3" and not r.influx.alerts("arp_poisoning"))

    r = Rig()
    r.ask("02:00:00:00:00:a1", "192.0.2.31", GW_IP, GW)
    r.close()
    r.influx.clear()
    r.ask("02:00:00:00:00:a2", "192.0.2.31", GW_IP, GW)
    r.close()
    a = r.influx.alerts("mac_changed")
    check("one clean change (a new DHCP lease): mac_changed, informational",
          len(a) == 1 and a[0][1]["severity"] == "4"
          and not r.influx.alerts("ip_conflict"), str(r.names()))

    r = Rig()
    r.ask(ATK, ATK_IP, GW_IP, GW)
    r.ask(H2, "192.0.2.32", GW_IP, GW)
    r.close()
    r.influx.clear()
    r.send(arp_frame(2, ATK, "192.0.2.32", GW, GW_IP))
    r.close()
    a = r.influx.alerts("mac_changed")
    check("taken over by a MAC that is another host: mac_changed, medium",
          len(a) == 1 and a[0][1]["severity"] == "3", str(a))

    r = Rig()
    for _ in range(4):
        r.ask(H1, "10.9.9.9", GW_IP, GW, vlan=10)
        r.ask(H2, "10.9.9.9", GW_IP, GW, vlan=20)
    r.close()
    check("same IP on two VLANs is two hosts", not r.influx.alerts("ip_conflict")
          and not r.influx.alerts("arp_poisoning"), str(r.names()))


def test_floods():
    print("floods, sweeps and malformed senders")
    r = Rig()
    quiet_lan(r)
    for i in range(30):
        r.send(arp_frame(2, ATK, ATK_IP, H1, H1_IP), dt=2)
    r.close()
    check("30 unsolicited replies: unsolicited_replies", len(r.influx.alerts("unsolicited_replies")) == 1)

    r = Rig()
    for i in range(30):
        r.ask(H1, H1_IP, H2_IP, H2)
    r.close()
    check("30 solicited replies: nothing", not r.influx.alerts("unsolicited_replies"))

    r = Rig()
    for i in range(40):
        r.send(arp_frame(1, H2, H2_IP, ZERO, H2_IP))
    r.close()
    check("40 gratuitous ARPs: garp_flood", len(r.influx.alerts("garp_flood")) == 1)
    r = Rig()
    for i in range(3):
        r.send(arp_frame(1, H2, H2_IP, ZERO, H2_IP))
    r.close()
    check("3 at boot: nothing", not r.influx.alerts("garp_flood"))

    r = Rig()
    for i in range(60):
        r.send(arp_frame(1, ATK, ATK_IP, ZERO, f"192.0.2.{100 + i}"))
    r.close()
    check("60 targets from one host: arp_scan", len(r.influx.alerts("arp_scan")) == 1)
    r = Rig()
    for i in range(60):
        r.send(arp_frame(1, GW, GW_IP, ZERO, f"192.0.2.{100 + i}"))
    r.close()
    check("the same from the (protected) router: nothing", not r.influx.alerts("arp_scan"))

    r = Rig()
    r.send(arp_frame(2, H1, H1_IP, GW, GW_IP, eth_src=ATK))
    r.close()
    a = r.influx.alerts("eth_mismatch")
    check("ARP sender != Ethernet source: eth_mismatch", len(a) == 1
          and a[0][2]["other_mac"] == f'"{ATK}"')

    r = Rig()
    r.send(arp_frame(2, "01:00:5e:00:00:01", "192.0.2.50", GW, GW_IP))
    r.send(arp_frame(2, H1, "224.0.0.1", GW, GW_IP))
    r.close()
    check("group sender MAC and multicast sender IP: bogus_arp",
          len(r.influx.alerts("bogus_arp")) == 2 and not any(
              p[0] == "arp_binding" and p[1]["ip"] in ("192.0.2.50", "224.0.0.1")
              for p in r.influx.points))


def test_state_and_repeat():
    print("restart, learning and repeat period")
    r = Rig()
    quiet_lan(r)
    r.close()
    state = r.w.export()
    import json
    state = json.loads(json.dumps(state))                     # what the file round-trips
    r2 = Rig(state=state)
    r2.t = r.t
    quiet_lan(r2)
    r2.close()
    check("a restart that remembers the stations raises no new_station",
          not r2.influx.alerts("new_station"), str(r2.names()))

    r = Rig(arp_watch__alert_repeat_seconds=300)
    quiet_lan(r)
    r.close()
    for w in range(6):
        for _ in range(3):
            r.ask("02:00:00:00:00:a1", "192.0.2.30", GW_IP, GW)
            r.ask("02:00:00:00:00:a2", "192.0.2.30", GW_IP, GW)
        r.close()
    a = r.influx.alerts("ip_conflict")
    check("a conflict over six windows is two points, not six",
          len(a) == 2, str([p[2]["count"] for p in a]))
    check("the second carries the windows in between",
          len(a) == 2 and a[1][2]["count"] == "5i", str([p[2]["count"] for p in a]))

    print("health state")
    ws = arpwatch.watch_state
    check("no tap", ws(False, 0, 0, 600, False) == arpwatch.STATE_NO_TAP)
    check("no mirror", ws(True, 700, 700, 600, False) == arpwatch.STATE_NO_MIRROR)
    check("traffic but no ARP", ws(True, 1, 700, 600, False) == arpwatch.STATE_NO_ARP)
    check("learning", ws(True, 1, 1, 600, True) == arpwatch.STATE_LEARNING)
    check("watching", ws(True, 1, 1, 600, False) == arpwatch.STATE_WATCHING)
    check("silent_seconds=0 never reports silence",
          ws(True, 99999, 99999, 0, False) == arpwatch.STATE_WATCHING)


def test_oui():
    print("OUI reader")
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "manuf")
        with open(path, "w") as fh:
            fh.write("# comment\n"
                     "48:A9:8A         \tRouterboardc\tRouterboard.com\n"
                     "70:B3:D5         \tIEEERegistr\tIEEE Registration Authority\n"
                     "70:B3:D5:12:30/36\tSmallCo     \tSmall Co. Ltd\n"
                     "00:55:DA:10/28   \tKoolPOS     \tKoolPOS Inc.\n")
        db = OUI(path)
        check("MA-L", db.vendor("48-A9-8A-01-02-03") == "Routerboard.com")
        check("MA-S beats the MA-L it sits in", db.vendor("70:b3:d5:12:30:05") == "Small Co. Ltd"
              and db.vendor("70:b3:d5:99:00:00") == "IEEE Registration Authority")
        check("MA-M", db.vendor("00:55:da:1f:ff:ff") == "KoolPOS Inc.")
        check("locally administered", db.vendor("02:42:ac:11:00:02") == "(randomized)")
        check("multicast / broadcast", db.vendor("01:00:5e:00:00:fb") == "(multicast)"
              and db.vendor("ff:ff:ff:ff:ff:ff") == "(broadcast)")
        check("unassigned", db.vendor("fc:ff:ff:00:00:00") == "(unknown)")
        with open(path, "w") as fh:
            fh.write("<html>captive portal</html>\n")
        os.utime(path, (time.time() + 5, time.time() + 5))
        db.maybe_reload(force=True)
        check("an empty/HTML file does not erase a working table",
              db.vendor("48:a9:8a:00:00:00") == "Routerboard.com")
    check("no database: None, not a guess", OUI("/nonexistent").vendor("48:a9:8a:00:00:00") is None)

    r = Rig(oui=None)
    r.ask(H1, H1_IP, GW_IP, GW)
    r.close()
    check("no database: no vendor tag at all", all("vendor" not in p[1] for p in r.influx.points
                                                   if p[0] == "arp_binding"))


def tzsp(frame):
    return struct.pack("!BBHB", 1, 0, 1, 1) + frame


def influx_query(flux):
    url = (f"{arpwatch.INFLUX_URL.rstrip('/')}/api/v2/query?org="
           f"{urllib.parse.quote(arpwatch.INFLUX_ORG)}")
    req = urllib.request.Request(url, data=flux.encode(), method="POST", headers={
        "Authorization": f"Token {arpwatch.INFLUX_TOKEN}",
        "Content-Type": "application/vnd.flux", "Accept": "application/csv"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode()


def live(host, port, wait):
    print(f"live: TZSP ARP to {host}:{port}")
    ip = f"192.0.2.{random.randint(100, 250)}"
    # Fresh documentation-range MACs each run: arp-watch persists every MAC it
    # has heard, so a pair reused from an earlier run is "known as another
    # host" and the conflict comes out as arp_poisoning. Either alert proves
    # the path; the classification itself is covered offline above.
    x, y = random.sample(range(256), 2)
    a, b = f"00:00:5e:00:53:{x:02x}", f"00:00:5e:00:53:{y:02x}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(4):
        for m in (a, b):
            sock.sendto(tzsp(arp_frame(1, m, ip, ZERO, "192.0.2.1")), (host, port))
            time.sleep(0.05)
    print(f"  sent 8 requests: {ip} claimed alternately by {a} and {b}; "
          f"waiting up to {wait}s for the window to close")
    flux = f'''from(bucket: "{arpwatch.INFLUX_BUCKET}")
  |> range(start: -10m)
  |> filter(fn: (r) => r._measurement == "arp_alert"
      and (r.alert == "ip_conflict" or r.alert == "arp_poisoning") and r.ip == "{ip}" and r._field == "count")
  |> count()'''
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(5)
        try:
            out = influx_query(flux)
        except OSError as exc:
            print(f"  influx query failed: {exc}")
            continue
        if ",_value" in out.replace("\r", "") and len(out.strip().splitlines()) > 1:
            return check(f"conflict alert for {ip} read back from InfluxDB", True)
    return check(f"conflict alert for {ip} read back from InfluxDB", False,
                 "check `docker compose logs arp-watch` for its state line")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=37008)
    ap.add_argument("--wait", type=int, default=150)
    args = ap.parse_args()
    arpwatch.log = lambda msg: None  # the checks are the output
    test_parse()
    test_bpf()
    test_quiet()
    test_gateway()
    test_poisoning()
    test_floods()
    test_state_and_repeat()
    test_oui()
    if args.live:
        live(args.host, args.port, args.wait)
    print()
    if failures:
        print(f"{len(failures)} FAILED: " + "; ".join(failures))
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
