"""Prove the wireless IDS without a radio, and without an attacker.

    docker compose exec wids python selftest.py            # offline
    docker compose exec wids python selftest.py --live     # + the running service

The offline part needs nothing running: it builds the 802.11 frames a sensor
would stream -- beacons, probe responses, deauths, auth requests, EAPOL -- wraps
them in TZSP exactly as a sniffer does, and drives the real parser and the real
Detector with a fake clock and InfluxDB stubbed out. Every detection is checked
in both directions, because a WIDS fails in two ways that both look like a
working dashboard: it never fires, or it fires on every ordinary AP until
somebody stops reading it. So for each attack there is a check that it fires
and a check that the normal shape next to it does not:

  * a normal AP (sequence wrap, a few deauths, its own SSID set) raises nothing;
  * evil twin needs the authorized list -- without it the AP is `unverified`;
  * sequence numbers going backwards from two transmitters is a spoof, the
    same beacons heard by two sensors are not;
  * a deauth flood, unicast or broadcast; PMF-protected ones are counted apart;
  * KARMA (one BSSID, many SSIDs), auth floods, beacon floods (but not on the
    first start, and not again after a restart that remembers the APs);
  * EAPOL M1 left unanswered by many clients, but not a completed handshake
    and not one still inside its grace period; repeated M3;
  * a frame with the FCS-error tag never becomes a "rogue" AP;
  * the security reading of every RSN/WPA/WEP/open variant that the downgrade
    check compares against wids.min_security;
  * random bytes never raise.

`--live` sends beacons for a documentation-style, locally administered BSSID
to tzsp-decap:37008 -- where a sensor streams -- so the run proves decap's
steering and forward as well as this service, and reads the wids_ap point
back out of InfluxDB. The test AP appears in the inventory for that one window.
`--host wids --port 37009` skips decap and sends straight here.
"""
import argparse
import json
import os
import random
import socket
import struct
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wids  # noqa: E402

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

    def of(self, measurement, **tags):
        return [p for p in self.points if p[0] == measurement
                and all(p[1].get(k) == v for k, v in tags.items())]

    def alerts(self, name=None):
        return [p for p in self.of("wids_alert") if name is None or p[1]["alert"] == name]

    def clear(self):
        self.points = []


def config(**values):
    cfg = wids.Config.__new__(wids.Config)  # no file, and no log line saying so
    cfg.present = True
    cfg.values = {f"wids.{k}": str(v) for k, v in values.items()}
    return cfg


# ---------------------------------------------------------------------------
# Frame builders
# ---------------------------------------------------------------------------
def m(text):
    return bytes(int(x, 16) for x in text.split(":"))


AP = "02:00:5e:00:53:01"
AP2 = "02:00:5e:00:53:02"
TWIN = "02:00:5e:00:53:66"
STA = "02:00:5e:00:53:a0"
BCAST = "ff:ff:ff:ff:ff:ff"
SENSOR, SENSOR2 = "192.0.2.10", "192.0.2.11"


def tzsp(frame, encap=wids.ENCAP_80211, rssi=None, channel=None, fcs=False):
    tags = b""
    if rssi is not None:
        tags += bytes([wids.TAG_RAW_RSSI, 1]) + struct.pack("b", rssi)
    if channel is not None:
        tags += bytes([wids.TAG_RX_CHANNEL, 1, channel])
    if fcs:
        tags += bytes([wids.TAG_FCS_ERROR, 1, 1])
    return struct.pack("!BBH", 1, 0, encap) + tags + b"\x01" + frame


def radiotap(frame, rssi=-50, freq=2437, tsft=None, flags=0):
    """TZSP encapsulation 126, laid out like the RouterOS sniffer's header:
    TSFT, flags, rate, channel, dBm signal."""
    present = 0b101110 | (1 if tsft is not None else 0)
    body = b""
    if tsft is not None:
        body += struct.pack("<Q", tsft)
    body += bytes([flags, 2]) + struct.pack("<HH", freq, 0xa0) + struct.pack("b", rssi)
    hdr = struct.pack("<BBHI", 0, 0, 8 + len(body), present) + body
    return struct.pack("!BBH", 1, 0, wids.ENCAP_RADIOTAP) + b"\x01" + hdr + frame


def header(ftype, sub, a1, a2, a3, seq=0, flags=0, duration=0):
    fc0 = (sub << 4) | (ftype << 2)
    return (bytes([fc0, flags]) + struct.pack("<H", duration)
            + m(a1) + m(a2) + m(a3) + struct.pack("<H", seq << 4))


def ie(eid, body):
    return bytes([eid, len(body)]) + body


def rsn_ie(akms=(2,), pairwise=(4,), group=4, caps=0):
    body = struct.pack("<H", 1) + wids.RSN_OUI + bytes([group])
    body += struct.pack("<H", len(pairwise)) + b"".join(wids.RSN_OUI + bytes([p]) for p in pairwise)
    body += struct.pack("<H", len(akms)) + b"".join(wids.RSN_OUI + bytes([a]) for a in akms)
    body += struct.pack("<H", caps)
    return ie(wids.IE_RSN, body)


def wpa_ie(pairwise=(2,)):
    body = wids.MS_OUI + b"\x01" + struct.pack("<H", 1) + wids.MS_OUI + b"\x02"
    body += struct.pack("<H", len(pairwise)) + b"".join(wids.MS_OUI + bytes([p]) for p in pairwise)
    body += struct.pack("<H", 1) + wids.MS_OUI + b"\x02"
    return ie(wids.IE_VENDOR, body)


WPS_IE = ie(wids.IE_VENDOR, wids.MS_OUI + b"\x04" + b"\x10\x4a\x00\x01\x10")


def beacon(bssid, ssid, seq=0, sec=None, channel=6, cap=0x0011, extra=b"",
           sub=wids.BEACON, dst=BCAST, tsf=0):
    sec = rsn_ie() if sec is None else sec
    body = struct.pack("<Q", tsf) + struct.pack("<HH", 100, cap)
    body += ie(wids.IE_SSID, ssid.encode() if isinstance(ssid, str) else ssid)
    body += ie(wids.IE_DS, bytes([channel])) + sec + extra
    return header(0, sub, dst, bssid, bssid, seq) + body


def deauth(bssid, dst, src=None, protected=False, reason=7):
    flags = 0x40 if protected else 0
    return header(0, wids.DEAUTH, dst, src or bssid, bssid, flags=flags) + struct.pack("<H", reason)


def auth(bssid, client):
    return header(0, wids.AUTH, bssid, client, bssid) + struct.pack("<HHH", 0, 1, 0)


def probe_req(src, ssid):
    return header(0, wids.PROBE_REQ, BCAST, src, BCAST) + ie(wids.IE_SSID, ssid.encode())


def eapol(bssid, sta, info, to_ap=False):
    """A QoS data frame carrying an EAPOL-Key with the given key-info bits."""
    if to_ap:
        hdr = header(2, 8, bssid, sta, bssid, flags=0x01)
    else:
        hdr = header(2, 8, sta, bssid, bssid, flags=0x02)
    key = bytes([2, 3]) + struct.pack("!H", 95) + bytes([2]) + struct.pack("!H", info)
    return hdr + b"\x00\x00" + wids.SNAP_EAPOL + key + b"\x00" * 92


M1, M2, M3, M4 = 0x008a, 0x010a, 0x13ca, 0x030a


def data(bssid, sta):
    return header(2, 0, bssid, sta, bssid, flags=0x41) + b"\x00" * 40


class Run:
    """A detector, a fake clock and a stub database."""

    def __init__(self, our=("corp",), authorized=(AP, AP2), state=None, **cfg):
        self.influx = StubInflux()
        policy = wids.Policy(list(our), list(authorized), cfg.pop("min_security", "wpa2"),
                             cfg.pop("require_pmf", False))
        self.det = wids.Detector(config(**cfg), policy, self.influx,
                                 state if state is not None else {"known": {"x": [0, 0, ""]}})
        self.now = 1_000_000.0

    def send(self, frame, sensor=SENSOR, **kw):
        self.det.datagram(sensor, tzsp(frame, **kw), self.now)

    def send_rt(self, frame, sensor=SENSOR, **kw):
        self.det.datagram(sensor, radiotap(frame, **kw), self.now)

    def flush(self, advance=60):
        self.now += advance
        return self.det.flush(self.now, wids.STATE_WATCHING)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
def test_tzsp():
    print("TZSP and radio headers")
    got = wids.parse_tzsp(tzsp(b"FRAME", rssi=-61, channel=11, fcs=True))
    check("RSSI, channel and the FCS-error flag are read from the tags",
          got is not None and got[1:4] == (-61, 11, True), f"got {got[:4] if got else None}")
    check("the frame follows TAG_END", got[4] == b"FRAME")
    check("a non-TZSP datagram is refused", wids.parse_tzsp(b"\x02\x00\x00\x12\x01") is None)
    check("a tag running past the end is refused",
          wids.parse_tzsp(b"\x01\x00\x00\x12\x0a\x09\x01") is None)
    prism = struct.pack("<II", 0x41, 144) + b"\x00" * 136 + b"FRAME"
    check("a Prism header is stripped by its own length",
          wids.strip_radio_header(wids.ENCAP_PRISM, prism) == b"FRAME")
    avs = struct.pack(">II", 0x80211001, 64) + b"\x00" * 56 + b"FRAME"
    check("so is an AVS header", wids.strip_radio_header(wids.ENCAP_AVS, avs) == b"FRAME")
    # The header the RouterOS wireless sniffer sends (encapsulation 126), as
    # captured from one: TSFT, flags, rate, channel 2427 MHz, dBm signal/noise,
    # antenna, plus a radiotap-namespace tail, 48 bytes in all.
    rt = bytes.fromhex("00003000 6f080040 e7ccdba8fb020000 00 02 7b09a000 c8 a2"
                       "00 000003 7f001000 00000000 fcff0000 e1000000 f8770000")
    got = wids.parse_radiotap(rt + b"FRAME")
    check("radiotap yields the frame, dBm signal and channel",
          got is not None and got[:4] == (b"FRAME", -56, 4, False), f"got {got}")
    check("radiotap's TSFT and frequency are read too",
          got is not None and got[4:] == (0x02fba8dbcce7, 2427), f"got {got}")
    fcs = bytearray(rt)
    fcs[16] = 0x50  # flags: FCS at end, and bad
    got = wids.parse_radiotap(bytes(fcs) + b"FRAME1234")
    check("radiotap's FCS is trimmed and its bad-FCS flag read",
          got is not None and got[0] == b"FRAME" and got[3] is True, f"got {got}")
    check("a claimed channel maps into the band it was heard in",
          (wids.channel_freq(4, 2427), wids.channel_freq(36, 5180),
           wids.channel_freq(5, 5975)) == (2427, 5180, 5975))
    check("a radiotap length past the end is refused",
          wids.parse_radiotap(rt[:20]) is None)
    check("Ethernet is not 802.11",
          wids.strip_radio_header(wids.ENCAP_ETHERNET, b"x" * 60) is None,
          "Ethernet TZSP sent straight to wids must read as wrong_encap")

    frame = tzsp(b"FRAME")
    got = wids.unwrap_forward(wids.FORWARD_MAGIC + bytes([192, 0, 2, 7]) + frame, "172.18.0.4")
    check("a datagram forwarded by tzsp-decap is credited to the sensor in its header",
          got == ("192.0.2.7", frame), f"got {got}")
    got = wids.unwrap_forward(wids.FORWARD_MAGIC + b"\x00" * 4 + frame, "172.18.0.4")
    check("...and to no sensor when decap did not know the address",
          got == (None, frame), f"got {got}")
    check("a datagram sent straight here keeps its own source",
          wids.unwrap_forward(frame, "192.0.2.9") == ("192.0.2.9", frame))
    check("a truncated forward header is not mistaken for one",
          wids.unwrap_forward(wids.FORWARD_MAGIC + b"\x01", "192.0.2.9")[0] == "192.0.2.9")
    check("the forward magic cannot be TZSP", wids.parse_tzsp(wids.FORWARD_MAGIC + frame) is None)


def test_security():
    print("\nreading an AP's security from its beacon")

    def sec(cap, extra):
        ies, vendor = wids.parse_ies(extra, 0)
        return wids.security(cap, ies, vendor)

    check("no privacy, no RSN: open", sec(0x01, b"")[0] == "open")
    check("privacy bit alone: WEP", sec(0x11, b"")[0] == "wep")
    got = sec(0x11, wpa_ie())
    check("the WPA vendor element: wpa, with TKIP", got[0] == "wpa" and got[2])
    got = sec(0x11, rsn_ie())
    check("RSN with PSK and CCMP: wpa2, no TKIP", got[0] == "wpa2" and not got[2])
    check("RSN with a TKIP group cipher is flagged",
          sec(0x11, rsn_ie(group=2, pairwise=(4, 2)))[2])
    check("SAE and PSK together: the WPA3 transition mode",
          sec(0x11, rsn_ie(akms=(2, 8)))[0] == "wpa2/wpa3")
    got = sec(0x11, rsn_ie(akms=(8,), caps=0x00c0))
    check("SAE only with MFPR: wpa3, PMF required",
          got[0] == "wpa3" and got[3] == wids.PMF_REQUIRED)
    check("PMF capable is not PMF required",
          sec(0x11, rsn_ie(caps=0x0080))[3] == wids.PMF_CAPABLE)
    check("802.1X: wpa2-eap", sec(0x11, rsn_ie(akms=(1,)))[0] == "wpa2-eap")
    check("EAP-SHA256 only with PMF required: wpa3-eap",
          sec(0x11, rsn_ie(akms=(5,), caps=0x00c0))[0] == "wpa3-eap")
    check("OWE ranks with WPA, not with the PSK modes",
          sec(0x01, rsn_ie(akms=(18,)))[1] == wids.SECURITY_RANK["wpa"])
    check("the WPS vendor element is noticed", sec(0x11, rsn_ie() + WPS_IE)[4])
    ies, _ = wids.parse_ies(ie(0, b"abc") + b"\x30\x40\x01", 0)
    check("a truncated trailing element (an appended FCS) is ignored, not fatal",
          ies.get(0) == b"abc" and wids.IE_RSN not in ies)
    check("a hidden SSID of NUL bytes reads as hidden", wids.ssid_text(b"\x00" * 8) == "")
    check("control characters cannot reach a tag",
          wids.ssid_text(b"bad\nname\x07") == "bad?name?")


def test_policy():
    print("\nwhich APs are ours")
    p = wids.Policy(["corp"], [AP, "02:00:5e:00:54:*"], "wpa2", False)
    check("an exact BSSID is authorized", p.classify(AP, "corp", False) == wids.CLASS_AUTHORIZED)
    check("so is one under a prefix entry",
          p.classify("02:00:5e:00:54:7f", "corp", False) == wids.CLASS_AUTHORIZED)
    check("an unlisted BSSID on our SSID is an evil twin",
          p.classify(TWIN, "corp", False) == wids.CLASS_EVIL_TWIN)
    loose = wids.Policy(["corp"], [], "wpa2", False)
    check("but only when there is a list to hold it against",
          loose.classify(TWIN, "corp", False) == wids.CLASS_UNVERIFIED,
          "otherwise every AP of ours is an alert on day one")
    check("an IBSS beacon is ad-hoc", p.classify(TWIN, "x", True) == wids.CLASS_ADHOC)
    check("DIRECT-* is Wi-Fi Direct", p.classify(TWIN, "DIRECT-ab-Printer", False) == wids.CLASS_DIRECT)
    check("everything else is a neighbour", p.classify(TWIN, "cafe", False) == wids.CLASS_NEIGHBOR)
    check("policy levels", (wids.Policy([], [], "wpa2", False).level, loose.level, p.level) == (0, 1, 2))


def test_quiet_ap():
    print("\nan ordinary AP raises nothing")
    r = Run()
    rng = random.Random(1)
    seq = 4000
    for i in range(600):  # one minute of beacons, across the 12-bit wrap
        r.send(beacon(AP, "corp", seq=seq & 0xFFF), rssi=-50, channel=6)
        seq += rng.choice((1, 1, 2, 7))  # data frames share the counter
        if i % 3 == 0:
            r.send(data(AP, STA))
    for _ in range(3):
        r.send(deauth(AP, STA))
    r.send(probe_req(STA, "corp"))
    r.send(eapol(AP, STA, M1))
    r.send(eapol(AP, STA, M2, to_ap=True))
    r.send(eapol(AP, STA, M3))
    r.send(eapol(AP, STA, M4, to_ap=True))
    fired = r.flush()
    check("no alert at all", fired == 0, str([p[1]["alert"] for p in r.influx.alerts()]))
    aps = r.influx.of("wids_ap", bssid=AP)
    check("the AP is in the inventory", len(aps) == 1)
    t, f = aps[0][1], aps[0][2]
    check("with its SSID, security and class",
          (t["ssid"], t["security"], t["class"]) == ("corp", "wpa2", "authorized"), str(t))
    check("its beacon count, channel, RSSI and one client",
          (f["beacons"], f["channel"], f["rssi"], f["clients"]) == ("600i", "6i", "-50.0", "1i"),
          str(f))
    ch = r.influx.of("wids_channel", sensor=SENSOR, channel="6")
    check("the channel row counts the sensor's frames", ch and ch[0][2]["frames"].endswith("i"))
    health = r.influx.of("wids")[0][2]
    check("the health point says RSSI and channel tags were present",
          health["rssi_frames"] == "600i" and health["channel_frames"] == "600i")
    check("our station is remembered", STA in r.det.our_clients)


def test_evil_twin():
    print("\nevil twin, downgrade and policy")
    r = Run()
    r.send(beacon(TWIN, "corp", sec=b"", cap=0x0001))
    r.flush()
    got = r.influx.alerts("evil_twin")
    check("an unlisted BSSID on our SSID is an evil twin, severity 1",
          len(got) == 1 and got[0][1]["severity"] == "1")
    check("and offering it open is a downgrade too", len(r.influx.alerts("security_downgrade")) == 1)
    check("the class tag says so", r.influx.of("wids_ap", bssid=TWIN)[0][1]["class"] == "evil_twin")

    r.influx.clear()
    for _ in range(3):
        r.send(beacon(TWIN, "corp", sec=b"", cap=0x0001))
        r.flush()
    check("a sustained twin is not a new row every window",
          len(r.influx.alerts("evil_twin")) == 0, "held until wids.alert_repeat_seconds")
    r.send(beacon(TWIN, "corp", sec=b"", cap=0x0001))
    r.flush(advance=300)
    got = r.influx.alerts("evil_twin")
    check("after the repeat interval it is written again, with the held count",
          len(got) == 1 and got[0][2]["count"] == "4i", str(got and got[0][2]["count"]))

    r = Run(our=("corp",), authorized=())
    r.send(beacon(TWIN, "corp"))
    r.flush()
    check("without an authorized list nothing is called a twin",
          not r.influx.alerts("evil_twin"))

    r = Run(require_pmf="true")
    r.send(beacon(AP, "corp", sec=rsn_ie(group=2, pairwise=(4, 2)), extra=WPS_IE))
    r.send(beacon(AP2, "corp", sec=b"", cap=0x0011))
    r.flush()
    got = r.influx.alerts("security_downgrade")
    check("one of OUR APs offering WEP is a downgrade at severity 2",
          len(got) == 1 and got[0][1]["severity"] == "2" and got[0][1]["bssid"] == AP2)
    check("TKIP on our SSID is flagged", len(r.influx.alerts("weak_cipher")) == 1)
    check("so is WPS", len(r.influx.alerts("wps_enabled")) == 1)
    check("and PMF not required, when wids.require_pmf is on",
          len(r.influx.alerts("pmf_not_required")) == 1)
    r.influx.clear()
    r.send(beacon(TWIN, "cafe", sec=b"", cap=0x0001))
    r.flush()
    check("a neighbour's open network is nobody's alert", not r.influx.alerts())


def test_spoof():
    print("\nBSSID spoofing by sequence number")
    r = Run()
    for i in range(20):  # the real AP near 100, the forger near 3000
        r.send(beacon(AP, "corp", seq=100 + i))
        r.send(beacon(AP, "corp", seq=3000 + i))
    r.flush()
    got = r.influx.alerts("bssid_spoof")
    check("two interleaved counters on our BSSID: spoof, severity 1",
          len(got) == 1 and got[0][1]["severity"] == "1")
    r = Run()
    for i in range(20):  # one AP, heard by two sensors with independent jitter
        r.send(beacon(AP, "corp", seq=100 + i), sensor=SENSOR2)
        r.send(beacon(AP, "corp", seq=100 + i - 1 if i else 100))
    r.flush()
    check("the same AP heard by two sensors is not", not r.influx.alerts("bssid_spoof"))


def test_floods():
    print("\nfloods")
    r = Run()
    for _ in range(40):
        r.send(deauth(AP, STA, src="02:00:5e:00:53:99"))
    r.flush()
    got = r.influx.alerts("deauth_flood")
    check("40 deauths in a window is a flood", len(got) == 1 and got[0][2]["count"] == "40i")
    check("the forged transmitter is in the record", '"02:00:5e:00:53:99"' == got[0][2]["source"])

    r = Run()
    for _ in range(6):
        r.send(deauth(AP, BCAST))
    r.flush()
    check("six BROADCAST deauths are enough on their own",
          len(r.influx.alerts("deauth_flood")) == 1)
    r = Run()
    for _ in range(40):
        r.send(deauth(AP, STA, protected=True))
    r.flush()
    got = r.influx.alerts("deauth_flood")
    check("PMF-protected deauths are counted apart", got and "40 PMF-protected" in got[0][2]["detail"])

    r = Run()
    for i in range(6):
        r.send(beacon(TWIN, f"net{i}", sub=wids.PROBE_RESP, dst=STA))
    r.flush()
    check("one BSSID answering as six SSIDs is KARMA", len(r.influx.alerts("karma")) == 1)
    r = Run()
    r.send(beacon(AP, "", seq=1))
    r.send(beacon(AP, "corp", sub=wids.PROBE_RESP, dst=STA))
    r.flush()
    check("a hidden AP answering with its one real SSID is not",
          not r.influx.alerts("karma"))
    check("and its inventory row reads hidden",
          r.influx.of("wids_ap", bssid=AP)[0][2]["hidden"] == "1i")

    r = Run()
    for i in range(50):
        r.send(auth(AP, f"02:00:5e:01:{i // 256:02x}:{i % 256:02x}"))
    r.flush()
    check("50 distinct clients authenticating at once is an auth flood",
          len(r.influx.alerts("auth_flood")) == 1)

    def flood(run, prefix):
        for i in range(60):
            run.send(beacon(f"02:{prefix}:00:00:{i // 256:02x}:{i % 256:02x}", f"x{i}"))
        run.flush()

    r = Run(state={})
    flood(r, "aa")
    flood(r, "bb")
    check("the first start is not a beacon flood", not r.influx.alerts("beacon_flood"),
          "every AP is new to a service that has never run")
    flood(r, "cc")
    check("60 never-seen BSSIDs after that is", len(r.influx.alerts("beacon_flood")) == 1)
    state = r.det.state()
    r2 = Run(state=state)
    flood(r2, "cc")
    check("a restart that remembers them sees nothing new", not r2.influx.alerts("beacon_flood"))

    r = Run()
    for _ in range(300):
        r.send(probe_req(STA, "home-wifi"))
    r.flush()
    check("300 probes from one source is a survey tool, severity 4",
          len(r.influx.alerts("probe_flood")) == 1)
    probes = r.influx.of("wids_probe", ssid="home-wifi")
    check("and the probed SSID is recorded with its client count",
          probes and probes[0][2] == {"count": "300i", "clients": "1i"})

    r = Run()
    for _ in range(120):
        r.send(header(1, 12, STA, STA, STA, duration=32000)[:10])
    r.flush()
    check("120 CTS frames reserving 32 ms each is NAV abuse",
          len(r.influx.alerts("nav_abuse")) == 1)


def test_eapol():
    print("\nhandshakes")
    r = Run()
    for i in range(6):
        r.send(eapol(AP, f"02:00:5e:02:00:{i:02x}", M1))
    r.now += 2
    r.det.flush(r.now, wids.STATE_WATCHING)
    check("M1 inside its grace period is not judged yet", not r.influx.alerts("eapol_harvest"))
    r.flush()
    got = r.influx.alerts("eapol_harvest")
    check("six clients that took M1 and never answered: harvesting",
          len(got) == 1 and got[0][2]["count"] == "6i")
    r = Run()
    for i in range(6):
        sta = f"02:00:5e:02:00:{i:02x}"
        r.send(eapol(AP, sta, M1))
        r.send(eapol(AP, sta, M2, to_ap=True))
    r.flush()
    check("six completed handshakes are not", not r.influx.alerts("eapol_harvest"))
    r = Run()
    for _ in range(5):
        r.send(eapol(AP, STA, M3))
    r.flush()
    check("M3 five times to one station is a retransmit alert",
          len(r.influx.alerts("m3_retransmit")) == 1)


def test_rogue_association():
    print("\nour clients on APs that are not ours")
    r = Run()
    r.send(beacon(TWIN, "corp"))
    r.send(data(TWIN, STA))
    r.flush()
    got = r.influx.alerts("client_on_evil_twin")
    check("a station exchanging data with an evil twin, severity 1",
          len(got) == 1 and got[0][1]["severity"] == "1")
    r = Run()
    r.send(beacon(AP, "corp"))
    r.send(data(AP, STA))
    r.flush()
    r.send(beacon(TWIN, "cafe"))
    r.send(data(TWIN, STA))
    r.flush()
    check("a station once seen on our AP, now on a foreign one",
          len(r.influx.alerts("client_on_foreign_ap")) == 1)
    r.send(data("02:00:5e:00:77:77", STA))
    r.flush()
    check("an AP never heard is no basis for a verdict",
          len(r.influx.alerts("client_on_foreign_ap")) == 1)


def test_clock():
    print("Beacon clock (TSF) against the sensor's clock")
    us = 1_000_000

    def stream(r, transmitters, beacons=30, restart_at=None):
        """Beacons 102.4 ms apart, alternating between transmitters that are
        given as beacon-clock offsets from the sensor's clock."""
        rx = 5_000 * us
        for i in range(beacons):
            off = transmitters[i % len(transmitters)]
            if restart_at is None or i < restart_at:
                tsf = rx + off
            else:  # rebooted: the AP's clock starts again from zero
                tsf = 1 + (i - restart_at) * 102_400
            r.send_rt(beacon(AP, "corp", seq=i, tsf=tsf), tsft=rx)
            rx += 102_400

    r = Run()
    stream(r, [123_456_789], beacons=200)
    r.flush()
    check("one transmitter: a steady beacon clock raises nothing",
          not r.influx.alerts(), f"{[a[1]['alert'] for a in r.influx.alerts()]}")
    r = Run()
    stream(r, [123_456_789, 987_654_321])
    r.flush()
    got = r.influx.alerts("tsf_spoof")
    check("two clocks on one BSSID are a spoof, critical on ours",
          got and got[0][1]["severity"] == "1", f"{got}")
    r = Run()
    stream(r, [7_200 * us], restart_at=10)
    r.flush()
    check("a jump back to a small clock is a restart, not a spoof",
          r.influx.alerts("ap_restart") and not r.influx.alerts("tsf_spoof"),
          f"{[a[1]['alert'] for a in r.influx.alerts()]}")
    r = Run()
    r.send_rt(beacon(AP, "corp", tsf=10 * us), tsft=1 * us)
    r.send_rt(beacon(AP, "corp", tsf=600 * us), tsft=500 * us)  # 499 s unheard
    r.send_rt(beacon(AP, "corp", tsf=601 * us), tsft=501 * us)
    r.flush()
    check("a BSSID unheard for minutes gets a new reference, not a jump",
          not r.det.tsf_jumps and not r.influx.alerts(), f"{r.det.tsf_jumps}")
    r = Run()
    for i in range(20):
        r.send(beacon(AP, "corp", seq=i, tsf=(i * 7919) << 20))
    r.flush()
    check("without a sensor clock (no radiotap TSFT) nothing is judged",
          not r.det.tsf and not r.influx.alerts())


def test_channel_mismatch():
    print("Claimed channel against the channel a beacon was heard on")
    r = Run()
    for i in range(10):
        r.send_rt(beacon(AP, "corp", seq=i, channel=5), freq=2427)   # heard on 4
        r.send_rt(beacon(AP2, "corp", seq=i, channel=11), freq=2427)
    r.flush()
    got = r.influx.alerts("channel_mismatch")
    check("an adjacent, overlapping channel (5 heard on 4) is not a mismatch",
          all(a[1]["bssid"] != AP for a in got))
    check("channel 11 heard on 4 is a mismatch on our AP",
          any(a[1]["bssid"] == AP2 for a in got), f"{got}")
    r = Run()
    for i in range(10):
        r.send_rt(beacon(TWIN, "someone-else", seq=i, channel=11), freq=2427)
    r.flush()
    check("a neighbour's mismatch is inventoried, not alerted",
          not r.influx.alerts("channel_mismatch")
          and r.influx.of("wids_ap", bssid=TWIN)[0][2].get("channel_mismatch") == "10i")


def test_signal_baseline():
    print("Signal strength against the AP's learnt baseline")
    r = Run(rssi_learn_windows=5, rssi_shift_windows=3, rssi_relearn_windows=8)

    def window(dbm, bssid=AP):
        for i in range(10):
            r.send_rt(beacon(bssid, "corp", seq=i), rssi=dbm + (i % 3) - 1)
        r.flush()

    for _ in range(6):
        window(-60)
    window(-68)
    check("fading of a few dB raises nothing", not r.influx.alerts())
    window(-40)
    window(-40)
    check("a shift held for fewer windows than required raises nothing",
          not r.influx.alerts("rssi_shift"))
    window(-40)
    got = r.influx.alerts("rssi_shift")
    check("20 dB held for 3 windows is a shift on our authorized AP (high)",
          got and got[0][1]["severity"] == "2", f"{got}")
    base = r.det.baselines[f"{SENSOR}|{AP}"][0]
    check("the baseline does not learn the deviation", -62 < base < -58, f"{base:.1f}")
    for _ in range(5):
        window(-40)
    base = r.det.baselines[f"{SENSOR}|{AP}"][0]
    check("after rssi_relearn_windows the new level is accepted",
          -42 < base < -38, f"{base:.1f}")
    r.influx.clear()
    window(-40)
    check("... and stops alerting", not r.influx.alerts("rssi_shift"))
    st = wids.Detector(config(rssi_learn_windows=5), wids.Policy(["corp"], [AP], "wpa2", False),
                       StubInflux(), r.det.state())
    check("baselines survive a restart", f"{SENSOR}|{AP}" in st.baselines)


def test_sensor_health():
    print("Sensor health")
    r = Run(sensor_silent_seconds=300)
    r.send(beacon(AP, "corp"), sensor=SENSOR)
    r.send(beacon(AP, "corp"), sensor=SENSOR2)
    r.flush()
    pts = r.influx.of("wids_sensor")
    check("each sensor heard gets a wids_sensor point",
          {p[1]["sensor"] for p in pts} == {SENSOR, SENSOR2}, f"{pts}")
    for _ in range(7):
        r.send(beacon(AP, "corp"), sensor=SENSOR)
        r.flush()
    check("a sensor heard only in one burst is shown but never alerts",
          not r.influx.alerts("sensor_silent"))
    r = Run(sensor_silent_seconds=300)
    for _ in range(6):
        r.send(beacon(AP, "corp"), sensor=SENSOR)
        r.send(beacon(AP, "corp"), sensor=SENSOR2)
        r.flush()
    r.influx.clear()
    for _ in range(6):
        r.send(beacon(AP, "corp"), sensor=SENSOR)
        r.flush()
    got = r.influx.alerts("sensor_silent")
    check("a sensor quiet past sensor_silent_seconds raises sensor_silent",
          len(got) == 1 and got[0][2]["source"] == f'"{SENSOR2}"', f"{got}")
    silent = [p for p in r.influx.of("wids_sensor", sensor=SENSOR2) if p[2]["silent"] == "1i"]
    check("... and is still written, as silent", bool(silent))
    check("the sensor still talking raises nothing",
          all(SENSOR not in a[2]["detail"].replace(SENSOR2, "") for a in got))
    r.influx.clear()
    r.flush()
    check("the alert repeats hourly, not every window", not r.influx.alerts("sensor_silent"))
    r = Run(sensor_silent_seconds=300, sensors=SENSOR2)
    for _ in range(6):
        r.flush()
    check("a configured sensor never heard at all is reported too",
          r.influx.alerts("sensor_silent"))


def test_policy_control():
    print("policy control from the dashboard")
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "policy.json")
    influx = StubInflux()
    det = wids.Detector(config(), wids.Policy([], [], "wpa2", False), influx, {"known": {"x": [0, 0, ""]}})
    cfg = config(our_ssids="corp", authorized_bssids=f"{AP}, junk")
    store = wids.PolicyStore(path, cfg, det, influx, True)
    check("the first start seeds from the property file, dropping junk",
          set(store.ssids) == {"corp"} and set(store.bssids) == {AP} and os.path.exists(path),
          f"{store.ssids} {store.bssids}")
    check("... and the seeded policy is live in the detector",
          det.policy.level == 2 and det.policy.authorized(AP))

    store.apply(add_ssid=["guest net"], add_bssid=["02-00-5E-00-53-99"], note="hr")
    check("an SSID with a space and a dash-separated BSSID are accepted",
          "guest net" in store.ssids and "02:00:5e:00:53:99" in store.bssids)
    check("the change is live without a restart",
          det.policy.authorized("02:00:5e:00:53:99") and "guest net" in det.policy.our_ssids)
    n = len(influx.of("wids_policy_control"))
    check("every change is audited", n == 2, f"{n}")
    store.apply(add_ssid=["guest net"], add_bssid=["02:00:5e:00:53:99"])
    check("re-sending the same boxes (every refresh) writes nothing",
          len(influx.of("wids_policy_control")) == n)

    for bad in ("*", "02:00:*", "zz:00:5e:00:53:01", "02:00:5e:00:53"):
        store.apply(add_bssid=[bad])
        check(f"BSSID {bad!r} is refused", bad not in store.bssids and "BSSID" in store.message,
              store.message)
    store.apply(add_bssid=["02:00:5e:*"])
    check("an OUI prefix is accepted", "02:00:5e:*" in store.bssids)
    for bad in ("", "x" * 33, "(hidden)", "a\x01b"):
        store.apply(add_ssid=[bad or " "])
        check(f"SSID {bad[:10]!r} is refused", (bad or " ") not in store.ssids, store.message)

    store.apply(remove_ssid=["corp"], remove_bssid=[AP.upper()])
    check("remove takes the value as listed (BSSID case forgiven)",
          "corp" not in store.ssids and AP not in store.bssids)
    store.apply(add_ssid=["x1"], remove_ssid=["x1"])
    check("a value in both boxes ends up removed", "x1" not in store.ssids)

    det2 = wids.Detector(config(), wids.Policy([], [], "wpa2", False), StubInflux(), {})
    again = wids.PolicyStore(path, config(our_ssids="ignored"), det2, StubInflux(), True)
    check("after the first start the dashboard owns the lists, not the properties",
          "ignored" not in again.ssids and "guest net" in again.ssids)

    ro = wids.PolicyStore(path, config(), det2, StubInflux(), False)
    ro.apply(add_ssid=["nope"], remove_ssid=["guest net"])
    check("control_enabled = false refuses both directions",
          "nope" not in ro.ssids and "guest net" in ro.ssids and "read-only" in ro.message)

    check("only the local site may act",
          wids.is_local({}) and wids.is_local({"site": ["InfluxDB_Flux"]})
          and not wids.is_local({"site": ["site-remote"]}))

    # The whole path through HTTP, as Grafana calls it.
    server = wids.serve_control(store, 0)
    port = server.server_address[1]
    base = f"http://127.0.0.1:{port}"

    def get(path):
        with urllib.request.urlopen(base + path, timeout=5) as r:
            return json.loads(r.read())

    rows = get("/apply?add_ssid=caf%C3%A9%20%26%20bar&add_bssid=&remove_ssid=&remove_bssid=&site=InfluxDB_Flux")
    check("HTTP /apply decodes a percent-encoded SSID and lists it",
          any(r["value"] == "café & bar" and r["ssid"] == "café & bar" and r["bssid"] == "" for r in rows), f"{rows}")
    check("another site's call changes nothing and lists nothing",
          get("/apply?add_ssid=other&site=site-remote") == [] and "other" not in store.ssids)
    st = get("/status")[0]
    check("/status reports the level and the lists' sizes",
          st["level"] == 2 and st["ssids"] == len(store.ssids), f"{st}")
    server.shutdown()


def test_robustness():
    print("\nwhat must not count")
    r = Run()
    r.send(beacon(TWIN, "corp"), fcs=True)
    r.send(b"\x80\x00", encap=wids.ENCAP_80211)
    r.send(beacon("03:00:5e:00:53:01", "corp"))  # a group address is no BSSID
    r.det.datagram(SENSOR, tzsp(b"\x00" * 60, encap=wids.ENCAP_ETHERNET), r.now)
    r.det.datagram(SENSOR, b"not tzsp at all", r.now)
    c = dict(r.det.c)
    r.flush()
    check("an FCS-error frame never becomes a rogue AP",
          not r.influx.of("wids_ap") and not r.influx.alerts(),
          "one flipped bit in a BSSID is a brand-new AP")
    check("and every reject is counted by kind",
          (c["fcs_errors"], c["malformed"], c["wrong_encap"], c["not_tzsp"]) == (1, 2, 1, 1),
          str(c))

    rng = random.Random(7)
    r = Run()
    try:
        for _ in range(5000):
            size = rng.randint(0, 300)
            junk = bytes(rng.getrandbits(8) for _ in range(size))
            r.det.datagram(SENSOR, b"\x01\x00\x00\x12\x01" + junk, r.now)
            r.det.datagram(SENSOR, junk, r.now)
        r.flush()
        check("10000 random datagrams raise nothing", True)
    except Exception as exc:  # noqa: BLE001 -- the point is to catch anything
        check("10000 random datagrams raise nothing", False, repr(exc))

    S = wids.wids_state
    check("state: nothing ever received", S(100, None, 0, 0, 300, 2) == wids.STATE_NO_STREAM)
    check("state: datagrams but no 802.11", S(100, 99, 5, 0, 300, 2) == wids.STATE_NOT_80211)
    check("state: one quiet window is not a fault", S(100, 50, 0, 0, 300, 2) == wids.STATE_WATCHING)
    check("state: silent past the limit", S(400, 50, 0, 0, 300, 2) == wids.STATE_NO_STREAM)
    check("state: no authorized list is inventory only", S(100, 99, 5, 5, 300, 1) == wids.STATE_INVENTORY)

    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "sub", "state.json")
    wids.save_state(path, {"known": {AP: [1, 2, "corp"]}, "clients": {STA: 3}})
    check("the state file round-trips", wids.load_state(path)["known"][AP] == [1, 2, "corp"])
    with open(path, "w") as fh:
        fh.write("{half")
    check("a corrupt state file starts empty instead of crashing", wids.load_state(path) == {})
    os.unlink(path)
    os.rmdir(os.path.dirname(path))
    os.rmdir(tmp)


# ---------------------------------------------------------------------------
# --live
# ---------------------------------------------------------------------------
LIVE_BSSID = "02:00:5e:00:53:5e"
LIVE_SSID = "tzsp-monitor-selftest"


def influx_query(flux):
    url = f"{wids.INFLUX_URL.rstrip('/')}/api/v2/query?org={wids.INFLUX_ORG}"
    req = urllib.request.Request(url, data=flux.encode(), method="POST", headers={
        "Authorization": f"Token {wids.INFLUX_TOKEN}",
        "Content-Type": "application/vnd.flux", "Accept": "application/csv"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", "replace")


def test_live(host, port, wait):
    print(f"\nthe running service: 802.11 TZSP -> {host}:{port} -> InfluxDB")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i in range(10):
        sock.sendto(tzsp(beacon(LIVE_BSSID, LIVE_SSID, seq=i), rssi=-42, channel=1),
                    (host, port))
    print(f"  sent 10 beacons for {LIVE_BSSID} ({LIVE_SSID}); waiting up to "
          f"{wait}s for a window to close")
    flux = f'''from(bucket: "{wids.INFLUX_BUCKET}")
  |> range(start: -10m)
  |> filter(fn: (r) => r._measurement == "wids_ap" and r._field == "beacons")
  |> filter(fn: (r) => r.bssid == "{LIVE_BSSID}")
  |> sum()'''
    deadline = time.time() + wait
    while time.time() < deadline:
        time.sleep(5)
        try:
            if LIVE_BSSID in influx_query(flux):
                return check("the test AP reached InfluxDB", True,
                             f"wids_ap bssid={LIVE_BSSID}")
        except (urllib.error.URLError, OSError) as exc:
            print(f"  ...InfluxDB not answering yet ({exc})")
    check("the test AP reached InfluxDB", False,
          "check the '802.11 to' count in `docker compose logs tzsp-decap`, "
          "the [WIDS] line in `docker compose logs wids`, and that wids.sensors "
          "(if set) includes this container's address")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true",
                    help="also send beacons to the running service and read them back")
    ap.add_argument("--host", default="tzsp-decap",
                    help="where to send: tzsp-decap (default), as a sensor does")
    ap.add_argument("--port", type=int, default=37008)
    ap.add_argument("--wait", type=int, default=150,
                    help="seconds to wait for a window to be written")
    args = ap.parse_args()

    test_tzsp()
    test_security()
    test_policy()
    test_quiet_ap()
    test_evil_twin()
    test_spoof()
    test_floods()
    test_eapol()
    test_rogue_association()
    test_clock()
    test_channel_mismatch()
    test_signal_baseline()
    test_sensor_health()
    test_policy_control()
    test_robustness()
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
