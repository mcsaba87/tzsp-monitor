r"""ARP watch: who claims which IPv4 address on the wire, and who lies about it.

    tzsp-decap --(tap tzsp0, ARP only, BPF)--> [this service] --> InfluxDB

ARP has no authentication. Every host believes the last reply it heard, so a
machine that answers "10.0.0.1 is at <my MAC>" -- unasked, every two seconds --
becomes the gateway for whoever listens: that is ARP spoofing, and the
man-in-the-middle it buys is ARP poisoning. Nothing else in this stack can see
it: Suricata and nfstream work on IP, and the flows of a poisoned host look
perfectly ordinary, they just take a detour through somebody else's NIC.

What it records:

* **bindings** (`arp_binding`): every IP -> MAC claim heard in a window, with
  the MAC's vendor from the IEEE registry (oui.py) and the VLAN. This is the
  station table the dashboards read, including the host drill-down.
* **alerts** (`arp_alert`), on the Suricata 1-4 scale:
    1 gateway_spoof     a protected address (a router, a gateway) claimed by a
                        MAC that is not the one it belongs to
    2 arp_poisoning     one IP claimed alternately by two MACs, one of which
                        is known as another host -- the MITM shape
    3 ip_conflict       one IP claimed alternately by two MACs, neither of
                        which is anybody else -- a duplicate address, usually
    3 unsolicited_replies  replies nobody asked for, in bulk (arpspoof sends
                        one every 2s per victim)
    3 garp_flood        gratuitous ARP in bulk from one MAC
    3 arp_scan          one MAC asking for many addresses (arp-scan, nmap -sn)
    3 eth_mismatch      Ethernet source != ARP sender address
    3 bogus_arp         a sender MAC or IP that cannot be a host
    3/4 mac_changed     an IP moved to another MAC (3 if that MAC already
                        holds another address -- a takeover, not a new lease)
    4 new_station       a MAC never seen before

Things that are easy to get wrong:

* **Two MACs on one IP is only an attack when they alternate.** A DHCP lease
  handed to a new machine is one change, once; poisoning is two claimants
  interleaving, because the real host keeps answering too. So the conflict
  checks count *switches* between claimants inside a window -- the same idea as
  the WIDS's sequence numbers going backwards -- and a single change is
  `mac_changed`, informational.
* **The gateway is the address that matters, and it is the one case that does
  not need two claimants.** For a protected address the rule is simpler: any
  MAC other than its own is an attack, the first time. The routers in
  `mikrotik.host` / `mikrotik.<name>.host` are protected automatically; more go
  in `arp_watch.protected`, optionally pinned to their MACs (`ip=mac|mac`). An
  address protected without a MAC adopts the first one it is heard with, and
  re-adopts only after `relearn_seconds` in which the old MAC was never heard --
  a replaced router stops alerting, a poisoner (whom the real gateway keeps
  contradicting) never does.
* **A request poisons as well as a reply.** RFC 826 has every receiver update
  its cache from the *sender* fields of any ARP packet, so every packet with a
  sender IP is a claim, request or reply. Probes (sender IP 0.0.0.0, RFC 5227)
  claim nothing.
* **Bindings are per VLAN.** 10.0.0.5 on VLAN 10 and on VLAN 20 are two
  machines. The tag can arrive in the frame or -- the kernel strips it on
  receive -- in the packet's auxdata; both are read.
* **Coverage is what the router's sniffer sees.** Broadcast ARP (requests,
  gratuitous) reaches it from every port; a unicast reply between two hosts
  on the same switch does not, unless that switch *is* the sniffing router with
  hardware offload off. Poisoning aimed at the router itself, or announced by
  broadcast, is always visible. An  virtual network carries no real ARP at
  all (the fabric answers it), so on the VXLAN-fed instance this service reads
  `NO ARP` and that is correct.

Headless like dns-monitor: no HTTP server, nothing to click, no router writes.
An ARP sender address is as forgeable as an 802.11 one, so -- as with wids --
there is nothing here it would be safe to block.
"""
import ctypes
import ipaddress
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

from oui import OUI, normalize as normalize_mac

PROPERTIES_FILE = os.getenv("PROPERTIES_FILE", "/etc/tzsp-monitor/suricata.properties")
TAP_INTERFACE = os.getenv("TAP_INTERFACE", "tzsp0")
STATE_DIR = os.getenv("ARP_WATCH_STATE", "/var/lib/arp-watch")
OUI_DB = os.getenv("OUI_DB", "/oui/manuf")

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

_log_lock = threading.Lock()


def log(msg):
    with _log_lock:
        sys.stdout.write(f"{datetime.now().strftime('%H:%M:%S')} {msg}\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Property file  (same shape as every other service's)
# ---------------------------------------------------------------------------
class Config:
    """`key = value` property file; `#` starts a comment only at line start."""

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
# InfluxDB  (the same stdlib writer as dns-monitor's)
# ---------------------------------------------------------------------------
def esc_tag(value):
    return (str(value).replace("\\", "\\\\").replace(" ", "\\ ")
            .replace(",", "\\,").replace("=", "\\="))


def esc_str(value):
    flat = str(value).replace("\r", " ").replace("\n", " ")
    return '"' + flat.replace("\\", "\\\\").replace('"', '\\"') + '"'


class Influx:
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
                continue  # an empty tag is dropped by InfluxDB anyway
            parts.append(f"{esc_tag(key)}={esc_tag(value)}")
        line = ",".join(parts) + " " + ",".join(
            f"{esc_tag(k)}={v}" for k, v in fields.items())
        if timestamp_ns:
            line += f" {timestamp_ns}"
        with self.lock:
            self.buffer.append(line)
            due = len(self.buffer) >= self.batch
        if due:
            # Not on the capture thread's time: a slow InfluxDB must not
            # back the socket up into kernel drops.
            threading.Thread(target=self.flush, daemon=True).start()

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
# Frame parsing
# ---------------------------------------------------------------------------
ETH_P_ARP = 0x0806
VLAN_TPIDS = (0x8100, 0x88A8)
OP_REQUEST, OP_REPLY = 1, 2
ZERO_MAC = "00:00:00:00:00:00"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def mac_str(raw):
    return ":".join(f"{b:02x}" for b in raw)


class ArpPacket:
    __slots__ = ("vlan", "eth_src", "eth_dst", "op", "sha", "spa", "tha", "tpa")

    def __init__(self, vlan, eth_src, eth_dst, op, sha, spa, tha, tpa):
        self.vlan, self.eth_src, self.eth_dst, self.op = vlan, eth_src, eth_dst, op
        self.sha, self.spa, self.tha, self.tpa = sha, spa, tha, tpa


def parse_frame(frame, aux_vlan=None):
    """An Ethernet frame -> ArpPacket, or None if it is not IPv4-over-Ethernet ARP.

    The VLAN comes from the frame when the tag is still in it, otherwise from
    the auxdata the kernel moved it into (`aux_vlan`); 0 means untagged. Only
    the outermost tag is the VLAN -- QinQ's inner one is the customer's.
    """
    if len(frame) < 14:
        return None
    eth_dst, eth_src = frame[0:6], frame[6:12]
    etype = struct.unpack_from("!H", frame, 12)[0]
    off, vlan = 14, aux_vlan or 0
    while etype in VLAN_TPIDS:
        if len(frame) < off + 4:
            return None
        tci, etype = struct.unpack_from("!HH", frame, off)
        if not aux_vlan and vlan == 0:
            vlan = tci & 0x0FFF
        off += 4
    if etype != ETH_P_ARP or len(frame) < off + 28:
        return None
    htype, ptype, hlen, plen, op = struct.unpack_from("!HHBBH", frame, off)
    if htype != 1 or ptype != 0x0800 or hlen != 6 or plen != 4:
        return None
    body = off + 8
    return ArpPacket(
        vlan, mac_str(eth_src), mac_str(eth_dst), op,
        mac_str(frame[body:body + 6]), socket.inet_ntoa(frame[body + 6:body + 10]),
        mac_str(frame[body + 10:body + 16]), socket.inet_ntoa(frame[body + 16:body + 20]))


def bogus_sender(pkt):
    """Why this sender cannot be a real host, or None."""
    if pkt.sha in (ZERO_MAC, BROADCAST_MAC) or int(pkt.sha[:2], 16) & 1:
        return f"sender MAC {pkt.sha} is a group/zero address"
    ip = ipaddress.IPv4Address(pkt.spa)
    if ip.is_multicast or ip.is_loopback or pkt.spa == "255.255.255.255":
        return f"sender IP {pkt.spa} is not a host address"
    return None


# ---------------------------------------------------------------------------
# Policy: protected addresses and trusted MACs
# ---------------------------------------------------------------------------
SEVERITY_NAMES = {1: "critical", 2: "high", 3: "medium", 4: "informational"}


class MacSet:
    """Exact MACs, or a prefix ending in `*` (VRRP is 00:00:5e:00:01:*)."""

    def __init__(self, items):
        self.exact, self.prefixes = set(), []
        for item in items:
            item = item.strip().lower()
            if item.endswith("*"):
                pre = item[:-1].replace("-", ":").rstrip(":")
                if len(pre.replace(":", "")) >= 6:  # never shorter than an OUI
                    self.prefixes.append(pre)
                else:
                    log(f"trusted MAC prefix {item!r} is shorter than an OUI: ignored")
            else:
                norm = normalize_mac(item)
                if norm:
                    self.exact.add(norm)
                else:
                    log(f"not a MAC address: {item!r}, ignored")

    def __contains__(self, mac):
        return mac in self.exact or any(mac.startswith(p) for p in self.prefixes)

    def __len__(self):
        return len(self.exact) + len(self.prefixes)


def parse_protected(items):
    """`ip` or `ip=mac|mac` -> {ip: set(macs)} (an empty set means "learn it")."""
    out = {}
    for item in items:
        ip, _, macs = item.partition("=")
        ip = ip.strip()
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            log(f"arp_watch.protected: {ip!r} is not an IPv4 address, ignored")
            continue
        pinned = {normalize_mac(m) for m in macs.split("|") if m.strip()}
        if None in pinned:
            log(f"arp_watch.protected: a MAC for {ip} does not parse, ignored")
            pinned.discard(None)
        out.setdefault(ip, set()).update(pinned)
    return out


def router_hosts(cfg):
    """Every router's address: the first router's plus mikrotik.<name>.host.

    Only the address is read -- this service needs no credentials. A router is
    the one address on the network every host's cache holds, which is why it
    is protected without anyone having to list it."""
    hosts = set()
    if cfg.get("mikrotik.host"):
        hosts.add(cfg.get("mikrotik.host"))
    for name in cfg.get_list("mikrotik.routers"):
        if cfg.get(f"mikrotik.{name}.host"):
            hosts.add(cfg.get(f"mikrotik.{name}.host"))
    out = []
    for h in hosts:
        try:
            ipaddress.IPv4Address(h)
            out.append(h)
        except ValueError:
            pass  # a hostname: nothing ARP would ever carry
    return out


# ---------------------------------------------------------------------------
# The detector  (no I/O: the selftest drives it with a fake clock)
# ---------------------------------------------------------------------------
class Settings:
    def __init__(self, cfg):
        self.window = max(10, cfg.get_int("arp_watch.window_seconds", 60))
        self.learn = max(0, cfg.get_int("arp_watch.learn_seconds", 3600))
        self.relearn = max(60, cfg.get_int("arp_watch.relearn_seconds", 3600))
        self.flip = max(1, cfg.get_int("arp_watch.flip_threshold", 2))
        self.unsolicited = max(1, cfg.get_int("arp_watch.unsolicited_threshold", 20))
        self.garp = max(1, cfg.get_int("arp_watch.garp_threshold", 30))
        self.scan = max(2, cfg.get_int("arp_watch.scan_threshold", 50))
        self.repeat = max(0, cfg.get_int("arp_watch.alert_repeat_seconds", 300))
        self.max_bindings = max(10, cfg.get_int("arp_watch.max_bindings", 5000))
        self.max_state = max(100, cfg.get_int("arp_watch.max_state", 50000))
        self.silent = max(0, cfg.get_int("arp_watch.silent_seconds", 600))
        protected = parse_protected(cfg.get_list("arp_watch.protected"))
        if cfg.get_bool("arp_watch.protect_routers", True):
            for ip in router_hosts(cfg):
                protected.setdefault(ip, set())
        self.protected = protected
        self.trusted = MacSet(cfg.get_list("arp_watch.trusted_macs"))


# How long a request makes a reply to it "solicited". A host answers in
# milliseconds; the slack is for the mirror delivering the two out of order.
SOLICIT_SECONDS = 5.0
MAX_PENDING_REQUESTS = 100000


class Watcher:
    """Accumulates one window of ARP, then turns it into bindings and alerts.

    Persistent state (survives restarts, `arp-watch-state` volume):
      bindings  "vlan|ip" -> {mac, since, last}   the current owner of each IP
      macs      mac -> [first_seen, last_seen]    every station ever heard
      gateways  "vlan|ip" -> {mac, cand, cand_since}  learned protected owners
      started   first-ever start, for the learning period
    """

    def __init__(self, settings, influx, oui, state=None, now=None):
        self.s = settings
        self.influx = influx
        self.oui = oui
        now = time.time() if now is None else now
        state = state or {}
        self.bindings = state.get("bindings", {})
        self.macs = state.get("macs", {})
        self.gateways = state.get("gateways", {})
        self.started = state.get("started", now)
        self.emitted = {}   # (alert, key) -> last time a point was written
        self.pending = {}   # (alert, key) -> {count, severity, ip, vlan, fields}
        self.requests = {}  # (vlan, asker_ip, target_ip) -> time of the request
        self.owned = {}     # (vlan, mac) -> owned IPs, rebuilt every window
        self.reset_window()
        self.totals = {"frames": 0, "malformed": 0}

    # --- per window --------------------------------------------------------
    def reset_window(self):
        self.claims = {}       # (vlan, ip) -> [macs in order of switches, switches]
        self.pair = {}         # (vlan, ip, mac) -> [packets, requests, replies, garp]
        self.per_mac = {}      # mac -> counters + target set
        self.counts = {"frames": 0, "requests": 0, "replies": 0, "gratuitous": 0,
                       "probes": 0, "unsolicited": 0, "bogus": 0, "mismatch": 0}

    def learning(self, now):
        return now - self.started < self.s.learn

    def vendor(self, mac):
        return self.oui.vendor(mac) if self.oui else None

    def _mac(self, mac):
        row = self.per_mac.get(mac)
        if row is None:
            row = self.per_mac[mac] = {"requests": 0, "replies": 0, "garp": 0,
                                       "unsolicited": 0, "mismatch": 0,
                                       "targets": set(), "ips": set(), "vlan": 0,
                                       "unsolicited_ips": set()}
        return row

    def observe(self, pkt, now):
        """One ARP packet. Cheap: only counting happens here."""
        c = self.counts
        c["frames"] += 1
        bogus = bogus_sender(pkt)
        if bogus:
            c["bogus"] += 1
            self.raise_alert("bogus_arp", 3, pkt.sha, now, ip=pkt.spa, vlan=pkt.vlan,
                             mac=pkt.sha, detail=bogus)
            return
        row = self._mac(pkt.sha)
        row["vlan"] = pkt.vlan
        if pkt.eth_src != pkt.sha and pkt.sha not in self.s.trusted:
            row["mismatch"] += 1
            row["mismatch_src"] = pkt.eth_src
            c["mismatch"] += 1

        gratuitous = pkt.spa == pkt.tpa and pkt.spa != "0.0.0.0"
        if pkt.op == OP_REQUEST:
            c["requests"] += 1
            row["requests"] += 1
            if pkt.spa == "0.0.0.0":
                c["probes"] += 1
            if gratuitous:
                c["gratuitous"] += 1
                row["garp"] += 1
            else:
                if len(row["targets"]) <= self.s.scan:
                    row["targets"].add(pkt.tpa)
                if len(self.requests) < MAX_PENDING_REQUESTS:
                    self.requests[(pkt.vlan, pkt.spa, pkt.tpa)] = now
        elif pkt.op == OP_REPLY:
            c["replies"] += 1
            row["replies"] += 1
            if gratuitous:
                c["gratuitous"] += 1
                row["garp"] += 1
            else:
                asked = self.requests.get((pkt.vlan, pkt.tpa, pkt.spa))
                if asked is None or now - asked > SOLICIT_SECONDS:
                    c["unsolicited"] += 1
                    row["unsolicited"] += 1
                    if len(row["unsolicited_ips"]) < 16:
                        row["unsolicited_ips"].add(pkt.spa)
        else:
            return  # RARP/InARP opcodes: nothing to bind

        if pkt.spa == "0.0.0.0":
            return  # a probe claims nothing (RFC 5227)
        key = (pkt.vlan, pkt.spa)
        row["ips"].add(key)
        seq = self.claims.get(key)
        if seq is None:
            seq = self.claims[key] = [[pkt.sha], 0, {pkt.sha}]
        elif seq[0][-1] != pkt.sha:
            # Trusted MACs (VRRP, proxy-ARP routers) answer for addresses that
            # are not theirs by design; switching to or from one is not a
            # second claimant, so it is not counted as one.
            if pkt.sha not in self.s.trusted and seq[0][-1] not in self.s.trusted:
                seq[1] += 1
            seq[0].append(pkt.sha)
            if len(seq[0]) > 8:
                del seq[0][1:-4]
        seq[2].add(pkt.sha)
        p = self.pair.get((pkt.vlan, pkt.spa, pkt.sha))
        if p is None:
            if len(self.pair) >= self.s.max_bindings:
                self.counts["overflow"] = self.counts.get("overflow", 0) + 1
                return
            p = self.pair[(pkt.vlan, pkt.spa, pkt.sha)] = [0, 0, 0, 0]
        p[0] += 1
        p[1 if pkt.op == OP_REQUEST else 2] += 1
        if gratuitous:
            p[3] += 1

    # --- alerts ------------------------------------------------------------
    def raise_alert(self, alert, severity, key, now, ip=None, vlan=0, mac="",
                    other="", detail="", count=1):
        """Queue an alert; written now if it is new, else once per repeat period.

        `count` accumulates between points, so a ten-minute flood is two rows
        with the whole count rather than ten rows -- or one row and silence."""
        slot = self.pending.get((alert, key))
        if slot is None:
            slot = self.pending[(alert, key)] = {"count": 0}
        slot.update(severity=severity, ip=ip, vlan=vlan, mac=mac, other=other,
                    detail=detail, last=now)
        slot["count"] += count

    def _emit_alerts(self, now, now_ns):
        written = 0
        for akey, slot in list(self.pending.items()):
            last = self.emitted.get(akey)
            if last is not None and now - last < self.s.repeat:
                continue
            alert = akey[0]
            fields = {"count": f"{slot['count']}i", "detail": esc_str(slot["detail"])}
            for name in ("mac", "other"):
                mac = slot[name]
                if mac:
                    fields["mac" if name == "mac" else "other_mac"] = esc_str(mac)
                    v = self.vendor(mac)
                    if v:
                        fields["vendor" if name == "mac" else "other_vendor"] = esc_str(v)
            self.influx.point("arp_alert", {
                "alert": alert, "severity": str(slot["severity"]),
                "severity_name": SEVERITY_NAMES[slot["severity"]],
                "ip": slot["ip"] or "none", "vlan": str(slot["vlan"])}, fields, now_ns)
            log(f"[ALERT] {SEVERITY_NAMES[slot['severity']]} {alert} "
                f"{slot['ip'] or ''} x{slot['count']}: {slot['detail']}")
            self.emitted[akey] = now
            del self.pending[akey]
            written += 1
        for akey, t in list(self.emitted.items()):
            if now - t > 2 * max(self.s.repeat, self.s.window) and akey not in self.pending:
                del self.emitted[akey]
        return written

    # --- describe a MAC for an alert detail ---------------------------------
    def who(self, mac, vlan, besides=None):
        """'aa:bb:.. (Vendor, also 10.0.0.9)' -- the vendor and the MAC's other IPs."""
        bits = []
        v = self.vendor(mac)
        if v:
            bits.append(v)
        others = sorted(self.other_ips(mac, vlan, besides))
        if others:
            bits.append("also " + ", ".join(others[:3]) + ("..." if len(others) > 3 else ""))
        return mac + (f" ({'; '.join(bits)})" if bits else "")

    def other_ips(self, mac, vlan, besides):
        """IPs this MAC holds besides `besides`: in this window, or as their owner."""
        row = self.per_mac.get(mac)
        ips = {ip for (vl, ip) in row["ips"] if vl == vlan} if row else set()
        ips |= self.owned.get((vlan, mac), set())
        ips.discard(besides)
        return ips

    def _index_owners(self):
        """(vlan, mac) -> IPs it owns, built once per window: a scan of every
        binding per question would be quadratic on a window full of changes."""
        owned = {}
        for bkey, b in self.bindings.items():
            vl, _, ip = bkey.partition("|")
            owned.setdefault((int(vl), b["mac"]), set()).add(ip)
        self.owned = owned

    # --- end of window -------------------------------------------------------
    def close_window(self, now):
        """Judge the window, write its points, start the next. Returns a summary."""
        now_ns = int(now * 1e9)
        learning = self.learning(now)
        s = self.s
        self._index_owners()

        # Per-claim judgments, before the bindings move.
        for (vlan, ip), (order, switches, macs) in self.claims.items():
            bkey = f"{vlan}|{ip}"
            prev = self.bindings.get(bkey)
            allowed = None
            if ip in s.protected:
                allowed = self._judge_protected(bkey, vlan, ip, order, macs, now)
            else:
                claimants = [m for m in macs if m not in s.trusted]
                if len(claimants) >= 2 and switches >= s.flip:
                    impostors = [m for m in claimants if self.other_ips(m, vlan, ip)]
                    owner = prev["mac"] if prev and prev["mac"] in claimants else None
                    if impostors:
                        bad = next((m for m in impostors if m != owner), impostors[0])
                        good = owner if owner and owner != bad else \
                            next(m for m in claimants if m != bad)
                        self.raise_alert(
                            "arp_poisoning", 2, ip + "|" + str(vlan), now, ip=ip, vlan=vlan,
                            mac=bad, other=good,
                            detail=f"{ip} claimed alternately by {self.who(bad, vlan, ip)} and "
                                   f"{self.who(good, vlan, ip)}, {switches} switches in one window")
                    else:
                        a, b = sorted(claimants)[:2]
                        self.raise_alert(
                            "ip_conflict", 3, ip + "|" + str(vlan), now, ip=ip, vlan=vlan,
                            mac=a, other=b,
                            detail=f"{ip} claimed alternately by {self.who(a, vlan, ip)} and "
                                   f"{self.who(b, vlan, ip)}, {switches} switches -- a duplicate "
                                   "address, unless one of them is impersonating the other")
                elif prev and prev["mac"] not in macs and order[-1] not in s.trusted \
                        and not learning:
                    new = order[-1]
                    takeover = bool(self.other_ips(new, vlan, ip))
                    self.raise_alert(
                        "mac_changed", 3 if takeover else 4, ip + "|" + str(vlan), now,
                        ip=ip, vlan=vlan, mac=new, other=prev["mac"],
                        detail=f"{ip} moved from {self.who(prev['mac'], vlan, ip)} to "
                               f"{self.who(new, vlan, ip)}"
                               + (" -- which already answers for another address" if takeover
                                  else ""))
            # The owner stays put while it is still answering: a poisoner
            # must not become "the" binding just by shouting more often.
            # A protected address is only ever bound to a MAC allowed to hold
            # it, so a window in which the gateway was silent and the forger
            # was not leaves the station table telling the truth.
            if prev and prev["mac"] in macs:
                prev["last"] = now
            elif allowed is None:
                self.bindings[bkey] = {"mac": order[-1], "since": now, "last": now}
            else:
                good = [m for m in order if m in allowed or m in s.trusted]
                if good:
                    self.bindings[bkey] = {"mac": good[-1], "since": now, "last": now}

        # Per-MAC judgments.
        new_macs = 0
        for mac, row in self.per_mac.items():
            vlan = row["vlan"]
            known = self.macs.get(mac)
            first_ip = min((ip for _, ip in row["ips"]), default=None)
            if known is None:
                self.macs[mac] = [now, now]
                new_macs += 1
                if not learning:
                    self.raise_alert("new_station", 4, mac, now, ip=first_ip, vlan=vlan,
                                     mac=mac, detail=f"first time heard: {self.who(mac, vlan)}")
            else:
                known[1] = now
            if mac in s.trusted:
                continue
            mine = {ip for _, ip in row["ips"]}
            infra = bool(mine & set(s.protected))
            if row["unsolicited"] >= s.unsolicited:
                ips = sorted(row["unsolicited_ips"])
                self.raise_alert(
                    "unsolicited_replies", 3, mac, now, ip=ips[0] if len(ips) == 1 else first_ip,
                    vlan=vlan, mac=mac, count=row["unsolicited"],
                    detail=f"{self.who(mac, vlan)} sent {row['unsolicited']} ARP replies nobody "
                           f"asked for, claiming {', '.join(ips[:5])}")
            if row["garp"] >= s.garp:
                self.raise_alert(
                    "garp_flood", 3, mac, now, ip=first_ip, vlan=vlan, mac=mac,
                    count=row["garp"],
                    detail=f"{self.who(mac, vlan)} sent {row['garp']} gratuitous ARPs in one window")
            if len(row["targets"]) >= s.scan and not infra:
                self.raise_alert(
                    "arp_scan", 3, mac, now, ip=first_ip, vlan=vlan, mac=mac,
                    count=len(row["targets"]),
                    detail=f"{self.who(mac, vlan)} asked for {len(row['targets'])}"
                           f"{'+' if len(row['targets']) > s.scan else ''} different addresses "
                           "in one window")
            if row["mismatch"]:
                src = row.get("mismatch_src", "")
                self.raise_alert(
                    "eth_mismatch", 3, mac, now, ip=first_ip, vlan=vlan, mac=mac, other=src,
                    count=row["mismatch"],
                    detail=f"{row['mismatch']} ARP packet(s) whose sender {mac} is not the "
                           f"Ethernet source {self.who(src, vlan)} -- a forged sender, or a "
                           "repeater/proxy that rewrites the frame")

        # Points.
        bindings_written = 0
        for (vlan, ip, mac), (packets, req, rep, garp) in self.pair.items():
            tags = {"ip": ip, "mac": mac, "vlan": str(vlan)}
            v = self.vendor(mac)
            if v:
                tags["vendor"] = v  # no database, no tag -- never a wrong one
            first = self.macs.get(mac, [now])[0]
            self.influx.point("arp_binding", tags, {
                "packets": f"{packets}i", "requests": f"{req}i", "replies": f"{rep}i",
                "gratuitous": f"{garp}i", "first_seen": f"{int(first)}i"}, now_ns)
            bindings_written += 1
        alerts = self._emit_alerts(now, now_ns)

        # Forget requests too old to solicit anything, and cap the state.
        cutoff = now - SOLICIT_SECONDS
        self.requests = {k: t for k, t in self.requests.items() if t >= cutoff}
        self._trim(self.bindings, lambda b: b["last"])
        self._trim(self.macs, lambda m: m[1])

        summary = dict(self.counts, bindings=bindings_written, alerts=alerts,
                       new_macs=new_macs, stations=len(self.bindings), macs=len(self.macs),
                       learning=learning)
        self.reset_window()
        return summary

    def _judge_protected(self, bkey, vlan, ip, order, macs, now):
        s = self.s
        pinned = s.protected.get(ip) or set()
        allowed = set(pinned)
        gw = self.gateways.get(bkey)
        if not pinned:
            if gw is None:
                # First sighting: adopt the claimant heard first. If an
                # attacker is already poisoning at install time this learns
                # the wrong MAC -- which is why pinning it is better, and why
                # the very next window with the real one in it alerts anyway.
                gw = self.gateways[bkey] = {"mac": order[0], "cand": None, "cand_since": None}
                log(f"protected {ip} (vlan {vlan}) learned as {self.who(order[0], vlan, ip)}")
            allowed.add(gw["mac"])
        bad = [m for m in macs if m not in allowed and m not in s.trusted]
        for m in bad:
            owner = sorted(allowed)[0] if allowed else ""
            self.raise_alert(
                "gateway_spoof", 1, ip + "|" + str(vlan) + "|" + m, now, ip=ip, vlan=vlan,
                mac=m, other=owner,
                detail=f"protected address {ip} claimed by {self.who(m, vlan, ip)}; it belongs to "
                       f"{self.who(owner, vlan, ip) if owner else 'nobody yet'}"
                       + (" (pinned)" if pinned else " (learned)"))
        # Re-adoption, only for a learned owner: one MAC alone, for a long
        # time, with the old one silent throughout. A poisoner never gets
        # here, because the real gateway keeps answering in between.
        if not pinned:
            sole = next(iter(macs)) if len(macs) == 1 else None
            if sole and sole != gw["mac"] and sole not in s.trusted:
                if gw["cand"] != sole:
                    gw["cand"], gw["cand_since"] = sole, now
                elif now - gw["cand_since"] >= s.relearn:
                    log(f"protected {ip} (vlan {vlan}) re-learned: {gw['mac']} -> {sole}, "
                        f"the only claimant for {int(now - gw['cand_since'])}s")
                    self.raise_alert(
                        "mac_changed", 3, ip + "|" + str(vlan), now, ip=ip, vlan=vlan,
                        mac=sole, other=gw["mac"],
                        detail=f"protected {ip} re-learned as {self.who(sole, vlan, ip)} after "
                               f"{int(now - gw['cand_since'])}s as its only claimant; it was "
                               f"{self.who(gw['mac'], vlan, ip)}")
                    gw.update(mac=sole, cand=None, cand_since=None)
            elif gw["mac"] in macs:
                gw["cand"], gw["cand_since"] = None, None
            allowed.add(gw["mac"])  # after a re-adoption, the new one
        return allowed

    def _trim(self, table, last):
        over = len(table) - self.s.max_state
        if over > 0:
            for k in sorted(table, key=lambda k: last(table[k]))[:over]:
                del table[k]

    def export(self):
        return {"bindings": self.bindings, "macs": self.macs,
                "gateways": self.gateways, "started": self.started}


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
STATE_NO_TAP, STATE_NO_MIRROR, STATE_NO_ARP, STATE_LEARNING, STATE_WATCHING = range(5)


def watch_state(tap_ok, mirror_silent_for, arp_silent_for, silent, learning):
    """0 no tap / 1 tap but nothing arriving / 2 traffic but no ARP / 3 learning / 4 watching.

    Computed here and not in a panel for the same reason as dns-monitor's:
    a value mapping can render the word, but not work out which applies --
    and "no ARP in the mirror" (a mangle-based mirror, an  TAP) has to
    look different from "nothing is wrong"."""
    if not tap_ok:
        return STATE_NO_TAP
    if silent and mirror_silent_for >= silent:
        return STATE_NO_MIRROR
    if silent and arp_silent_for >= silent:
        return STATE_NO_ARP
    return STATE_LEARNING if learning else STATE_WATCHING


def tap_rx_packets(iface):
    """Received-packet counter of the tap, from this namespace's /proc/net/dev."""
    try:
        with open("/proc/net/dev") as fh:
            for line in fh:
                name, _, rest = line.partition(":")
                if name.strip() == iface:
                    return int(rest.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------
SOL_PACKET = 263
PACKET_AUXDATA = 8
PACKET_STATISTICS = 6
SO_ATTACH_FILTER = 26
ETH_P_ALL = 0x0003
PACKET_OUTGOING = 4
TP_STATUS_VLAN_VALID = 0x10
AUXDATA = struct.Struct("IIIHHHH")

# Classic BPF: ARP, untagged or behind one 802.1Q/802.1ad tag. The kernel
# normally strips the tag into metadata before this runs, so the second half
# is for the frames it does not (and costs nothing for the rest):
#   0 ldh [12]
#   1 jeq #0x0806      -> 6 accept
#   2 jeq #0x8100      -> 4
#   3 jeq #0x88a8      -> 4, else 7 drop
#   4 ldh [16]
#   5 jeq #0x0806      -> 6 accept, else 7 drop
#   6 ret #65535
#   7 ret #0
ARP_FILTER = ((0x28, 0, 0, 12), (0x15, 4, 0, ETH_P_ARP), (0x15, 1, 0, 0x8100),
              (0x15, 0, 3, 0x88A8), (0x28, 0, 0, 16), (0x15, 0, 1, ETH_P_ARP),
              (0x06, 0, 0, 0xFFFF), (0x06, 0, 0, 0))


def open_capture(iface):
    """AF_PACKET socket on the tap, filtered to ARP before it is bound.

    The filter goes on before bind() so not one non-ARP frame is queued in
    between. ETH_P_ALL rather than ETH_P_ARP: a tagged frame whose VLAN has
    no interface here is handed to taps with its *inner* protocol only on
    some paths, and the BPF already does the selecting."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    insns = b"".join(struct.pack("HBBI", *i) for i in ARP_FILTER)
    code = ctypes.create_string_buffer(insns, len(insns))
    fprog = struct.pack("HL", len(ARP_FILTER), ctypes.addressof(code))
    sock.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fprog)
    sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
    sock.bind((iface, ETH_P_ALL))
    sock.settimeout(1.0)
    return sock


def capture_drops(sock):
    """Frames the kernel dropped since the last call (the counter resets on read)."""
    try:
        _, drops = struct.unpack("II", sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
        return drops
    except OSError:
        return 0


def save_state(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def load_state(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        log(f"state file {path} unreadable ({exc}); starting fresh")
        return None


def main():
    cfg = Config(PROPERTIES_FILE)
    if not cfg.get_bool("arp_watch.enabled", True):
        log("arp_watch.enabled=false: nothing to do, idling")
        while True:
            time.sleep(3600)

    settings = Settings(cfg)
    os.makedirs(STATE_DIR, exist_ok=True)
    state_path = os.path.join(STATE_DIR, "state.json")
    state = load_state(state_path)
    oui = OUI(OUI_DB)
    influx = Influx(INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG, INFLUX_BUCKET)
    watcher = Watcher(settings, influx, oui, state)
    log(f"window={settings.window}s learn={settings.learn}s "
        f"({'learning' if watcher.learning(time.time()) else 'watching'}) "
        f"protected={sorted(settings.protected) or 'none'} trusted={len(settings.trusted)} "
        f"stations={len(watcher.bindings)} macs={len(watcher.macs)} "
        f"oui={'%d blocks' % oui.entries if oui.loaded else 'NOT LOADED (' + str(oui.error) + ')'}")
    if not settings.protected:
        log("no protected addresses (mikrotik.host unset, arp_watch.protected empty): "
            "gateway spoofing -- the attack that matters most -- will only show up as "
            "a conflict")

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())

    sock, ifindex, waited = None, None, 0
    last_rx = tap_rx_packets(TAP_INTERFACE)
    mono = time.monotonic()
    last_mirror = last_arp = mono
    next_window = mono + settings.window
    next_save = mono + 300
    drops = 0
    code_logged = None

    while not stop.is_set():
        # (Re)open the capture whenever the tap is missing or was recreated:
        # restarting tzsp-decap destroys tzsp0 and makes a new one with a new
        # ifindex, and a socket bound to the old one just goes quiet.
        if sock is None:
            try:
                sock = open_capture(TAP_INTERFACE)
                ifindex = socket.if_nametoindex(TAP_INTERFACE)
                log(f"capturing ARP on {TAP_INTERFACE} (ifindex {ifindex})")
                waited = 0
            except OSError as exc:
                if waited % 30 == 0:
                    log(f"waiting for {TAP_INTERFACE}: {exc}")
                waited += 1
                sock = None
                stop.wait(1.0)
        if sock is not None:
            try:
                data, anc, _, addr = sock.recvmsg(65535, socket.CMSG_SPACE(AUXDATA.size))
                if addr[2] != PACKET_OUTGOING:
                    vlan = None
                    for level, ctype, cdata in anc:
                        if level == SOL_PACKET and ctype == PACKET_AUXDATA \
                                and len(cdata) >= AUXDATA.size:
                            status, _, _, _, _, tci, _ = AUXDATA.unpack_from(cdata)
                            if status & TP_STATUS_VLAN_VALID:
                                vlan = tci & 0x0FFF
                    pkt = parse_frame(data, vlan)
                    if pkt is None:
                        watcher.totals["malformed"] += 1
                    else:
                        watcher.observe(pkt, time.time())
                        last_arp = time.monotonic()
            except socket.timeout:
                pass
            except OSError as exc:
                log(f"capture error on {TAP_INTERFACE}: {exc}; reopening")
                sock.close()
                sock = None

        now_m = time.monotonic()
        if now_m < next_window:
            continue
        next_window = now_m + settings.window
        tap_ok = sock is not None
        if tap_ok:
            try:
                if socket.if_nametoindex(TAP_INTERFACE) != ifindex:
                    raise OSError("ifindex changed")
            except OSError:
                log(f"{TAP_INTERFACE} was recreated; reopening the capture")
                sock.close()
                sock, tap_ok = None, False
        if tap_ok:
            drops = capture_drops(sock)
        rx = tap_rx_packets(TAP_INTERFACE)
        if rx is not None and last_rx is not None and rx != last_rx:
            last_mirror = now_m
        tap_delta = rx - last_rx if rx is not None and last_rx is not None \
            and rx >= last_rx else 0
        last_rx = rx
        oui.maybe_reload()

        now = time.time()
        summary = watcher.close_window(now)
        code = watch_state(tap_ok, now_m - last_mirror, now_m - last_arp,
                           settings.silent, summary["learning"])
        influx.point("arp_watch", {}, {
            "up": "1i", "state_code": f"{code}i",
            "frames": f"{summary['frames']}i", "requests": f"{summary['requests']}i",
            "replies": f"{summary['replies']}i", "gratuitous": f"{summary['gratuitous']}i",
            "probes": f"{summary['probes']}i", "unsolicited": f"{summary['unsolicited']}i",
            "bogus": f"{summary['bogus']}i", "mismatch": f"{summary['mismatch']}i",
            "bindings": f"{summary['bindings']}i", "overflow": f"{summary.get('overflow', 0)}i",
            "stations": f"{summary['stations']}i", "macs": f"{summary['macs']}i",
            "new_macs": f"{summary['new_macs']}i", "alerts": f"{summary['alerts']}i",
            "protected": f"{len(settings.protected)}i",
            "learning": f"{1 if summary['learning'] else 0}i",
            "malformed": f"{watcher.totals['malformed']}i",
            "capture_drops": f"{drops}i", "tap_packets": f"{tap_delta}i",
            "oui_loaded": f"{1 if oui.loaded else 0}i",
        }, int(now * 1e9))
        watcher.totals["malformed"] = 0
        if summary["frames"] or summary["alerts"]:
            log(f"[ARP] {summary['frames']} frame(s): {summary['requests']} req, "
                f"{summary['replies']} rep ({summary['unsolicited']} unsolicited), "
                f"{summary['gratuitous']} gratuitous; {summary['bindings']} binding(s), "
                f"{summary['alerts']} alert(s), {summary['stations']} stations known"
                + (f", {drops} DROPPED" if drops else ""))
        if code != code_logged:
            log({STATE_NO_TAP: f"state: NO TAP -- {TAP_INTERFACE} is not there",
                 STATE_NO_MIRROR: f"state: NO MIRROR -- nothing received on {TAP_INTERFACE} "
                                  f"for {settings.silent}s",
                 STATE_NO_ARP: f"state: NO ARP -- the mirror carries traffic but no ARP for "
                               f"{settings.silent}s: a mangle (IP-only) mirror, a filtered "
                               "sniffer, or a VXLAN TAP whose fabric answers ARP itself",
                 STATE_LEARNING: "state: LEARNING (no change/new-station alerts yet)",
                 STATE_WATCHING: "state: WATCHING"}[code])
            code_logged = code
        if now_m >= next_save:
            next_save = now_m + 300
            save_state(state_path, watcher.export())

    save_state(state_path, watcher.export())
    influx.flush()
    log("stopped; state saved")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
