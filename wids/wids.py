r"""Wireless IDS: raw 802.11 frames over TZSP -> detections and an AP inventory.

    sensor (RouterOS sniffer, 802.11) --TZSP/UDP 37008--> tzsp-decap
        --802.11 only, with the sensor's address--> [this service :37009] --> InfluxDB

Everything else in this stack reads the *wired* mirror, decapsulated to
Ethernet on tzsp0. A wireless sniffer streams something else: TZSP whose
encapsulation is 802.11 (18), or 802.11 behind a Prism (119), radiotap (126,
what the RouterOS wireless sniffer sends) or AVS (127) radio header. Neither
Suricata nor nfstream can do anything with those, and a tap only carries
Ethernet, so this is a branch of its own rather than a
consumer of tzsp0:

* **It shares 37008 with the wired mirror, because it has to.** The RouterOS
  wireless sniffer has no setting for the target port, so a sensor streams to
  37008 like a /tool sniffer does. tzsp-decap owns that port; it steers 802.11
  TZSP onto a socket of its own (SO_REUSEPORT plus a BPF selector, so the
  wired loop pays nothing) and passes each datagram on to this service's
  UDP 37009 -- unpublished, compose network only -- behind an 8-byte header
  carrying the sensor's address (`unwrap_forward`). The address matters:
  sensor identity keys spoof detection and channel coverage, and every
  forwarded datagram's own source is tzsp-decap. Rebuilding or stopping this
  service still cannot recreate tzsp-decap's namespace; while it is down,
  decap counts the frames it could not pass on and the IDS is unaffected.
* **It reads the cleartext half of Wi-Fi.** With WPA2/WPA3 every data payload
  is encrypted, so there is no Suricata-style inspection to do. What is in the
  clear is who is on the air and what they claim to be: beacons, probes,
  authentication, (de)association, EAPOL, and the 802.11 header of every frame
  -- addresses, sequence number, retry bit, duration. Every detection here is
  built from those.
* **Aggregated per window, like dns-monitor.** A point per frame would be one
  series write per beacon (an AP sends ten a second). Everything is counted
  over `wids.window_seconds` and written once, and every detection threshold
  is "per window" for the same reason.
* **Alerts only, never a router write.** Every source address in 802.11 is
  forgeable by anyone with a radio: blocking the transmitter of a deauth flood
  on the AP's access list would block the client the attacker impersonated.
  So unlike mikrotik-responder there is no response path here at all.
"""
import json
import os
import re
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROPERTIES_FILE = os.getenv("PROPERTIES_FILE", "/etc/tzsp-monitor/suricata.properties")

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

# The port is the container's, and NOT published: sensors stream to 37008 and
# tzsp-decap forwards the 802.11 to this one (its WIDS_FORWARD). Not in the
# property file because changing it means changing decap's target too, and a
# mismatch between the two would be a silent outage.
LISTEN_ADDR = os.getenv("WIDS_LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = int(os.getenv("WIDS_LISTEN_PORT", "37009"))
RCVBUF = int(os.getenv("WIDS_RCVBUF", str(8 * 1024 * 1024)))
# The policy control API (our SSIDs, authorized BSSIDs). Not published:
# Grafana calls it from the compose network as http://wids:8060.
CONTROL_PORT = int(os.getenv("WIDS_CONTROL_PORT", "8060"))
SO_RCVBUFFORCE = 33

# tzsp-decap's forward header: magic (0xFF cannot start TZSP), then the
# sensor's IPv4 address. tzsp-decap/decap.py FORWARD_MAGIC is the other half.
FORWARD_MAGIC = b"\xffWF\x01"


def unwrap_forward(data, src):
    """(sensor, tzsp) for a datagram as received from `src`.

    Forwarded by tzsp-decap: the sensor is the address in the header, None if
    decap did not know it. Anything else came straight here (the selftest, or
    a sensor that can be aimed at this port) and its own source is the sensor.
    """
    if data[:4] == FORWARD_MAGIC and len(data) >= 8:
        ip = data[4:8]
        return (socket.inet_ntoa(ip) if ip != b"\x00\x00\x00\x00" else None), data[8:]
    return src, data

_log_lock = threading.Lock()


def log(msg):
    with _log_lock:
        sys.stdout.write(f"{datetime.now().strftime('%H:%M:%S')} {msg}\n")
        sys.stdout.flush()


# ---------------------------------------------------------------------------
# Property file (same shape as every other reader of suricata.properties)
# ---------------------------------------------------------------------------
class Config:
    """`key = value` property file with typed access and defaults.

    `#` only starts a comment at the start of a line: an SSID may contain one.
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
    """Buffered InfluxDB v2 line-protocol writer, stdlib only (dns-monitor's)."""

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
# TZSP -> 802.11
# ---------------------------------------------------------------------------
TZSP_VERSION = 1
TAG_PADDING = 0x00
TAG_END = 0x01
TAG_RAW_RSSI = 10
TAG_FCS_ERROR = 17
TAG_RX_CHANNEL = 18

ENCAP_ETHERNET = 1
ENCAP_80211 = 18
ENCAP_PRISM = 119
ENCAP_RADIOTAP = 126
ENCAP_AVS = 127

# Radiotap fields this reads, by present-bit: (alignment, size). Fields are
# laid out in bit order, so only the ones up to the last bit used need sizes.
RT_TSFT, RT_FLAGS, RT_RATE, RT_CHANNEL, RT_FHSS, RT_DBM_SIGNAL = range(6)
RT_LAYOUT = ((8, 8), (1, 1), (1, 1), (2, 4), (1, 2), (1, 1))
RT_F_FCS = 0x10      # the frame carries its 4-byte FCS at the end
RT_F_BADFCS = 0x40   # ... and it failed the check
RT_EXT = 1 << 31     # another present word follows


def parse_tzsp(data):
    """(encap, rssi, channel, fcs_error, payload) or None if this is not TZSP.

    Unlike tzsp-decap this reads the tags rather than skipping them: on an
    802.11 stream they carry the receive signal strength and the channel, which
    are evidence here (a spoofed AP is usually somewhere else, so it is heard at
    a different strength) and which a wired mirror never has. Which tags a
    given sensor actually sends is not something to assume -- the `wids`
    health point counts how many frames carried each.
    """
    n = len(data)
    if n < 5 or data[0] != TZSP_VERSION:
        return None
    encap = (data[2] << 8) | data[3]
    rssi = channel = None
    fcs_error = False
    i = 4
    while i < n:
        tag = data[i]
        if tag == TAG_END:
            return encap, rssi, channel, fcs_error, data[i + 1:]
        if tag == TAG_PADDING:
            i += 1
            continue
        if i + 1 >= n:
            return None
        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        if len(value) < length:
            return None
        if tag == TAG_RAW_RSSI and length in (1, 2):
            rssi = int.from_bytes(value, "big", signed=True)
        elif tag == TAG_RX_CHANNEL and length >= 1:
            channel = value[0]
        elif tag == TAG_FCS_ERROR and length >= 1:
            fcs_error = value[0] != 0
        i += 2 + length
    return None


def freq_to_channel(mhz):
    if mhz == 2484:
        return 14
    if 2407 < mhz < 2484:
        return (mhz - 2407) // 5
    if 5950 < mhz <= 7125:
        return (mhz - 5950) // 5
    if 5000 <= mhz < 5950:
        return (mhz - 5000) // 5
    return None


def parse_radiotap(payload):
    """(frame, rssi, channel, fcs_error, tsft, freq) for a radiotap-wrapped
    802.11 frame, or None if the header does not hold together.

    This is what the RouterOS wireless sniffer streams (TZSP encapsulation
    126), and it sends no TZSP RSSI/channel tags: the signal and the channel
    are radiotap fields instead. All radiotap integers are little-endian and
    each field is aligned to its own size from the start of the header.

    `tsft` is the *sensor's* microsecond clock when the frame arrived, which
    is what the beacon clock check measures against (see `clock`); `freq` is
    the MHz it was heard on, which the channel-mismatch check compares with
    the channel a beacon claims.
    """
    n = len(payload)
    if n < 8 or payload[0] != 0:
        return None
    hlen = payload[2] | (payload[3] << 8)
    if hlen < 8 or hlen > n:
        return None
    present = int.from_bytes(payload[4:8], "little")
    off = 8
    word = present
    while word & RT_EXT:           # extended bitmaps: skip, only word 0 is read
        if off + 4 > hlen:
            return None
        word = int.from_bytes(payload[off:off + 4], "little")
        off += 4
    flags = 0
    rssi = channel = tsft = freq = None
    for bit, (align, size) in enumerate(RT_LAYOUT):
        if not present & (1 << bit):
            continue
        off = (off + align - 1) & ~(align - 1)
        if off + size > hlen:
            return None
        if bit == RT_TSFT:
            tsft = int.from_bytes(payload[off:off + 8], "little")
        elif bit == RT_FLAGS:
            flags = payload[off]
        elif bit == RT_CHANNEL:
            freq = payload[off] | (payload[off + 1] << 8)
            channel = freq_to_channel(freq)
        elif bit == RT_DBM_SIGNAL:
            rssi = payload[off] - 256 if payload[off] > 127 else payload[off]
        off += size
    frame = payload[hlen:]
    if flags & RT_F_FCS and len(frame) >= 4:
        frame = frame[:-4]
    return frame, rssi, channel, bool(flags & RT_F_BADFCS), tsft, freq


def channel_freq(channel, heard_freq):
    """MHz of `channel` in the band `heard_freq` is in: a channel number alone
    is ambiguous (6 GHz reuses 2.4 GHz numbers), the band it was heard in is
    not."""
    if heard_freq < 3000:
        return 2484 if channel == 14 else 2407 + 5 * channel
    if heard_freq < 5950:
        return 5000 + 5 * channel
    return 5950 + 5 * channel


def strip_radio_header(encap, payload):
    """The bare 802.11 frame, or None for an encapsulation that is not 802.11."""
    if encap == ENCAP_80211:
        return payload
    if encap == ENCAP_RADIOTAP:
        parsed = parse_radiotap(payload)
        return parsed[0] if parsed else None
    if encap == ENCAP_AVS and len(payload) >= 8:
        # AVS: magic 0x80211001, then the header length, both big-endian.
        hlen = int.from_bytes(payload[4:8], "big")
        return payload[hlen:] if 8 <= hlen < len(payload) else None
    if encap == ENCAP_PRISM and len(payload) >= 8:
        # Prism: msgcode, msglen -- host byte order of the sender, which in
        # practice is little-endian; the other order is tried before giving up.
        for order in ("little", "big"):
            hlen = int.from_bytes(payload[4:8], order)
            if 8 <= hlen <= 1024 and hlen < len(payload):
                return payload[hlen:]
        return None
    return None


# ---------------------------------------------------------------------------
# 802.11 management bodies
# ---------------------------------------------------------------------------
BROADCAST = b"\xff" * 6
SNAP_EAPOL = b"\xaa\xaa\x03\x00\x00\x00\x88\x8e"

# Management subtypes
ASSOC_REQ, REASSOC_REQ, PROBE_REQ, PROBE_RESP = 0, 2, 4, 5
BEACON, DISASSOC, AUTH, DEAUTH = 8, 10, 11, 12

IE_SSID, IE_DS, IE_RSN, IE_HT_OP, IE_VENDOR = 0, 3, 48, 61, 221

RSN_OUI = b"\x00\x0f\xac"
MS_OUI = b"\x00\x50\xf2"
WFA_OUI = b"\x50\x6f\x9a"

AKM_EAP = {1, 3, 5}
AKM_PSK = {2, 4, 6}
AKM_SAE = {8, 9, 24, 25}
AKM_EAP_192 = {12, 13}
AKM_OWE = {18}
CIPHER_TKIP = 2

# Ordinal used by wids.min_security. OWE encrypts but authenticates nobody, so
# it ranks with WPA rather than with the PSK modes.
SECURITY_RANK = {"open": 0, "wep": 1, "wpa": 2, "owe": 2, "wpa2": 3,
                 "wpa2-eap": 3, "wpa2/wpa3": 3, "wpa3": 4, "wpa3-eap": 4}

PMF_OFF, PMF_CAPABLE, PMF_REQUIRED = 0, 1, 2


def mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def parse_ies(frame, offset):
    """{element id: first body} plus every vendor element body, in order.

    Stops at the first element that runs past the end instead of failing:
    some sensors append the 4-byte FCS, which then reads as one truncated
    element, and nothing before it is any less valid for that.
    """
    ies = {}
    vendor = []
    n = len(frame)
    i = offset
    while i + 2 <= n:
        eid, length = frame[i], frame[i + 1]
        end = i + 2 + length
        if end > n:
            break
        body = frame[i + 2:end]
        if eid == IE_VENDOR:
            vendor.append(body)
        elif eid not in ies:
            ies[eid] = body
        i = end
    return ies, vendor


def _suites(body, off):
    """Read a 2-byte count and that many 4-byte suites: (list, new offset)."""
    if off + 2 > len(body):
        return [], off
    count = body[off] | (body[off + 1] << 8)
    off += 2
    out = []
    for _ in range(count):
        if off + 4 > len(body):
            break
        out.append(bytes(body[off:off + 4]))
        off += 4
    return out, off


def parse_rsn(body):
    """(group, pairwise list, akm list, capabilities) from an RSN element."""
    if len(body) < 2:
        return None
    off = 2  # version
    group = bytes(body[off:off + 4]) if off + 4 <= len(body) else b""
    off += 4
    pairwise, off = _suites(body, off)
    akms, off = _suites(body, off)
    caps = body[off] | (body[off + 1] << 8) if off + 2 <= len(body) else 0
    return group, pairwise, akms, caps


def parse_wpa(body):
    """Same tuple from the pre-standard WPA vendor element (00:50:f2, type 1)."""
    if len(body) < 6:
        return None
    off = 6  # OUI, type, version
    group = bytes(body[off:off + 4]) if off + 4 <= len(body) else b""
    off += 4
    pairwise, off = _suites(body, off)
    akms, off = _suites(body, off)
    return group, pairwise, akms, 0


def security(capability, ies, vendor):
    """What an AP says about its security, from its beacon or probe response.

    Returns (label, rank, tkip, pmf, wps). Kept pure because it is what the
    downgrade detection compares against wids.min_security, and an AP that is
    read as stronger than it is would never be reported.
    """
    rsn = parse_rsn(ies[IE_RSN]) if IE_RSN in ies else None
    wpa = wps = None
    for body in vendor:
        if body[:3] == MS_OUI and len(body) >= 4:
            if body[3] == 1 and wpa is None:
                wpa = parse_wpa(body)
            elif body[3] == 4:
                wps = True
    pmf = PMF_OFF
    tkip = False

    if rsn:
        group, pairwise, akm_suites, caps = rsn
        akms = {s[3] for s in akm_suites if s[:3] == RSN_OUI}
        tkip = any(s[:3] == RSN_OUI and s[3] == CIPHER_TKIP
                   for s in pairwise + [group])
        if caps & 0x0040:
            pmf = PMF_REQUIRED
        elif caps & 0x0080:
            pmf = PMF_CAPABLE
        if akms & AKM_EAP_192:
            label = "wpa3-eap"
        elif akms & AKM_EAP:
            # WPA3-Enterprise "only" mode is EAP-SHA256 with PMF required and
            # no legacy EAP suite offered; anything else is WPA2-Enterprise.
            only_sha256 = 5 in akms and not akms & {1, 3}
            label = "wpa3-eap" if only_sha256 and pmf == PMF_REQUIRED else "wpa2-eap"
        elif akms & AKM_SAE and akms & AKM_PSK:
            label = "wpa2/wpa3"
        elif akms & AKM_SAE:
            label = "wpa3"
        elif akms & AKM_OWE:
            label = "owe"
        else:
            label = "wpa2"
        if wpa:
            tkip = tkip or any(s[:3] == MS_OUI and s[3] == CIPHER_TKIP
                               for s in wpa[1] + [wpa[0]])
    elif wpa:
        label = "wpa"
        tkip = any(s[:3] == MS_OUI and s[3] == CIPHER_TKIP for s in wpa[1] + [wpa[0]])
    elif capability & 0x0010:
        label = "wep"
    else:
        label = "open"
    return label, SECURITY_RANK[label], tkip, pmf, bool(wps)


def ssid_text(raw):
    """A printable tag value for an SSID, or "" for a hidden one.

    SSIDs are 32 arbitrary bytes. Control characters would end up in a tag and
    in a log line, so they are replaced; a hidden network sends either a
    zero-length SSID or one made of NUL bytes, and both are "".
    """
    if not raw or not raw.strip(b"\x00"):
        return ""
    text = bytes(raw[:32]).decode("utf-8", errors="replace")
    return "".join(c if c.isprintable() else "?" for c in text)


def ap_channel(ies):
    if IE_DS in ies and len(ies[IE_DS]) >= 1:
        return ies[IE_DS][0]
    if IE_HT_OP in ies and len(ies[IE_HT_OP]) >= 1:  # 5 GHz has no DS element
        return ies[IE_HT_OP][0]
    return None


# ---------------------------------------------------------------------------
# Policy: which APs are ours
# ---------------------------------------------------------------------------
CLASS_AUTHORIZED = "authorized"
CLASS_EVIL_TWIN = "evil_twin"
CLASS_UNVERIFIED = "unverified"
CLASS_NEIGHBOR = "neighbor"
CLASS_ADHOC = "adhoc"
CLASS_DIRECT = "direct"


class Policy:
    """wids.our_ssids / wids.authorized_bssids, and what follows from them.

    `authorized_bssids` entries may end in `*` to match a prefix, because one
    physical AP usually owns a run of BSSIDs (one per SSID per radio) and
    listing each is how a list goes stale.
    """

    def __init__(self, our_ssids, authorized, min_security, require_pmf):
        self.our_ssids = set(our_ssids)
        self.exact = set()
        self.prefixes = []
        for entry in authorized:
            entry = entry.lower()
            if entry.endswith("*"):
                self.prefixes.append(entry[:-1])
            else:
                self.exact.add(entry)
        self.min_rank = SECURITY_RANK.get(min_security.lower(), 3)
        self.require_pmf = require_pmf

    @property
    def level(self):
        """0 nothing configured / 1 SSIDs only / 2 SSIDs and authorized BSSIDs."""
        if not self.our_ssids:
            return 0
        return 2 if (self.exact or self.prefixes) else 1

    def authorized(self, bssid):
        return bssid in self.exact or any(bssid.startswith(p) for p in self.prefixes)

    def classify(self, bssid, ssid, ibss):
        """The `class` tag of an AP. Pure, and covered by the selftest.

        An AP on one of our SSIDs is an evil twin only when there is a list to
        hold it against: with `wids.authorized_bssids` empty every AP of ours
        would otherwise be reported, which is how a WIDS gets switched off on
        its first day. Those read `unverified` instead, and the dashboard lists
        them so the list can be filled in from what is actually on the air.
        """
        if self.authorized(bssid):
            return CLASS_AUTHORIZED
        if ssid in self.our_ssids:
            return CLASS_EVIL_TWIN if self.level == 2 else CLASS_UNVERIFIED
        if ibss:
            return CLASS_ADHOC
        if ssid.startswith("DIRECT-"):
            return CLASS_DIRECT
        return CLASS_NEIGHBOR


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
SEVERITY_NAME = {1: "critical", 2: "high", 3: "medium", 4: "info"}

# The service's health, computed here like dns-monitor's: a value mapping can
# render the word but cannot work out which case applies.
STATE_NO_STREAM = 0
STATE_NOT_80211 = 1
STATE_INVENTORY = 2
STATE_WATCHING = 3

# Frames whose Duration/ID field has bit 15 clear carry a NAV in microseconds.
NAV_MAX = 0x8000
# An M1 still unanswered after this long is a handshake that is not coming.
EAPOL_GRACE = 5.0
CAPPED = "(capped)"
# The beacon clock check (Detector.clock): an AP unheard for longer than this
# gets a new reference rather than a jump, and a TSF below this after a jump
# backwards is a restart.
TSF_RESYNC_US = 60 * 1_000_000
TSF_RESTART_US = 3600 * 1_000_000


class WindowAP:
    """What one BSSID did in the current window."""
    __slots__ = ("ssid", "hidden", "channel", "beacons", "probe_resps", "rssi_sum",
                 "rssi_n", "security", "rank", "tkip", "pmf", "wps", "ibss",
                 "ssids", "sensor", "is_new", "mismatch")

    def __init__(self, sensor):
        self.ssid = ""
        self.hidden = False
        self.channel = None
        self.beacons = 0
        self.probe_resps = 0
        self.rssi_sum = 0
        self.rssi_n = 0
        self.security = None
        self.rank = 0
        self.tkip = False
        self.pmf = PMF_OFF
        self.wps = False
        self.ibss = False
        self.ssids = set()
        self.sensor = sensor
        self.is_new = False
        self.mismatch = 0


class Detector:
    """Everything between a parsed frame and the points of one window.

    No sockets and no clock of its own -- `now` is passed in -- so the selftest
    drives it with synthetic frames and a fake time, which is how every
    threshold below is checked both ways (fires on the attack, stays quiet on
    an ordinary AP).
    """

    def __init__(self, cfg, policy, influx, state=None):
        g = cfg.get_int
        self.policy = policy
        self.influx = influx
        self.window = max(10, g("wids.window_seconds", 60))
        self.repeat = max(0, g("wids.alert_repeat_seconds", 300))
        self.policy_repeat = max(0, g("wids.policy_repeat_seconds", 3600))
        self.max_aps = g("wids.max_aps", 2000)
        self.max_known = g("wids.max_known_aps", 20000)
        self.max_probe_ssids = g("wids.max_probe_ssids", 200)
        self.record_probes = cfg.get_bool("wids.record_probes", True)
        self.deauth_threshold = g("wids.deauth_threshold", 30)
        self.deauth_bcast_threshold = g("wids.deauth_broadcast_threshold", 5)
        self.beacon_flood = g("wids.beacon_flood_threshold", 50)
        self.karma_ssids = g("wids.karma_ssids", 5)
        self.auth_flood = g("wids.auth_flood_clients", 40)
        self.probe_flood = g("wids.probe_flood_threshold", 300)
        self.spoof_backsteps = g("wids.spoof_backsteps", 3)
        self.eapol_unanswered = g("wids.eapol_unanswered", 5)
        self.m3_retransmits = g("wids.m3_retransmits", 4)
        self.nav_us = g("wids.nav_threshold_us", 15000)
        self.nav_frames = g("wids.nav_frames", 100)
        self.track_clients = cfg.get_bool("wids.track_clients", True)
        self.known_ttl = g("wids.known_ap_days", 30) * 86400
        self.tsf_jump_us = max(1, g("wids.tsf_jump_ms", 50)) * 1000
        self.tsf_jumps_min = g("wids.tsf_jumps", 3)
        self.mismatch_mhz = g("wids.channel_mismatch_mhz", 25)
        self.mismatch_frames = g("wids.channel_mismatch_frames", 3)
        self.rssi_learn = max(1, g("wids.rssi_learn_windows", 30))
        self.rssi_shift_db = g("wids.rssi_shift_db", 15)
        self.rssi_shift_windows = g("wids.rssi_shift_windows", 3)
        self.rssi_relearn = g("wids.rssi_relearn_windows", 60)
        self.rssi_min_frames = max(1, g("wids.rssi_min_frames", 3))
        self.max_baselines = g("wids.max_baselines", 8000)
        self.sensor_silent = max(self.window, g("wids.sensor_silent_seconds", 300))
        self.sensor_forget = g("wids.sensor_forget_days", 7) * 86400

        state = state or {}
        # Persistent (survive a restart, see save_state): every BSSID ever
        # seen, so "new AP" means new and a restart is not a beacon flood; and
        # the stations seen on our own APs, for the rogue-association check.
        self.known = state.get("known", {})        # bssid -> [first, last, ssid]
        self.our_clients = state.get("clients", {})  # sta -> last seen
        # "sensor|bssid" -> [mean dBm, windows learned, deviant windows, last
        # seen]. Persisted because a baseline relearnt after every restart is
        # learnt from whatever is on the air then -- an attacker included.
        self.baselines = state.get("rssi", {})
        # sensor -> [first heard, last heard], persisted so a sensor that died
        # while this service was down is still missed when it comes back.
        self.sensor_seen = state.get("sensors", {})
        # wids.sensors are expected even before they are first heard; seeded
        # on the first flush, whose clock is the one everything else uses.
        self.expected_sensors = cfg.get_list("wids.sensors")
        self.configured_sensors = set(self.expected_sensors)
        self.sensor_quiet = set()
        self.warmup = 0 if self.known else 2       # windows to ignore new APs
        # Long-lived but not persisted: per (sensor, bssid) beacon sequence.
        self.last_seq = {}
        self.tsf = {}          # (sensor, bssid) -> (offset, beacon tsf, rx tsft)
        self.pending_m1 = {}   # (bssid, sta) -> first unanswered M1 time
        self.alert_last = {}   # (alert, bssid) -> last written time
        self.alert_held = {}   # (alert, bssid) -> count not yet written
        self.reset()

    # -- window state -------------------------------------------------------
    def reset(self):
        self.aps = {}           # bssid -> WindowAP
        self.ap_overflow = 0
        self.new_aps = 0
        self.deauth = {}        # bssid -> [total, broadcast, protected, reason, src, dst]
        self.auth = {}          # bssid -> [count, set(clients)]
        self.probes_by_src = {}  # sta -> count
        self.probe_ssids = {}    # ssid -> [count, set(clients)]
        self.backsteps = {}     # (sensor, bssid) -> count
        self.tsf_jumps = {}     # (sensor, bssid) -> count
        self.restarts = {}      # (sensor, bssid) -> beacon TSF after the restart
        self.mismatch = {}      # (sensor, bssid) -> [count, claimed, heard channel]
        self.ap_rssi = {}       # (sensor, bssid) -> [dBm sum, frames]
        self.m3 = {}            # (bssid, sta) -> count
        self.eap_ids = {}       # bssid -> cleartext non-anonymous identities
        self.nav = [0, 0]       # frames over threshold, max duration
        self.clients = {}       # bssid -> set(sta)
        self.rogue = {}         # (alert, bssid) -> (sta, ssid)
        self.channels = {}      # (sensor, channel) -> [frames, mgmt, ctrl, data,
                                #   retries, bytes, rssi_sum, rssi_n]
        self.c = dict(datagrams=0, frames=0, not_tzsp=0, wrong_encap=0,
                      fcs_errors=0, malformed=0, rssi_frames=0, channel_frames=0,
                      tsft_frames=0)
        self.sensors = set()

    # -- input --------------------------------------------------------------
    def datagram(self, sensor, data, now):
        """One UDP payload from a sensor."""
        c = self.c
        c["datagrams"] += 1
        parsed = parse_tzsp(data)
        if parsed is None:
            c["not_tzsp"] += 1
            return
        encap, rssi, channel, fcs_error, payload = parsed
        tsft = freq = None
        if encap == ENCAP_RADIOTAP:
            rt = parse_radiotap(payload)
            frame = None
            if rt is not None:
                frame, rt_rssi, rt_channel, rt_fcs_error, tsft, freq = rt
                # A TZSP tag, if a sensor sends one too, wins over radiotap.
                rssi = rssi if rssi is not None else rt_rssi
                channel = channel if channel is not None else rt_channel
                fcs_error = fcs_error or rt_fcs_error
        else:
            frame = strip_radio_header(encap, payload)
        if frame is None:
            c["wrong_encap"] += 1
            return
        self.sensors.add(sensor)
        if fcs_error:
            # A corrupt frame is the classic false positive of a WIDS: one
            # flipped bit in a BSSID is a brand-new "rogue" AP.
            c["fcs_errors"] += 1
            return
        if rssi is not None:
            c["rssi_frames"] += 1
        if channel is not None:
            c["channel_frames"] += 1
        if tsft is not None:
            c["tsft_frames"] += 1
        self.frame(sensor, frame, rssi, channel, now, freq, tsft)

    def frame(self, sensor, f, rssi, channel, now, freq=None, tsft=None):
        n = len(f)
        if n < 10:
            self.c["malformed"] += 1
            return
        self.c["frames"] += 1
        fc0, fc1 = f[0], f[1]
        ftype = (fc0 >> 2) & 3
        sub = (fc0 >> 4) & 15
        duration = f[2] | (f[3] << 8)

        ch = self.channels.get((sensor, channel))
        if ch is None:
            ch = self.channels[(sensor, channel)] = [0, 0, 0, 0, 0, 0, 0, 0]
        ch[0] += 1
        ch[1 + min(ftype, 2)] += 1
        if fc1 & 0x08:
            ch[4] += 1
        ch[5] += n
        if rssi is not None:
            ch[6] += rssi
            ch[7] += 1

        if duration < NAV_MAX and duration >= self.nav_us:
            self.nav[0] += 1
            self.nav[1] = max(self.nav[1], duration)

        if ftype == 1:  # control: nothing else to read
            return
        if n < 24:
            self.c["malformed"] += 1
            return
        a1, a2, a3 = f[4:10], f[10:16], f[16:22]
        if ftype == 0:
            self.management(sensor, f, sub, fc1, a1, a2, a3, rssi, channel, now,
                            freq, tsft)
        elif ftype == 2:
            self.data(f, sub, fc1, a1, a2, now)

    def management(self, sensor, f, sub, fc1, a1, a2, a3, rssi, channel, now,
                   freq=None, tsft=None):
        if sub in (BEACON, PROBE_RESP):
            if len(f) < 36 or a3[0] & 1:
                # A group address is never a BSSID: it is a corrupt frame the
                # FCS check did not catch, and would otherwise be a new AP.
                self.c["malformed"] += 1
                return
            bssid = mac(a3)
            ap = self.aps.get(bssid)
            if ap is None:
                if len(self.aps) >= self.max_aps:
                    self.ap_overflow += 1
                    return
                ap = self.aps[bssid] = WindowAP(sensor)
                if bssid not in self.known:
                    ap.is_new = True
                    self.new_aps += 1
            capability = f[34] | (f[35] << 8)
            ies, vendor = parse_ies(f, 36)
            name = ssid_text(ies.get(IE_SSID, b""))
            if sub == BEACON:
                ap.beacons += 1
                if not name:
                    ap.hidden = True
                seq = (f[22] | (f[23] << 8)) >> 4
                self.sequence(sensor, bssid, seq)
                if tsft is not None:
                    self.clock(sensor, bssid, int.from_bytes(f[24:32], "little"),
                               tsft)
            else:
                ap.probe_resps += 1
            if name:
                if not ap.ssid:
                    ap.ssid = name
                if len(ap.ssids) < 64:
                    ap.ssids.add(name)
            if ap.security is None:
                (ap.security, ap.rank, ap.tkip, ap.pmf,
                 ap.wps) = security(capability, ies, vendor)
                # IBSS bit set and ESS bit clear: an ad-hoc network.
                ap.ibss = bool(capability & 0x0002) and not (capability & 0x0001)
            claimed = ap_channel(ies)
            if ap.channel is None:
                ap.channel = claimed or channel
            if claimed and freq and abs(channel_freq(claimed, freq) - freq) \
                    >= self.mismatch_mhz:
                row = self.mismatch.setdefault((sensor, bssid), [0, claimed, channel])
                row[0] += 1
                ap.mismatch += 1
            if rssi is not None:
                ap.rssi_sum += rssi
                ap.rssi_n += 1
                key = (sensor, bssid)
                row = self.ap_rssi.get(key)
                if row is None:
                    row = self.ap_rssi[key] = [0, 0]
                row[0] += rssi
                row[1] += 1

        elif sub in (DEAUTH, DISASSOC):
            bssid = mac(a3)
            row = self.deauth.get(bssid)
            if row is None:
                row = self.deauth[bssid] = [0, 0, 0, None, "", ""]
            row[0] += 1
            if a1 == BROADCAST:
                row[1] += 1
            if fc1 & 0x40:
                row[2] += 1  # PMF-protected: the body is encrypted
            elif len(f) >= 26:
                row[3] = f[24] | (f[25] << 8)
            row[4], row[5] = mac(a2), mac(a1)

        elif sub in (AUTH, ASSOC_REQ, REASSOC_REQ):
            if a2 == a3:  # the AP's own half of an exchange
                return
            bssid = mac(a3)
            row = self.auth.get(bssid)
            if row is None:
                row = self.auth[bssid] = [0, set()]
            row[0] += 1
            if len(row[1]) < 4096:
                row[1].add(bytes(a2))

        elif sub == PROBE_REQ:
            src = bytes(a2)
            if src in self.probes_by_src or len(self.probes_by_src) < 10000:
                self.probes_by_src[src] = self.probes_by_src.get(src, 0) + 1
            if not self.record_probes:
                return
            ies, _ = parse_ies(f, 24)
            name = ssid_text(ies.get(IE_SSID, b""))
            if not name:
                return  # a wildcard probe names nothing
            if name not in self.probe_ssids and len(self.probe_ssids) >= self.max_probe_ssids:
                name = CAPPED
            row = self.probe_ssids.setdefault(name, [0, set()])
            row[0] += 1
            if len(row[1]) < 4096:
                row[1].add(src)

    def sequence(self, sensor, bssid, seq):
        """Count beacons whose sequence number went *backwards*.

        One transmitter's 12-bit counter only moves forward: a missed frame is
        a bigger step, never a negative one. Two transmitters with the same
        BSSID -- the real AP and somebody forging it -- interleave two counters,
        and every switch between them is a step back. Keyed per sensor too,
        because two sensors hearing the same AP deliver its beacons with
        independent jitter and would interleave them just the same.
        """
        key = (sensor, bssid)
        last = self.last_seq.get(key)
        if last is None and len(self.last_seq) >= 4 * self.max_aps:
            return
        self.last_seq[key] = seq
        if last is None:
            return
        step = (seq - last) & 0xFFF
        if step > 2048:
            self.backsteps[key] = self.backsteps.get(key, 0) + 1

    def clock(self, sensor, bssid, beacon_tsf, rx_tsft):
        """Count jumps in a BSSID's beacon clock, measured against the sensor's.

        Every beacon carries the AP's 64-bit microsecond timer (TSF), and
        radiotap's TSFT is the sensor's own timer at the moment the frame
        arrived. For one transmitter their difference is constant to well
        under a millisecond (measured: 0.1 ms spread on a RouterOS sensor);
        a second transmitter with the same BSSID has a clock of its own, so
        every switch between the two is a jump. Unlike sequence numbers this
        cannot be dodged by a forger who also counts upwards.

        A single jump *backwards* to a small TSF is the AP restarting, not a
        second transmitter, and is counted apart. A long silence resets the
        reference instead of counting: two clocks drift apart by a few ppm,
        which over an hour unheard is tens of milliseconds.
        """
        if not beacon_tsf:
            return  # an all-zero timestamp is a frame that does not fill it in
        key = (sensor, bssid)
        offset = beacon_tsf - rx_tsft
        prev = self.tsf.get(key)
        if prev is None and len(self.tsf) >= 4 * self.max_aps:
            return
        self.tsf[key] = (offset, beacon_tsf, rx_tsft)
        if prev is None:
            return
        last_offset, last_tsf, last_rx = prev
        if rx_tsft < last_rx or rx_tsft - last_rx > TSF_RESYNC_US:
            return  # the sensor's clock reset, or this BSSID was unheard
        if abs(offset - last_offset) < self.tsf_jump_us:
            return
        if beacon_tsf < last_tsf and beacon_tsf < TSF_RESTART_US:
            self.restarts[key] = beacon_tsf
            return
        self.tsf_jumps[key] = self.tsf_jumps.get(key, 0) + 1

    def data(self, f, sub, fc1, a1, a2, now):
        tods, fromds = fc1 & 0x01, fc1 & 0x02
        if tods and not fromds:
            bssid_raw, sta_raw = a1, a2
        elif fromds and not tods:
            bssid_raw, sta_raw = a2, a1
        else:
            return  # IBSS or WDS: no station-to-AP relation to read
        if sta_raw[0] & 1:
            return  # group address
        bssid, sta = mac(bssid_raw), mac(sta_raw)

        if self.track_clients:
            members = self.clients.setdefault(bssid, set())
            if len(members) < 512:
                members.add(sta)
            self.association(bssid, sta, now)

        if fc1 & 0x40:
            return  # encrypted: EAPOL is never protected during a handshake
        hdr = 24
        if sub & 0x08:  # QoS data
            hdr += 2
            if fc1 & 0x80:  # +HTC
                hdr += 4
        body = f[hdr:]
        if len(body) < 12 or body[:8] != SNAP_EAPOL:
            return
        etype = body[9]
        if etype == 3 and len(body) >= 15:
            self.eapol_key(bssid, sta, (body[13] << 8) | body[14], now)
        elif etype == 0 and len(body) >= 17:
            # EAP: code, id, length(2), type. Response(2)/Identity(1) is the
            # outer identity, which is cleartext by design.
            if body[12] == 2 and body[16] == 1:
                eap_len = (body[14] << 8) | body[15]
                ident = bytes(body[17:12 + eap_len]).decode("utf-8", "replace")
                if ident and not ident.lower().startswith(("anonymous", "@")):
                    self.eap_ids[bssid] = self.eap_ids.get(bssid, 0) + 1

    def eapol_key(self, bssid, sta, info, now):
        """Track the 4-way handshake by its key-information bits.

        M1 is Ack without MIC. A client that is really joining answers it with
        M2 within milliseconds; a PMKID harvester only wants M1 (the PMKID
        rides in it) and never answers. M3 is Ack+MIC+Install, and an AP
        repeating it over and over is either a terrible link or somebody
        replaying it, which is the KRACK shape.
        """
        ack, mic, install = info & 0x0080, info & 0x0100, info & 0x0040
        key = (bssid, sta)
        if ack and not mic:
            if len(self.pending_m1) < 10000:
                self.pending_m1.setdefault(key, now)
        elif mic and not ack:
            self.pending_m1.pop(key, None)  # M2, or M4
        elif ack and mic and install:
            self.m3[key] = self.m3.get(key, 0) + 1

    def association(self, bssid, sta, now):
        """Remember our clients; notice them on an AP that is not ours.

        Limited by MAC randomisation: modern clients use a different random
        address per SSID, so the same phone on an evil twin of *our* SSID keeps
        its address (and is caught), but on somebody else's network it is a
        different address that was never "ours". Said in the docs, not hidden.
        """
        if self.policy.authorized(bssid):
            if sta in self.our_clients or len(self.our_clients) < 20000:
                self.our_clients[sta] = int(now)
            return
        ap = self.aps.get(bssid)
        known = self.known.get(bssid)
        ssid = ap.ssid if ap else (known[2] if known else "")
        if not ssid:
            return  # an AP not heard yet this run: no basis for a verdict
        cls = self.policy.classify(bssid, ssid, ap.ibss if ap else False)
        if cls == CLASS_EVIL_TWIN:
            self.rogue[("client_on_evil_twin", bssid)] = (sta, ssid)
        elif sta in self.our_clients and cls in (CLASS_NEIGHBOR, CLASS_DIRECT,
                                                 CLASS_ADHOC):
            self.rogue[("client_on_foreign_ap", bssid)] = (sta, ssid)

    # -- output -------------------------------------------------------------
    def alert(self, now_s, ts, name, severity, bssid, count, detail,
              ssid="", source="", repeat=None, key=None):
        """Write one wids_alert point, or hold it while the last one is fresh.

        A deauth flood is fifty windows long; written every window it is fifty
        identical rows that push everything else off the Recent Alerts table.
        So one point per (alert, BSSID) per `wids.alert_repeat_seconds`, whose
        count is everything seen since the previous point for that pair.
        """
        key = (name, bssid if key is None else key)
        held = self.alert_held.pop(key, 0) + count
        last = self.alert_last.get(key)
        window = self.repeat if repeat is None else repeat
        if last is not None and now_s - last < window:
            self.alert_held[key] = held
            return False
        self.alert_last[key] = now_s
        self.influx.point("wids_alert", {
            "alert": name, "severity": str(severity),
            "severity_name": SEVERITY_NAME[severity], "bssid": bssid or "none"},
            {"count": f"{held}i", "detail": esc_str(detail),
             "ssid": esc_str(ssid), "source": esc_str(source)}, ts)
        log(f"[ALERT] sev {severity} {name} bssid={bssid or '-'} "
            f"ssid={ssid or '-'}: {detail}")
        return True

    def flush(self, now, state_code, extra=None):
        """Turn one window into points. Returns the number of alerts written.

        `extra` is merged into the health point -- the socket-level counters
        (UDP drops, refused sensors) that only the receive loop knows.
        """
        ts = time.time_ns()
        now_s = now
        fired = 0
        p = self.policy
        ours = p.our_ssids

        for bssid, ap in self.aps.items():
            cls = p.classify(bssid, ap.ssid, ap.ibss)
            prev = self.known.get(bssid)
            first = prev[0] if prev else int(now)
            if prev or len(self.known) < self.max_known:
                self.known[bssid] = [first, int(now),
                                     ap.ssid or (prev[2] if prev else "")]
            fields = {
                "beacons": f"{ap.beacons}i", "probe_resps": f"{ap.probe_resps}i",
                "clients": f"{len(self.clients.get(bssid, ()))}i",
                "pmf": f"{ap.pmf}i", "wps": f"{int(ap.wps)}i",
                "tkip": f"{int(ap.tkip)}i", "hidden": f"{int(ap.hidden)}i",
                "first_seen": f"{first}i", "ssids": f"{len(ap.ssids)}i",
                "sensor": esc_str(ap.sensor)}
            if ap.channel is not None:
                fields["channel"] = f"{ap.channel}i"
            if ap.rssi_n:
                fields["rssi"] = f"{ap.rssi_sum / ap.rssi_n:.1f}"
            base = self.baselines.get(f"{ap.sensor}|{bssid}")
            if base and base[1] >= self.rssi_learn:
                fields["rssi_baseline"] = f"{base[0]:.1f}"
            if ap.mismatch:
                fields["channel_mismatch"] = f"{ap.mismatch}i"
            self.influx.point("wids_ap", {
                "bssid": bssid, "ssid": ap.ssid or "(hidden)",
                "security": ap.security or "unknown", "class": cls}, fields, ts)

            sec = f"{ap.security}{' +TKIP' if ap.tkip else ''}"
            if cls == CLASS_EVIL_TWIN:
                fired += self.alert(
                    now_s, ts, "evil_twin", 1, bssid, ap.beacons + ap.probe_resps,
                    f"unlisted BSSID advertising our SSID ({sec}, channel "
                    f"{ap.channel}, sensor {ap.sensor})", ap.ssid, bssid)
            if ap.ssid in ours:
                if ap.rank < p.min_rank:
                    sev = 2 if cls == CLASS_AUTHORIZED else 1
                    fired += self.alert(
                        now_s, ts, "security_downgrade", sev, bssid, 1,
                        f"our SSID offered as {sec}, below the configured minimum",
                        ap.ssid, bssid, repeat=self.policy_repeat if sev == 2 else None)
                if ap.tkip:
                    fired += self.alert(
                        now_s, ts, "weak_cipher", 3, bssid, 1,
                        "our SSID still offers TKIP", ap.ssid, bssid,
                        repeat=self.policy_repeat)
                if ap.wps:
                    fired += self.alert(
                        now_s, ts, "wps_enabled", 3, bssid, 1,
                        "WPS is advertised on our SSID", ap.ssid, bssid,
                        repeat=self.policy_repeat)
                if p.require_pmf and ap.pmf != PMF_REQUIRED and ap.rank >= 3:
                    fired += self.alert(
                        now_s, ts, "pmf_not_required", 4, bssid, 1,
                        "PMF (802.11w) is " + ("optional" if ap.pmf else "off")
                        + ", so forged deauthentication frames are obeyed",
                        ap.ssid, bssid, repeat=self.policy_repeat)
            if cls == CLASS_ADHOC:
                fired += self.alert(
                    now_s, ts, "adhoc_network", 3, bssid, ap.beacons,
                    "an ad-hoc (IBSS) network is beaconing", ap.ssid, bssid,
                    repeat=self.policy_repeat)
            if len(ap.ssids) >= self.karma_ssids:
                names = ", ".join(sorted(ap.ssids)[:8])
                fired += self.alert(
                    now_s, ts, "karma", 1, bssid, len(ap.ssids),
                    f"one BSSID answered as {len(ap.ssids)} different SSIDs "
                    f"({names}) -- an AP impersonating whatever clients ask for",
                    ap.ssid, bssid)

        for (sensor, bssid), steps in self.backsteps.items():
            if steps < self.spoof_backsteps:
                continue
            ap = self.aps.get(bssid)
            ssid = ap.ssid if ap else ""
            mine = p.authorized(bssid) or ssid in ours
            fired += self.alert(
                now_s, ts, "bssid_spoof", 1 if mine else 3, bssid, steps,
                f"beacon sequence numbers stepped backwards {steps} times "
                f"(sensor {sensor}) -- two transmitters share this BSSID", ssid, bssid)

        def ours_(bssid):
            ap = self.aps.get(bssid)
            ssid = ap.ssid if ap else (self.known.get(bssid) or [0, 0, ""])[2]
            return ssid, p.authorized(bssid), ssid in ours

        for (sensor, bssid), jumps in self.tsf_jumps.items():
            if jumps < self.tsf_jumps_min:
                continue
            ssid, auth, our_ssid = ours_(bssid)
            fired += self.alert(
                now_s, ts, "tsf_spoof", 1 if auth or our_ssid else 3, bssid, jumps,
                f"beacon clock jumped {jumps} times against sensor {sensor}'s "
                "-- two transmitters with two clocks share this BSSID", ssid, bssid)

        for (sensor, bssid), tsf in self.restarts.items():
            ssid, auth, our_ssid = ours_(bssid)
            if auth or our_ssid:
                fired += self.alert(
                    now_s, ts, "ap_restart", 4, bssid, 1,
                    f"beacon clock restarted ({tsf // 1_000_000}s uptime, sensor "
                    f"{sensor})", ssid, bssid)

        for (sensor, bssid), (count, claimed, heard) in self.mismatch.items():
            if count < self.mismatch_frames:
                continue
            ssid, auth, our_ssid = ours_(bssid)
            if auth or our_ssid:
                fired += self.alert(
                    now_s, ts, "channel_mismatch", 2, bssid, count,
                    f"{count} beacons claiming channel {claimed} were heard on "
                    f"channel {heard} by sensor {sensor} -- relayed or forged",
                    ssid, bssid)

        fired += self.signal_baselines(now_s, ts, ours_)

        for bssid, (total, bcast, prot, reason, src, dst) in self.deauth.items():
            if total < self.deauth_threshold and bcast < self.deauth_bcast_threshold:
                continue
            ap = self.aps.get(bssid)
            fired += self.alert(
                now_s, ts, "deauth_flood", 2, bssid, total,
                f"{total} deauth/disassoc in {self.window}s ({bcast} broadcast, "
                f"{prot} PMF-protected); reason {reason}, last {src} -> {dst}",
                ap.ssid if ap else "", src)

        for bssid, (count, stas) in self.auth.items():
            if len(stas) < self.auth_flood:
                continue
            ap = self.aps.get(bssid)
            fired += self.alert(
                now_s, ts, "auth_flood", 2, bssid, count,
                f"{count} auth/assoc requests from {len(stas)} distinct "
                f"addresses in {self.window}s", ap.ssid if ap else "")

        if self.warmup > 0:
            self.warmup -= 1
        elif self.new_aps >= self.beacon_flood:
            fired += self.alert(
                now_s, ts, "beacon_flood", 2, "", self.new_aps,
                f"{self.new_aps} never-seen BSSIDs appeared in {self.window}s")

        for src, count in self.probes_by_src.items():
            if count >= self.probe_flood:
                fired += self.alert(
                    now_s, ts, "probe_flood", 4, "", count,
                    f"{mac(src)} sent {count} probe requests in {self.window}s "
                    "(survey or wardriving tool)", source=mac(src))

        unanswered = {}
        for key, since in list(self.pending_m1.items()):
            if now - since >= EAPOL_GRACE:
                del self.pending_m1[key]
                unanswered.setdefault(key[0], set()).add(key[1])
        for bssid, stas in unanswered.items():
            if len(stas) < self.eapol_unanswered:
                continue
            ap = self.aps.get(bssid)
            fired += self.alert(
                now_s, ts, "eapol_harvest", 2, bssid, len(stas),
                f"{len(stas)} clients took handshake message 1 and never answered "
                "-- the shape of PMKID / handshake harvesting",
                ap.ssid if ap else "", sorted(stas)[0])

        for (bssid, sta), count in self.m3.items():
            if count >= self.m3_retransmits:
                ap = self.aps.get(bssid)
                fired += self.alert(
                    now_s, ts, "m3_retransmit", 3, bssid, count,
                    f"handshake message 3 sent {count} times to {sta} -- a very "
                    "bad link, or a key-reinstallation (KRACK) attempt",
                    ap.ssid if ap else "", sta)

        for bssid, count in self.eap_ids.items():
            ap = self.aps.get(bssid)
            ssid = ap.ssid if ap else (self.known.get(bssid) or [0, 0, ""])[2]
            if ssid in ours:
                fired += self.alert(
                    now_s, ts, "eap_identity_cleartext", 4, bssid, count,
                    f"{count} EAP outer identities sent in clear (not "
                    "anonymous@realm) -- usernames readable from the air",
                    ssid, repeat=self.policy_repeat)

        if self.nav[0] >= self.nav_frames:
            fired += self.alert(
                now_s, ts, "nav_abuse", 3, "", self.nav[0],
                f"{self.nav[0]} frames reserved the medium for >= {self.nav_us} us "
                f"(max {self.nav[1]} us) -- virtual jamming")

        for (name, bssid), (sta, ssid) in self.rogue.items():
            sev = 1 if name == "client_on_evil_twin" else 3
            fired += self.alert(
                now_s, ts, name, sev, bssid, 1,
                f"station {sta} is exchanging data with "
                + ("an evil twin of our SSID" if sev == 1 else
                   "an AP that is not ours"), ssid, sta)

        for name, (count, stas) in self.probe_ssids.items():
            self.influx.point("wids_probe", {"ssid": name},
                              {"count": f"{count}i", "clients": f"{len(stas)}i"}, ts)

        for (sensor, channel), row in self.channels.items():
            frames, mgmt, ctrl, data, retries, nbytes, rsum, rn = row
            fields = {"frames": f"{frames}i", "mgmt": f"{mgmt}i", "ctrl": f"{ctrl}i",
                      "data": f"{data}i", "retries": f"{retries}i",
                      "bytes": f"{nbytes}i"}
            if rn:
                fields["rssi"] = f"{rsum / rn:.1f}"
            self.influx.point("wids_channel", {
                "sensor": sensor,
                "channel": str(channel) if channel is not None else "unknown"},
                fields, ts)

        fired += self.sensor_health(now_s, ts)

        c = self.c
        health = {
            "up": "1i", "state_code": f"{state_code}i", "policy": f"{p.level}i",
            "datagrams": f"{c['datagrams']}i", "frames": f"{c['frames']}i",
            "not_tzsp": f"{c['not_tzsp']}i", "wrong_encap": f"{c['wrong_encap']}i",
            "fcs_errors": f"{c['fcs_errors']}i", "malformed": f"{c['malformed']}i",
            "rssi_frames": f"{c['rssi_frames']}i",
            "channel_frames": f"{c['channel_frames']}i",
            "tsft_frames": f"{c['tsft_frames']}i",
            "sensors": f"{len(self.sensors)}i", "aps": f"{len(self.aps)}i",
            "new_aps": f"{self.new_aps}i", "ap_overflow": f"{self.ap_overflow}i",
            "alerts": f"{fired}i"}
        health.update(extra or {})
        self.influx.point("wids", {}, health, ts)
        self.prune(now)
        self.reset()
        return fired

    def signal_baselines(self, now_s, ts, ours_):
        """Hold each (sensor, BSSID)'s mean signal against what it usually is.

        A sensor hears a fixed AP at a steady level: fading moves single frames
        by several dB, but a window's mean barely moves. A second transmitter
        with the same BSSID is almost never in the same place, so the mean
        shifts -- and stays shifted. So the alert needs `rssi_shift_db` held
        for `rssi_shift_windows` windows in a row, and the baseline is frozen
        while it deviates, or it would learn the attacker. After
        `rssi_relearn_windows` deviant windows the new level is accepted: an
        AP that was really moved or re-antenna'd must stop alerting some day.
        Alerts only for our APs; every AP is tracked, so a policy filled in
        later has baselines already.
        """
        fired = 0
        alpha = 0.1
        for (sensor, bssid), (total, n) in self.ap_rssi.items():
            if n < self.rssi_min_frames:
                continue
            mean = total / n
            key = f"{sensor}|{bssid}"
            base = self.baselines.get(key)
            if base is None:
                if len(self.baselines) < self.max_baselines:
                    self.baselines[key] = [mean, 1, 0, int(now_s)]
                continue
            base[3] = int(now_s)
            if base[1] < self.rssi_learn:
                base[0] += (mean - base[0]) / (base[1] + 1)  # plain mean while learning
                base[1] += 1
                continue
            shift = mean - base[0]
            if abs(shift) < self.rssi_shift_db:
                base[2] = 0
                base[0] += alpha * shift
                continue
            base[2] += 1
            ssid, auth, our_ssid = ours_(bssid)
            if base[2] >= self.rssi_shift_windows and (auth or our_ssid):
                fired += self.alert(
                    now_s, ts, "rssi_shift", 2 if auth else 3, bssid, base[2],
                    f"sensor {sensor} hears this BSSID at {mean:.0f} dBm, "
                    f"{shift:+.0f} dB from its usual {base[0]:.0f} dBm, for "
                    f"{base[2]} windows -- moved, or a second transmitter",
                    ssid, bssid, key=key)
            if self.rssi_relearn and base[2] >= self.rssi_relearn:
                log(f"signal baseline of {bssid} at sensor {sensor} re-learnt: "
                    f"{base[0]:.0f} -> {mean:.0f} dBm after {base[2]} windows")
                self.baselines[key] = [mean, self.rssi_learn, 0, int(now_s)]
        return fired

    def sensor_health(self, now_s, ts):
        """One wids_sensor point per sensor ever heard, and an alert for a
        silent one.

        The global health tile only says whether *anything* arrives; with two
        sensors, one dead is half the air unwatched and the tile still reads
        WATCHING. A silent sensor is written too (frames 0, silent 1): a sensor
        missing from a table looks the same as one that never existed.
        """
        fired = 0
        per = {}
        for (sensor, channel), row in self.channels.items():
            entry = per.setdefault(sensor, [0, set()])
            entry[0] += row[0]
            if channel is not None:
                entry[1].add(channel)
        for sensor in self.expected_sensors:
            self.sensor_seen.setdefault(sensor, [now_s, now_s])
        self.expected_sensors = ()
        for sensor in self.sensors:
            seen = self.sensor_seen.get(sensor)
            if seen is None:
                if len(self.sensor_seen) >= 256:
                    continue
                seen = self.sensor_seen[sensor] = [now_s, now_s]
                log(f"new sensor {sensor}")
            seen[1] = now_s
        for sensor, (first, last) in list(self.sensor_seen.items()):
            age = now_s - last
            # Only a sensor that streamed for at least one silence window (or
            # is listed in wids.sensors) is missed when it stops: a burst --
            # the live selftest, someone trying a radio for a minute -- is
            # shown, but would otherwise alert hourly for a week.
            established = (sensor in self.configured_sensors
                           or last - first >= self.sensor_silent)
            forget = self.sensor_forget if established else 86400
            if forget and age >= forget:
                del self.sensor_seen[sensor]
                self.sensor_quiet.discard(sensor)
                log(f"sensor {sensor} forgotten after {age / 86400:.0f} days of silence")
                continue
            frames, chans = per.get(sensor, [0, set()])
            silent = age >= self.sensor_silent
            self.influx.point("wids_sensor", {"sensor": sensor}, {
                "frames": f"{frames}i", "channels": f"{len(chans)}i",
                "channel_list": esc_str(",".join(str(c) for c in sorted(chans))),
                "silent": f"{int(silent)}i", "last_seen_age": f"{int(age)}i",
                "first_seen": f"{int(first)}i"}, ts)
            if silent and established:
                if sensor not in self.sensor_quiet:
                    self.sensor_quiet.add(sensor)
                    log(f"sensor {sensor} silent for {int(age)}s")
                fired += self.alert(
                    now_s, ts, "sensor_silent", 2, "", 1,
                    f"sensor {sensor} has sent nothing for {int(age)}s -- that "
                    "part of the air is unwatched", source=sensor,
                    repeat=self.policy_repeat, key=sensor)
            elif sensor in self.sensor_quiet:
                self.sensor_quiet.discard(sensor)
                log(f"sensor {sensor} is back")
        return fired

    def prune(self, now):
        cutoff = now - self.known_ttl
        if len(self.known) > self.max_known // 2:
            for bssid in [b for b, v in self.known.items() if v[1] < cutoff]:
                del self.known[bssid]
        for sta in [s for s, t in self.our_clients.items() if t < cutoff]:
            del self.our_clients[sta]
        for key in [k for k, t in self.pending_m1.items() if now - t > 600]:
            del self.pending_m1[key]
        for key in [k for k, t in self.alert_last.items() if now - t > 86400]:
            del self.alert_last[key]
            self.alert_held.pop(key, None)
        if len(self.last_seq) > 4 * self.max_aps:
            self.last_seq.clear()
        if len(self.tsf) > 4 * self.max_aps:
            self.tsf.clear()
        for key in [k for k, v in self.baselines.items() if v[3] < cutoff]:
            del self.baselines[key]

    def state(self):
        return {"known": self.known, "clients": self.our_clients,
                "rssi": self.baselines, "sensors": self.sensor_seen}


def wids_state(now, last_datagram, datagrams, frames, silent_seconds, policy_level):
    """0 no stream / 1 stream but no 802.11 / 2 inventory only / 3 watching.

    A window with no datagram at all is *quiet*, not broken, until
    `silent_seconds` have passed since the last one: a sensor on an empty
    channel at night still hears beacons, so true silence is rare, but a
    single empty window is not worth a red tile. `last_datagram` is None until
    the first one arrives.
    """
    if last_datagram is None or now - last_datagram >= silent_seconds:
        return STATE_NO_STREAM
    if datagrams and not frames:
        return STATE_NOT_80211
    if policy_level < 2:
        return STATE_INVENTORY
    return STATE_WATCHING


# ---------------------------------------------------------------------------
# Persistence and the receive loop
# ---------------------------------------------------------------------------
def load_state(path):
    try:
        with open(path, encoding="utf-8") as fh:
            state = json.load(fh)
        return state if isinstance(state, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        log(f"state file {path} unreadable ({exc}); starting empty")
        return {}


def save_state(path, state):
    """Write-then-rename, so a kill mid-write cannot leave half a file."""
    tmp = path + ".tmp"
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)
    except OSError as exc:
        log(f"could not save state to {path}: {exc}")


# ---------------------------------------------------------------------------
# Policy control: our SSIDs and authorized BSSIDs, owned by the dashboard
# ---------------------------------------------------------------------------
# Same shape as rule-control / dns-filter / pcap-dump: Grafana cannot write,
# but the Infinity datasource fetches a URL server-side on every refresh, so a
# data link that pre-fills a dashboard variable becomes one call to /apply.
# The lists live in the wids-state volume; wids.our_ssids and
# wids.authorized_bssids only seed the very first start (optional), after
# which the dashboard owns them -- like dns_filter.categories.
LOCAL_SITE_UID = "InfluxDB_Flux"
MAX_SSIDS = 64
MAX_BSSIDS = 1024
# An exact BSSID, or a prefix ending in `*` that names at least the OUI: a
# bare `*` would authorize every transmitter on the air, which is the one
# input that switches evil-twin detection off without saying so.
BSSID_EXACT = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
BSSID_PREFIX = re.compile(r"^([0-9a-f]{2}:){2}[0-9a-f]{2}(:[0-9a-f]{0,2}){0,2}\*$")
RESERVED_SSIDS = {"(hidden)", CAPPED}


def normalize_bssid(raw):
    """(value, None) or (None, why). `-` separators and case are forgiven."""
    value = raw.strip().lower().replace("-", ":")
    if BSSID_EXACT.match(value) or BSSID_PREFIX.match(value):
        return value, None
    return None, (f"'{raw}' is not a BSSID: give aa:bb:cc:dd:ee:ff, or a prefix "
                  "of at least the first three octets ending in * (aa:bb:cc:*)")


def check_ssid(raw):
    """(value, None) or (None, why). Not stripped: a space is a valid SSID byte."""
    if not raw or not raw.strip():
        return None, "an empty SSID cannot be ours (a hidden network has no name to match)"
    if len(raw.encode("utf-8")) > 32:
        return None, f"'{raw[:40]}' is longer than 32 bytes, which no SSID can be"
    if raw in RESERVED_SSIDS:
        return None, f"'{raw}' is a placeholder on the dashboard, not a network name"
    if not raw.isprintable():
        return None, "SSID contains control characters"
    return raw, None


class PolicyStore:
    """The two lists, their persistence, and the live swap into the Detector.

    `apply` is idempotent because Grafana re-sends the boxes on every refresh:
    it writes, swaps and audits only when a list actually changes. Removes are
    applied after adds, so a value in both boxes ends up removed -- the data
    links clear the other boxes, so that only happens by hand.
    """

    def __init__(self, path, cfg, det, influx, enabled):
        self.path = path
        self.det = det
        self.influx = influx
        self.enabled = enabled
        self.min_security = cfg.get("wids.min_security", "wpa2")
        self.require_pmf = cfg.get_bool("wids.require_pmf", False)
        self.lock = threading.Lock()
        self.message = ""
        self.ssids, self.bssids = {}, {}
        state = load_state(path) if os.path.exists(path) else None
        if state is not None:
            self.ssids = dict(state.get("ssids", {}))
            self.bssids = dict(state.get("bssids", {}))
            source = "the dashboard (policy file)"
        else:
            # First start: seed from the property file, if it says anything.
            for name in cfg.get_list("wids.our_ssids"):
                value, _ = check_ssid(name)
                if value:
                    self.ssids[value] = {"since": now_iso(), "note": "seeded from properties"}
            for entry in cfg.get_list("wids.authorized_bssids"):
                value, _ = normalize_bssid(entry)
                if value:
                    self.bssids[value] = {"since": now_iso(), "note": "seeded from properties"}
            self.save()
            source = "the property file (first start)"
        self.install()
        log(f"policy from {source}: {len(self.ssids)} SSID(s), "
            f"{len(self.bssids)} BSSID(s); control "
            f"{'enabled' if enabled else 'DISABLED (read-only)'}")

    def policy(self):
        return Policy(list(self.ssids), list(self.bssids), self.min_security,
                      self.require_pmf)

    def install(self):
        # One reference assignment: the receive loop sees the old Policy or
        # the new one, never half of either.
        self.det.policy = self.policy()

    def save(self):
        save_state(self.path, {"ssids": self.ssids, "bssids": self.bssids})

    def rows(self):
        # `ssid`/`bssid` repeat the value in the column of its kind (the other
        # is empty) so the dashboard's remove link can set both boxes at once:
        # each box appears in the link exactly once, whichever kind it is.
        out = [{"kind": "SSID", "value": k, "since": v.get("since", ""),
                "note": v.get("note", ""), "ssid": k, "bssid": ""}
               for k, v in sorted(self.ssids.items())]
        out += [{"kind": "BSSID", "value": k, "since": v.get("since", ""),
                 "note": v.get("note", ""), "ssid": "", "bssid": k}
                for k, v in sorted(self.bssids.items())]
        return out

    def status(self):
        return {"control_enabled": 1 if self.enabled else 0,
                "level": self.det.policy.level, "ssids": len(self.ssids),
                "bssids": len(self.bssids), "message": self.message or "-"}

    def apply(self, add_ssid=(), remove_ssid=(), add_bssid=(), remove_bssid=(),
              note=""):
        """Returns the rows after the change. Every refusal becomes `message`."""
        wanted = [v for v in (*add_ssid, *remove_ssid, *add_bssid, *remove_bssid) if v]
        if not wanted:
            return self.rows()
        with self.lock:
            changes, problems = [], []
            note = note[:200]

            def add(table, value, limit, action):
                if value in table:
                    return
                if len(table) >= limit:
                    problems.append(f"{action}: list full ({limit})")
                    return
                table[value] = {"since": now_iso(), "note": note}
                changes.append((action, value))

            def remove(table, value, action):
                if table.pop(value, None) is not None:
                    changes.append((action, value))

            if not self.enabled:
                problems.append("wids.control_enabled = false: the lists are read-only")
            else:
                for raw in add_ssid:
                    if raw:
                        value, why = check_ssid(raw)
                        add(self.ssids, value, MAX_SSIDS, "add_ssid") if value else problems.append(why)
                for raw in add_bssid:
                    if raw:
                        value, why = normalize_bssid(raw)
                        add(self.bssids, value, MAX_BSSIDS, "add_bssid") if value else problems.append(why)
                for raw in remove_ssid:
                    if raw:
                        remove(self.ssids, raw, "remove_ssid")
                for raw in remove_bssid:
                    if raw:
                        value, _ = normalize_bssid(raw)
                        remove(self.bssids, value or raw.strip().lower(), "remove_bssid")
            if changes:
                self.save()
                self.install()
                ts = time.time_ns()
                for action, value in changes:
                    self.influx.point("wids_policy_control", {"action": action},
                                      {"count": "1i", "value": esc_str(value),
                                       "detail": esc_str(note)}, ts)
                summary = ", ".join(f"{a} {v}" for a, v in changes)
                log(f"policy: {summary}" + (f" ({note})" if note else "")
                    + f" -> {len(self.ssids)} SSID(s), {len(self.bssids)} BSSID(s)")
            if problems or changes:
                self.message = "; ".join(problems) if problems else (
                    f"{now_iso()[11:19]} UTC: " + ", ".join(f"{a.replace('_', ' ')} {v}"
                                                           for a, v in changes))
                for why in problems:
                    log(f"policy: refused: {why}")
            return self.rows()


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_local(query):
    return query.get("site", [LOCAL_SITE_UID])[0] in ("", LOCAL_SITE_UID)


def serve_control(store, port):
    """The control API: :8060, NOT published -- Grafana reaches it as wids:8060."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            local = is_local(q)
            if parsed.path in ("/apply", "/policy"):
                if not local:
                    # Another site's APs listed as this site's policy would
                    # mislead, and a click there must not change this one.
                    body = []
                elif parsed.path == "/apply":
                    body = store.apply(q.get("add_ssid", []), q.get("remove_ssid", []),
                                       q.get("add_bssid", []), q.get("remove_bssid", []),
                                       q.get("note", [""])[0])
                else:
                    body = store.rows()
            elif parsed.path == "/status":
                body = [store.status() if local else
                        {"control_enabled": 2, "level": -1, "ssids": -1,
                         "bssids": -1, "message": "another site: this one's wids is not shown"}]
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
            pass  # changes are logged by apply; reads are noise

    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def udp_drops(port):
    """Kernel receive drops on our socket, from /proc/net/udp (as tzsp-decap)."""
    needle = ":%04X" % port
    total = 0
    for proc in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            with open(proc) as fh:
                next(fh, None)
                for line in fh:
                    cols = line.split()
                    if len(cols) > 12 and cols[1].endswith(needle):
                        total += int(cols[12])
        except (OSError, ValueError):
            pass
    return total


def main():
    cfg = Config(PROPERTIES_FILE)
    if not cfg.get_bool("wids.enabled", True):
        log("wids.enabled=false: nothing to do, idling")
        while True:
            time.sleep(3600)

    sensors = set(cfg.get_list("wids.sensors"))
    silent_seconds = max(30, cfg.get_int("wids.silent_seconds", 300))
    state_path = cfg.get("wids.state_file", "/var/lib/wids/state.json")
    policy_path = os.path.join(os.path.dirname(state_path), "policy.json")

    influx = Influx(INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG, INFLUX_BUCKET)
    det = Detector(cfg, Policy([], [], "wpa2", False), influx, load_state(state_path))
    store = PolicyStore(policy_path, cfg, det, influx,
                        cfg.get_bool("wids.control_enabled", True))
    serve_control(store, CONTROL_PORT)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, RCVBUF)
    except OSError:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))
    sock.settimeout(1.0)

    policy = det.policy
    level = ["NOTHING (inventory only)", "SSIDs only (no evil-twin verdicts)",
             "SSIDs and authorized BSSIDs"][policy.level]
    log(f"listening for 802.11 TZSP on {LISTEN_ADDR}:{LISTEN_PORT}; "
        f"policy: {level}; our SSIDs={sorted(policy.our_ssids) or '-'}; "
        f"sensors={sorted(sensors) or 'any'}; window={det.window}s; "
        f"{len(det.known)} known APs")
    if not policy.our_ssids:
        log("no SSID is marked as ours yet: every AP is inventoried as a neighbour "
            "and no evil-twin, downgrade or policy alert can fire -- mark them on "
            "the Wireless IDS dashboard")

    def stop(*_):
        save_state(state_path, det.state())
        log("state saved, exiting")
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)

    start = time.monotonic()
    last_datagram = None
    next_flush = start + det.window
    saves = 0
    prev_drops = udp_drops(LISTEN_PORT)
    prev_code = None
    refused = 0

    while True:
        try:
            data, (src, _) = sock.recvfrom(65535)
        except socket.timeout:
            data = None
        except OSError as exc:
            log(f"recv error: {exc}")
            data = None
        now = time.monotonic()
        if data is not None:
            src, data = unwrap_forward(data, src)
            if sensors and src not in sensors:
                refused += 1
            else:
                last_datagram = now
                det.datagram(src or "unknown", data, time.time())

        if now < next_flush:
            continue
        next_flush = now + det.window
        frames, dg, aps = det.c["frames"], det.c["datagrams"], len(det.aps)
        code = wids_state(now, last_datagram, dg, frames, silent_seconds,
                          det.policy.level)
        drops = udp_drops(LISTEN_PORT)
        d_drops = max(0, drops - prev_drops)
        fired = det.flush(time.time(), code, {"udp_drops": f"{d_drops}i",
                                              "refused": f"{refused}i"})
        log(f"[WIDS] {dg} datagram(s), {frames} frame(s), {aps} AP(s), "
            f"{fired} alert(s) in {det.window}s | udp drops {d_drops}"
            + (f" | {refused} from sensors not in wids.sensors" if refused else ""))
        prev_drops, refused = drops, 0
        if code != prev_code:
            if code == STATE_NO_STREAM:
                log(f"no 802.11 TZSP for {silent_seconds}s: check the sensor streams "
                    "to <this host>:37008, the host firewall, and the '802.11 to' "
                    "count in `docker compose logs tzsp-decap`")
            elif code == STATE_NOT_80211:
                log("datagrams arrive but none is 802.11: something is sending "
                    "Ethernet TZSP to this port directly -- only tzsp-decap should")
            prev_code = code
        saves += 1
        if saves * det.window >= 300:
            save_state(state_path, det.state())
            saves = 0


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        log(f"fatal: {exc}")
        sys.exit(1)
