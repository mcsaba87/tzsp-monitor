#!/usr/bin/env python3
"""Poll a Cisco ASA's capture buffer and feed it to tzsp-monitor as TZSP.

The ASA cannot stream a mirror, but it can keep a capture in a circular buffer
and hand it out as a pcap over HTTPS. This script downloads that buffer every
few seconds, keeps only the packets it has not sent before, and sends each one
as a TZSP datagram to tzsp-monitor's UDP 37008 -- exactly what a MikroTik
sniffer would send, so nothing in tzsp-monitor needs to change.

    ASA  capture (circular buffer)
      ^  HTTPS GET /admin/capture/<name>/pcap        every few seconds
    this script  (only packets newer than the last poll)
      -> TZSP/UDP -> tzsp-monitor:37008

Python 3.8+, standard library only. Edit the CONFIG section below, then:

    python3 asa-capture-tzsp.py              # run for ever
    python3 asa-capture-tzsp.py --once       # one poll, then exit
    python3 asa-capture-tzsp.py --dry-run    # download and report, send nothing
    python3 asa-capture-tzsp.py --show-cert  # print the ASA certificate's SHA-256

------------------------------------------------------------------------------
ASA side (once; adapt names and addresses)
------------------------------------------------------------------------------
    ! HTTPS management for the host running this script only
    http server enable
    http <poller-ip> 255.255.255.255 <interface the poller reaches>
    aaa authentication http console LOCAL
    username tzsp-poll password <secret> privilege 15

    ! Leave the poller's own downloads OUT of the capture -- otherwise every
    ! 32 MB download is captured and the buffer fills with copies of itself.
    access-list CAP-IDS extended deny tcp host <poller-ip> host <asa-ip> eq https
    access-list CAP-IDS extended deny tcp host <asa-ip> eq https host <poller-ip>
    access-list CAP-IDS extended permit ip any4 any4

    ! The capture. VPN users' decrypted traffic (with their pool addresses) is
    ! normally visible on the interface the tunnel terminates on; check with
    ! `show capture IDS` while a VPN client browses, and use `inside` instead if
    ! only that shows it. A narrower access-list (e.g. the VPN pool only) is how
    ! to stay under the throughput ceiling below.
    capture IDS type raw-data access-list CAP-IDS buffer 33554432 circular-buffer packet-length 1522 interface outside

  Try the download by hand first:
    curl -k -u tzsp-poll:<secret> -o t.pcap https://<asa>/admin/capture/IDS/pcap
    tcpdump -r t.pcap -e -c 5
  (older ASA releases serve /capture/IDS/pcap instead; see CAPTURE_PATH)

------------------------------------------------------------------------------
tzsp-monitor side
------------------------------------------------------------------------------
  Nothing to change for Suricata, dns-monitor, pcap-dump and arp-watch: they
  read tzsp-decap's tap, wherever the TZSP came from. The host firewall must
  let this script's datagrams in on 37008/udp.

  The collector (flow panels) is different: it sniffs a NIC (SNIFF_INTERFACE)
  and decodes the TZSP it sees there. If this script runs on ANOTHER host, the
  datagrams arrive on the monitor's NIC and the collector sees them. If it runs
  on the monitor host itself, they never cross a NIC -- not even when sent to
  the host's own LAN address -- so the flow panels stay empty unless the
  collector is moved onto the tap, as docker-compose.vxlan.yml does
  (`network_mode: service:tzsp-decap`, SNIFF_INTERFACE=tzsp0).

------------------------------------------------------------------------------
Limits worth knowing
------------------------------------------------------------------------------
  * Ceiling: a 32 MB buffer polled every 5 s holds about 50 Mbit/s of captured
    traffic, less once the download time counts. More than that and the buffer
    wraps between two polls: the script says so ("OVERRUN ... lost") and how
    many seconds were missed. Narrow the capture's access-list rather than
    poll faster.
  * Delay: packets reach Suricata up to one poll interval (plus the download)
    after the ASA saw them, and are re-sent at the pace below rather than with
    their original spacing. Flow durations are already meaningless in
    tzsp-monitor; alert times are late by that delay.
  * Load: every captured packet costs ASA CPU, and every poll is a download
    of up to the whole buffer from its management plane. Watch `show cpu`.
  * The ASA's clock stamps the packets; turn NTP on there. Duplicate removal
    only needs the ASA's clock to move forward, not to agree with this host's.
"""

# =============================================================================
# CONFIG -- everything this script needs. No environment, no other file.
# =============================================================================

# The ASA's management address, as https://host[:port]. Required.
ASA_URL = ""                    # e.g. "https://192.0.2.1" or "https://asa.example.net:8443" (https:// may be left out)

# The local user the script logs in as (see "ASA side" above). Required.
ASA_USER = ""                   # e.g. "tzsp-poll"
ASA_PASSWORD = ""               # e.g. "s3cret" -- keep this file chmod 600

# The capture's name on the ASA (`capture <name> ...`).
CAPTURE_NAME = "IDS"

# Where the ASA serves it. {name} is replaced by CAPTURE_NAME. Redirects are
# followed (9.x sends /admin/... on to /gadmin/...), and the form login that
# newer releases put in front of it is done for you.
CAPTURE_PATH = "/admin/capture/{name}/pcap"
# Older releases:  CAPTURE_PATH = "/capture/{name}/pcap"

# The ASA's certificate is normally self-signed, so it is PINNED rather than
# verified against a CA: the SHA-256 of the certificate the ASA presents. Get
# it with `python3 asa-capture-tzsp.py --show-cert` (after checking, on the
# ASA's console, that it is the ASA you are talking to). Empty refuses to run
# unless INSECURE_SKIP_TLS_CHECK is True.
CERT_SHA256 = ""                # e.g. "3f:a1:...:9c" (colons and case don't matter)
# True verifies the certificate against the system CAs instead (an ASA with a
# real certificate whose name matches ASA_URL).
VERIFY_WITH_CA = False
# Last resort, for a first test only: no certificate check at all. The
# password then goes to whoever answers on ASA_URL.
INSECURE_SKIP_TLS_CHECK = False

# tzsp-monitor: the host running tzsp-decap, and its published TZSP port.
# Required. Use the monitor's LAN address even when this script runs on the
# monitor host itself: 127.0.0.1 goes through Docker's userland UDP proxy,
# which was measured to lose ~5% of a 20,000 pps burst (the LAN address goes
# through the kernel's NAT and lost nothing at the same rate).
DEST_HOST = ""                  # e.g. "10.0.0.20" (see "tzsp-monitor side" above)
DEST_PORT = 37008

# The capture's buffer size on the ASA (`buffer` in the capture command), in
# bytes. Only used to choose the poll interval.
BUFFER_BYTES = 33554432

# Polling. The interval adapts so the buffer is about half full at each poll,
# between these two bounds (seconds).
MIN_INTERVAL = 5
MAX_INTERVAL = 60

# On the very first start (no state file yet), forward only this many seconds
# of what the buffer already holds, so a full buffer of old traffic does not
# reach Suricata as if it were new. 0 forwards nothing old at all.
START_WINDOW_SECONDS = 60

# Send rate cap, packets per second, so a poll's worth of packets does not
# arrive at tzsp-decap in one burst it has to drop. 0 = as fast as possible.
PACE_PPS = 20000

# The high-water mark (what was already sent) survives restarts here, so a
# restart neither re-sends nor skips anything still in the buffer. A relative
# path is relative to this script's directory.
STATE_FILE = "asa-capture-state.json"

# How many times a refused login is retried within one poll once the login
# has worked before (a real ASA sometimes shows its form again at random).
LOGIN_RETRIES = 3

# HTTP timeout, seconds: how long the ASA may stay silent mid-download, not
# the whole download (a full 32 MB buffer took 71 s over a 4 Mbit/s VPN link).
HTTP_TIMEOUT = 60

# Optional: write an `asa_capture` point per poll to tzsp-monitor's InfluxDB,
# so the pipeline can be watched from Grafana. Empty = off.
INFLUX_URL = ""                 # e.g. "http://10.0.0.20:8086"
INFLUX_TOKEN = "my-super-secret-token"
INFLUX_ORG = "my-org"
INFLUX_BUCKET = "network_traffic"

# =============================================================================
# End of CONFIG
# =============================================================================

import argparse
import base64
import hashlib
import http.client
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime

PCAP_MAGICS = (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
               b"\xa1\xb2\x3c\x4d")
TZSP_HEADER = b"\x01\x00\x00\x01\x01"   # v1, received, encap Ethernet, TAG_END
IP_MTU_DISCOVER, IP_PMTUDISC_DONT = 10, 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = (101, 228, 229, 12, 14)   # raw IP / IPv4 / IPv6 (and BSD aliases)
STATE_PATH = (STATE_FILE if os.path.isabs(STATE_FILE)
              else os.path.join(os.path.dirname(os.path.abspath(__file__)), STATE_FILE))


def log(msg):
    print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)


class Fatal(Exception):
    """A configuration problem: retrying will not fix it."""


# -----------------------------------------------------------------------------
# HTTPS with a pinned certificate
# -----------------------------------------------------------------------------
def norm_fp(text):
    return "".join(c for c in text.lower() if c in "0123456789abcdef")


def parse_url():
    text = ASA_URL.strip()
    if "://" not in text:
        text = "https://" + text          # a bare host or IP is fine
    url = urllib.parse.urlparse(text)
    if url.scheme != "https" or not url.hostname:
        raise Fatal("ASA_URL must look like https://host[:port]")
    return url.hostname, url.port or 443


class Asa:
    """One kept-alive HTTPS connection; the certificate is checked on every
    (re)connect, before the password is sent."""

    def __init__(self):
        self.host, self.port = parse_url()
        self.conn = None
        if VERIFY_WITH_CA:
            self.ctx = ssl.create_default_context()
        else:
            if not CERT_SHA256 and not INSECURE_SKIP_TLS_CHECK:
                raise Fatal("CERT_SHA256 is empty: run with --show-cert and pin it "
                            "(or set INSECURE_SKIP_TLS_CHECK = True for a first test)")
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        # Old ASA images speak only older TLS/ciphers; allow what Python allows.
        try:
            self.ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        except ssl.SSLError:
            pass
        self.auth = "Basic " + base64.b64encode(
            f"{ASA_USER}:{ASA_PASSWORD}".encode()).decode()

    def connect(self):
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=HTTP_TIMEOUT,
                                           context=self.ctx)
        conn.connect()
        if not VERIFY_WITH_CA and CERT_SHA256:
            der = conn.sock.getpeercert(binary_form=True)
            got = hashlib.sha256(der).hexdigest()
            if got != norm_fp(CERT_SHA256):
                conn.close()
                raise Fatal(f"certificate fingerprint mismatch: the ASA presented "
                            f"{fmt_fp(got)}, CERT_SHA256 is {CERT_SHA256}")
        self.conn = conn

    def request(self, method, path, body=None, extra=None):
        """(status, headers, body) over the kept-alive connection, with one
        fresh retry for a connection the ASA closed in between."""
        headers = {"Authorization": self.auth, "Connection": "keep-alive",
                   "User-Agent": "tzsp-monitor asa-capture-tzsp"}
        headers.update(extra or {})
        for attempt in (1, 2):
            if self.conn is None:
                self.connect()
            try:
                self.conn.request(method, path, body=body, headers=headers)
                resp = self.conn.getresponse()
                data = resp.read()
            except (http.client.HTTPException, OSError):
                self.close()
                if attempt == 2:
                    raise
                continue
            if (resp.getheader("Connection") or "").lower() == "close":
                self.close()
            return resp.status, resp, data
        raise OSError("unreachable")

    def form_login(self, path, form_page):
        """POST the login form; (status, data) with the pcap.

        A real ASA sometimes answers a correct login with its form again --
        seen minutes apart between successful polls, same credentials, so it
        is the ASA (its web session table, a token it dropped), not the
        password. So once a login has worked, a re-shown form is retried on a
        fresh connection with a fresh token, and if that keeps failing it is
        an ordinary poll failure (retried with back-off), never fatal. Only a
        login that has NEVER worked since start is reported as a
        configuration problem."""
        page = form_page
        for attempt in range(1, LOGIN_RETRIES + 2):
            token = re.search(rb'name=["\']?csrf_token["\']?[^>]*value=["\']?([^"\' >]+)',
                              page, re.I)
            form = urllib.parse.urlencode({"username": ASA_USER, "password": ASA_PASSWORD,
                                           "csrf_token": token.group(1).decode() if token
                                           else ""})
            status, resp, data = self.request(
                "POST", path, body=form,
                extra={"Content-Type": "application/x-www-form-urlencoded"})
            refused = (status == 200 and data[:4] not in PCAP_MAGICS
                       and b"Authorization Required" in data)
            if not refused:
                if attempt > 1:
                    log(f"login accepted on attempt {attempt}")
                self.logins_ok = getattr(self, "logins_ok", 0) + 1
                return status, data
            if not getattr(self, "logins_ok", 0):
                raise Fatal("login refused (the ASA showed its login form again): check "
                            "ASA_USER/ASA_PASSWORD, `aaa authentication http console "
                            "LOCAL` and the user's privilege")
            if attempt > LOGIN_RETRIES:
                break
            log(f"the ASA showed its login form again although the login has worked "
                f"before (attempt {attempt}/{LOGIN_RETRIES + 1}); retrying with a fresh "
                "connection and token")
            self.close()
            time.sleep(attempt)
            status, resp, page = self.request("GET", path)
            if status == 200 and page[:4] in PCAP_MAGICS:
                return status, page          # it let us straight in this time
        raise OSError("the ASA kept showing its login form (it has accepted this login "
                      "before, so this is the ASA, not the password)")

    def download(self):
        """The capture as bytes. Raises Fatal for what retrying cannot fix.

        Two ASA behaviours are handled, both seen on a real 9.x box:
          * /admin/capture/<name>/pcap answers 301 to /gadmin/capture/... --
            the redirect is followed (same host only) and remembered;
          * HTTP Basic alone is not accepted there: the ASA answers 200 with
            an "Authorization Required" form (username, password, csrf_token)
            and sends the pcap as the answer to posting it. No session cookie
            is set, so every poll is a GET for the token plus the POST.
        A request without any Authorization header gets a bare 400, which is
        why Basic is still sent on every request."""
        path = getattr(self, "path", None) or CAPTURE_PATH.format(
            name=urllib.parse.quote(CAPTURE_NAME, safe=""))
        for _ in range(4):
            status, resp, data = self.request("GET", path)
            if status in (301, 302, 303, 307, 308):
                target = urllib.parse.urlparse(resp.getheader("Location") or "")
                if not target.path or (target.hostname and target.hostname != self.host):
                    raise Fatal(f"{path} redirects to {resp.getheader('Location')!r}, "
                                "which is not a path on this ASA")
                log(f"{path} redirects to {target.path}; using that")
                path = target.path
                continue
            break
        else:
            raise Fatal(f"too many redirects from {path}")
        if status == 200 and data[:4] not in PCAP_MAGICS and b"csrf_token" in data:
            status, data = self.form_login(path, data)
            if getattr(self, "method", "") != "form":
                log(f"the ASA wants a form login at {path}; doing that on every poll")
            self.method = "form"
        if status in (401, 403):
            raise Fatal(f"login refused (HTTP {status}): check ASA_USER/"
                        "ASA_PASSWORD, `aaa authentication http console LOCAL` "
                        "and the user's privilege")
        if status == 404:
            raise Fatal(f"HTTP 404 for {path}: no capture named {CAPTURE_NAME!r} "
                        "(`show capture` on the ASA lists them)")
        if status != 200:
            raise OSError(f"HTTP {status} for {path}")
        self.path = path
        return data

    def close(self):
        if self.conn is not None:
            try:
                self.conn.close()
            except OSError:
                pass
        self.conn = None


def fmt_fp(hexdigest):
    return ":".join(hexdigest[i:i + 2] for i in range(0, len(hexdigest), 2))


def show_cert():
    host, port = parse_url()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
    except ssl.SSLError:
        pass
    with socket.create_connection((host, port), timeout=15) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
    print(f"{host}:{port} presents a certificate with SHA-256\n"
          f"  {fmt_fp(hashlib.sha256(der).hexdigest())}\n"
          "Compare it with the ASA's own view before pinning it, e.g.\n"
          "  show crypto ca certificates   /   show ssl\n"
          "then put it in CERT_SHA256.")


# -----------------------------------------------------------------------------
# pcap
# -----------------------------------------------------------------------------
def parse_pcap(data):
    """(linktype, [(ts_ns, frame bytes, truncated)]) from a classic pcap.

    Both byte orders and both timestamp resolutions are read; pcapng is
    refused with a clear message rather than misread."""
    if len(data) < 24:
        if not data:
            return LINKTYPE_ETHERNET, []
        raise ValueError(f"{len(data)} bytes is not a pcap file")
    magic = data[:4]
    table = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
             b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
    if magic == b"\x0a\x0d\x0d\x0a":
        raise ValueError("the ASA sent pcapng; this script reads classic pcap only")
    if magic not in table:
        snippet = data[:60].decode("latin-1", "replace").replace("\n", " ")
        raise ValueError(f"not a pcap file (starts {snippet!r}): an error page?")
    endian, unit = table[magic]
    linktype = struct.unpack(endian + "I", data[20:24])[0] & 0x0FFFFFFF
    out = []
    rec = struct.Struct(endian + "IIII")
    off, end = 24, len(data)
    while off + 16 <= end:
        sec, frac, caplen, origlen = rec.unpack_from(data, off)
        off += 16
        if caplen > 262144 or off + caplen > end:
            break                           # a torn tail: stop, keep what parsed
        out.append((sec * 1_000_000_000 + frac * unit, data[off:off + caplen],
                    caplen < origlen))
        off += caplen
    return linktype, out


def to_ethernet(linktype, frame):
    """An Ethernet frame for TZSP encapsulation 1, or None."""
    if linktype == LINKTYPE_ETHERNET:
        return frame
    if linktype in LINKTYPE_RAW and frame:
        version = frame[0] >> 4
        ethertype = b"\x08\x00" if version == 4 else b"\x86\xdd" if version == 6 else None
        if ethertype is None:
            return None
        # Locally administered placeholder MACs: there is no Ethernet header
        # on the wire to report, and arp-watch/the collector key on IPs anyway.
        return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + ethertype + frame
    return None


def digest(ts_ns, frame):
    return hashlib.sha1(ts_ns.to_bytes(8, "big") + frame).hexdigest()[:16]


# -----------------------------------------------------------------------------
# State: what has been sent
# -----------------------------------------------------------------------------
def load_state():
    try:
        with open(STATE_PATH) as fh:
            s = json.load(fh)
        return {"hwm": int(s.get("hwm", 0)), "at_hwm": list(s.get("at_hwm", [])),
                "asa": s.get("asa", "")}
    except (OSError, ValueError):
        return None


def save_state(state):
    tmp = STATE_PATH + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(state, fh)
    os.replace(tmp, STATE_PATH)


def select_new(packets, state, first_start):
    """The packets not sent yet, plus what the poll found out.

    The high-water mark is the newest timestamp already sent, with the digests
    of the packets carrying exactly that timestamp -- an ASA stamps in
    microseconds, so two packets can share one, and a boundary between polls
    can fall between them. Strictly newer is new; equal is new unless its
    digest was sent. If the OLDEST packet in the buffer is newer than the mark,
    the buffer wrapped between two polls: whatever was in between is gone."""
    packets = sorted(packets, key=lambda p: p[0])     # stable: buffer order kept
    info = {"overrun_s": 0.0, "old": 0}
    if not packets:
        return [], info
    hwm, at_hwm = state["hwm"], set(state["at_hwm"])
    if first_start:
        newest = packets[-1][0]
        floor = newest - START_WINDOW_SECONDS * 1_000_000_000
        new = [p for p in packets if p[0] > floor] if START_WINDOW_SECONDS > 0 else []
        info["old"] = len(packets) - len(new)
        return new, info
    if hwm and packets[0][0] > hwm:
        info["overrun_s"] = (packets[0][0] - hwm) / 1e9
    new = [p for p in packets
           if p[0] > hwm or (p[0] == hwm and digest(p[0], p[1]) not in at_hwm)]
    return new, info


def advance(state, sent):
    if not sent:
        return
    top = sent[-1][0]
    if top > state["hwm"]:
        state["hwm"], state["at_hwm"] = top, []
    marks = set(state["at_hwm"])
    marks.update(digest(ts, f) for ts, f, _ in sent if ts == top)
    state["at_hwm"] = sorted(marks)


# -----------------------------------------------------------------------------
# Sending
# -----------------------------------------------------------------------------
class Sender:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # TZSP adds 5 bytes plus IP/UDP: a full-size frame no longer fits a
        # 1500 MTU. Let the kernel fragment rather than refuse it.
        try:
            self.sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
        except OSError:
            pass
        self.addr = None
        self.resolve()

    def resolve(self):
        try:
            self.addr = (socket.gethostbyname(DEST_HOST), DEST_PORT)
        except OSError as exc:
            log(f"cannot resolve DEST_HOST {DEST_HOST!r}: {exc}")

    def send(self, frames):
        """(sent, errors). Paced in 10 ms slices."""
        if self.addr is None:
            self.resolve()
            if self.addr is None:
                return 0, len(frames)
        sent = errors = 0
        per_slice = max(1, PACE_PPS // 100) if PACE_PPS > 0 else len(frames) or 1
        slice_start = time.monotonic()
        for i, frame in enumerate(frames):
            try:
                self.sock.sendto(TZSP_HEADER + frame, self.addr)
                sent += 1
            except OSError:
                errors += 1
            if PACE_PPS > 0 and (i + 1) % per_slice == 0:
                spare = 0.01 - (time.monotonic() - slice_start)
                if spare > 0:
                    time.sleep(spare)
                slice_start = time.monotonic()
        return sent, errors


def influx_point(fields):
    if not INFLUX_URL:
        return
    line = "asa_capture,capture=" + CAPTURE_NAME.replace(" ", "\\ ").replace(",", "\\,") + " " + \
        ",".join(f"{k}={v}" for k, v in fields.items())
    url = (f"{INFLUX_URL.rstrip('/')}/api/v2/write?org={urllib.parse.quote(INFLUX_ORG)}"
           f"&bucket={urllib.parse.quote(INFLUX_BUCKET)}&precision=s")
    req = urllib.request.Request(url, data=line.encode(), method="POST",
                                 headers={"Authorization": f"Token {INFLUX_TOKEN}",
                                          "Content-Type": "text/plain"})
    try:
        urllib.request.urlopen(req, timeout=5).close()
    except (urllib.error.URLError, OSError) as exc:
        log(f"influx write failed: {exc}")


# -----------------------------------------------------------------------------
def check_config(sending=True):
    required = [("ASA_URL", ASA_URL), ("ASA_USER", ASA_USER), ("ASA_PASSWORD", ASA_PASSWORD)]
    if sending:
        required.append(("DEST_HOST", DEST_HOST))
    missing = [n for n, v in required if not v]
    if missing:
        raise Fatal("set " + ", ".join(missing) + " in the CONFIG section at the top")
    if not 1 <= MIN_INTERVAL <= MAX_INTERVAL:
        raise Fatal("need 1 <= MIN_INTERVAL <= MAX_INTERVAL")


def poll(asa, sender, state, first_start, dry_run):
    started = time.monotonic()
    data = asa.download()
    dl_ms = (time.monotonic() - started) * 1000.0
    linktype, packets = parse_pcap(data)
    new, info = select_new(packets, state, first_start)
    frames, unusable, truncated = [], 0, 0
    for ts, frame, cut in new:
        eth = to_ethernet(linktype, frame)
        if eth is None:
            unusable += 1
            continue
        truncated += cut
        frames.append(eth)
    sent = errors = 0
    if frames and not dry_run:
        sent, errors = sender.send(frames)
    advance(state, new)        # in memory; a dry run only skips saving it
    span = (packets[-1][0] - packets[0][0]) / 1e9 if len(packets) > 1 else 0.0
    return {"bytes": len(data), "packets": len(packets), "new": len(new), "sent": sent,
            "errors": errors, "unusable": unusable, "truncated": truncated,
            "linktype": linktype, "span_s": span, "download_ms": dl_ms,
            "new_bytes": sum(len(p[1]) + 16 for p in new), **info}


def next_interval(stats, elapsed):
    """Half a buffer between polls, at the rate the buffer is filling."""
    if elapsed <= 0 or stats["new_bytes"] <= 0:
        return MAX_INTERVAL
    rate = stats["new_bytes"] / elapsed                 # bytes/s into the buffer
    return max(MIN_INTERVAL, min(MAX_INTERVAL, (BUFFER_BYTES * 0.5) / rate))


def main():
    ap = argparse.ArgumentParser(description="Poll an ASA capture, send it as TZSP.")
    ap.add_argument("--once", action="store_true", help="one poll, then exit")
    ap.add_argument("--dry-run", action="store_true",
                    help="download and report; send nothing, change no state")
    ap.add_argument("--show-cert", action="store_true",
                    help="print the ASA certificate's SHA-256 and exit")
    args = ap.parse_args()
    try:
        if args.show_cert:
            show_cert()
            return 0
        check_config(sending=not args.dry_run)
        asa = Asa()
        sender = None if args.dry_run else Sender()
    except (Fatal, OSError) as exc:
        log(f"fatal: {exc}")
        return 2
    saved = load_state()
    asa_id = f"{asa.host}:{asa.port}/{CAPTURE_NAME}"
    first_start = saved is None or saved.get("asa") != asa_id
    state = saved if not first_start else {"hwm": 0, "at_hwm": [], "asa": asa_id}
    log(f"polling {asa_id} -> TZSP {DEST_HOST or '(nowhere)'}:{DEST_PORT}, every {MIN_INTERVAL}-"
        f"{MAX_INTERVAL}s, pace {PACE_PPS or 'unlimited'} pps"
        + (", DRY RUN" if args.dry_run else "")
        + (f", first start: last {START_WINDOW_SECONDS}s of the buffer only"
           if first_start else ", resuming from the saved position"))
    interval, last_poll, failures, polls = MIN_INTERVAL, None, 0, 0
    while True:
        now = time.monotonic()
        try:
            stats = poll(asa, sender, state, first_start, args.dry_run)
        except Fatal as exc:
            log(f"fatal: {exc}")
            return 2
        except (OSError, ValueError, http.client.HTTPException, ssl.SSLError) as exc:
            failures += 1
            asa.close()
            wait = min(MAX_INTERVAL, MIN_INTERVAL * (2 ** min(failures, 4)))
            log(f"poll failed ({exc}); retrying in {wait:.0f}s")
            influx_point({"up": "0i", "error": json.dumps(str(exc)[:200])})
            if args.once:
                return 1
            time.sleep(wait)
            continue
        failures = 0
        resumed = polls == 0 and not first_start
        polls += 1
        elapsed = (now - last_poll) if last_poll is not None else 0.0
        last_poll = now
        if not args.dry_run:
            save_state(state)
            if first_start:
                state["asa"] = asa_id
                save_state(state)
        fill = 100.0 * stats["bytes"] / BUFFER_BYTES if BUFFER_BYTES else 0.0
        note = ""
        if stats["overrun_s"] > 0 and resumed:
            note += (f" | resumed after a stop: ~{stats['overrun_s']:.1f}s of traffic "
                     "was never captured")
        elif stats["overrun_s"] > 0:
            note += f" | OVERRUN: buffer wrapped, ~{stats['overrun_s']:.1f}s lost"
        if first_start and stats["old"]:
            note += f" | {stats['old']} older packet(s) skipped (START_WINDOW_SECONDS)"
        if stats["unusable"]:
            note += (f" | {stats['unusable']} packet(s) not forwardable "
                     f"(pcap linktype {stats['linktype']})")
        if stats["errors"]:
            note += f" | {stats['errors']} send error(s)"
        log(f"[ASA] {stats['packets']} pkt in buffer ({stats['bytes'] / 1e6:.1f} MB, "
            f"{fill:.0f}% of {BUFFER_BYTES / 1e6:.0f} MB, {stats['span_s']:.0f}s) | "
            f"{stats['new']} new, {stats['sent']} sent | download "
            f"{stats['download_ms']:.0f} ms{note}")
        if stats["truncated"]:
            log(f"      {stats['truncated']} frame(s) truncated by the capture's "
                "packet-length; Suricata sees only their first bytes")
        influx_point({"up": "1i", "buffer_packets": f"{stats['packets']}i",
                      "buffer_bytes": f"{stats['bytes']}i", "fill_percent": f"{fill:.1f}",
                      "new_packets": f"{stats['new']}i", "sent": f"{stats['sent']}i",
                      "send_errors": f"{stats['errors']}i",
                      "overrun_seconds": f"{stats['overrun_s']:.1f}",
                      "unusable": f"{stats['unusable']}i",
                      "truncated": f"{stats['truncated']}i",
                      "download_ms": f"{stats['download_ms']:.0f}",
                      "interval_s": f"{interval:.0f}", "error": '""'})
        first_start = False
        if args.once:
            return 0
        if elapsed > 0:
            interval = next_interval(stats, elapsed)
        if stats["overrun_s"] > 0 and not resumed:
            interval = MIN_INTERVAL
        if sender is not None:
            sender.resolve()            # tzsp-monitor may have moved
        time.sleep(max(0.0, interval - (time.monotonic() - now)))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
