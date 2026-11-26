"""Strip the TZSP tunnel off the mirror stream and hand the inner frames to Suricata.

Suricata has decoders for GRE, ERSPAN, VXLAN, GENEVE and Teredo, but *not* for
TZSP, so it cannot read the Mikrotik mirror stream directly: every packet would
look like one UDP datagram to port 37008 and no rule would ever match. This
service therefore does the decapsulation itself:

    router --TZSP/UDP 37008--> [this service] --inner Ethernet--> tap tzsp0
                                                                    ^
                                                       Suricata sniffs here

The inner frames are injected into a TAP device. Writing a frame to a TAP file
descriptor makes the kernel treat it as *received* on that interface, which is
exactly what an AF_PACKET sniffer such as Suricata wants to see.

Two design points worth keeping:

* **The tap must live in an isolated network namespace, not the host's.**
  Injected frames are handed to the local IP stack of whatever namespace the tap
  is in. Mirrored broadcast/multicast traffic (ARP, DHCP, mDNS, SSDP) from the
  monitored network would then be delivered to any service listening on 0.0.0.0
  there, and the stack would try to answer ARP for its own addresses. In
  docker-compose this container keeps its own namespace and Suricata joins it
  with `network_mode: "service:tzsp-decap"`, so the mirror can never reach the
  host. The tap deliberately gets no IP address and is never read from, so
  nothing the kernel emits on it can escape either.

* **This is the throughput bottleneck of the IDS path.** It is one Python loop
  doing recv + write per packet, so it is written to allocate nothing per
  packet: a single preallocated buffer, `recv_into`, and a memoryview slice
  handed straight to `os.write`. UDP receive drops are reported from
  /proc/net/udp (out-of-band, zero per-packet cost) because a silently dropping
  receiver makes the IDS blind without any other symptom.

* **802.11 arriving here is passed on to `wids`, not dropped.** The RouterOS
  wireless sniffer cannot be told a port: it streams to 37008 like everything
  else, so radio frames (TZSP encapsulation 18, or 119/126/127 behind a
  Prism/radiotap/AVS header) land on the same socket as the wired mirror. They go to the wids
  service with an 8-byte header carrying the sensor's address, because wids
  keys spoof detection and channel coverage by sensor and the forward would
  otherwise make every sensor look like this container.

  Reading a sender's address costs `recvfrom_into` -- measured ~0.4 us a
  packet over `recv_into`, a tuple and a string each time -- and the wired
  loop does not need it. So the port is bound TWICE with SO_REUSEPORT and a
  classic-BPF selector (`SO_ATTACH_REUSEPORT_CBPF`) picks the socket from the
  TZSP encapsulation field: Ethernet to the wired loop, unchanged, everything
  else to a second thread that does read the address. The kernel runs the
  selector after reassembly, so fragmented 802.11 datagrams are steered whole
  (verified across a 1500-MTU bridge). If the selector cannot be attached,
  there is one socket and it reads addresses -- slower, never wrong. Both
  loops handle both kinds, so a misrouted datagram is still processed.
"""
import ctypes
import fcntl
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

TAP_NAME = os.getenv("TAP_INTERFACE", "tzsp0")
# 9000 so VLAN-tagged or jumbo mirror frames are not rejected on write; the tap
# never transmits anywhere, so a large MTU costs nothing.
TAP_MTU = int(os.getenv("TAP_MTU", "9000"))
LISTEN_ADDR = os.getenv("TZSP_LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = int(os.getenv("TZSP_LISTEN_PORT", "37008"))
RCVBUF = int(os.getenv("TZSP_RCVBUF", str(32 * 1024 * 1024)))
STATS_INTERVAL = int(os.getenv("STATS_INTERVAL", "30"))

# Where 802.11 TZSP is passed on to (host:port, resolved by name on every
# stats tick, because a recreated wids comes back on a new address). Empty
# drops it as bad-encap, which is what happened before wids existed.
WIDS_FORWARD = os.getenv("WIDS_FORWARD", "wids:37009")

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

# --- Linux tap plumbing -----------------------------------------------------
TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000  # no 4-byte prefix, so a write is exactly one raw frame
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
SIOCSIFMTU = 0x8922
IFF_UP = 0x0001
IFF_RUNNING = 0x0040
# struct ifreq is 40 bytes on Linux; a shorter buffer makes ioctl return EFAULT.
IFREQ_PAD = 40

# --- TZSP wire format (see the TZSP spec / Wireshark's packet-tzsp.c) -------
# byte 0    version (1)
# byte 1    type (0 = received tag list, 1 = packet for transmit, ...)
# byte 2-3  encapsulated protocol, big endian
# then      tagged fields, terminated by TAG_END; the raw frame follows
TZSP_VERSION = 1
TAG_PADDING = 0x00  # single byte, no length field
TAG_END = 0x01  # single byte, the frame starts right after it
ENCAP_ETHERNET = 1
# Raw 802.11, and 802.11 behind a Prism, radiotap or AVS radio header: what a
# wireless sniffer streams. Passed on to wids; anything else is bad-encap.
# 126 (radiotap) is what the RouterOS wireless sniffer actually sends.
WIRELESS_ENCAPS = frozenset((18, 119, 126, 127))

# Forward header in front of a TZSP datagram passed on to wids: a magic that
# cannot start TZSP (version byte 0xFF), then the sensor's IPv4 address
# (0.0.0.0 if unknown). wids/wids.py `unwrap_forward` is the other half.
FORWARD_MAGIC = b"\xffWF\x01"

SO_REUSEPORT = 15
# Python's socket module does not export these (vxlan-tzsp defines them too).
IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0
SO_ATTACH_REUSEPORT_CBPF = 51
# Classic BPF over the UDP payload (the kernel pulls the UDP header first):
#   ldh [2]          TZSP encapsulation
#   jeq #1, 0, 1     Ethernet?
#   ret #0           -> socket 0, the wired loop
#   ret #1           -> socket 1, the address-reading loop
# A datagram too short to load from aborts the program with 0, i.e. the wired
# loop, which counts it as not-tzsp exactly as before.
STEER_PROGRAM = ((0x28, 0, 0, 2), (0x15, 0, 1, ENCAP_ETHERNET),
                 (0x06, 0, 0, 0), (0x06, 0, 0, 1))

# SO_RCVBUFFORCE: with CAP_NET_ADMIN this sets the receive buffer past
# net.core.rmem_max, which we cannot raise from inside the container.
SO_RCVBUFFORCE = 33


def _log(msg):
    print(msg, flush=True)


def open_tap(name, mtu):
    """Create tap `name`, bring it up, and return its file descriptor."""
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name.encode()[:15], IFF_TAP | IFF_NO_PI)
    fcntl.ioctl(fd, TUNSETIFF, ifr.ljust(IFREQ_PAD, b"\x00"))

    ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        fcntl.ioctl(ctl, SIOCSIFMTU,
                    struct.pack("16si", name.encode()[:15], mtu).ljust(IFREQ_PAD, b"\x00"))
        cur = fcntl.ioctl(ctl, SIOCGIFFLAGS,
                          struct.pack("16sH", name.encode()[:15], 0).ljust(IFREQ_PAD, b"\x00"))
        flags = struct.unpack("16sH", cur[:18])[1] | IFF_UP | IFF_RUNNING
        fcntl.ioctl(ctl, SIOCSIFFLAGS,
                    struct.pack("16sH", name.encode()[:15], flags).ljust(IFREQ_PAD, b"\x00"))
    finally:
        ctl.close()
    return fd


def harden_interface(name):
    """Best-effort: stop the local stack from acting on injected mirror traffic.

    Only a hardening layer on top of the namespace isolation, so a read-only
    /proc/sys (Docker's default) is not an error -- it is reported once and the
    setup continues.
    """
    wanted = {
        "/proc/sys/net/ipv6/conf/%s/disable_ipv6": "1",
        "/proc/sys/net/ipv4/conf/%s/arp_ignore": "8",  # never answer ARP here
        "/proc/sys/net/ipv4/conf/%s/arp_filter": "1",
        "/proc/sys/net/ipv4/conf/%s/forwarding": "0",
        "/proc/sys/net/ipv4/conf/%s/accept_local": "0",
    }
    blocked = False
    for path, value in wanted.items():
        try:
            with open(path % name, "w") as fh:
                fh.write(value)
        except OSError:
            blocked = True
    if blocked:
        _log(f"note: could not tighten sysctls on {name} (/proc/sys is read-only in "
             f"the container). Harmless here: the tap lives in this container's own "
             f"network namespace, so mirrored traffic still cannot reach the host.")


def parse_tzsp(buf, length):
    """Return (frame_offset, encap_protocol), or None if this is not TZSP.

    Kept branch-light and index-based: it runs once per mirrored packet.
    """
    if length < 5 or buf[0] != TZSP_VERSION:
        return None
    encap = (buf[2] << 8) | buf[3]
    i = 4
    while i < length:
        tag = buf[i]
        if tag == TAG_END:
            return i + 1, encap
        if tag == TAG_PADDING:
            i += 1
            continue
        if i + 1 >= length:
            return None
        i += 2 + buf[i + 1]
    return None


def udp_drops(port):
    """Kernel receive drops for our listening socket, from /proc/net/udp.

    Read on the stats tick instead of per packet (SO_RXQ_OVFL would add an
    ancillary-data read to every single recv).
    """
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


class Influx:
    """Minimal InfluxDB v2 line-protocol writer (stdlib only, best effort)."""

    def __init__(self, url, token, org, bucket):
        self.endpoint = f"{url.rstrip('/')}/api/v2/write?org={org}&bucket={bucket}&precision=s"
        self.headers = {"Authorization": f"Token {token}",
                        "Content-Type": "text/plain; charset=utf-8"}

    def write(self, line):
        req = urllib.request.Request(self.endpoint, data=line.encode(),
                                     headers=self.headers, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5).close()
        except (urllib.error.URLError, OSError) as exc:
            _log(f"influx write error: {exc}")


class Counters:
    """Packet counters. Only the reporter thread reads them, so plain ints are
    enough: a torn read would cost one slightly-off stats point, never a packet."""

    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.not_tzsp = 0
        self.bad_encap = 0
        self.runts = 0
        self.write_errors = 0
        self.wireless = 0         # 802.11 datagrams passed on to wids
        self.wireless_errors = 0  # ... that could not be (no target, send error)


FIELDS = ("packets", "bytes", "not_tzsp", "bad_encap", "runts", "write_errors",
          "wireless", "wireless_errors")


def total(counter_sets):
    """Sum the per-loop counters. Each loop owns its own Counters, so no
    counter is ever incremented from two threads."""
    out = Counters()
    for c in counter_sets:
        for f in FIELDS:
            setattr(out, f, getattr(out, f) + getattr(c, f))
    return out


def resolve(spec):
    """'host:port' -> (ip, port), or None if empty or not resolvable now."""
    if not spec:
        return None
    host, _, port = spec.rpartition(":")
    try:
        return socket.getaddrinfo(host, int(port), socket.AF_INET,
                                  socket.SOCK_DGRAM)[0][4]
    except (OSError, ValueError):
        return None


def report_forever(counter_sets, influx, port, interval, target):
    prev = Counters()
    prev_drops = udp_drops(port)
    while True:
        time.sleep(interval)
        # Re-resolved every tick: a recreated wids comes back on another
        # address, and the forward would keep sending to the old one.
        target[0] = resolve(WIDS_FORWARD)
        now = total(counter_sets)
        d = {f: getattr(now, f) - getattr(prev, f) for f in FIELDS}
        pkts, byts = d["packets"], d["bytes"]
        drops = udp_drops(port)
        d_drops = max(0, drops - prev_drops)
        errors = d["not_tzsp"] + d["bad_encap"] + d["runts"] + d["write_errors"]

        wireless = ""
        if WIDS_FORWARD and (now.wireless or now.wireless_errors):
            wireless = (f" | 802.11 to {WIDS_FORWARD} {d['wireless']}"
                        + (f" (failed {d['wireless_errors']})" if d["wireless_errors"] else ""))
        _log(f"[TZSP] {pkts} pkt / {byts} B in {interval}s "
             f"({pkts // max(1, interval)} pps) | udp drops {d_drops} | "
             f"not-tzsp {d['not_tzsp']} "
             f"bad-encap {d['bad_encap']} "
             f"runts {d['runts']} "
             f"write-err {d['write_errors']}{wireless}")
        if WIDS_FORWARD and d["wireless_errors"] and target[0] is None:
            _log(f"cannot resolve {WIDS_FORWARD}: 802.11 frames are being dropped "
                 f"(is the wids service running?)")

        # Deltas, not the running totals: a restart would otherwise put a
        # cliff in every panel built on these. `errors` stays the wired
        # path's: a stopped wids is not a fault of the IDS.
        influx.write(
            f"tzsp_decap,interface={TAP_NAME} "
            f"packets={pkts}i,bytes={byts}i,udp_drops={d_drops}i,errors={errors}i,"
            f"wireless={d['wireless']}i,wireless_errors={d['wireless_errors']}i,"
            f"pps={pkts / float(interval)},"
            f"packets_total={now.packets}i,udp_drops_total={drops}i"
        )

        prev = now
        prev_drops = drops


def bind_sockets(addr, port, rcvbuf):
    """[wired] or [wired, wireless]: the port bound once, or twice behind the
    reuseport selector. Returns the sockets and a note on what was done."""
    def make(reuseport):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if reuseport:
            sock.setsockopt(socket.SOL_SOCKET, SO_REUSEPORT, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, rcvbuf)
        except OSError:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        return sock

    if WIDS_FORWARD:
        wired = wireless = None
        try:
            insns = b"".join(struct.pack("HBBI", *i) for i in STEER_PROGRAM)
            code = ctypes.create_string_buffer(insns, len(insns))
            fprog = struct.pack("HL", len(STEER_PROGRAM), ctypes.addressof(code))
            # Group index = bind order: the wired socket must be bound first.
            wired = make(True)
            wired.setsockopt(socket.SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, fprog)
            wired.bind((addr, port))
            wireless = make(True)
            wireless.bind((addr, port))
            return [wired, wireless], "802.11 steered to its own socket"
        except OSError as exc:
            for sock in (wired, wireless):
                if sock is not None:
                    sock.close()
            note = (f"reuseport selector unavailable ({exc}): one socket, reading "
                    f"sender addresses for every packet")
    else:
        note = "WIDS_FORWARD is empty: 802.11 is dropped as bad-encap"
    sock = make(False)
    sock.bind((addr, port))
    return [sock], note


def serve(sock, tap_fd, fwd, target, counters, with_source):
    """The per-packet loop. `with_source` is False only for the wired socket
    of a steered pair, which then never pays for the sender's address."""
    buf = bytearray(65535)
    view = memoryview(buf)
    write = os.write
    recv_into = sock.recv_into
    recvfrom_into = sock.recvfrom_into
    header = bytearray(FORWARD_MAGIC + b"\x00\x00\x00\x00")
    src = None

    while True:
        try:
            if with_source:
                n, src = recvfrom_into(buf)
            else:
                n = recv_into(buf)
        except OSError as exc:
            _log(f"recv error: {exc}")
            continue

        parsed = parse_tzsp(buf, n)
        if parsed is None:
            counters.not_tzsp += 1
            continue
        offset, encap = parsed
        if encap != ENCAP_ETHERNET:
            if encap not in WIRELESS_ENCAPS or fwd is None:
                # Nothing that can go on an Ethernet tap, and not a radio's.
                counters.bad_encap += 1
                continue
            # A radio in sniffer mode: wids reads it, nothing here can.
            dest = target[0]
            if dest is None:
                counters.wireless_errors += 1
                continue
            try:
                header[4:8] = socket.inet_aton(src[0]) if src else b"\x00\x00\x00\x00"
                fwd.sendmsg([header, view[:n]], (), 0, dest)
            except OSError:
                counters.wireless_errors += 1
                continue
            counters.wireless += 1
            continue
        if n - offset < 14:  # shorter than an Ethernet header
            counters.runts += 1
            continue

        try:
            write(tap_fd, view[offset:n])
        except OSError:
            counters.write_errors += 1
            continue
        counters.packets += 1
        counters.bytes += n - offset


def main():
    tap_fd = open_tap(TAP_NAME, TAP_MTU)
    harden_interface(TAP_NAME)
    _log(f"tap {TAP_NAME} up (mtu {TAP_MTU}); Suricata should sniff this interface")

    socks, note = bind_sockets(LISTEN_ADDR, LISTEN_PORT, RCVBUF)
    actual = socks[0].getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    _log(f"listening for TZSP on {LISTEN_ADDR}:{LISTEN_PORT} "
         f"(rcvbuf {actual} B, asked {RCVBUF} B); {note}")

    fwd = None
    target = [None]
    if WIDS_FORWARD:
        fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # An 802.11 frame plus TZSP and this header can exceed the bridge
        # MTU; fragment rather than let PMTU discovery refuse it (as vxlan-tzsp).
        fwd.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
        target[0] = resolve(WIDS_FORWARD)
        _log(f"802.11 TZSP is passed on to {WIDS_FORWARD} "
             f"({target[0][0] if target[0] else 'not resolvable yet'})")

    counter_sets = [Counters() for _ in socks]
    influx = Influx(INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG, INFLUX_BUCKET)
    threading.Thread(target=report_forever, daemon=True,
                     args=(counter_sets, influx, LISTEN_PORT, STATS_INTERVAL, target)).start()

    if len(socks) == 2:
        threading.Thread(target=serve, daemon=True,
                         args=(socks[1], tap_fd, fwd, target, counter_sets[1], True)).start()
        serve(socks[0], tap_fd, fwd, target, counter_sets[0], False)
    else:
        serve(socks[0], tap_fd, fwd, target, counter_sets[0], fwd is not None)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # keep the reason in the container log, then let
        _log(f"fatal: {exc}")  # the restart policy try again
        sys.exit(1)
