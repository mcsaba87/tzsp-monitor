"""Re-wrap a VXLAN mirror stream as TZSP and forward it to tzsp-decap.

's virtual network TAP delivers mirrored traffic as VXLAN over UDP (4789
by default), while everything downstream here speaks TZSP: tzsp-decap only
parses TZSP, and so does nfstream -- its decode_tunnels handles TZSP but *not*
VXLAN (verified on 6.5.3: a VXLAN capture comes out as one flow per tunnel
endpoint pair, not as the inner hosts). Rather than teach every consumer a
second tunnel, this service turns one into the other:

     TAP --VXLAN/UDP 4789--> [this service] --TZSP/UDP 37008--> tzsp-decap

The two headers are close enough that no copy is needed. VXLAN is 8 bytes and
then the inner Ethernet frame; TZSP is 5 bytes (version, type, encapsulation,
TAG_END) and then the same frame. So the TZSP header is written over the last
5 bytes of the VXLAN one, in the receive buffer, and the datagram is sent from
offset 3 -- the inner frame never moves.

Things worth keeping:

* **The converted stream never crosses the physical NIC**, so a collector
  sniffing that NIC cannot see it. On a host fed by VXLAN the collector has to
  sniff tzsp-decap's tap instead; docker-compose.vxlan.yml does both.

* **The datagram grows by 25 bytes** (5 + a new IP/UDP header, minus the 8 of
  VXLAN), so a full 1514-byte inner frame no longer fits a 1500 MTU bridge.
  Fragmentation is forced on (IP_PMTUDISC_DONT) rather than left to path-MTU
  discovery, which could otherwise answer EMSGSIZE and drop exactly the large
  frames. Fragments on a local bridge are reassembled by the receiving kernel.

* **The destination is re-resolved on every stats tick.** The socket is
  connected (one lookup instead of one per packet), but recreating tzsp-decap
  can give it a new address, and a connected UDP socket would keep sending to
  the old one forever.

* Like tzsp-decap, this is one Python loop doing recv + send per packet and
  allocating nothing per packet; UDP receive drops are read from /proc/net/udp
  on the stats tick, because they are the only sign that it is falling behind.
"""
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

LISTEN_ADDR = os.getenv("VXLAN_LISTEN_ADDR", "0.0.0.0")
LISTEN_PORT = int(os.getenv("VXLAN_LISTEN_PORT", "4789"))
TZSP_HOST = os.getenv("TZSP_HOST", "tzsp-decap")
TZSP_PORT = int(os.getenv("TZSP_PORT", "37008"))
RCVBUF = int(os.getenv("VXLAN_RCVBUF", str(32 * 1024 * 1024)))
STATS_INTERVAL = int(os.getenv("STATS_INTERVAL", "30"))
# Comma-separated VNIs to forward; empty forwards every VNI.  sets the VNI
# on the TAP configuration, so this is how two TAPs aimed at one host are told
# apart.
VNIS = frozenset(int(v) for v in os.getenv("VXLAN_VNIS", "").replace(" ", "").split(",") if v)

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
INFLUX_ORG = os.getenv("INFLUXDB_ORG", "my-org")
INFLUX_BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")

# --- VXLAN (RFC 7348) -------------------------------------------------------
# byte 0    flags; 0x08 = the VNI is valid, which a real VXLAN sender always sets
# byte 1-3  reserved
# byte 4-6  VNI, big endian
# byte 7    reserved
# then      the inner Ethernet frame
VXLAN_HLEN = 8
VXLAN_FLAG_VNI = 0x08

# --- TZSP: version 1, type 0 (received tag list), encap 1 (Ethernet), TAG_END
TZSP_HEADER = b"\x01\x00\x00\x01\x01"
TZSP_OFFSET = VXLAN_HLEN - len(TZSP_HEADER)

ETH_HLEN = 14
SO_RCVBUFFORCE = 33  # past net.core.rmem_max, needs CAP_NET_ADMIN
IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0


def _log(msg):
    print(msg, flush=True)


def udp_drops(port):
    """Kernel receive drops for our listening socket, from /proc/net/udp."""
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
    """Only the reporter thread reads these, so plain ints are enough."""

    def __init__(self):
        self.packets = 0
        self.bytes = 0
        self.not_vxlan = 0
        self.filtered = 0
        self.send_errors = 0
        self.last_vni = -1


class Output:
    """The connected socket towards tzsp-decap, re-pointed if its address moves."""

    def __init__(self, host, port):
        self.host, self.port = host, port
        self.addr = None
        self.sock = None
        self.refresh()

    def refresh(self):
        try:
            addr = socket.gethostbyname(self.host)
        except OSError as exc:
            if self.sock is None:
                _log(f"cannot resolve {self.host} yet ({exc}); retrying on the next tick")
            return
        if addr == self.addr:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
        sock.connect((addr, self.port))
        old, self.sock, self.addr = self.sock, sock, addr
        if old is not None:
            old.close()
        _log(f"forwarding TZSP to {self.host} ({addr}:{self.port})")


def report_forever(counters, output, influx, port, interval):
    prev = Counters()
    prev_drops = udp_drops(port)
    while True:
        time.sleep(interval)
        output.refresh()
        pkts = counters.packets - prev.packets
        byts = counters.bytes - prev.bytes
        not_vxlan = counters.not_vxlan - prev.not_vxlan
        filtered = counters.filtered - prev.filtered
        send_errors = counters.send_errors - prev.send_errors
        drops = udp_drops(port)
        d_drops = max(0, drops - prev_drops)

        _log(f"[VXLAN] {pkts} pkt / {byts} B in {interval}s "
             f"({pkts // max(1, interval)} pps) | udp drops {d_drops} | "
             f"not-vxlan {not_vxlan} other-vni {filtered} send-err {send_errors} | "
             f"last vni {counters.last_vni}")

        # Deltas, not running totals, for the same reason as tzsp_decap: a
        # restart would otherwise put a cliff in every panel built on them.
        influx.write(
            f"vxlan_tzsp,port={port} "
            f"packets={pkts}i,bytes={byts}i,udp_drops={d_drops}i,"
            f"not_vxlan={not_vxlan}i,filtered={filtered}i,send_errors={send_errors}i,"
            f"pps={pkts / float(interval)},last_vni={counters.last_vni}i,"
            f"packets_total={counters.packets}i,udp_drops_total={drops}i"
        )

        prev.packets, prev.bytes = counters.packets, counters.bytes
        prev.not_vxlan, prev.filtered = counters.not_vxlan, counters.filtered
        prev.send_errors = counters.send_errors
        prev_drops = drops


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.SOL_SOCKET, SO_RCVBUFFORCE, RCVBUF)
    except OSError:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF)
    actual = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))
    _log(f"listening for VXLAN on {LISTEN_ADDR}:{LISTEN_PORT} "
         f"(rcvbuf {actual} B, asked {RCVBUF} B; "
         f"VNIs {sorted(VNIS) if VNIS else 'all'})")

    output = Output(TZSP_HOST, TZSP_PORT)
    counters = Counters()
    influx = Influx(INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG, INFLUX_BUCKET)
    threading.Thread(target=report_forever, daemon=True,
                     args=(counters, output, influx, LISTEN_PORT, STATS_INTERVAL)).start()

    buf = bytearray(65535)
    view = memoryview(buf)
    header = view[TZSP_OFFSET:VXLAN_HLEN]
    frame = view[TZSP_OFFSET:]
    min_len = VXLAN_HLEN + ETH_HLEN

    while True:
        try:
            n = sock.recv_into(buf)
        except OSError as exc:
            _log(f"recv error: {exc}")
            continue

        # The I flag plus all-zero reserved bytes, so a stray datagram -- or a
        # TZSP sender pointed at the wrong port -- is counted, not forwarded.
        if (n < min_len or buf[0] != VXLAN_FLAG_VNI or buf[1] or buf[2]
                or buf[3] or buf[7]):
            counters.not_vxlan += 1
            continue
        vni = (buf[4] << 16) | (buf[5] << 8) | buf[6]
        counters.last_vni = vni
        if VNIS and vni not in VNIS:
            counters.filtered += 1
            continue

        header[:] = TZSP_HEADER
        out = output.sock
        try:
            out.send(frame[:n - TZSP_OFFSET])
        except (OSError, AttributeError):
            # AttributeError: tzsp-decap has never resolved yet. OSError
            # includes ECONNREFUSED, which a connected UDP socket reports after
            # the receiver went away -- the next packet is tried regardless.
            counters.send_errors += 1
            continue
        counters.packets += 1
        counters.bytes += n - VXLAN_HLEN


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as exc:  # keep the reason in the container log, then let
        _log(f"fatal: {exc}")  # the restart policy try again
        sys.exit(1)
