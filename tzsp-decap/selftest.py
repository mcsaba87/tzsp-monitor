"""Inject a synthetic TZSP packet so the whole IDS path can be proven end to end.

The mirror only exists in production, so there is otherwise no way to tell a
working pipeline from a silent one on a dev box. This builds a TZSP-encapsulated
Ethernet/IPv4/UDP packet whose payload carries the magic string matched by the
self-test rule in suricata/rules/local.rules, and sends it to the collector port.

    python3 selftest.py                          # -> 127.0.0.1:37008
    python3 selftest.py --host 10.0.0.5 --count 5
    python3 selftest.py --src 203.0.113.66       # pick the "attacker" IP
    python3 selftest.py --vxlan                  # via vxlan-tzsp -> 127.0.0.1:4789

A successful run should produce, within a few seconds:
  * a rising packet count in `docker compose logs tzsp-decap`
  * a "TZSP-MONITOR pipeline self-test" alert in the Suricata Alerts dashboard

With --vxlan the same frame is wrapped in VXLAN instead and sent to vxlan-tzsp
(docker-compose.vxlan.yml), so the run also proves the re-wrap; its [VXLAN]
log line should count the packets before tzsp-decap's [TZSP] line does.

The self-test signature has priority 4, so it stays below the severity that
triggers a router block -- running this never touches the firewall.
"""
import argparse
import socket
import struct

MAGIC = b"TZSPMONITORSELFTEST"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_packet(src_ip, dst_ip, src_port, dst_port, vxlan=False):
    payload = MAGIC + b" " + b"x" * 32

    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload

    ip_len = 20 + len(udp)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 0x1234, 0, 64, 17, 0,
                         socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]

    ether = (b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"
             + struct.pack("!H", 0x0800))

    if vxlan:
        # VXLAN: I flag, reserved, VNI 1 in the top 24 bits, reserved.
        return struct.pack("!BBHI", 0x08, 0, 0, 1 << 8) + ether + header + udp
    # TZSP: version 1, type 0 (received tag list), encap 1 (Ethernet), TAG_END.
    tzsp = struct.pack("!BBHB", 1, 0, 1, 1)
    return tzsp + ether + header + udp


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1", help="where tzsp-decap listens")
    ap.add_argument("--port", type=int, help="default 37008, or 4789 with --vxlan")
    ap.add_argument("--vxlan", action="store_true",
                    help="wrap in VXLAN and send to vxlan-tzsp instead")
    ap.add_argument("--src", default="203.0.113.66", help="inner source IP")
    ap.add_argument("--dst", default="198.51.100.20", help="inner destination IP")
    ap.add_argument("--count", type=int, default=3)
    args = ap.parse_args()

    port = args.port or (4789 if args.vxlan else 37008)
    packet = build_packet(args.src, args.dst, 40000, 8099, vxlan=args.vxlan)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(args.count):
        sock.sendto(packet, (args.host, port))
    print(f"sent {args.count} {'VXLAN' if args.vxlan else 'TZSP'} packet(s) of "
          f"{len(packet)} B to {args.host}:{port} carrying {args.src} -> {args.dst}")


if __name__ == "__main__":
    main()
