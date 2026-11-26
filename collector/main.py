import os
import sys
from nfstream import NFStreamer
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS

from geoip import GeoIP

INFLUX_URL = os.getenv("INFLUXDB_URL", "http://influxdb:8086")
TOKEN = os.getenv("INFLUXDB_TOKEN", "my-super-secret-token")
ORG = os.getenv("INFLUXDB_ORG", "my-org")
BUCKET = os.getenv("INFLUXDB_BUCKET", "network_traffic")
INTERFACE = os.getenv("SNIFF_INTERFACE", "wlp0s20f3")
# Written by dns-resolver into the shared `geoip` volume (mounted read-only
# here); re-read by itself when the monthly update replaces it.
GEOIP_DB = os.getenv("GEOIP_DB", "/geoip/country.mmdb")

# Destination ports are bucketed into service names before being used as a tag:
# the raw port would add tens of thousands of series, these buckets add ~50.
# The numeric port is still written as a field, so drill-down stays possible.
SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 123: "ntp", 137: "netbios", 138: "netbios", 139: "netbios",
    143: "imap", 161: "snmp", 162: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 500: "ipsec", 514: "syslog", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1701: "l2tp", 1723: "pptp", 1812: "radius", 1900: "ssdp",
    3128: "http-proxy", 3306: "mysql", 3389: "rdp", 4500: "ipsec-nat",
    5060: "sip", 5061: "sip-tls", 5353: "mdns", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb", 51820: "wireguard",
}


# Only these carry port numbers; everything else (ICMP, IGMP, GRE, ...) reports
# dst_port 0, which would otherwise be misfiled as a real low port.
PORTED_PROTOCOLS = {6, 17, 33, 132}  # TCP, UDP, DCCP, SCTP


def service_name(protocol, port):
    """Bucket a destination port into a bounded set of tag values."""
    if protocol not in PORTED_PROTOCOLS:
        return "portless"
    known = SERVICES.get(port)
    if known:
        return known
    if port < 1024:
        return "other-system"
    if port < 49152:
        return "other-registered"
    return "ephemeral"  # a high dst_port usually means we caught the reply direction


geo = GeoIP(GEOIP_DB)
print(f"GeoIP: {GEOIP_DB} " + (f"loaded ({geo.meta.get('database_type')})" if geo.loaded
      else f"not loaded ({geo.error}); country tags are left off until it appears"), flush=True)
geo_was_loaded = geo.loaded

print("Connecting to InfluxDB...", flush=True)
client = InfluxDBClient(url=INFLUX_URL, token=TOKEN, org=ORG)
write_api = client.write_api(write_options=SYNCHRONOUS)

print(f"Starting NFStreamer on interface: {INTERFACE} (listening for TZSP)...", flush=True)

streamer = NFStreamer(
    source=INTERFACE,
    decode_tunnels=True,  # Decodes TZSP on the fly
    promiscuous_mode=True,
    idle_timeout=2,
    active_timeout=5,
    # Gates the TCP flag counters and the packet-size stats below. Without it
    # nfstream does not populate bidirectional_syn/rst/fin_packets or *_ps at
    # all (they are absent from the flow object, not zero).
    statistical_analysis=True,
)

for flow in streamer:
    service = service_name(flow.protocol, flow.dst_port)
    # nfstream fills requested_server_name from TLS SNI and from DNS/mDNS
    # queries. It tracks dst_ip closely, which is already a tag, so making it a
    # tag costs little extra cardinality and makes "top server names" groupable.
    server_name = flow.requested_server_name or "none"

    # Print clean flow logs to console
    print(f"[FLOW] {flow.src_ip} -> {flow.dst_ip}:{flow.dst_port} ({service}) | "
          f"App: {flow.application_name} | "
          f"Up: {flow.src2dst_bytes} Down: {flow.dst2src_bytes}", flush=True)

    # Using bidirectional_duration_ms (ms) instead of non-existent .duration.
    # Note active_timeout=5 caps duration_ms at ~5000, so it is saturated and
    # carries little signal; prefer the byte/packet counters.
    point = Point("network_flow") \
        .tag("src_ip", flow.src_ip) \
        .tag("dst_ip", flow.dst_ip) \
        .tag("protocol", flow.protocol) \
        .tag("application", flow.application_name) \
        .tag("category", flow.application_category_name) \
        .tag("service", service) \
        .tag("server_name", server_name) \
        .field("bytes", flow.bidirectional_bytes) \
        .field("packets", flow.bidirectional_packets) \
        .field("duration_ms", flow.bidirectional_duration_ms) \
        .field("bytes_up", flow.src2dst_bytes) \
        .field("bytes_down", flow.dst2src_bytes) \
        .field("dst_port", flow.dst_port) \
        .field("syn_packets", flow.bidirectional_syn_packets) \
        .field("rst_packets", flow.bidirectional_rst_packets) \
        .field("fin_packets", flow.bidirectional_fin_packets) \
        .field("mean_ps", flow.bidirectional_mean_ps) \
        .field("max_ps", flow.bidirectional_max_ps)

    # Country of each end: an ISO code, "local" (private/non-global) or
    # "unknown". It is a function of the address, which is already a tag, so it
    # adds no series -- only an IP that changes country in a monthly database
    # update starts a new one. Left off entirely while no database is loaded,
    # rather than written as "unknown": that would be a wrong fact, kept forever.
    geo.maybe_reload()
    if geo.loaded:
        if not geo_was_loaded:
            print(f"GeoIP: {GEOIP_DB} loaded ({geo.meta.get('database_type')}); "
                  f"country tags start now", flush=True)
            geo_was_loaded = True
        point.tag("src_country", geo.country(flow.src_ip)[0] or "unknown") \
             .tag("dst_country", geo.country(flow.dst_ip)[0] or "unknown")

    try:
        write_api.write(bucket=BUCKET, org=ORG, record=point)
    except Exception as e:
        print(f"Write error: {e}", file=sys.stderr, flush=True)
