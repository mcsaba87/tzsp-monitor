"""The IP-reputation path without a router.

    docker compose exec ip-reputation python selftest.py
    docker compose exec ip-reputation python selftest.py --feeds

Offline it checks what decides what reaches the firewall: the feed parsers
(plain lists, netsets, Spamhaus' JSON lines, DShield's columns), the filter
that keeps our own and reserved space out -- FireHOL level1 really does list
10.0.0.0/8 -- the cross-feed merge and its budget, and `reconcile` against a
stub router: add, remove, refresh, a hand-made row left alone, dry-run, and
giving up on a router that has gone away -- and the hit watcher's matching of
flow pairs against the merged list (which end is ours, which feed lists the
other).

`--feeds` also downloads every feed in the catalogue and parses it, which is
the check that a URL or a format has not changed under us. It writes nothing.
"""
import ipaddress
import sys

import reputation as r

failures = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  -- {detail}" if detail else ""))
    if not ok:
        failures.append(label)


def nets(*items):
    return [ipaddress.IPv4Network(i) for i in items]


class StubRouter:
    """Records calls; raises for the addresses it is told to."""

    def __init__(self, dry_run=False, existing=(), fail=False):
        self.dry_run = dry_run
        self.calls = []
        self.existing = set(existing)
        self.fail = fail

    def call(self, method, path, body=None, timeout=None):
        self.calls.append((method, path, body))
        if self.fail:
            raise r.RouterError("connection refused")
        if method == "PUT" and body["address"] in self.existing:
            raise r.RouterError('HTTP 400 {"detail":"failure: already have such entry"}')
        return {}


def offline():
    print("1. parsing")
    spamhaus = ('{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}\n'
                '{"type":"metadata","timestamp":1793000000,"size":2}\n')
    check("Spamhaus JSON lines", r.parse_feed(spamhaus, "cidr") == nets("1.10.16.0/20"))
    plain = "# comment\n; another\n50.16.16.211\n\n2001:db8::1\n1.2.3.4 # trailing\n"
    check("plain list: comments and IPv6 skipped",
          r.parse_feed(plain, "cidr") == nets("50.16.16.211/32", "1.2.3.4/32"))
    dshield = ("Start\tEnd\tNetblock\tAttacks\tName\n"
               "151.243.11.0\t151.243.11.255\t24\t358\tRASANA\tIR\tabuse@x\n")
    check("DShield columns become a /24, header skipped",
          r.parse_feed(dshield, "dshield") == nets("151.243.11.0/24"))
    check("host bits are cleared, junk ignored",
          r.parse_feed("1.2.3.4/24\n999.1.1.1\nnot an ip\n", "cidr") == nets("1.2.3.0/24"))

    print("2. never block our own or reserved space")
    cfg = r.Config("/nonexistent")
    cfg.values = {"suricata.home_net": "[10.0.0.0/8,172.16.0.0/12,!10.9.0.0/16]",
                  "whitelist.ips": "8.8.8.8", "ip_reputation.never": "9.9.9.0/24",
                  "mikrotik.host": "192.168.88.1"}
    protected = r.protected_networks(cfg)
    firehol = nets("0.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "224.0.0.0/3",
                   "8.8.8.0/24", "9.9.0.0/16", "1.10.16.0/20", "4.0.0.0/7")
    desired, stats = r.build_desired({"firehol_level1": firehol}, protected, 8, 1000)
    check("bogons, a whitelisted address's /24, a never-list supernet and a /7 "
          "are all dropped", list(desired) == ["1.10.16.0/20"],
          f"{list(desired)} dropped={stats['firehol_level1']['dropped']}")
    check("the drop count is reported", stats["firehol_level1"]["dropped"] == 7)
    cfg.values.update({"mikrotik.routers": "edge2", "mikrotik.edge2.host": "5.6.7.8",
                       "mikrotik.edge2.roles": "block"})
    check("every router's address is protected, whatever its roles",
          ipaddress.IPv4Network("5.6.7.8/32") in r.protected_networks(cfg))

    print("3. merging feeds")
    parsed = {"big": nets("1.0.0.0/16", "2.2.2.2/32", "3.3.3.3/32", "4.4.4.4/32"),
              "small": nets("1.0.5.0/24", "2.2.2.2/32")}
    desired, stats = r.build_desired(parsed, protected, 8, 1000)
    check("the smaller feed goes first and keeps a shared address",
          desired["2.2.2.2"] == "small")
    check("a /16 after its own /24 is still added (it covers more)",
          desired.get("1.0.0.0/16") == "big")
    parsed = {"a": nets("1.0.0.0/16"), "b": nets("1.0.5.0/24", "1.0.6.7/32",
                                                 "5.5.5.5/32", "6.6.6.6/32")}
    desired, stats = r.build_desired(parsed, protected, 8, 1000)
    check("entries inside an earlier, broader network are skipped",
          "1.0.5.0/24" not in desired and stats["b"]["duplicate"] == 2, str(stats["b"]))
    check("a /32 is written as a bare address, like RouterOS shows it",
          "5.5.5.5" in desired)
    desired, stats = r.build_desired(
        {"x": nets(*[f"7.0.0.{i}/32" for i in range(0, 20, 2)])}, protected, 8, 5)
    check("the budget truncates and marks the feed capped",
          len(desired) == 5 and stats["x"]["capped"])

    print("4. reconcile against a stub router")
    rows = [{".id": "*1", "address": "5.5.5.5", "comment": "iprep:a", "timeout": "2d"},
            {".id": "*2", "address": "6.6.6.6", "comment": "iprep:a", "timeout": "3h"},
            {".id": "*3", "address": "7.7.7.7", "comment": "iprep:a", "timeout": "2d"},
            {".id": "*4", "address": "8.8.4.4", "comment": "by hand"}]
    want = {"5.5.5.5": "a", "6.6.6.6": "a", "9.0.0.0/24": "b", "1.1.1.0/24": "b"}
    stub = StubRouter(existing={"1.1.1.0/24"})
    counts = r.reconcile(stub, "reputation-blocked", "iprep", want, rows, "3d", 86400)
    methods = sorted((m, p.rsplit("/", 1)[-1] if m != "PUT" else b["address"])
                     for m, p, b in stub.calls)
    check("removes what no feed lists, adds what is new, refreshes what is "
          "about to expire", methods == [("DELETE", "*3"), ("PATCH", "*2"),
                                        ("PUT", "1.1.1.0/24"), ("PUT", "9.0.0.0/24")],
          str(methods))
    check("a hand-made row is never touched, and a clash with one is counted",
          all("*4" not in p and "%2A4" not in p for _, p, _ in stub.calls)
          and counts["foreign"] == 1 and counts["added"] == 1, str(counts))
    check("the entry carries the list, the feed and the timeout",
          ("PUT", "/ip/firewall/address-list",
           {"list": "reputation-blocked", "address": "9.0.0.0/24",
            "comment": "iprep:b", "timeout": "3d"}) in stub.calls)
    dry = StubRouter(dry_run=True)
    r.reconcile(dry, "l", "iprep", want, rows, "3d", 86400)
    check("dry-run calls nothing", dry.calls == [])
    dead = StubRouter(fail=True)
    try:
        r.reconcile(dead, "l", "iprep", {f"9.0.{i}.0/24": "b" for i in range(50)},
                    [], "3d", 86400, stop_after_errors=5)
        gave_up = False
    except r.RouterError:
        gave_up = True
    check("a router that has gone away is given up on, not hammered",
          gave_up and len(dead.calls) == 5, f"{len(dead.calls)} calls")

    print("5. hit watcher: which of our hosts talked to a listed address")
    home = r.v4_networks(["10.0.0.0/8", "192.168.0.0/16"])
    listed = {"5.6.7.0/24": "feodo", "9.9.9.9": "spamhaus_drop", "1.0.0.0/8": "wide"}

    def row(src, dst, nbytes=100, flows=1):
        return {"src_ip": src, "dst_ip": dst, "bytes": nbytes, "flows": flows}

    rows = [row("10.1.2.3", "5.6.7.8", 1500, 3),       # outbound, inside a /24
            row("9.9.9.9", "192.168.1.5", 60, 1),      # inbound, a /32 entry
            row("10.1.2.3", "10.4.4.4"),               # internal to internal
            row("5.6.7.8", "9.9.9.9"),                 # external to external
            row("10.1.2.3", "8.8.8.8"),                # unlisted
            row("10.1.2.3", "9.9.9.10"),               # next to a /32, not in it
            row("10.1.2.3", "1.2.3.4"),                # inside a /8 (min prefix)
            row("fe80::1", "5.6.7.8"),                 # IPv6 never matches
            row("10.1.2.3", "not-an-ip")]
    hits = {(h["internal_ip"], h["remote_ip"]): h
            for h in r.match_hits(rows, listed, home, 8)}
    out = hits.get(("10.1.2.3", "5.6.7.8"), {})
    check("outbound: our host opened a flow to an address in a listed /24",
          out.get("direction") == "outbound" and out.get("feed") == "feodo"
          and out.get("listed") == "5.6.7.0/24" and out.get("flows") == 3
          and out.get("bytes") == 1500, str(out))
    inb = hits.get(("192.168.1.5", "9.9.9.9"), {})
    check("inbound: a listed /32 opened a flow to our host",
          inb.get("direction") == "inbound" and inb.get("feed") == "spamhaus_drop"
          and inb.get("listed") == "9.9.9.9", str(inb))
    check("a listed /8 still matches at the minimum prefix",
          hits.get(("10.1.2.3", "1.2.3.4"), {}).get("listed") == "1.0.0.0/8")
    check("internal-to-internal, external-to-external, unlisted, a neighbour of "
          "a /32, IPv6 and junk are all ignored", len(hits) == 3, str(sorted(hits)))
    check("a network shorter than the minimum prefix is never looked up",
          r.match_hits([row("10.1.2.3", "1.2.3.4")], listed, home, 9) == [])
    check("nothing listed, nothing matched", r.match_hits(rows, {}, home, 8) == [])
    flux = [{"result": "bytes", "src_ip": "10.1.2.3", "dst_ip": "5.6.7.8", "_value": "1500"},
            {"result": "flows", "src_ip": "10.1.2.3", "dst_ip": "5.6.7.8", "_value": "3"},
            {"result": "bytes", "src_ip": "10.1.2.3", "dst_ip": "8.8.8.8", "_value": "40"}]
    joined = {(p["src_ip"], p["dst_ip"]): p for p in r.join_flow_rows(flux)}
    check("the two yields are joined per pair in Python",
          joined[("10.1.2.3", "5.6.7.8")]["bytes"] == 1500
          and joined[("10.1.2.3", "5.6.7.8")]["flows"] == 3
          and joined[("10.1.2.3", "8.8.8.8")]["flows"] == 0, str(joined))
    csv_text = (",result,table,src_ip,dst_ip,_value\n"
                ",bytes,0,10.1.2.3,5.6.7.8,1500\n,bytes,1,10.1.2.3,8.8.8.8,40\n\n"
                ",result,table,src_ip,dst_ip,_value\n,flows,0,10.1.2.3,5.6.7.8,3\n")
    check("Flux CSV: a header per result, blank line between",
          len(r.parse_flux_csv(csv_text)) == 3
          and r.parse_flux_csv(csv_text)[2]["result"] == "flows")
    query = r.hits_query(1793000000, 1793000060)
    check("the query is two pushdown aggregates over one contiguous window",
          query.count("|> group(columns: [\"src_ip\", \"dst_ip\"])") == 2
          and "|> sum()" in query and "|> count()" in query
          and "map(" not in query and "range(start: 2026-10-26T07:33:20Z" in query,
          query.splitlines()[1])

    print("6. plumbing")
    check("RouterOS durations",
          [r.duration_seconds(t, -1) for t in ("3d", "2d23h59m51s", "1w", "23:59:58",
                                               "1d02:00:00", "500ms", "junk")]
          == [259200, 259191, 604800, 86398, 93600, 0, -1])


def feeds():
    print("7. every catalogued feed downloads and parses")
    for name, spec in r.FEEDS.items():
        try:
            parsed = r.parse_feed(r.fetch(spec["url"]), spec["format"])
            check(f"{name}", len(parsed) > 0, f"{len(parsed)} networks")
        except Exception as exc:                     # noqa: BLE001
            check(f"{name}", False, str(exc))


def main():
    offline()
    if "--feeds" in sys.argv:
        feeds()
    print()
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
