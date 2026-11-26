"""The quarantine and domain-blocking decisions, offline.

    docker compose exec mikrotik-responder python selftest.py

No router, no dns-filter, no eve.json: the decision classes are fed alert
records directly. The three base records are real Suricata 8.0.6 output -- a
pcap of a DNS query, an HTTP request and a TLS ClientHello run through the
stack's own suricata.yaml with three test rules -- so the field shapes
(`dns.queries[].rrname`, `tls.sni`, `http.hostname`, `flow.src_ip`) are the
ones the engine actually writes, not the ones its documentation implies.

Each response has to fire, and the shape next to it has to stay quiet: a
single alert, a never-listed host, a PUP-class rule, the hourly cap, our own
web server's domain, a shared platform, an IP literal.
"""
import copy
import json
import sys

import responder as r

FIXTURES = [json.loads(line) for line in r"""
{"event_type": "alert", "src_ip": "192.168.1.50", "src_port": 40000, "dest_ip": "8.8.8.8", "dest_port": 53, "alert": {"signature_id": 9100001, "signature": "ET MALWARE test dns", "category": "A Network Trojan was detected", "severity": 1}, "dns": {"version": 3, "type": "request", "tx_id": 0, "id": 4660, "flags": "100", "rd": true, "opcode": 0, "rcode": "NOERROR", "queries": [{"rrname": "c2-dns.evil-test.example", "rrtype": "A"}]}, "direction": "to_server", "flow": {"src_ip": "192.168.1.50", "dest_ip": "8.8.8.8", "src_port": 40000, "dest_port": 53}}
{"event_type": "alert", "src_ip": "192.168.1.50", "src_port": 40002, "dest_ip": "203.0.113.10", "dest_port": 443, "alert": {"signature_id": 9100003, "signature": "ET MALWARE test tls", "category": "A Network Trojan was detected", "severity": 1}, "tls": {"sni": "c2-tls.evil-test.example", "version": "TLS 1.3"}, "direction": "to_server", "flow": {"src_ip": "192.168.1.50", "dest_ip": "203.0.113.10", "src_port": 40002, "dest_port": 443}}
{"event_type": "alert", "src_ip": "192.168.1.50", "src_port": 40001, "dest_ip": "203.0.113.9", "dest_port": 80, "alert": {"signature_id": 9100002, "signature": "ET MALWARE test http", "category": "Malware Command and Control Activity Detected", "severity": 1}, "http": {"hostname": "c2-http.evil-test.example", "url": "/beacon", "http_method": "GET"}, "direction": "to_server", "flow": {"src_ip": "192.168.1.50", "dest_ip": "203.0.113.9", "src_port": 40001, "dest_port": 80}}
""".strip().splitlines()]
DNS, TLS, HTTP = FIXTURES

failures = []


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  -- {detail}" if detail else ""))
    if not ok:
        failures.append(label)


def config(**values):
    cfg = r.Config("/nonexistent/selftest.properties")
    cfg.values = {"suricata.home_net": "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]",
                  "mikrotik.host": "192.168.1.1", "whitelist.ips": "192.168.1.53"}
    cfg.values.update({k.replace("__", "."): v for k, v in values.items()})
    return cfg


def event(base, **changes):
    ev = copy.deepcopy(base)
    for key, value in changes.items():
        if key == "alert":
            ev["alert"].update(value)
        else:
            ev[key] = value
    return ev


def main():
    print("1. quarantine")
    cfg = config()
    q = r.Quarantine(cfg, r.Policy(cfg))
    check("the internal end of a C2 alert is the candidate",
          q.host(TLS) == "192.168.1.50", str(q.host(TLS)))
    check("one alert is not enough", q.decide(TLS, 0) == (None, None))
    check("the second one quarantines",
          q.decide(TLS, 0) == ("192.168.1.50", "quarantining"))
    check("a repeat inside the refresh window is not re-sent",
          q.decide(TLS, 0)[0] is None)

    stale = r.Quarantine(cfg, r.Policy(cfg))
    stale.decide(TLS, 0)
    check("a backlog alert (restart catch-up) never quarantines",
          stale.decide(TLS, 9999)[0] is None)

    pup = event(TLS, alert={"signature": "ET MALWARE Win32/Adware.Foo",
                            "category": "Possibly Unwanted Program Detected"})
    info = event(TLS, alert={"signature": "ET INFO Observed DNS over HTTPS",
                             "category": "A Network Trojan was detected"})
    q2 = r.Quarantine(cfg, r.Policy(cfg))
    check("an ET MALWARE rule of the PUP classtype does not count",
          all(q2.decide(pup, 0)[0] is None for _ in range(3)))
    check("an ET INFO rule of the trojan classtype does not count",
          all(q2.decide(info, 0)[0] is None for _ in range(3)))
    sev3 = event(TLS, alert={"severity": 3})
    check("severity 3 does not count",
          all(q2.decide(sev3, 0)[0] is None for _ in range(3)))

    resolver = event(DNS, src_ip="192.168.1.53", flow={"src_ip": "192.168.1.53",
                                                         "dest_ip": "8.8.8.8"})
    q3 = r.Quarantine(cfg, r.Policy(cfg))
    q3.decide(resolver, 0)
    check("a whitelist.ips host (our resolver) is never quarantined",
          q3.decide(resolver, 0) == (None, "quarantine-exempt"))
    to_router = event(DNS, dest_ip="192.168.1.1",
                      flow={"src_ip": "192.168.1.50", "dest_ip": "192.168.1.1"})
    check("both ends internal: the client asking the router, not the router",
          q3.host(to_router) == "192.168.1.50", str(q3.host(to_router)))
    reply = event(HTTP, src_ip="203.0.113.9", dest_ip="192.168.1.77",
                  flow={"src_ip": "192.168.1.77", "dest_ip": "203.0.113.9"})
    check("an alert on the C2's reply still names the internal host",
          q3.host(reply) == "192.168.1.77", str(q3.host(reply)))
    outside = event(TLS, src_ip="198.51.100.1", dest_ip="203.0.113.10",
                    flow={"src_ip": "198.51.100.1", "dest_ip": "203.0.113.10"})
    check("two external ends: nothing to quarantine", q3.host(outside) is None)

    capped = r.Quarantine(config(quarantine__max_per_hour="3"), r.Policy(cfg))
    results = []
    for n in range(4):
        ev = event(TLS, src_ip=f"10.9.0.{n + 1}",
                   flow={"src_ip": f"10.9.0.{n + 1}", "dest_ip": "203.0.113.10"})
        capped.decide(ev, 0)
        results.append(capped.decide(ev, 0))
    check("the hourly cap stops the fourth new host",
          [x[1] for x in results] == ["quarantining"] * 3 + ["quarantine-capped"],
          str(results))

    off = r.Quarantine(config(quarantine__enabled="false"), r.Policy(cfg))
    check("quarantine.enabled = false does nothing",
          all(off.decide(TLS, 0) == (None, None) for _ in range(3)))

    print("2. domains an alert points at")
    internal = q.internal
    check("Suricata 8 DNS: dns.queries[].rrname",
          r.alert_domains(DNS, internal) == ["c2-dns.evil-test.example"],
          str(r.alert_domains(DNS, internal)))
    check("TLS SNI", r.alert_domains(TLS, internal) == ["c2-tls.evil-test.example"])
    check("HTTP Host, port stripped",
          r.alert_domains(event(HTTP, http={"hostname": "C2-HTTP.evil-test.example:8080"}),
                          internal) == ["c2-http.evil-test.example"])
    inbound = event(HTTP, src_ip="203.0.113.9", dest_ip="192.168.1.80",
                    http={"hostname": "www.our-shop.example"},
                    flow={"src_ip": "203.0.113.9", "dest_ip": "192.168.1.80"})
    check("an attack on our own web server does not name our domain",
          r.alert_domains(inbound, internal) == [])
    literal = event(HTTP, http={"hostname": "203.0.113.9"})
    check("an IP literal is not a domain", r.alert_domains(literal, internal) == [])
    legacy = event(DNS, dns={"rrname": "old.evil-test.example.", "rrtype": "A"})
    check("the pre-v3 flat rrname, trailing dot stripped",
          r.alert_domains(legacy, internal) == ["old.evil-test.example"])
    check("the alert table shows the Suricata 8 DNS name",
          "c2-dns.evil-test.example" in r.alert_details(DNS), r.alert_details(DNS))

    print("3. domain blocking")
    d = r.DomainPolicy(cfg, r.Policy(cfg), internal)
    check("one alert is not enough", d.decide(TLS, 0) == ([], None))
    other_host = event(TLS, src_ip="192.168.1.60",
                       flow={"src_ip": "192.168.1.60", "dest_ip": "203.0.113.10"})
    check("the second -- from another host -- blacklists the domain",
          d.decide(other_host, 0) == (["c2-tls.evil-test.example"], "domain-blocking"))
    check("not re-sent inside domain_block.refresh_seconds",
          d.decide(TLS, 0) == ([], None))
    drive = event(TLS, tls={"sni": "drive.google.com"})
    check("a shared platform is never blacklisted",
          all(d.decide(drive, 0) == ([], None) for _ in range(3)))
    phish = event(HTTP, alert={"signature": "ET PHISHING Credential page",
                               "category": "Possible Social Engineering Attempted"})
    d.decide(phish, 0)
    check("phishing counts for domains (not for quarantine)",
          d.decide(phish, 0)[1] == "domain-blocking"
          and r.match_gate(phish["alert"], 2, q.categories, q.signature_re))
    dcap = r.DomainPolicy(config(domain_block__max_per_hour="1",
                                 domain_block__min_alerts="1"), r.Policy(cfg), internal)
    first = dcap.decide(TLS, 0)
    second = dcap.decide(HTTP, 0)
    check("the hourly cap holds", first[1] == "domain-blocking"
          and second == ([], "domain-capped"), f"{first} {second}")

    print("4. plumbing")
    check("RouterOS durations",
          [r.duration_seconds(t, -1) for t in ("4h", "1d12h", "30m", "90", "00:30:00", "x")]
          == [14400, 129600, 1800, 90, 1800, -1])
    check("one decision per alert, actions joined",
          r.combine_decision("blocking", "quarantining", "domain-blocking")
          == "blocking+quarantining+domain-blocking"
          and r.combine_decision("below-threshold", None, None) == "below-threshold"
          and r.combine_decision("whitelisted", "quarantine-capped", None)
          == "quarantine-capped")
    nets = r.home_networks(config(suricata__home_net="[10.0.0.0/8,!10.1.0.0/16,$X]"))
    check("suricata.home_net syntax: negations and variables skipped",
          [str(n) for n in nets] == ["10.0.0.0/8"], str(nets))

    print("5. several routers")
    one = config(mikrotik__user="ids", mikrotik__password="pw")
    check("no mikrotik.routers: one router, named main, as before",
          [rc.name for rc in r.router_configs(one, "block")] == ["main"])
    many = config(**{"mikrotik.user": "ids", "mikrotik.password": "pw",
                     "mikrotik.routers": "edge2, Branch, bad name!, edge2",
                     "mikrotik.edge2.host": "10.2.0.1",
                     "mikrotik.edge2.password": "pw2",
                     "mikrotik.branch.host": "10.3.0.1",
                     "mikrotik.branch.roles": "block, nonsense"})
    blockers = r.router_configs(many, "block")
    check("listed routers are added, bad and duplicate names skipped",
          [rc.name for rc in blockers] == ["main", "edge2", "branch"],
          str([rc.name for rc in blockers]))
    edge2 = blockers[1]
    check("a router's own key wins, the unprefixed one is the fallback",
          edge2.get("mikrotik.password") == "pw2" and edge2.get("mikrotik.user") == "ids")
    check("roles narrow a router: branch takes the block list only",
          [rc.name for rc in r.router_configs(many, "quarantine")] == ["main", "edge2"])
    narrowed = config(**{"mikrotik.roles": "block", "mikrotik.routers": "edge2",
                         "mikrotik.edge2.host": "10.2.0.1"})
    check("roles and host are not inherited from the first router",
          [rc.name for rc in r.router_configs(narrowed, "quarantine")] == ["edge2"]
          and r.RouterConfig(narrowed, "nohost", False).get("mikrotik.host") == "")
    hostless = config(**{"mikrotik.host": "", "mikrotik.routers": "a, b",
                         "mikrotik.a.host": "10.4.0.1", "mikrotik.b.host": "10.5.0.1"})
    check("a hostless first router is left out when others are named",
          [rc.name for rc in r.router_configs(hostless, "block")] == ["a", "b"])
    check("every router's address is known, whatever its roles",
          r.router_hosts(many) == ["192.168.1.1", "10.2.0.1", "10.3.0.1"],
          str(r.router_hosts(many)))
    qm = r.Quarantine(config(**{"mikrotik.routers": "edge2",
                                "mikrotik.edge2.host": "192.168.7.1"}), r.Policy(cfg))
    check("no router is ever quarantined, not only the first",
          qm.exempt("192.168.7.1") and qm.exempt("192.168.1.1"))

    print("6. port scanners")
    sp = r.ScanPolicy(cfg, r.Policy(cfg), q.internal)
    check("an external source is eligible", sp.ineligible("198.51.100.7") is None)
    check("an internal one is not, by default (scanners.scope = external)",
          sp.ineligible("192.168.1.99") == "internal")
    check("a router or a whitelist.ips host never is",
          sp.ineligible("192.168.1.1") == "never" and sp.ineligible("192.168.1.53") == "never")
    check("multicast / reserved never are",
          sp.ineligible("224.0.0.5") == "reserved" and sp.ineligible("240.0.0.9") == "reserved")
    allscope = r.ScanPolicy(config(scanners__scope="all"), r.Policy(cfg), q.internal)
    check("scanners.scope = all lets an internal scanner be listed",
          allscope.ineligible("192.168.1.99") is None
          and allscope.ineligible("192.168.1.1") == "never")
    check("listing admits once, then not inside the refresh window",
          sp.admit("198.51.100.7") == "scanner-listing" and sp.admit("198.51.100.7") is None)
    small = r.ScanPolicy(config(scanners__max_per_hour="2"), r.Policy(cfg), q.internal)
    got = [small.admit(f"198.51.100.{n}") for n in range(10, 13)]
    check("the hourly cap holds back the third new source",
          got == ["scanner-listing", "scanner-listing", "scanner-capped"], str(got))
    scan = {"event_type": "alert", "src_ip": "203.0.113.77", "dest_ip": "192.168.1.10",
            "alert": {"signature_id": 2001219, "signature": "ET SCAN Potential SSH Scan",
                      "category": "Attempted Information Leak", "severity": 2}}
    sa = r.ScanPolicy(cfg, r.Policy(cfg), q.internal)
    first, second = sa.decide_alert(scan, 0), sa.decide_alert(scan, 0)
    check("an ET SCAN source is listed on its second alert",
          first == (None, None) and second == ("203.0.113.77", "scanner-listing"),
          f"{first} {second}")
    other = event(scan, alert={"signature": "ET POLICY Something"})
    check("a non-SCAN signature is not", all(sa.decide_alert(other, 0) == (None, None)
                                             for _ in range(3)))
    check("the verdict query is the dashboard's, parameterised",
          "-15m" in sp.query() and ">= 50" in sp.query() and "limit(n: 200)" in sp.query()
          and "completion < 20.0" in sp.query())
    # The shape InfluxDB 2.7 really answers with (captured): a leading empty
    # column, CRLF, and a header per table after a blank line.
    csv_text = (",result,table,src_ip,attempts,targets,services,completion\r\n"
                ",_result,0,198.51.100.7,312,250,3,0.4\r\n\r\n"
                ",result,table,src_ip,attempts,targets,services,completion\r\n"
                ",_result,1,198.51.100.8,90,4,30,2\r\n\r\n")
    rows = r.parse_flux_csv(csv_text)
    check("Flux CSV with a header per table",
          [row["src_ip"] for row in rows] == ["198.51.100.7", "198.51.100.8"]
          and rows[0]["attempts"] == "312", str(rows))
    # One run of the watcher on stubbed Flux rows: every SCAN candidate is a
    # port_scan point whatever happened to it, internal scanners included,
    # and scan_watch is still written.
    class FakeInflux:
        def __init__(self):
            self.points = []

        def point(self, measurement, tags, fields, timestamp_ns=None):
            self.points.append((measurement, dict(tags), dict(fields), timestamp_ns))

    class FakeWorker:
        def __init__(self):
            self.sent = []

        def submit(self, ip, why, ts, target=None):
            self.sent.append(ip)

    real_flux_rows = r.flux_rows
    r.flux_rows = lambda query, timeout=60: [
        {"src_ip": "198.51.100.20", "attempts": "312", "targets": "250",
         "services": "3", "completion": "0.4"},
        {"src_ip": "192.168.1.99", "attempts": "90", "targets": "4.0",
         "services": "30"},                              # completion missing
        {"src_ip": "192.168.1.1", "attempts": "x"},       # a router: never
    ]
    try:
        fi, fw = FakeInflux(), FakeWorker()
        watcher = r.ScanWatcher(r.ScanPolicy(cfg, r.Policy(cfg), q.internal), [fw],
                                fi, __import__("threading").Lock())
        counts, error = watcher.run_once()
        # No router takes the list: detect only, every eligible source is a
        # port_scan point with outcome=detected and nothing is admitted.
        fd = FakeInflux()
        detect = r.ScanWatcher(r.ScanPolicy(cfg, r.Policy(cfg), q.internal), [],
                               fd, __import__("threading").Lock())
        detect.run_once()
    finally:
        r.flux_rows = real_flux_rows
    det = {p[1]["src_ip"]: p for p in fd.points if p[0] == "port_scan"}
    dsw = [p for p in fd.points if p[0] == "scan_watch"]
    check("no router takes the list: SCAN source recorded outcome=detected, state 1",
          det.get("198.51.100.20") is not None
          and det["198.51.100.20"][1]["outcome"] == "detected"
          and det["192.168.1.99"][1]["outcome"] == "internal"
          and len(dsw) == 1 and dsw[0][2]["state_code"] == "1i"
          and dsw[0][2]["detected"] == "1i" and dsw[0][2]["listed"] == "0i", str(det))
    scans = {p[1]["src_ip"]: p for p in fi.points if p[0] == "port_scan"}
    ext, inn, rtr = (scans.get("198.51.100.20"), scans.get("192.168.1.99"),
                     scans.get("192.168.1.1"))
    check("an external SCAN source is listed and recorded scope=external outcome=listed",
          ext is not None and ext[1]["scope"] == "external" and ext[1]["outcome"] == "listed"
          and ext[2]["attempts"] == "312i" and ext[2]["targets"] == "250i"
          and ext[2]["source"] == '"flow"' and fw.sent == ["198.51.100.20"], str(ext))
    check("an internal scanner is recorded scope=internal outcome=internal, not listed",
          inn is not None and inn[1]["scope"] == "internal"
          and inn[1]["outcome"] == "internal" and inn[2]["targets"] == "4i"
          and inn[2]["completion"] == "0.00" and inn[2]["count"] == "1i", str(inn))
    check("a router is recorded as never, with unparseable numbers as 0",
          rtr is not None and rtr[1]["outcome"] == "never" and rtr[2]["attempts"] == "0i",
          str(rtr))
    check("all port_scan points carry the run's timestamp",
          len({p[3] for p in scans.values()}) == 1 and None not in {p[3] for p in scans.values()})
    sw = [p for p in fi.points if p[0] == "scan_watch"]
    check("scan_watch is still written once per run",
          len(sw) == 1 and sw[0][2]["candidates"] == "3i" and sw[0][2]["listed"] == "1i"
          and sw[0][2]["internal"] == "1i" and not error, str(sw))
    check("scope does not follow scanners.scope",
          allscope.ours("192.168.1.99") and sp.ours("192.168.1.99")
          and not sp.ours("198.51.100.20") and not sp.ours("not-an-ip"))
    fa = FakeInflux()
    r.write_port_scan(fa, sa, "203.0.113.77", "listed", "alert", timestamp_ns=123)
    check("an ET SCAN listing is a port_scan point with source=alert",
          fa.points and fa.points[0][1] == {"src_ip": "203.0.113.77", "scope": "external",
                                            "outcome": "listed"}
          and fa.points[0][2]["source"] == '"alert"' and fa.points[0][2]["attempts"] == "0i"
          and fa.points[0][3] == 123, str(fa.points))
    check("a scanner listing joins the decision label",
          r.combine_decision("blocking", None, None, "scanner-listing")
          == "blocking+scanner-listing"
          and r.combine_decision("below-severity", None, None, "scanner-capped")
          == "scanner-capped")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
