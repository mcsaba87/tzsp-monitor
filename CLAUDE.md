# CLAUDE.md

Guidance for Claude Code in this repository. Kept short on purpose: the
rationale behind each service is in its module docstring and inline comments
(read those before changing a service), and the long-form history of this file
is in git (`git log -p CLAUDE.md`).

## Overview

Self-hosted network monitoring, all Docker Compose. A Mikrotik router mirrors
traffic as TZSP to UDP 37008; everything writes to one InfluxDB bucket
(`network_traffic`) and Grafana shows it.

Pipelines:

- **flows**: NIC → `collector` (nfstream, host network) → `network_flow`
- **IDS**: TZSP → `tzsp-decap` (writes inner frames to tap `tzsp0`) →
  `suricata` → `eve.json` → `mikrotik-responder` → InfluxDB + RouterOS address
  lists (block, quarantine, port-scanners) + `dns-filter` blacklist (domains)
- **DNS visibility**: `suricata` DNS events over a unix socket → `dns-monitor`
- **pcap**: `tzsp0` → `pcap-dump` (tcpdump) → rotating files in `PCAP_DIR`
- **ARP**: `tzsp0` → `arp-watch` → bindings + spoofing alerts (no router writes)
- **wireless**: 802.11 TZSP on the same 37008 → `tzsp-decap` forwards to
  `wids:37009` → wireless IDS (no router writes)
- **VXLAN host** (`docker-compose.vxlan.yml`): VXLAN 4789 → `vxlan-tzsp` →
  TZSP → `tzsp-decap`; the collector moves onto `tzsp0`
- **control surfaces** (Grafana → service → router/Suricata): `rule-control`
  (suppress sids, globally or per src/dst IP/CIDR), `dns-filter` (UT1
  categories → `/ip/dns/adlist`), `ip-reputation` (public blocklists → address
  list), `wids` (our SSIDs / BSSIDs), `pcap-dump` (capture on/off/CIDR),
  `alerter` (shell command per alert, optional syslog)
- **support**: `disk-guard` (bounds eve.json and InfluxDB retention under 90%
  disk), `dns-resolver` (PTR, GeoIP, OUI vendor lookups for Grafana)

## Commands

```bash
python3 install.py            # interactive: writes .env, suricata.properties, properties.yml
python3 install.py --check    # read-only probe of host + routers

docker compose up -d --build                 # whole stack
docker compose logs -f <service>

# Rebuild ONE service. Always --no-deps: suricata, pcap-dump and arp-watch live
# in tzsp-decap's network namespace, and anything depending on suricata would
# otherwise recreate tzsp-decap + suricata (ruleset re-fetch, ~1 min IDS hole).
docker compose up -d --build --no-deps <service>
# Property-file / env changes need a recreate, not a restart:
docker compose up -d --force-recreate --no-deps <service>

# Selftests (no test suite/linter exists; these are it). --live variants inject
# synthetic TEST-NET traffic through the running stack and clean up after.
python3 tzsp-decap/selftest.py [--vxlan]     # whole IDS path, sev4 => never touches the router
docker compose exec <svc> python selftest.py [--live]
#   alerter arp-watch disk-guard dns-filter dns-monitor ip-reputation
#   mikrotik-responder pcap-dump wids   (ip-reputation: --feeds downloads feeds)

# Control APIs are unpublished; call them inside the container, 127.0.0.1 not
# localhost (IPv4-only servers). note= is only possible by hand.
docker compose exec rule-control  wget -qO- 'http://127.0.0.1:8020/apply?disable=<sid>[@src|dst|either:<ip/cidr>]&note=...'
docker compose exec dns-filter    wget -qO- 'http://127.0.0.1:8040/status'
docker compose exec pcap-dump     wget -qO- 'http://127.0.0.1:8050/status'
docker compose exec wids          wget -qO- 'http://127.0.0.1:8060/policy'
docker compose exec ip-reputation wget -qO- 'http://127.0.0.1:8070/status'
docker compose exec alerter       wget -qO- 'http://127.0.0.1:8090/status'

# Is the mirror arriving at all? (every IDS/DNS panel depends on this)
docker compose logs --tail=3 tzsp-decap      # [TZSP] ... pps, udp drops

docker exec influxdb influx query --org my-org --token my-super-secret-token '<flux>'
```

Grafana http://localhost:3000 (admin password from `properties.yml`), InfluxDB
http://localhost:8086.

## Traps (read before editing compose or config)

- **Capture namespace coupling.** `tzsp-decap` owns a private netns holding
  `tzsp0` (never the host netns: injected frames would hit the host's IP stack).
  `suricata`, `pcap-dump`, `arp-watch` (and the collector on a VXLAN host) use
  `network_mode: service:tzsp-decap`. Recreating `tzsp-decap` strands them →
  restart them afterwards. `docker compose restart tzsp-decap` is fine.
- **InfluxDB data is in an anonymous volume.** Any change to the `influxdb`
  service recreates it with a fresh empty volume (old data left dangling). Treat
  that block as append-only until the volume is named (needs a data move).
- **`suricata.properties`** (git-ignored, from `.example`) holds router
  credentials and every `<service>.*` key; mounted read-only into most services,
  read once at start. Copy it **before** the first `up`, or Docker creates a
  directory in its place. Deliberately *not* mounted into `alerter` (runs
  dashboard-typed commands) — that one uses `ALERTING_*` env vars from `.env`
  and tokens in git-ignored `alerting.env`.
- **`properties.yml`** (git-ignored) is Grafana's env_file: admin password,
  `REMOTE_SITE_*`, `LOCAL_SITE_NAME`. No router credentials there.
- **Adding the DNS output to a running stack** needs `docker compose up -d
  suricata` (recreate); `restart` keeps old mounts and the socket is missing.
- **`SNIFF_INTERFACE`** (in `.env`) must match the host NIC. Wrong = only
  collector-fed panels go blank; IDS/DNS keep working (decap binds a UDP socket).
- **Addressing differs per service**: collector is `network_mode: host` →
  `http://localhost:8086`; everything else uses `http://influxdb:8086`. Grafana
  reaches services by name (`rule-control:8020`, `dns-filter:8040`,
  `tzsp-decap:8050`/`8051` for pcap-dump, `wids:8060`, `ip-reputation:8070`,
  `alerter:8090`, `dns-resolver:8000`). Published: 37008/udp (decap), 8041/tcp
  (dns-filter hosts files, fetched by the router), 3000, 8086, and 4789/udp
  on a VXLAN host.
- **Dev InfluxDB credentials are plaintext and duplicated** (compose,
  `datasource.yml`, service defaults). Keep them in sync.
- **Code written more than once, between markers — change all copies, `diff`
  must print nothing**: router config lookup (`responder.py`, `filter.py`,
  `reputation.py`, plus `RouterProps` in `install.py`); `geoip.py`
  (`dns-resolver/`, `collector/`); `oui.py` (`dns-resolver/`, `arp-watch/`).
  Each service is its own stdlib-only build context.
- **Scanner verdict is written twice**: `SCAN_QUERY` in `responder.py` must stay
  in step with the candidates query of `port_scanners.json`.
- Docker json logs are capped by the `x-logging` anchor (not on `influxdb`).

## Conventions shared by the services

- **Stdlib-only Python** on `python:alpine` (urllib for RouterOS REST and
  InfluxDB line protocol), except the collector (nfstream).
- **Control-surface pattern** (rule-control, dns-filter, ip-reputation, wids,
  pcap-dump, alerter): Grafana's Infinity datasource fetches `/apply?...` on
  every panel refresh, so a data link filling a variable = one click = one call.
  Consequences, all to be preserved:
  - endpoints are **idempotent** (boxes are re-sent every refresh; only a real
    change writes, reloads and audits);
  - each link **clears the opposite box**; sticky boxes default to `-`;
  - **anyone who can view the dashboard can act** (Infinity uses the
    datasource's identity) → per-service read-only switch
    (`*.control_enabled = false` / `ALERTING_CONTROL=ro`), and an audit
    measurement (no *who*, except pcap downloads via `X-Grafana-User`);
  - control ports are **never published**; anything the outside must fetch is
    a separate read-only listener (dns-filter 8041, pcap-dump 8051 via Grafana's
    datasource proxy);
  - `site=<uid>` gate: act only when it is `InfluxDB_Flux` or absent;
  - the dashboard owns the state (state volume); property-file values only seed
    the first start;
  - `/apply` records intent and returns; a worker records the outcome.
  - alerter additionally: typed commands are only *staged* until a one-time
    confirm code; test links are one-shot; commands run as nobody with a clean env.
- **Router writes** (responder, dns-filter, ip-reputation) need RouterOS 7.1+
  REST (`www-ssl`; adlist needs 7.15+). Lists block nothing until a hand-made
  firewall rule references them (deliberate). Entries carry router-side
  timeouts so the stack fails open. Several routers: `mikrotik.routers` +
  `mikrotik.<name>.<key>` (falls back to unprefixed key, except `host`/`roles`);
  decisions are made once and fanned out with one worker/queue per router;
  tiles show the worst router; no router address is ever blocked/quarantined.
- **Responder gates** (whitelist/reserved, `max_severity`, `min_alerts` in
  window, `max_age_seconds`, refresh throttle, router timeout) and hourly caps
  on quarantine/domains/scanners exist for specific failure modes — don't
  loosen without reading `responder.py`.
- **Health tiles read a `state_code` computed in the service**, never derived
  in the panel, and tiles union a `-1` sentinel so "stopped" ≠ "healthy empty"
  (sentinel type must match the field: `-1.0` vs `-1`).
- **Counters are written as deltas** (+ `*_total`), because sources reset on
  restart.
- **Cardinality rule**: groupable low-cardinality values are tags; anything
  high-cardinality (ports, payloads, details, station MACs, query names except
  blocked ones) is a field. Port-like things get bucketed tags (`service`) with
  the raw value as a field.
- **Suricata**: `suricata.yaml` holds only deltas from defaults (checksums off,
  full stock `port-groups`, modbus/dnp3 on). `HOME_NET` comes from
  `suricata.home_net` via the entrypoint. Rules download only on start (if >24h
  old); reloads go through the unix command socket in the `suricata-control`
  volume — **messages must end with `\n`**. Rules are suppressed via
  `threshold.config`, not removed. eve.json has only `alert` + `stats`
  (`rotate-interval` is inert on 8.0.6; `disk-guard` rotates it via
  rename + `reopen-log-files`). DNS goes to a second eve output on a unix
  socket; in a DNS *response* event the client is `dest_ip`.
- **disk-guard** never deletes the live eve.json or InfluxDB points: it rotates
  and prunes rotations by byte budget, and lowers bucket retention stepwise
  (with cooldown, floor, and a refusal when the bucket isn't the problem).
- **Collector schema** (`network_flow`): `duration_ms` is saturated by
  `active_timeout=5` (useless); `statistical_analysis=True` is required for
  syn/rst/fin/ps fields; country tags only when a GeoIP DB is present. Older
  points lack newer tags — filter out empty tag values.

## Measurements (all in `network_traffic`)

Field lists are in the writing service; this is the index.

| Service | Measurements |
|---|---|
| collector | `network_flow` (tags src/dst_ip, protocol, application, category, service, server_name, src/dst_country) |
| tzsp-decap / vxlan-tzsp | `tzsp_decap`, `vxlan_tzsp` |
| responder | `suricata_alert`, `suricata_block` (tag `router`, `list`), `suricata_stats`, `mikrotik_api`, `scan_watch`, `port_scan` |
| rule-control | `suricata_rule_control` |
| dns-filter | `dns_filter_control`, `dns_filter_list`, `dns_filter_router`, `dns_filter_status` |
| dns-monitor | `dns_query` (src_ip, result), `dns_block` (src_ip, qname), `dns_monitor` |
| disk-guard | `disk_guard`, `disk_guard_action` |
| pcap-dump | `pcap_dump`, `pcap_dump_control` |
| arp-watch | `arp_binding`, `arp_alert`, `arp_watch` |
| wids | `wids_alert`, `wids_ap`, `wids_probe`, `wids_channel`, `wids_sensor`, `wids_policy_control`, `wids` |
| ip-reputation | `ip_reputation_status`, `_router`, `_feed`, `_sync`, `_control`, `_hit`, `_hits` |
| alerter | `alert_dispatch`, `alerter`, `alerting_control` |

Severities everywhere use Suricata's 1 (critical) – 4 (info) scale.

## Grafana

- **Provisioning** (`grafana/provisioning/`): one dashboard provider per section
  folder (`overview/`, `traffic/`, `security/`, `dns/`); a new dashboard = a
  JSON file in the right folder **plus a line in
  `grafana/entrypoint/home.json`** (the hand-ordered home page). Pin a `uid` on
  every dashboard. Datasource uids are pinned (`InfluxDB_Flux`); changing one
  needs `--force-recreate grafana`. `grafana.ini` replaces the image config
  (restart after editing); branding is overwritten at start by `branding.sh`.
- **Sites**: each `REMOTE_SITE_<NAME>` becomes datasource `site-<name>`; every
  dashboard but `dns_filter.json` has a `Site` variable; in-dashboard links
  carry `${site:queryparam}`. Sites are never merged (private ranges overlap).
  Controls and PTR lookups never follow the Site box. `Sites Overview` is
  **generated** by `sites.sh`/`expand.awk` from
  `grafana/entrypoint/overview/` (edit there, then restart grafana).
- **Flux cost rules** (prod: ~200k points/h, 3.5k hosts, 30s timeout — local
  speed proves nothing; verify with `POST /api/ds/query` against prod):
  - `sum/count/min/max/first/last/aggregateWindow` push down; `map`, `reduce`,
    `contains` do not → aggregate first, per-row work after.
  - no `group()` before `aggregateWindow`; aggregate per series, group, again.
  - filter tags with anchored regex, not `contains()` (except values with `/`).
  - bound series (<1000): group / threshold / top-N anything per IP.
  - timeseries buckets: `spanNs / 96` floored, with `timeSrc: "_start"` and
    `barAlignment: 1` so zooming selects what drew the bar.
  - after `pivot`, `map` only with `{r with ...}` (a new record can return empty).
- **`cidr` box**: compiled to an anchored prefix regex (pushes down), rounds to
  octet boundaries (wider, never narrower). Inlined into every `network_flow`
  query. Not on `network_health`, `subnet_*`, `host_drilldown`, control boards.
- **Panel gotchas**:
  - tables joining Infinity (hostname/country) must **not** set a panel-level
    InfluxDB datasource (the Infinity target is silently dropped) and need
    `renameByRegex` (`^host.*$`, `^country.*$`) before `organize` (joinByField
    suffixes `host B`).
  - pin colours per series with overrides (status colours are for tiles only);
    pair every status colour with a word; sid/ID columns `unit: none`, links use
    `${__value.raw}`.
  - data links can only read fields that survive transforms (hide with
    `custom.hidden`), and must name each variable once.
  - custom variable options must use `label : value` form or labels are lost.
  - `nodeGraph` (camelCase) ignores units/display names → format strings in Flux.
- `network_health.json` is a wallboard: original schema only, measured
  thresholds, sentinels, no cidr box.
- Reverse DNS / GeoIP / OUI come from `dns-resolver` (`/resolve?ips=`,
  `/vendor?macs=`) through Infinity (`parser: "backend"`); GeoIP and OUI DBs are
  local copies it downloads (`GEOIP_UPDATE` / `OUI_UPDATE=false` for offline).
