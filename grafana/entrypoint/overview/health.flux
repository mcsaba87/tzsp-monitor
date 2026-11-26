import "array"

// One row describing one site, built from the same readings as that site's own
// health tiles and with the same sentinels: a reading that is missing must not
// look like a healthy one. Every metric becomes a (m, v) row so they can all
// share one pivot at the end.
// Seconds since the newest point of a field, looked for over the last 6h.
age = (m, meas, field) => from(bucket: "network_traffic")
  |> range(start: -6h, stop: now())
  |> filter(fn: (r) => r._measurement == meas and r._field == field)
  |> group()
  |> max(column: "_time")
  |> map(fn: (r) => ({k: "x", m: m, v: float(v: int(v: now()) - int(v: r._time)) / 1000000000.0}))

// The newest value of a field inside the dashboard range.
newest = (m, meas, field, start) => from(bucket: "network_traffic")
  |> range(start: start, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == meas and r._field == field)
  |> last()
  |> group()
  |> sort(columns: ["_time"])
  |> last()
  |> map(fn: (r) => ({k: "x", m: m, v: float(v: r._value)}))

// The lowest of each series' newest value: one series per router, and with
// several routers a single one that is down has to read as down.
worst = (m, meas, field, start) => from(bucket: "network_traffic")
  |> range(start: start, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == meas and r._field == field)
  |> last()
  |> group()
  |> min()
  |> map(fn: (r) => ({k: "x", m: m, v: float(v: r._value)}))

// Sum over the dashboard range: per series first so it pushes down.
total = (m, tables) => tables
  |> sum()
  |> group()
  |> sum()
  |> map(fn: (r) => ({k: "x", m: m, v: float(v: r._value)}))

alerts = from(bucket: "network_traffic")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "suricata_alert" and r._field == "count")

ages = union(tables: [
    age(m: "flow_age", meas: "network_flow", field: "bytes"),
    age(m: "ids_age", meas: "suricata_stats", field: "uptime"),
    array.from(rows: [{k: "x", m: "flow_age", v: 99999.0}, {k: "x", m: "ids_age", v: 99999.0}]),
  ])
  |> group(columns: ["k", "m"])
  |> min(column: "v")

levels = union(tables: [
    newest(m: "capture_loss", meas: "suricata_stats", field: "drop_percent", start: v.timeRangeStart),
    newest(m: "disk_used", meas: "disk_guard", field: "used_percent", start: v.timeRangeStart),
    newest(m: "disk_guard", meas: "disk_guard", field: "state_code", start: v.timeRangeStart),
    newest(m: "dns_monitor", meas: "dns_monitor", field: "state_code", start: v.timeRangeStart),
    worst(m: "router_api", meas: "mikrotik_api", field: "up", start: -15m),
    total(m: "traffic", tables: from(bucket: "network_traffic")
      |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
      |> filter(fn: (r) => r._measurement == "network_flow" and r._field == "bytes")),
    total(m: "alerts", tables: alerts),
    total(m: "crit_high", tables: alerts |> filter(fn: (r) => r.severity == "1" or r.severity == "2")),
    total(m: "blocked", tables: from(bucket: "network_traffic")
      |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
      |> filter(fn: (r) => r._measurement == "dns_query" and r._field == "count" and r.result == "blocked")),
    array.from(rows: [
      {k: "x", m: "capture_loss", v: -1.0}, {k: "x", m: "disk_used", v: -1.0},
      {k: "x", m: "disk_guard", v: -1.0}, {k: "x", m: "dns_monitor", v: -1.0},
      {k: "x", m: "router_api", v: -1.0}, {k: "x", m: "traffic", v: 0.0},
      {k: "x", m: "alerts", v: 0.0}, {k: "x", m: "crit_high", v: 0.0},
      {k: "x", m: "blocked", v: 0.0},
    ]),
  ])
  |> group(columns: ["k", "m"])
  |> max(column: "v")

union(tables: [ages, levels])
  |> group()
  |> pivot(rowKey: ["k"], columnKey: ["m"], valueColumn: "v")
  |> map(fn: (r) => ({r with site: "__SITE__", site_uid: "__UID__", reachable: 1}))
  |> drop(columns: ["k"])
