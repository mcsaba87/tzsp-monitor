// Top 50 signatures by alert count at this site; summed across sites by the
// panel, with the same top-N caveat as the applications.
from(bucket: "network_traffic")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "suricata_alert" and r._field == "count")
  |> group(columns: ["signature", "severity"])
  |> sum()
  |> group()
  |> top(n: 50)
  |> map(fn: (r) => ({r with alerts: float(v: r._value), site: "__SITE__"}))
  |> keep(columns: ["signature", "severity", "alerts", "site"])
