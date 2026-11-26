// Top 50 blocked names at this site (dns-monitor's dns_block). `(capped)` is
// the overflow bucket, not a domain -- see dns-monitor in CLAUDE.md.
from(bucket: "network_traffic")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "dns_block" and r._field == "count")
  |> group(columns: ["qname"])
  |> sum()
  |> group()
  |> top(n: 50)
  |> map(fn: (r) => ({r with lookups: float(v: r._value), site: "__SITE__"}))
  |> keep(columns: ["qname", "lookups", "site"])
