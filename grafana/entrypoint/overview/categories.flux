// Bytes per nDPI category at this site. There are a few dozen categories,
// so all of them are returned and the cross-site sum is exact.
from(bucket: "network_traffic")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "network_flow" and r._field == "bytes")
  |> group(columns: ["category"])
  |> sum()
  |> group()
  |> map(fn: (r) => ({r with bytes: float(v: r._value), site: "__SITE__"}))
  |> keep(columns: ["category", "bytes", "site"])
