// Top 50 applications by bytes at this site. The panel sums these across
// sites and shows 10: an application ranked below 50 at every site can be
// missing from the combined list, which is the price of not moving raw data.
// Each row carries its site, so two sites reporting the same name and the same
// number stay two rows when the panel merges them, instead of collapsing.
from(bucket: "network_traffic")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "network_flow" and r._field == "bytes")
  |> group(columns: ["application"])
  |> sum()
  |> group()
  |> top(n: 50)
  |> map(fn: (r) => ({r with bytes: float(v: r._value), site: "__SITE__"}))
  |> keep(columns: ["application", "bytes", "site"])
