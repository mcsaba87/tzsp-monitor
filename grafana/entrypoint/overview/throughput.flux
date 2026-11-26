// This site's throughput in bits/s, as one series labelled with the site, so
// the panel can stack the sites. Same ~96-bucket window as the other boards.
spanNs = int(v: v.timeRangeStop) - int(v: v.timeRangeStart)
everyNs = if spanNs / 96 < 60000000000 then 60000000000 else spanNs / 96
every = duration(v: everyNs)

from(bucket: "network_traffic")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "network_flow" and r._field == "bytes")
  |> aggregateWindow(every: every, fn: sum, timeSrc: "_start", createEmpty: false)
  |> group()
  |> aggregateWindow(every: every, fn: sum, timeSrc: "_start", createEmpty: false)
  |> map(fn: (r) => ({r with _value: float(v: r._value) * 8.0 / float(v: everyNs) * 1000000000.0, site: "__SITE__"}))
  |> group(columns: ["site"])
  |> keep(columns: ["_time", "_value", "site"])
