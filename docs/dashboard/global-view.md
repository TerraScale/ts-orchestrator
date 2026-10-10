# Global dashboard view (TS-805)

Status: design for TS-805. It supersedes TS-794 (its PR #363 was closed
unmerged) and replaces the per-page region fan-out on main. It builds on the
TS-803 [region registry and subject interface](../region-registry.md).

Every region's dashboard shows the whole global deployment: every region,
node, volume, service and NATS link. It stays fast at 20 regions × 12 nodes.
Adding a region adds a row; nothing is configured anywhere.

## Budget

- Overview first paint at 20 regions: under 500 ms and under 100 KB on the
  wire. That covers the gzip HTML plus render-blocking CSS. Deferred scripts
  and the world map load after first paint.
- No page load or stream tick sends a NATS request to another region.
- A test with 20 simulated regions of 12 nodes measures both limits on every
  PR (`internal/dashboard`, `TestOverviewBudgetTwentyRegions`).

## Data path

```
region leader --5 s--> ts.orch.v1.<cell>.region.rollup --> every controller's globalview.View
                                                       \-> TS_DASHBOARD_ROLLUPS[<cell>] (last-known, 30 s)
pages + SSE stream <-- View (memory only)
```

1. **Publish.** Every 5 s, each region's authority leader
   (`fencer.Current().CanMutate()`) builds one `globalview.Rollup` from local
   state only and publishes it on `ts.orch.v1.<cell>.region.rollup`. Followers
   publish nothing.
2. **Follow.** Every controller subscribes to `ts.orch.v1.*.region.rollup`
   and keeps the newest rollup per region in memory. Decoding is tolerant
   (`protocol.DecodeTolerant`), so during a rolling upgrade an older region
   accepts a newer region's added fields. The subject cell must equal the
   payload cell.
   Messages are capped at 256 KB, and an older `observed_at` is ignored.
3. **Last-known.** The leader writes each region's newest rollup to KV
   bucket `TS_DASHBOARD_ROLLUPS`, key `<cell>`, at most every 30 s per region.
   The bucket is regional, file-backed, uses the cell's replicas and keeps
   history 1. On start, the view loads every key before it subscribes.
4. **Which regions.** The region list is `regionlink.Requester.Regions()`,
   which the TS-803 roster feeds. A roster region with no rollup yet shows
   `no data`. A region that leaves the roster leaves the view, and the leader
   deletes its KV key.
5. **Freshness.** A rollup older than 20 s (four missed publishes) is
   `stale`. The page keeps its last-known values with a stale badge and
   `last seen <age>`. TS-796's probe decides `unreachable`. Staleness alone
   never marks a region down.

Traffic at 20 regions: one roughly 10 KB message per region every 5 s,
about 40 KB/s into each controller. The view holds at most 32 rollups.

### Subject and grants (proposed to TS-803)

`region.rollup` is a broadcast fact about one region, like `region.health`.
The grants are pattern-based and never name a region:

| Role | Publish | Subscribe |
| --- | --- | --- |
| controller | own `ts.orch.v1.<cell>.region.>` (already in own-cell grant) | `ts.orch.v1.*.region.>` |
| link (leaf) | own `ts.orch.v1.{{tag(cell)}}.region.>` | every `ts.orch.v1.*.region.>` |

`protocol.RegionRollupSubject(cell)` names the subject.

## Rollup v1

One JSON object per region. It holds compact current values, not history.
Lists are capped. A capped list sets `truncated`.

| Field | Content | Local source |
| --- | --- | --- |
| `version`, `cell`, `observed_at` | `1`, cell token, build time | |
| `health` | status (`healthy`/`degraded`/`critical`), score, reasons | `regionview` score |
| `quorum`, `leaders`, `versions` | controllers expected/ready, authority and meta leader, build → count | cluster snapshot |
| `totals` | nodes, ready nodes, CPU cores and used, memory, disk, network rx/tx bytes/s, load | sum of `nodes` |
| `nodes` (≤ 64) | name, health, CPU, memory, disk, network rx/tx, load 1m, report time, services (role, state, digest), distinct filesystems | host reports (`hostload`), host grants |
| `volumes` (≤ 256) | ID, node, state, detail, state since | `insights.VolumeProvider` |
| `links` (≤ 32) | per peer region: RTT, TerraBase replication lag, reach, last error, observed time | TS-796 link probe, TerraBase WAN report |
| `routes` (≤ 64) | controller → controller NATS routes inside the region: RTT, JetStream lag, error | cluster snapshot `RouteRTTs`, `MetaPeers` |
| `replication` | worst inbound TerraBase replication lag (seconds, groups) | TerraBase WAN report |
| `autoscale` | per service: replicas, goal, reason | `workload.Reconciler` |
| `cost` | per hour now, month to date, month forecast, currency (TS-807) | TS-807 |
| `databases` (≤ 10) | top databases by replication bytes/s, with lag (TS-806) | TS-806 |
| `errors` (≤ 10) | newest errors: time, node, component, message (TS-808) | leader event bus, TS-808 |

Host reports gain three fields: `net_rx_bps`, `net_tx_bps` (from
`/proc/net/dev`, every non-loopback interface) and `load1` (`/proc/loadavg`).
Controllers decode host reports strictly, so controllers must update before
hosts do. The TS-803 adoption already orders them that way.

### Sections other tickets fill

`globalview.Sources` has one function per section. Each function returns that
feature's latest cached value. It must not do I/O, because the publisher calls
it every 5 s. A nil result renders as `not reported`. Owners wire their
function in `internal/app`. Section types live in `globalview` and are part of
rollup v1. Adding a field is compatible; renaming or removing a field is not.

| Section | Owner | Type |
| --- | --- | --- |
| `databases` | TS-806 | `[]Database{Name, ReplicationBytesPerSecond, LagSeconds}` |
| `cost` | TS-807 | `Cost{Currency, PerHour, MonthToDate, MonthForecast}`: this region's resources only |
| `errors` | TS-808 | `[]Error{At, Node, Component, Message}` |

The budget cap is global, not per region: TS-804 keeps one `KindBudget`
document in `TS_GLOBAL_CONTROL`. The overview reads it from the region's own
mirror and compares it with the sum of every region's `cost.month_forecast`.

Drill-down into these features (full log search, per-database history, cost
breakdown) uses each owner's `query.<verb>.v1` service for one region.

## Pages

All global pages render from the view. Each page uses the existing Datastar
SSE stream: it re-renders from memory every 2 s and sends a patch only when
the HTML changed.

| Page | Shows |
| --- | --- |
| `/` Overview | Global totals; world map; region table (health, stale badge, nodes, CPU/memory/disk/network, load, replication lag, cost, autoscale); region × region link matrix (RTT, lag, last error); top databases; recent errors |
| `/regions/<cell>` | Region totals, node table, controller × controller route matrix, volumes, autoscale, cost, errors |
| `/regions/<cell>/nodes/<node>` | Node values, services, volumes |
| `/regions/<cell>/volumes/<id>` | Volume, its node and the services on that node |
| `/regions/<cell>/nodes/<node>/services/<role>` | Service state, digest, autoscale state |
| `/nodes`, `/volumes` | Every region's nodes or volumes, region filter, sort, 50 rows per page |

HTML pages are served gzip-compressed when the client accepts it.

The local region's deep pages (`/members`, `/nats`, `/storage`,
`/terrabase`, `/topology`, `/insights`, history charts) stay local and
unchanged. Remote history charts are not part of the global view. To see a
remote region's history, open that region's own dashboard.

## Deleted

From main:

- `regionview.Provider.Regions` fan-out and its cache. The region switcher,
  `/v1/regions` and the insight engine read the view.
- The old `/` global page (`global.go`, `global.templ`) and the remote-region
  summaries of `/region?r=`, replaced by `/` and `/regions/<cell>`.

The `obs.region` summary responder stays: TS-796's link probe and WAN check
use it.

## Slices

1. This design.
2. Host network/load fields and the `globalview` package: rollup, publisher,
   view, last-known KV, wiring, and a 20-region embedded-NATS test.
3. Overview, region, node, volume and service pages, `/nodes` and
   `/volumes`, gzip, and the budget test.
4. Delete the region fan-out and the old global page, and move
   `/v1/regions` and insights to the view.
5. Live proof from the GRU and SFO URLs with timings, after the TS-803
   adoption links both regions.
