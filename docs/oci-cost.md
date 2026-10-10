# OCI cost: spend, forecast and budget (TS-807)

Status: design for TS-807. Each section names the slice that implements it.

Every region reports its own OCI spend, forecasts it and checks it against
its budget cap. The dashboard and the capacity controller (TS-804) read the
same numbers from the same record. Adding a region needs no code, setting or
manual step: its controllers find their OCI region from the cell token and
start reporting.

## Rules

1. **One record per region.** The regional authority leader reads its own
   OCI region's cost every hour and writes one report to the region's NATS
   KV. Everything else reads that report.
2. **One forecast.** `ocicost.Project` is the only projection. The dashboard
   shows it, the budget state is computed from it and the host pool budget
   gate admits launches against it.
3. **No stored credential.** The collector uses the controller's instance
   principal, like the region subscription code. No secret exists to copy,
   rotate or leak.
4. **No region list.** The cell token gives the OCI region; the dashboard
   asks every region in the roster ([registry](region-registry.md)).

## Collection

Slice: collector.

The regional authority leader runs `ocicost.Collector` at start and every
hour; after a failed read it retries after five minutes. It calls the OCI
Usage API (`RequestSummarizedUsages`, served by the tenancy's home region)
with the instance principal, filtered to its own OCI region:

| Query | Granularity | Range | Grouping | Gives |
| --- | --- | --- | --- | --- |
| days | `DAILY` | first day of the rate window or of the month, whichever is earlier, to tomorrow | none | daily totals, today partial |
| services | `MONTHLY` | first day of the month to tomorrow | `service` | month to date by service |
| components | `MONTHLY` | first day of the month to tomorrow | `tagNamespace`, `tagKey`, `tagValue` | month to date by freeform tag `terrascale-component` |

The Usage API refuses a region filter together with `groupByTag`, so the
component query groups by tag dimensions instead and keeps only the
`terrascale-component` rows (checked live 2026-10-10). Cost without that tag
is "untagged": month to date minus the tagged lines.

The report is cached in KV bucket `TS_OCI_COST`, key `report`, replicated
like the cell's other buckets, history 1:

```json
{
  "version": 1,
  "cell": "gru",
  "oci_region": "sa-saopaulo-1",
  "currency": "BRL",
  "observed_at": "2026-10-10T19:00:00Z",
  "through": "2026-10-08T00:00:00Z",
  "days": [{"day": "2026-10-01T00:00:00Z", "cents": 267}],
  "services": [{"name": "Block Storage", "cents": 807}],
  "components": [{"name": "terrabase", "cents": 437}]
}
```

- Amounts are whole cents of the tenancy currency. A day or line rounds up;
  credits count as zero. One currency per report; a mixed answer is refused.
- `through` ends the last complete day: today's midnight minus 48 hours
  (`UsageLag`), because OCI usage data arrives late.
- Bounds: at most 64 days and 64 lines of each kind; a larger or malformed
  answer is refused and the previous report stays.

Followers never call OCI. A report older than six hours (`MaxReportAge`) is
stale: the dashboard says so and the budget state is `unknown`.

The controllers need one tenancy statement that names no region:
`Allow dynamic-group <every region's controllers> to read usage-report in tenancy`.
TS-803 owns that region-agnostic controller group. Until it exists the
collector's error shows on the dashboard; no per-region statement is added.

## Forecast

Slice: collector.

`ocicost.Project(report, now, hosts)`, where hosts are the autoscaled hosts with their creation time and monthly list price:

| Number | Method |
| --- | --- |
| Month to date | Sum of this month's days, including the partial ones after `through`. Matches the OCI console. |
| Daily rate | Average of the 7 complete days before `through` that have usage (a new region averages the days it has). |
| Pending autoscale | Cents a day not yet in the average: for each pool host launched inside or after the 7-day window, its list price for the window days it missed. TS-804's cell autoscaler adds its own launches the same way. |
| Month end | This month's complete days + (daily rate + pending) × days from `through` to month end. |
| Next month | (daily rate + pending) × days in next month. |

Hosts removed during the window still count in the average until it moves
past them, so a scale-down shows late. A region whose cost is ramping up (a
new region) forecasts low until its complete days catch up; usage data lags 48 h.

## Budget cap

Slice: collector.

The cap is the cell spec's signed `budget` (`monthly_cap_cents`, `currency`).
`projected = max(month end, next month)`:

| State | When |
| --- | --- |
| `none` | the cell spec sets no budget |
| `unknown` | no report, a stale report, or a currency other than the cap's |
| `ok` | projected < 80 % of the cap |
| `warn` | projected ≥ 80 % (TS-804 raises the alert) |
| `over` | projected ≥ the cap |

The host pool budget gate (`hostpool`) admits a launch while its monthly
price fits in `cap − projected`, and holds every launch when the state is
`unknown`. Its own per-tick OCI reader (`hostpool.OCIUsage`, `Spend`) is
deleted: it reads the KV report every tick instead.

## Dashboard

Slice: dashboard.

- The region summary (`ts.orch.v1.<cell>.obs.region`, `regionview.Summary`)
  gains `cost`: the report's month to date, the forecast, the budget state
  and at most 32 service and 32 component lines. No new subject is needed,
  so `query.cost.v1` from the registry table stays unused.
- `/cost` sums every region's `cost` (one currency) and lists:
  totals, a row per region (month to date, daily rate, pending, month end,
  next month, budget and state, data through, observed), month to date by
  service and by component, and the method above with each region's numbers
  filled in.
- The landing page gets an "OCI spend" tile linking to `/cost`.
- A region that does not answer shows as unknown; totals say "partial".

## Tags

Slice: tags.

Two freeform tags, the house `terrascale-*` convention, which the Usage API
groups by (checked live):

| Tag | Value |
| --- | --- |
| `terrascale-region` | the region as the fleet already writes it, `strings.ToUpper(cell)` (`GRU`) |
| `terrascale-component` | one of `controller`, `terrabase`, `node-pool`, `apps`, `network`, `releases`, `images`, `disaster-recovery`, `storage` |

Freeform, not defined tags: no tenancy namespace to create, no new IAM verb,
and the existing tag writers only replace freeform tags by merging.

**One reconciler stamps everything.** 52 create sites exist, almost all in
operator CLIs that set no tags at all, and implicit boot volumes never carry
any. Changing each of them would still leave the existing resources, so the
regional authority leader runs one pass an hour, `ocicost.Tagger`:

1. Resource Search in its own OCI region for `Instance`, `BootVolume`,
   `Volume`, `BootVolumeBackup`, `VolumeBackup`, `Image`, `Bucket` and
   `LoadBalancer` (the billable types). The controller's IAM limits the
   results to its own compartments; the CLI names compartments explicitly.
2. Infer the component from marks the resource already has, first match:

   | Mark | Component |
   | --- | --- |
   | `terrascale-component` already valid | unchanged |
   | `terrascale-dr-source` | `disaster-recovery` |
   | `terrascale-resource` `member-*`, `terrabase-host`; `ts-role=db` | `terrabase` |
   | `terrascale-resource=managed-volume`, `terrascale-app` | `apps` |
   | `ts-pool` | `node-pool` |
   | name (boot volume: its instance's name) with `-ctl-` or `ts-<cell>-<n>` | `controller` |
   | name with `-db-` | `terrabase` |
   | name with `-pool-` | `node-pool` |
   | `Bucket` ending `-backup` / `-head` / `-material` or `-ledger` | `terrabase` / `releases` / `controller` |
   | other `Bucket` | `storage` |
   | `Image` | `images` |
   | `LoadBalancer` | `network` |

   No match: the resource stays untagged and is counted, never guessed.
3. For a resource whose two tags differ: read it, merge the two keys into
   its freeform tags and update with `If-Match` on the read ETag. A changed
   ETag skips it until the next pass. A permission error skips it and is
   counted.
4. Resources younger than one hour are skipped, so a pass never changes an
   ETag in the middle of a create flow. The TerraBase fleet stamps
   `terrascale-component=terrabase` itself at create (`hostTags`,
   `volumeTags`, backup planner), so its new resources never need a pass.

Cost before a resource is tagged stays "untagged" in that month's lines;
tags are not retroactive in OCI usage data.

IAM: the controllers already manage `instance-family` and `volume-family`
in their compartments. Buckets, images and load balancers need update
rights in the region-agnostic controller group (TS-803); until then
`ts-orch cost tag` with the operator's config stamps them.

## CLI

Slices: collector and tags.

- `ts-orch cost report --region <oci-region>` runs the collector once with
  the operator's OCI config and prints the report and forecast. It is how
  numbers are checked before a release reaches a region.
- `ts-orch cost tag --region <oci-region> --compartment <ocid>...` prints
  the tag plan for those compartments with the operator's OCI config, and
  applies it with `--apply`. It only touches the named compartments.

## Slices

1. Design (this document).
2. Collector: `internal/ocicost` (report, Usage API reader, KV store,
   forecast, budget state), the leader loop, the hostpool switch and
   `ts-orch cost report`.
3. Dashboard: summary field, `/cost`, landing tile.
4. Tags: reconciler and `ts-orch cost tag`; live pass in GRU and SFO.

## Coordination

- TS-803: registry, roster and the controller IAM group.
- TS-804: reads `ocicost.Report`/`Project` and the budget state; adds its cell
  autoscaler's pending launches; owns the 80 % alert.
- TS-805: global dashboard pages read the summary field.
