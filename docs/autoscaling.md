# Autoscaling

> Superseded by [capacity](capacity.md) (TS-804) for node pools and the budget cap. This page and its code are deleted in TS-804's last slice.

TS-565 makes ts-orch scale on its own: replicas follow load, and node
pools of OCI A1 hosts follow the replicas, within a monthly budget cap from
the cell spec. This note records the design and the slice order.

## Reuse of the earlier autoscaler work

TS-565 reuses the earlier autoscaler work and replaces none of it:

| Package | From | Role in TS-565 |
| --- | --- | --- |
| `internal/autoscale` | #124 | Pure replica decision: target per signal, tolerance, stabilization windows, cooldowns, step limits. The horizontal autoscaler of every app. |
| `internal/workload` | #124, #135 | Level-triggered reconciler of `ServiceSpec`s (min/max, scaling policy, rollout limits) on the authority leader. Asks a node pool for capacity when placement fails. |
| `internal/hostload` | #139 | Metrics pipeline: host agent → `load` host operation over NATS → per-node windows on the leader. |
| `internal/hostpool` | #124, #135 | Cluster autoscaler planner: fewest pool hosts that fit unplaceable demand, idle reclaim after a cooldown. Recommend-only until now. |
| `internal/cellscale` | TS-476 (#150) | TerraBase db-cell autoscaler with the node pressure contract. It stays the scaler of TerraBase cells; pool hosts never hold TerraBase seats. |

The `cos-hold/ts-476-autoscaler` branch merged as #150; nothing on it is
left to port.

## Slices

1. **Budget cap** (#202). A `budget` section in the cell spec, spend from
   the OCI usage API, and a gate that holds pool launches the cell cannot
   afford.
2. **Pool hosts**, in three PRs; only the last wires launches into the
   controller, so a launched host can always enroll:
   1. Pool host names and membership (#212): see [pool hosts](#pool-hosts).
   2. The OCI provisioner (this PR): see [launching](#launching-pool-hosts).
   3. Enrollment: a pool host enrolls only when OCI shows the tagged
      instance at its address; the controller wires the provisioner.
3. **Drain-first scale-down.** Cordon an underused pool host, let the
   reconciler move its replicas within rollout and quorum limits, then
   reclaim it. Node pools move into the cell spec so `ts-orch apply` edits
   them; while a budget is set, a lower host price or a higher pool `max`
   then needs a root.
4. **App signals.** Requests per second, p95 latency, connections and queue
   depth from workloads into host load reports and new scaling signals.

Region bring-up from one `ts-orch apply` (VCN, LB, DNS, hosts) goes through
the existing OCI reconcilers and region lifecycle; it is tracked after these
slices.

## Pool hosts

A node pool's hosts are cell servers named `<cell>-pool-<pool>-<n>`
(`gru-1-pool-app-3`, `internal/naming`), so a pool name is 2 to 12
lower-case letters and digits. With a provisioner, OCI is the truth about
which pool hosts exist, because a host registration outlives its host:

| OCI holds the host | Host registration | The scaler sees |
| --- | --- | --- |
| yes | live session | a member: capacity, reclaimed when idle |
| yes | none | a launch in progress, also one a former leader made; terminated (`launch-expired`) without a live session within the 15-minute launch grace |
| yes | silent session | neither capacity nor free: it keeps its name for host repair (TS-568) |
| terminating | any | not capacity; its name is free once OCI deleted it |
| no | any | a stale registration; the name is free and a new host registers its next generation |

Without a provisioner (recommend-only), registrations with a live session
are members and silent ones keep their names. A provisioner launches only
under a cell budget (`hostpool.budget-missing` otherwise).

## Launching pool hosts

`hostpool.OCIProvisioner` launches a pool host from the cell's managed OCI
region config (compartment, availability domain, subnet, NSGs) and boots
the image new managed hosts boot: the cell spec's `launch_image`, or the
fleet pin ([image updates](image-updates.md)). The image is qualified when
chosen and again right before the launch, under the cell spec version that
chose it, which stays fenced until OCI answers. The pool's shape sizes the A1 Flex host: CPU cores are
OCPUs, memory is whole GiB, and the disk is the boot volume (at least 50
GB). The pool's failure domains are OCI fault domains in lower case
(`fault-domain-1`).

- **Identity.** The display name and hostname are the pool host name. The
  host boots the image with the cell's launch material (the public
  enrollment bundle) and a static boot descriptor naming it, and enrolls
  like any static host.
- **Ownership.** Every host carries `ts-cell`, `ts-pool` and
  `ts-launch-token` tags. The provisioner reports, adopts and terminates
  only this cell's tagged pool hosts: an untagged instance holding a pool
  host's name is refused, never adopted or terminated, so a TerraBase or
  controller server is out of its reach.
- **Idempotent launches.** A launch first asks OCI for a host of that name.
  Its retry token and exact request are journaled in `TS_HOSTPOOL_LAUNCHES`
  before the request, with an attempt count. While OCI keeps the token (23
  hours) every retry replays that exact request and token, also by a new
  leader and whatever the pool or launch image is by then; its image is
  admitted again under the current cell spec. Only a fresh launch whose
  single attempt OCI refused without effect (quota, limits, bad request)
  forgets its token; a refused replay proves nothing about the first
  request. Each tick makes one attempt; the SDK does not retry a launch.
- **Reclaim** first retires the host: a mark in host state that every
  desired commit reads, so a later leader enforces it too. In the leader's
  process the mark and the allocation check are one step against desired
  writes; a host that holds an allocation is not retired, and a retired host
  takes no new one (withdrawals still apply). Only then is the host
  terminated with its boot volume. A retired host stays retired whatever
  the termination's outcome; only a new host launched under its name
  returns it.

## Budget

The cell spec's optional `budget` caps what node pools may add to the
cell's OCI region:

```json
"budget": {"monthly_cap_cents": 50000, "currency": "BRL"}
```

Every node pool names what one of its hosts costs per month,
`host_monthly_cents`; a spec with a budget is refused while a pool has
none. The pool scaler reads the region's spend from the OCI usage API and
admits a pool's launches only while

```
projected spend + (unbilled + new hosts) x host_monthly_cents <= cap
```

- **Spend.** Daily cost of the cell's OCI region (every compartment and
  environment in it), read in the tenancy's home region, which serves the
  usage API. The `region` filter takes the full name (`sa-saopaulo-1`; the
  key `GRU` matches nothing). An answer without rows is no cost only in a
  new cell: until the data covers a whole day after the cell's replicated
  authority log was created, a date restarts and failovers keep. After
  that, or when the log cannot be read, it is a broken query and holds
  launches. A day
  counts once it ended at least 48 hours ago (`Through`). Days round up to
  whole cents; credits count as zero. The currency is the tenancy's billing
  currency: TerraScale's is BRL.
- **Projection.** The larger of this month (its complete days, then the
  costliest of the last three complete days repeated until the month ends)
  and a whole month at that peak day, so the cap also holds next month.
- **Hosts.** Each new host costs its full monthly price, whatever the day:
  a host launched on the 30th still costs its full price next month.
- **Unbilled hosts.** A pool host is in the reading once a whole complete
  day followed its creation in OCI. Until then it is charged on top, so
  launches add up across ticks while the data lags, also across failovers:
  the creation time comes from OCI, not the leader's memory.
- **Whole plans.** A pool's planned launches pass or hold together: part of
  a plan may place nothing. Pools take the headroom in config order.
- **Reads.** At most hourly; after a failed read or once a new month began,
  again within five minutes. A failed read keeps the last good reading for
  up to six hours.
- **Fail closed.** No usable reading (none, older than six hours, from
  another month, in another currency) or a pool without a price holds every
  launch. Holds and their end are journaled (`hostpool.budget-capped`,
  `hostpool.budget-unknown`, `hold_cleared`). A missing usage policy shows
  as a lasting `budget-unknown` hold, also for launches up to a pool's `min`.
- **Never removes capacity.** Over the cap, launches stop. Idle reclaim
  keeps its normal rules; nothing is terminated to save money.
- **Without a budget** pools recommend as before, and a provisioner launches nothing.
- **Not TerraBase.** `cellscale` sizes TerraBase db cells under its own
  `monthly_budget`; this cap gates pool launches only, but the spend it
  reads includes TerraBase hosts.
- **Trust.** Lowering the cap is an ordinary amendment. Adding, raising or
  removing a budget, or changing its currency, needs a root signature:
  the release leaf may already scale services down, never spend more.
  The section needs binary level 3.

The usage API needs a tenancy policy for the controllers' dynamic group:
`Allow dynamic-group <controllers> to read usage-reports in tenancy`.
