# Autoscale telemetry

Host agents can publish their load to the regional controller, and the
workload autoscaler can use it as its signal source. Both halves are off by
default and are enabled separately.

## Flags

| Where | Field | Default | Effect |
| --- | --- | --- | --- |
| host config | `host.load_telemetry_seconds` | `0` (off) | The agent samples its load every N seconds (5..3600) and sends it as the `load` host operation. Keep it below 300 for scaling: the aggregator treats a 5 minute silence of every host as a break. |
| signed controller config | `controller.autoscale.host_telemetry` | `false` | The authority leader accepts `load` reports and feeds them to the autoscaler. Scaling policies (`services[].scaling`) are refused without it. |

A host with telemetry on and a controller with it off is harmless: the
controller answers "not enabled", and the agent backs off exponentially up
to ten minutes (or the configured interval, if longer) between attempts. A controller with telemetry on and hosts
without it holds every scaling policy with `no-signal-data`; bounds and
self-healing still work.

## What a host reports

`hostload.Sampler` builds one bounded `hostload.Report` per interval:

- **Host:** CPU utilization (diff of `/proc/stat`), memory utilization
  (`MemAvailable`), and disk utilization of the fullest of the state, install
  and managed-runtime filesystems (statfs). Fractions in `[0,1]`.
- **Per role (cgroup v2):** CPU cores used (diff of `cpu.stat usage_usec`; a recreated group restarts the baseline)
  and the working set (`memory.current` minus `inactive_file`), read from the
  native runner's role groups. The first sample of a role, and the first
  after its group vanished, only sets the CPU baseline.
- **TerraBase load block:** for a TerraBase member, the latest optional
  `load` block of its member status (`connections`, `storage_bytes`,
  `replication_lag_seq`, `write_qps`). It is taken only from a status that
  passed every identity, mount and serving check and was reported, and is
  dropped after two minutes without a refresh. An incomplete or out-of-range
  block is dropped instead of failing the status, so a telemetry bug can
  never stop a serving member. A TerraBase release without the block simply
  reports none.

## How the controller uses it

The `load` operation is authenticated like every other host request (signed
request, current session, registration key). The controller then:

1. validates the report bounds (`hostload.Report.Validate`);
2. keeps only roles registered for that host **with a current, non-withdrawn
   desired allocation**, so a host cannot report load for a service it does
   not run;
3. takes the cell, environment and node from its own registration state;
4. accepts at most one report per node every 5 seconds;
5. stamps every sample with the controller's receive time, so a host clock
   cannot place samples in the future or keep them inside a window.

`hostload.Aggregator` records one sample per role per report into a
bounded `autoscale.WindowStore` **per node** (at most one sample per 5s for
an hour, so a large replica set can never truncate a configured window).
A reading reduces each node's samples in the window with the signal's
aggregation and then reduces the per-node values the same way, so every
reporting replica counts once whatever its report interval. A node that has
not supplied a series for 5 minutes (scaled down, replaced or silent) no
longer contributes to it, even inside a longer window:

| Signal | Value |
| --- | --- |
| `cpu_util` | cores used / the role's signed CPU request (workload profile) |
| `mem_util` | working set / the role's signed memory request |
| `disk_util` | the host's disk utilization, for roles that run there |
| `tb_connections_per_member`, `tb_storage_bytes`, `tb_replication_lag_seq`, `tb_write_qps` | the TerraBase load block |

A signal whose input or request is missing is not recorded, so the
autoscaler sees it as unavailable (which blocks a scale-down) rather than as
zero load. Signed config accepts only `cpu_util`, `mem_util` and `disk_util`
for the stateless services the reconciler owns; the TerraBase signals feed
the dashboard until TerraBase seats are reconciled.

Only the authority leader serves host requests, so only its aggregator
fills. The reconciler resets the aggregator on every authority term
change, so a leader returning after a short failover never scales on its
earlier term's samples. Per service and signal, the aggregator returns no
samples until they have arrived without a break for the whole signal window
(less one 5s report interval), and none once the latest is older than 5
minutes, so a new term, a first enablement, a newly reporting service or a
cell whose hosts went silent holds with `no-signal-data` instead of scaling
on a partial or stale window. The reconciler's history reset on every term
change applies the cooldowns from the start of the term on top. Host load
intervals should therefore stay below 5 minutes. Members that are not the
leader record no autoscale or TerraBase load history, and a demoted leader,
or one whose re-acquired lease the reconciler has not adopted yet, stops
presenting its last results.

The warm-up establishes that a series has been reported without a 5 minute
break for the window; it does not establish how densely. A `window_seconds`
shorter than the hosts' `load_telemetry_seconds` (or a short publication
outage) leaves only the latest one or two samples in the window. Choose
windows of several host intervals and set the signal's `min_samples`
accordingly, remembering that it counts the samples of all replicas
together (for example `window_seconds: 120` with 15s hosts and
`min_samples` of 4 per minimum replica), so a sparse window reads as
unavailable and holds.

## Trust decision

With `host_telemetry` on, an authenticated host's self-reported load can
move a service **within its signed replica bounds**: a compromised host can
push a service toward its maximum (bounded by the signed `max` and by
placement capacity) or keep one signal from agreeing to a scale-down. It
cannot exceed the bounds, write desired state, or affect fencing, signing or
TerraBase lifecycle decisions; nothing outside the autoscaler and the
dashboard reads the reports. Turn the flag on only where hosts are trusted
to that degree.

## Where the data shows

- **Decision journal:** every applied `scale_up`/`scale_down` carries each
  policy signal's reading and target (`workload.recordScale`).
- **Insights:** `autoscaler_at_max` reads the reconciler's real goals.
- **Metric history and dashboard:** the leader records
  `autoscale_replicas`, `autoscale_goal`, `autoscale_signal` and
  `autoscale_signal_target` per service, and `terrabase_connections`,
  `terrabase_storage_bytes`, `terrabase_replication_lag_seq` and
  `terrabase_write_qps` per member. The TerraBase page charts replicas
  against the goal and every signal against its target per service, and
  replication lag and connections per member.

## Not in this slice

Host pools still run in recommend-only mode. Launching and reclaiming
generic OCI hosts needs a generic-host launch path in `oci.Fleet` (today
`EnsureHost` is bound to a TerraBase seat's boot pins and launch scope) and a
generic-host enrollment trust path, which is its own trust decision.
