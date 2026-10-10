# Autoscale telemetry

Host agents publish measured resource load every fifteen seconds. Autoscaling
must consume verified evidence without a feature enable step; production
cadence and bounds have one correct setting in code.

**Current gap (TS-796):** `controller.autoscale.host_telemetry` still guards
signal consumption. Removing that control is runtime work, not a signed
opt-in procedure. Collection already runs independently of autoscaling.

Reports require valid regional authority; demotion and a new authority term
discard cached observations. Failed publications back off exponentially up
to ten minutes and return to the fixed fifteen-second interval after recovery.
Missing or stale signals must hold unsafe actions rather than be replaced
with invented values.


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
minutes, so a new term, a newly reporting service or a
cell whose hosts went silent holds with `no-signal-data` instead of scaling
on a partial or stale window. The reconciler's history reset on every term
change applies the cooldowns from the start of the term on top. The fixed host reporting interval stays below five minutes. Members that are not the
leader record no autoscale or TerraBase load history, and a demoted leader,
or one whose re-acquired lease the reconciler has not adopted yet, stops
presenting its last results.

A window must also be densely covered: if any gap between consecutive
samples of the series inside the window, or since its latest sample, is
longer than half the window (at least 10s), the reading is unavailable.
A `window_seconds` below thirty seconds therefore never scales; choose
windows of several fifteen-second host intervals. The
signal's `min_samples` counts the samples of all replicas together.

## Trust decision

An authenticated host's self-reported load can
move a service **within its signed replica bounds**: a compromised host can
push a service toward its maximum (bounded by the signed `max` and by
placement capacity) or keep one signal from agreeing to a scale-down. It
cannot exceed the bounds, write desired state, or affect fencing, signing or
TerraBase lifecycle decisions; nothing outside the autoscaler and the
dashboard reads the reports. Automatic admission must preserve that trust
boundary and signed replica limits; always-on telemetry grants no broader
authority to a compromised host.

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
