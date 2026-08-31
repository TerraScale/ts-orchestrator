# Rootless podman hosting, stateful-first operation, and the autonomous node autoscaler

Status: lane design (contracts landed 2026-08-30)

Goal: [`../../GOAL.md`](../../GOAL.md)

Related ADRs:
[ADR 0024](../adr/0024-greenfield-bringup.md) (greenfield estate),
[ADR 0020](../adr/0020-provider-actuator-threat-model.md) (mutation fencing),
[ADR 0029](../adr/0029-offer-stateless-tenant-compute.md) (stateless tenant compute),
[ADR 0031](../adr/0031-run-tenant-workloads-as-unprivileged-oci-containers.md) (unprivileged OCI workloads),
[ADR 0033](../adr/0033-gru-global-authority-and-regional-autonomy.md) (GRU global authority and regional autonomy).
The deleted ADR 0028 stays retired.

## Goal

TerraScale hosts its own workloads safely on ordinary rootless Linux user
accounts, keeps stateful services such as TerraBase available across node
churn, and grows or shrinks the node fleet without a human in the loop. This
lane adds three things on top of the existing canonical runtime plan:

1. workload hosting as plain binaries under rootless systemd **user** units
   and as OCI containers via **rootless podman**, for safety;
2. stateful-first operation: persistent volumes, drain safety, and
   anti-affinity placement; and
3. an autonomous node autoscaler that provisions nodes when capacity is
   short and drains and retires them when headroom is sustained.

The contracts of the lane live in four packages that the parallel
implementers build against:

- `src/orchestrator/runtime/podman_contracts.go` — the podman allocation
  vocabulary, the validated `PodmanRunRequest`, the `PodmanClient` seam, and
  the fail-closed `RootlessPodmanContext`.
- `src/orchestrator/hostagent/contracts.go` — the `NodeId` token, heartbeat
  metrics, the `terrascale.node.v1.*` NATS subject map, workload command
  requests, and the four typed receipts.
- `src/orchestrator/stateful/contracts.go` — persistent volume bindings,
  replica health, drain candidates, drain decisions, and the
  `DrainSafetyEvaluator` seam.
- `src/orchestrator/autoscaling/contracts.go` — node observations and
  demand, the bounded `AutoscalerConfig`, the closed `AutoscalerAction`
  union, and the `NodeProvisioner` seam.

## The two hosting modes

Both modes execute the **same** canonical `HostRuntimePlan`
(`src/orchestrator/runtime/host_runtime_plan.go`). No new `RuntimeDriver`
value is introduced: the plan still carries exactly
`RuntimeDriverNativeSystemd` or `RuntimeDriverOciContainer`, and the
admitted-role catalog keeps deciding which driver a role may use. What
changes is the adapter behind the OCI driver on nodes that host workloads
rootlessly.

1. **Binaries via systemd user units.** The existing
   `SystemdHostRuntimeAdapter`, composed with `userManager=true`, places the
   unit in the node account's user manager (`systemd-run --user ...`,
   `systemctl --user show ...`). The catalog security properties
   (`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryMax`, `TasksMax`,
   `CPUQuota`, ...) are unchanged; the unit runs under the unprivileged host
   account, so the workload never gains root even if the unit file layer is
   compromised.
2. **OCI containers via rootless podman.** A new
   `PodmanRootlessHostRuntimeAdapter` implements the same
   Converge/Observe/Stop/Delete surface as the existing
   `SystemdHostRuntimeAdapter` and `ContainerdHostRuntimeAdapter`: it takes
   a canonical plan, fences it with `CanonicalPlanFingerprint`, and drives a
   `PodmanClient` (preflight, pull, create, start, stop, delete, inspect,
   ensure-volume). The plan's `OciExecutionPlan` maps onto the validated
   `PodmanRunRequest`: container id, digest-pinned image reference, platform,
   UID/GID, capability drops, cgroup parent under the user slice, memory/PID
  /CPU limits, and the fencing labels. The client creates the container with
   `podman create` and starts it separately, and every created container
   loads the seccomp profile named by the validated rootless context; the
   plan's IoWeight, Nice, and memory-high dimensions are not expressible on
   this podman surface and stay enforced by the native systemd driver only.

Every adapter accepts only plans whose derived execution plan is byte-equal
to what `NewHostRuntimePlan` would produce for the same admitted role;
injected executables, properties, or image references are fenced exactly
like the two existing adapters do.

## Rootless safety model

The lane is named rootless for a reason: **no workload, and no podman
invocation, ever runs as uid 0.**

- `ValidateRootlessContext` fails closed when `RunAsUid` is 0 — there is no
  configuration in which root podman is acceptable on these nodes. The
  context names an explicit podman binary path and XDG runtime dir
  (`/run/user/<uid>`), both bounded absolute paths.
- The client `Preflight` step is fail-closed: if the podman binary, the user
  runtime directory, or cgroup v2 delegation is missing, converge refuses to
  proceed rather than degrading.
- **Label fencing.** Every container the adapter creates carries
  `terrascale.allocation=<allocation-id>` and
  `terrascale.fingerprint=<canonical-plan-fingerprint>`. `Inspect` returns
  the labels, and an existing container whose labels do not match the plan
  being converged is treated as foreign and never touched, mirroring the
  containerd adapter's `requireMatchingAllocation`.
- **Capabilities dropped.** `NewPodmanRunRequest` requires the `ALL`
  capability drop; additional drops are allowed, additions are impossible.
- **Read-only rootfs.** `PodmanRunRequest.ReadOnlyRootfs` is fixed `true`
  by the constructor; writable state exists only on named volumes
  (`PodmanVolumeMount`, mounted at bounded absolute destinations, one mount
  per destination).
- **`NoNewPrivileges` fixed true**, nonzero UID/GID enforced, and the
  cgroup parent must be a bounded slash-separated token path under the
  user's own slice (for example `terrascale/<allocation-id>`), never a
  system slice.
- Identifiers and labels are bounded canonical tokens (the same DNS-style
  vocabulary as `NewRuntimeAllocationId`), and image references must be
  whitespace-free and flag-safe so nothing can smuggle a podman option
  through a value.

## NATS transport map

Each node runs one host agent that connects to the regional embedded NATS
(ADR 0033 keeps NATS the control transport). The subjects are closed and
built only from validated `NodeId` tokens:

| Subject | Pattern | Use |
| --- | --- | --- |
| converge | `terrascale.node.v1.<nodeId>.converge` | request-reply: drive one plan to running |
| observe | `terrascale.node.v1.<nodeId>.observe` | request-reply: fenced observation of one plan |
| stop | `terrascale.node.v1.<nodeId>.stop` | request-reply: stop one running allocation |
| delete | `terrascale.node.v1.<nodeId>.delete` | request-reply: remove one allocation |
| heartbeat | `terrascale.node.v1.<nodeId>.heartbeat` | publish: periodic `NodeHeartbeat` metrics |
| cordon | `terrascale.node.v1.<nodeId>.cordon` | mark the node unschedulable |
| drain-status | `terrascale.node.v1.<nodeId>.drain-status` | report drain progress |

Command payloads are `WorkloadCommandRequest{PlanJson, CommandId}` — the
serialized canonical plan (bounded, syntactically validated JSON) plus a
bounded command token. Replies are the typed `ConvergeReceipt`, 
`ObserveReceipt`, `StopReceipt`, and `DeleteReceipt`, each carrying the
`CommandId`, an `Accepted` flag, a bounded log-safe `Detail`, and the
`PlanFingerprint` the agent actually acted on, so the control plane can
prove which version of a plan a node is running. Heartbeats carry
`NodeMetricsSample` (memory total/used, CPU quota/used, task counts,
pending allocations) which is exactly the input the autoscaler needs.

## Autoscaler decision rules

The autoscaler is a control-plane role. On every tick it observes the
cluster as `NodeObservation`s plus the unsatisfied `AllocationDemand` set,
and it emits at most actions from the closed `AutoscalerAction` union
(provision, cordon, drain, retire) — constructed only through the four
`New*Action` constructors, mirroring the closed-union shape of
`AdmittedRole`.

**Scale up.** For each resource dimension (memory, CPU percent, tasks),
project demand as `cluster usage + pending demand`. When projected demand
exceeds `capacity * (1 - ScaleUpHeadroomPercent/100)` on any dimension for
`ScaleUpConfirmTicks` consecutive ticks, provision new nodes:

- new nodes are sized to the **largest unschedulable demand** (a node that
  can host the biggest workload nothing else can fit also hosts smaller
  ones);
- nodes already in `Provisioning` count against the remaining deficit, so
  the autoscaler never double-provisions for the same shortfall;
- the number of concurrently in-flight provisions never exceeds
  `MaxConcurrentProvisions`, and the fleet never exceeds `MaxNodes`.

**Scale down.** When cluster headroom (capacity minus projected demand,
per dimension, expressed as the minimum over dimensions) exceeds
`ScaleDownHeadroomPercent` for `ScaleDownConfirmTicks` consecutive ticks,
choose the **lowest-utilization Ready nodes first**, cordon them, and drain
them. The fleet never shrinks below `MinNodes`. A node hosting stateful
replicas may be cordoned **only after** the `DrainSafetyEvaluator` allows
it: every replica on the node must have a healthy replica set on *other*
nodes — `PeerAckCount` plus up-replicas elsewhere at least `MinReplicas` —
and replication lag below the configured bound. If any replica fails that
test, the drain decision is `Allowed=false` with the blocking allocation
IDs, and the autoscaler picks a different node or defers.

**Drain sequence.** cordon → wait for drain-safety plus all allocations
stopped (the agent reports this on `drain-status`) → `Retire` through the
`NodeProvisioner`. Retiring a node that was never drained is an invalid
operation, not a fast path.

## Stateful placement policy

- **Anti-affinity:** two replicas of the same stateful role never share a
  node. Placement consults the per-role replica sets exactly as the
  scheduler's anti-affinity check does, so a node loss never removes more
  than one replica of a role.
- **Volume/data locality:** a stateful allocation prefers the node that
  already holds its persistent volume (`VolumeBinding`), because a
  cross-node move means a volume migration, not just a process restart.
  Locality is a preference; anti-affinity and drain safety are hard
  constraints.
- Volumes are named, validated tokens bound to `(roleKind, allocationId,
  destination, readOnly)`; the podman adapter materializes them with
  `EnsureVolume` before create.

## Composition

- **`cmd/ts-node`** — a new per-node host-agent binary. It owns the node's
  `NodeId`, serves the six node subjects (the converge, observe, stop,
  delete, cordon, and drain-status requests), executes commands against the
  local adapter (systemd user units or rootless podman, chosen by the
  plan's driver), returns typed receipts, and publishes heartbeats whose
  running-task gauge comes from its own tracked allocations. It holds no
  cluster credentials beyond its regional NATS connection.
- **Autoscaler role** — a control-plane role that consumes heartbeats and
  the schedule state, applies the decision rules above, and drives a
  `NodeProvisioner` implementation (the greenfield OCI estate of ADR 0024
  provides the provisioning seam; ADR 0033 gives the regional autonomy
  model).
- **DrainSafetyEvaluator** — one implementation in the control plane that
  combines replica health from heartbeats with the placement state.

The workload-level security posture follows ADR 0031's hardening rules
(digest-pinned images, dropped capabilities, read-only rootfs, seccomp
where supported); this lane applies them to first-party workloads on
rootless nodes, and ADR 0020's fencing discipline (mutate only what you
can prove you own) is the model for the podman label fence.
