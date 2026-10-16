# CORE runtime removal inventory

Source baseline: `7a7abb41`, inspected 2026-10-16. Owner: CORE removal worker
`/root/core/removal`, GPT 6.1 Sol/high. Worktree:
`/tmp/ts-orchestrator-core-removal`, branch `refactor/core-runtime-removal`.
Initial inventory ETA: 10 minutes. This is source evidence, not a live runtime
qualification or permission to remove persisted production state.

## First deletion slice

| Removed source | Reachability and retained behavior |
| --- | --- |
| `placement.PlanReplicas` in `internal/placement/workload.go` | No production caller. It only constructed `WorkloadRequest` and called `PlanWorkload`. Both real production callers already call `PlanWorkload` directly. |
| Two cases in `internal/placement/workload_test.go` | Deleted the only two `PlanReplicas` callers: `TestPlanWorkloadKeepsHealthyAndPendingAssignmentsAndWithdrawsFailedOnes` and `TestPlanWorkloadWithdrawsAllAssignmentsWhenTargetIsZero`. No tests were renamed or presented as integration. Other existing direct planner tests remain pending owning-stream conversion. |
| `internal/workload/stateful.go` | `StatefulScaleDown`, `StatefulCanRetire`, `ReplicationLag`, and their private supporting types/functions had no production callers. DATA explicitly agreed to retire these duplicate wrappers. |
| `internal/workload/stateful_test.go` | Deleted its three isolated unit tests alongside the unused wrappers. Actual drain, volume and writer safety stays with DATA's integration qualification. |
| Stale `StatefulScaleDown` reference in `internal/workload/spec.go` | Retained the complete policy schema and validation. |

CORE approved the positional-wrapper deletion; DATA approved the stateful-wrapper
deletion. `placement.CanBeginRetirement`, `placement.CanRetire`, member lifecycle
proofs, `internal/storage/failover`, and host drain/backup/volume code are retained.
The placement controller currently holds retirement stages rather than running
these wrappers: `internal/placement/controller.go` explicitly reports that the
integrated evidence-driven scale-in path is still required. Retaining the safety
predicates must not be described as an already working scale-in implementation.

`internal/machines/schedule.go` and `schedule_test.go` were already deleted in the
user's main checkout. This worker did not edit, restore, stage or commit them.
Their production-unwired scheduler is a separate existing change.

## Current active task graph

```text
app.Run("run")
  -> app.runController
     -> regionalDeliveryPlanner
     -> delivery.Open(Planner: planner, Writer: planner)
     -> host.NewController
     -> startWorkloadAutoscale
        -> workload.New
        -> planner.workloads = workloadReconciler
     -> workers: delivery.Service.Run, host.Controller.Run,
        workload.Reconciler.Run, managed placement.Controller.Run

signed service channel / operator deployment
  -> serviceReleases / nativeDeployer / nativeHistory preparation
  -> delivery.Service.Submit / SubmitVerified
  -> delivery.Service.processDelivery
  -> regionalDeliveryPlanner.PlanShaped -> plan
  -> workload.Observe -> placement.PlanWorkload
  -> []host.Desired
  -> regionalDeliveryPlanner.ApplyDesired
  -> nativeHistory.ApplyDesired or host.Controller.ApplyDesired
  -> ordered authority host desired mutation

workload.Reconciler.Run -> Tick -> reconcile
  -> hosts.ListHosts + ListDesired
  -> workload.Observe + CurrentRelease
  -> autoscale.Decide (desired replica policy)
  -> PlanStep -> placement.PlanWorkload
  -> applyCurrent -> nativeHistory.ApplyDesired / host.Controller.ApplyDesired

app.Run("host") -> runHost -> host.NewAgent
  -> NewProcessRunner (default when no test runner supplied)
  -> Agent.Run -> session acquisition/renewal + reconcile(role)
  -> desired RPC -> artifact bytes -> cycle RPC -> runner.Apply
  -> processRunner.Apply -> launchNativeWorkload -> native helper/process
  -> report RPC -> controller host reports
```

The two direct production generic planner callers are
`workload.PlanStep` (`internal/workload/plan.go`) and
`regionalDeliveryPlanner.plan` (`internal/app/delivery_planner.go`). Deleting only
the reconciler leaves delivery's one-shot scheduler and native task dispatch
reachable. Deleting only `PlanWorkload` breaks both paths.

`Agent.stopForLostSession` cancels the agent, revokes managed native roots and
closes its runner. `processRunner.Recover` reconstructs native process ownership;
it is not a containerd task recovery implementation. Stateless task survival
therefore needs a replacement executor and agent boundary, not removal of the
session check alone.

## Mixed responsibilities to preserve or split

| Feature slice | Active callers and required replacement |
| --- | --- |
| `internal/workload` | Reconciler/spec/result types are consumed by app wiring, signed cell specs, native release generation shaping, bootstrap rendering, global views and insights. Keep replica policy as needed; replace task host selection, step rollout and desired writes with SwarmKit services. |
| `internal/host` | Used by app run/host commands, delivery, placement, nodescale, identity rekey, host enrollment, managed material, seat rollout, global observations and qualification tooling. Separate identity/telemetry, controller self-update, NetBird foundation supervision and DATA lifecycle before removing native runner/session dispatch. |
| `internal/placement` | `workload.go` is generic scheduling. The remaining controller/store/managed-update/seat/volume files also own OCI host creation, mounted-volume binding, independent TerraBase serving proofs and fail-closed database updates. DATA owns the safety extraction; a whole-directory deletion is unsafe. |
| `internal/rollout` + `internal/rolloutexec` | Also drive orchestrator controller and host binary self-update. `rolloutControl.start` creates `ReleaseProgram`, health collector, KV driver, systemd relay, cluster/quorum gates and host units. Retain infrastructure/controller bootstrap and recovery outside application SwarmKit tasks. Generic application update progression should move upstream. |
| `internal/machines` + `internal/machinesapi` | `startMachinesAPI` and `machinesAPILoop` serve authenticated app/machine intent and status using the product stores. The old `machines.Plan` was unwired; its removal does not make Machines execute workloads. Map accepted intent into services and observed tasks without adding another scheduler. |

The app files that must move together for a stateless cutover are
`controller.go`, `app.go`, `workload_autoscale.go`, `delivery_planner.go`,
`native_history.go`, `service_releases.go`, `release_fence.go`,
`native_restore.go`, `cell_spec_registry.go`, `cell_spec_operator.go`,
`autoscale_history.go`, `observability.go`, `insight_providers.go`, and
`machines_api.go`, plus the matching CLI/operator and dashboard consumers.
These are inventory references, not this worker's edit claims.

Deletion blockers for the autoscale adapter handoff: `delivery_planner.go` owns
`*workload.Reconciler` and consumes `Observation`/`Observe`/`Snapshot`;
`workload_autoscale.go` consumes `ReleaseShape` and `Observation`.
`autoscale_history.go`, `observability.go` and `insight_providers.go` consume
`*Reconciler`; `globalview/sources.go` and `build.go` consume `workload.Result`
including its step information. The native release paths in `release_fence.go`,
`native_history.go`, `native_restore.go`, and `operator_terrabase_csharp.go` still
consume `ReleaseOf`, `ReleaseGeneration`, or `ErrGenerationSpace`. Preserve
generation interpretation until those actual release paths migrate; moving
read-only view types must not reintroduce task ownership.

## Transport, persisted state and configuration inventory

| Boundary | Current state and deletion condition |
| --- | --- |
| Host execution RPC | `protocol.AgentObservationSubject` constructs `ts.orch.v1.<cell>.agent.<user-nkey>.observation.<operation>`. Session/desired/artifact/cycle/report are native execution operations; the same family also carries load, role identity, rollout, NetBird, drain, backup and volume initialization. Remove individual grants/handlers only after their retained consumers move. |
| Host records | `TS_HOST_STATE`: `session.<cell>.<node>`, `desired.<cell>.<node>.<role>`, `report...`, `cycle...`; desired and registration authority also use ordered control mutations. Inventory `host/mutations.go`, `controller_state.go`, readers, snapshots and authority entries before any persisted retirement. |
| Native delivery | `TS_DELIVERY_ADMISSIONS`, `TS_DELIVERY_OPERATIONS`, `TS_DELIVERY_INTENTS`, durable `TS_DELIVERY_WORKER`; native signed profile/history is `TS_NATIVE_RELEASES`. Artifact admission, anti-rollback and retained release evidence must survive migration; native task plans must cease being authoritative. |
| Placement / rollout / Machines | `TS_PLACEMENT_STATE`, `TS_ROLLOUTS`, `TS_APPS`, `TS_MACHINES`, `TS_MACHINE_STATUS`. Rollout status/proof NATS subjects also support controller binary updates. Preserve historical records and DATA proofs; SwarmKit Raft must become sole generic task authority. |
| Config and producers | `ControllerConfig.Workloads`, `ControllerConfig.Autoscale`, `AutoscaleConfig.Enabled`, `HostTelemetry`, interval fields, `HostConfig` native roots/UID/GID/poll fields, cell spec service `Spec`, bootstrap renderers, fixture JSON and docs. Legacy switches must be removed as new wiring lands; no engine selector or production fake is acceptable. |

Other connected removal consumers include `internal/managedmaterial`,
`internal/hostenroll`, `internal/identityrekey`, `internal/seatrollout`,
`internal/nodescale`, `internal/cellspec`, `internal/bootstrap/cli`,
`internal/globalview`, `internal/qualification/memberstatus`,
`internal/qualification/firecracker`, and `tests/firecracker` native-member
drivers. No dependency is proven dead solely by removing the wrappers in this
slice, so `go.mod` and `go.sum` need no edit.

## Bounded replacement handoff for the shared app integrator

1. Consume CORE's regional manager/agent and containerd executor contracts from
   `runController`/`runHost`; infer admitted region and durable identity through
   the existing foundation boundary. Establish real container task identity and
   restart recovery before connecting accepted production intent.
2. Change one admitted stateless service's translation from per-node
   `host.Desired` writes to one retry-safe SwarmKit `ServiceSpec`, including
   digest, platform, resource limits, replicas, readiness and update policy.
   Move both delivery and reconciler ownership for that service in the same
   slice. The owning SwarmKit API must return observations and errors used by
   release admission, traffic gates and operation receipts.
3. Replace that service's native release/rollback observation with SwarmKit
   service/task state plus application readiness. Remove its old task desired
   writes/cycle dispatch and obsolete subject grants together. Keep database
   and controller update paths separately owned; do not route one workload to
   both engines or add an engine-selection switch.
4. Qualify through real service/control/runtime boundaries: admitted digest
   starts, readiness gates traffic, unhealthy update rolls back, manager/agent
   restart recovers the same container identity, and invalid architecture or
   ports fail without losing the healthy task. Retain exact-candidate evidence.
5. Feed service/task observations to CLI, dashboard, metrics and global views;
   remove the now-unreachable scheduling helpers, state schemas, native-only
   tests/fixtures/tooling, and repeat for each independent workload. DATA safety
   migration has its own gate.

This worker proposes no shared-file implementation diff until the executor and
regional lifecycle contracts land. A stub adapter in `controller.go` would leave
two authorities or present an unqualified dependency as working.

## Verification and remaining coverage

`git diff --check` passed. Exact-symbol search found no remaining Go references
under `internal/` to `PlanReplicas`, `StatefulScaleDown`, `StatefulCanRetire` or
`ReplicationLag` after deletion. Modern Go Guidelines CLI was read for both
edited production Go files. `nice -n 19 go build -p 2 ./internal/placement
./internal/workload ./internal/app` passed. This is compile evidence only;
deleting unreachable helpers requires no new runtime logic or isolated test.

Before this slice, the direct feature inventory contained 51 host test files,
17 placement test files, 14 rollout test files, 9 rolloutexec test files, and
3 workload test files. This slice deletes the workload stateful unit file and
two cases from placement; it does not claim the remaining suites are integration
only. No isolated unit suite was run or relabeled.

Not checked: live OCI/NetBird, secrets, production containers, on-disk task-state
retirement, full dependency reachability beyond the listed graph, and runtime
performance. The active native engine remains pending qualified replacement;
this slice only removes unreachable helpers.
