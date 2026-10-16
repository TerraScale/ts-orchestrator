# Database executor safety hooks — 2026-10-16

Scope: `internal/storage/execution`. Baseline `01348c66`, with member boundary
commit `1db52a29` (local cherry-pick `0d8cec69`) supplying `Client.Drain`.
This is an isolated source slice; it does not authorize database cutover.

## Consumer contract

`Hooks` implements `BeforePrepare`, `BeforeStart`, `BeforeShutdown`, and
`BeforeRemove`, each `(context.Context, *api.Task) error`. The executor must call
these inside `WithTaskEffect(ctx, task, func(context.Context) error) error`, using
the supplied context for the entire synchronous runtime mutation and readback.
All kill/terminate/delete routes require the corresponding safety hook; merely
calling a hook and dropping the gate before a runtime call is unsafe.

The wrapper reuses `authority.Fencer` and the authority runtime's existing
`BeginActiveWorkloadEffect` gate for the exact database/partition. Every hook
re-reads the trusted binding and checks the current authority epoch after its
OCI/member boundary call. A captured context cannot reuse a released holder.
Task/service labels only demand the gate; they cannot establish proof.

`BindingSource.VerifyTaskBinding` must authenticate the full task/assignment hash,
signed member/volume mapping, current writer authority, admitted artifact and
retained disk/CPU compatibility evidence, and independent predecessor writer
exclusion where a predecessor exists. The digest identifies that retained
admission, rather than proving it by itself. Member Client and FileStore handles
must remain stable across rechecks of the same admission. `VerifyRemoval` must
also verify the retained final survivor receipt and independently observed stop
of this exact writer process. Generic task status, readiness and kill success
cannot satisfy that check.

The OCI inspector verifies owned host/attachment/volume bindings. The retained
host initializer must prepare the mounted volume before runtime admission.
`InspectVolumeInitialization` can consume its one-time first-format grant;
the hook refuses any returned first-format authority and never forwards it to
the runtime. It performs no format, detach, reattach, termination or deletion.
Shutdown uses the real member Client's durable drain workflow and refuses
pending, ambiguous or invalid final survivor/root-frontier results. Removal
uses retained evidence after process exit, without requiring the stopped process
to answer a new Unix request.

## Qualification scenario

Focused command (serialized with the shared local CPU/memory limit):

```sh
flock /tmp/ts-orch-refactor-heavy-check.lock env GOMAXPROCS=2 GOFLAGS=-p=2 nice -n 19 go test ./internal/storage/execution -run TestExecutorSafetyIntegration -count=1 -v
```

The scenario crosses real embedded NATS TCP/JetStream persistence with
`authority.Runtime`, real OCI Fleet inspection and its JetStream journal, and a
real Unix HTTP subprocess peer with `memberstatus.Client` and reopened FileStore.
The external peer is a controlled test protocol simulator; no TerraBase binary
is downloaded or run. The admission provider and prepared-volume success
projection are test-only adapters. The actual OCI Fleet path is exercised with
missing owned host/volume inventory and must deny execution.

Assertions cover missing admission/holder, nil tasks, holder reuse, authority
loss during volume inspection, changed admission, unavailable member control,
pending drain, survivor below final source frontier, final completed drain after
durable request reopen, absent independent writer-stop proof, and missing owned
OCI resources. Only two prepared-volume simulator effects and one verified drain
effect may reach their runtime callback.

Result: pending the serialized focused check. No passing or live claim is made.

## Remaining cutover blockers

1. There is no production `BindingSource` adapter. Missing dependencies fail
   closed; this package cannot admit a production stateful task by itself.
2. CORE must integrate the wrapper across every runtime mutation, including
   force-kill/remove routes, and retain process/mount checks during serving.
3. Container member-control observations must preserve/translate host PID,
   kernel start and cgroup identity against SO_PEERCRED deliberately.
4. Retained release/disk/CPU evidence, independent predecessor stop and removal
   proof must come from the real admitted lifecycle, preserving the existing
   scoped native-root capability boundary.
5. Live owned OCI volume, same-commit TerraBase restore/replication, cross-CPU
   compatibility and STATEFUL acceptance remain unqualified. No live cloud or
   destructive operation was performed.
