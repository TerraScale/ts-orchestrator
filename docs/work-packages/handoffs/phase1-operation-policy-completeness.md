# Phase 1 operation policy completeness handoff

## Result

This audit closes five pure operation-policy gaps for `INV-004`, `INV-005`, and
`INV-006` without performing provider, NATS, filesystem, process, clock, or any
other external I/O.

- A persisted dispatch replayed at or after its deadline now emits only the
  narrow read-only provider reconciliation intent. It does not repeat the
  mutation.
- Replaying an exact persisted `Unknown` or `InProgress` observation re-emits
  that read-only reconciliation intent from the persisted provider work-request
  data. A crash between journal append and output handling therefore cannot
  strand the operation.
- An observation identity cannot be rebound to a nonidentical provider result.
  Both command handling and journal replay reject that conflict with the
  existing `ConflictingTerminalObservation` code.
- A persisted `DeadlineExpired` hold cannot be bypassed with a regressed
  decision time. Authorization or first dispatch stays exactly held until a
  future explicit action-specific recovery policy exists. Forged journal events
  after that hold fail as `InvalidJournal`.
- Malformed persisted authorization/hold records with null nested evidence or
  error values fail closed without changing the prior state. Fatal runtime
  failures are not translated into ordinary input errors.

The mutation-bearing `DispatchProviderIntent` now exposes the exact frozen
aggregate, desired generation/resource version, authorizing observation
identity/resource version, and ordered permitted-compensation allowlist. The
allowlist is defensively copied and read-only. Because this changes the
canonical shape, its digest domain is explicitly `dispatch-intent-v2`.

`ReconcileProviderIntent` deliberately remains a narrow read-only query
boundary: operation, target, desired generation, idempotency key, optional
provider work-request ID, and authorization sequence/digest. It cannot mutate a
provider and therefore does not duplicate the six mutation-context additions.

## Deterministic evidence

The operation inventories are hard-pinned at seven checkpoints, five provider
outcomes, thirteen errors, five commands, seven events, and two intents. Exact
public fields are pinned for both accepted intents.

Two new 1,000-case deterministic families independently exercise:

- exact mutation output and pre-deadline idempotent replay;
- post-deadline read-only reconciliation;
- crash replay for both non-final provider outcomes and optional work-request
  identity;
- command and replay rejection of rebound observation identities;
- authorization and dispatch deadline holds at equality and after equality;
- regressed decision time and forged post-hold authorization/dispatch events;
- defensive ordered compensation capture and exact state preservation.

Focused regressions separately cover null authorization evidence, null nested
observation, null held error, fatal enumeration propagation, closed inventories,
and exact accepted-output fields.

## Evidence boundary

`PermittedCompensations` is only a frozen authorization allowlist. This tranche
does not implement, select, or claim compensation execution, cancellation, or
an action-specific recovery policy. It does not claim L0/L0C, adapter
conformance, provider correctness, destructive acceptance, or deployment
authority.

## Verification

On the exact rebased tree rooted at `6084068`:

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx --configuration Release --no-restore --nologo -warnaserror
Build succeeded: 0 warnings, 0 errors

Focused regressions: 10/10 passed
Operation completeness properties: 2/2 passed (2,000 generated cases)
ControlPlane: 505/505 passed
Contract: 24/24 passed
Protocol: 65/65 passed
Scheduler: 72/72 passed
Model: 38/38 passed
All suites: 704/704 passed
git diff --check: clean
```
