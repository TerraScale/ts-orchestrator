# Phase 1 compute autoscaling and regional survival core

## Predecessor

- Contract steward commit: `069fccf`
- Demand windows, cooldown/lifetime, node floors/caps, fallback order, cost/SLO targets, and survival-bundle expiry values remain explicit inputs.

## Goal

Implement the pure regional compute scale-out/scale-in/replacement and survival-readiness state machines from `ORCHESTRATOR.md:623-756`. It composes typed scheduler/budget/provider evidence but performs no provider action.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Compute/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Compute*.cs`
- `docs/work-packages/handoffs/phase1-compute-autoscaling-core.md`

## Required behavior

- Immutable bounded cell/node/node-class/template/shape/domain/artifact/secret-version/bundle/demand/operation identities; checked counts/resources/generations/epochs; closed trigger, lifecycle, readiness, veto, and action catalogs.
- Scale-out follows DemandObserved through persisted plan, budget/quota/capacity authorization, provider request recording, identity attestation, enrollment, bootstrap/disk checks, readiness, placement, service health, and completion. Lost provider response never emits a second create.
- Scale-in requires sustained explicit low-use/cooldown/lifetime evidence, replacement capacity and availability headroom, fresh regional control/NATS health, no conflicting operation, caller-owned stateful approvals, exact LB/volume/revocation proofs, exact instance termination, boot-volume absence, and orphan audit. Seed/control floors cannot reach zero and blind instance-pool count reduction is unrepresentable.
- Missing/stale demand may permit only explicitly bounded safety scale-out and always holds scale-in. Failed host replacement is fenced and preserves retained stateful volumes for their owning controllers.
- Regional survival readiness binds signed/encrypted bundle metadata, exact accepted+rollback artifacts and encrypted secret versions, templates, provider/trust/NATS/DNS/backup references, authority/snapshot positions, and explicit freshness/expiry evidence. Plaintext secrets/offline roots are unrepresentable. Disconnected replacement is allowed only when bundle/current regional authority proofs are complete.
- Emit closed observe/persist-plan/authorize/request-create/enroll/ready/cordon/drain/deregister/detach/revoke/terminate/audit/hold intents with exact proofs and stable code/numeric trace; no provider/runtime/network command, secret, callback, SDK, or I/O.
- Defensive copies; culture/permutation/replay; every scale transition crash; stale demand; conflicting operations; floor/quorum/budget veto; stateful veto; lost response; failed seed replacement; bundle missing/expired/rollback gaps; disconnected GRU; and secret-safe tests.
- No provider/NATS/runtime/filesystem/network/clock package, trigger/cooldown/floor/fallback/default policy, or mutation.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`

