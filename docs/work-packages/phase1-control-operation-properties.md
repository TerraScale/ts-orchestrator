# Phase 1 control/operation deterministic property shard

## Base and scope

- Base: `origin/chore/phase0-bootstrap`
- Deterministic property/replay tests under `ControlPlane.Tests/Properties/Operations/**`
- Bounded embedded corpus under `test-corpus/control-operations/**`
- Review-approved construction-closure expansion in `Authority/AuthorityContracts.cs`

## Goal

Run at least 1,000 explicit-seed cases per Authority, Operations, Reconciliation, and cross-core property family. Independently oracle identity, generation/epoch fencing, durable-before-dispatch, idempotency, deadline/retry/compensation closure, stale/unknown/duplicate/reordered evidence, single-writer behavior, replay/culture/permutation stability, checked arithmetic, closed accepted outputs, and secret-safe errors.

The cross-core family exercises an orchestrated handoff convention: it obtains a permit, carries its epoch into operation preparation/authorization, proves durable authorization precedes dispatch, and binds the dispatched identity into reconciliation. Operations does not consume or cryptographically verify `MutationAuthorityPermit`; this shard therefore does not claim that an arbitrary operation epoch is enforced as authority-derived.

The shard uses no external property or mutation package and performs no filesystem I/O, networking, process execution, clock reads, cloud action, or deployment. It does not claim 100,000 cases, full-domain property evidence, a mutation score, L0, or deployment qualification.

## Verification

```text
dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-restore --verbosity minimal
Passed: 291, Failed: 0, Skipped: 0
```

See `docs/work-packages/handoffs/phase1-control-operation-properties.md` for the compatibility report and evidence boundary.
