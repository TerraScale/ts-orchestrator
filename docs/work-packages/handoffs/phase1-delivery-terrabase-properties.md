# Phase 1 delivery and TerraBase property/replay handoff

## Result

Added four deterministic 1,000-case property families covering immutable Delivery source evidence, promotion and rollout behavior, TerraBase topology/writer fencing, and backup/restore recovery. Independent mode oracles assert exact actions or closed error codes for stale and conflicting generations, exact digests/signatures, dependency permutation, promotion invalidation, rollout rollback and terminal replay, permanent membership, quorum/loss floors, writer conflicts, chain gaps, terminal backup identity, and restore anti-rollback behavior. Each family is replayed under Turkish and Arabic cultures with stable summaries.

The strict embedded corpus is bounded to 32 KiB and 64 entries, rejects unknown/duplicate/malformed fields, pins the complete resource SHA-256, pins every entry's length-delimited canonical digest, and proves changed replay inputs change the exercised decision.

Production hardening replaces unbounded enumerable materialization with named technical snapshots. Delivery dependencies, trust zones, capabilities, rollout cells/completions/availability are capped, and direct runner evidence lists have an explicit count cap. TerraBase writer and backup inputs use the stricter of the caller maximum and a 4,096-item technical ceiling. Max+1 is detected before reading the extra `Current`; nulls and ordinary iterator failures become generic `ArgumentException` values without source exception text, while `OutOfMemoryException`, `StackOverflowException`, and `AccessViolationException` propagate. Tests cover exact bounds, max+1, infinite inputs, extra-`Current`, all iterator phases, dispose-time mutation, defensive copying, nulls, and fatal propagation.

A follow-up audit found that out-of-catalog enum values at legitimate checkpoints were not distinguished from
defined `Unknown` values. In particular, forged numeric values could reach `Add`, `CatchUp`, `Remove`, `Upgrade`,
or `Restore` outputs. All 44 enum-valued TerraBase evidence fields now reject undefined values as exact
`InvalidInput` holds before mutation. Defined `Unknown` and `Contradicted` values retain the pre-existing checkpoint
precedence. A new bounded shard runs 1,000 independent cases across the complete enum inventory and another 1,000
across all ten scope dimensions for all six planners plus exact all-field authorizing subjects and traces. The shard
reuses the already pinned TerraBase replay corpus; it does not invent duplicate saved examples or acceptance evidence.

## Compatibility impact

- Delivery collections above the new published technical ceilings now throw `ArgumentException` during construction instead of attempting unbounded allocation.
- TerraBase writer/backup inputs above the existing caller maximum now throw `ArgumentException` during construction instead of producing an `IsValid == false` object after fully enumerating the source.
- Existing valid inputs and caller maxima remain unchanged. The constants are technical resource-safety limits, not business rules or deployment claims.

## Verification

```text
dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo
Build succeeded: 0 warnings, 0 errors

dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore -- --no-progress --output Normal
Passed: 315, failed: 0, skipped: 0

Other executable test projects passed serially: Contract 24, Model 38, Protocol 50, Scheduler 69.
Whole repository total: 496 passed, 0 failed, 0 skipped.

git diff --check
Passed
```

## Non-claims

This shard contains no Git/Forgejo, process, network, filesystem runtime, NATS, cloud/provider, package, signing implementation, or deployment execution. It is unit/property/replay evidence for pure decisions only and does not satisfy L0, L3S, L4, production readiness, or deployment acceptance.
