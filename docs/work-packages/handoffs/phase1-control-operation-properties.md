# Phase 1 control/operation property shard handoff

## Result

- Added four deterministic, explicit-seed property families with 1,000 cases each for Authority, Operations, Reconciliation, and their cross-core handoff.
- Added strict, whole-resource- and per-entry-content-addressed embedded minimal counterexamples whose replay behavior is driven by each entry's seed, mutation, delta, and expected outcome.
- Closed public construction of `AuthorityDecision` and `MutationAuthorityPermit`, so accepted authority results and mutation permits can only originate inside the ControlPlane assembly.
- Added a public decision-surface audit and construction-closure assertions.

## Covered invariants

- exact aggregate, operation, resource, target, generation, authorization, executor, and fencing identity
- monotonic epochs/revisions and checked overflow behavior
- durable authorization before dispatch, retry/idempotency behavior, deadlines, compensation preservation, and terminal closure
- stale, unknown, duplicate, conflicting, and reordered observations/journal events
- single-writer fencing and absence of candidate/operation identity leakage in sampled errors
- replay, input permutation, and `tr-TR`/`ar-SA` culture determinism
- reconciliation resource bounds and construction-closed mutation outputs

## Compatibility

`AuthorityDecision` and `MutationAuthorityPermit` keep the same public type names and readable property names/types. Existing consumers that inspect or serialize their public getters remain compatible. Their formerly public positional constructors and positional-record deconstruction surface are intentionally removed; source or binary consumers that directly forged either accepted output must move to decisions returned by `AuthorityEngine`. No wire format is claimed by these in-process contracts.

The cross-core test demonstrates an orchestrated convention, not permit enforcement by the Operations engine. It obtains an authority permit and carries the epoch into the operation journal, but Operations neither consumes nor cryptographically verifies `MutationAuthorityPermit`; an arbitrary epoch is not proven to have originated from `AuthorityEngine` by this shard.

## Validation

```text
dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-restore --verbosity minimal
Passed: 291, Failed: 0, Skipped: 0
```

## Evidence boundary

This shard is bounded evidence only. It performs 4,000 generated cases plus corpus and reflection checks without external I/O, networking, process execution, clock reads, cloud actions, or deployment. It does not claim 100,000 cases, exhaustive/full-domain coverage, mutation-score evidence, L0 qualification, or deployment qualification.
