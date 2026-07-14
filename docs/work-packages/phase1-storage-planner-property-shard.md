# Phase 1 storage planner property and replay shard

## Goal

Exercise the existing pure storage create, format, attachment, expansion, deletion, and crash-recovery planners with deterministic generated cases and a fixed replay corpus. This shard strengthens pure decision evidence only; it performs no provider, filesystem, process, network, or deployment operation.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Storage/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/StoragePlanner*`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/StorageTestData.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`
- this work package

## Property evidence

- 1,000 materially distinct create and format cases cover every checkpoint and exact action, target, stable code, mutation classification, intent scope, and numeric trace field under culture changes and replay.
- 1,000 attachment cases cover zero, one, and conflicting writers; stop/lease/detach proof; exact new writer epoch; same-node health; permutation; and idempotent recovery.
- 1,000 expansion cases cover the first unproven irreversible step, provider convergence, guest/layout/filesystem/application/metrics recovery, conflict serialization, exact capacity/performance traces, and prevention of duplicate provider growth.
- 1,000 deletion cases cover permanent, quarantined elastic, and explicitly disposable retention precedence plus delete/provider-convergence/post-delete-audit recovery without duplicate deletion.
- 1,000 cross-planner authority and evidence-scope cases independently select provider, claim, cell, workload, member, fence, generation, epoch, or operation mismatch and require the exact fail-closed result.
- A strict, bounded, embedded JSON corpus is pinned by SHA-256. Its exact shape, closed vocabulary, family completeness, seed range, seed-sensitive expectations, byte bound, and fatal exception behavior are tested.

## Narrow production hardening

`StorageReattachEvidence` previously trusted its caller-provided `maximumWriterObservations` as the only acquisition limit. A caller could pass `int.MaxValue` and supply an endless or extremely large enumerable, and the former `foreach` read the maximum-plus-one `Current` before rejecting it.

The capture path now applies a named 4,096-item technical ceiling in addition to the caller's business limit, checks maximum-plus-one after `MoveNext` but before `Current`, returns secret-safe malformed evidence for ordinary iterator failures, and propagates `OutOfMemoryException`, `StackOverflowException`, and `AccessViolationException`. The ceiling is not storage topology policy: the planner's valid state admits at most one writer and rejects more than one as `DualWriter`, so 4,096 cannot exclude a planner-accepted topology. Null writer input retains its prior empty-snapshot behavior.

The compatibility change is intentionally limited to malformed evidence whose writer enumeration exceeds 4,096 while declaring a larger caller maximum; it now fails closed. Existing valid zero/one-writer evidence and caller maxima remain unchanged.

The exact intent-subject oracle also exposed that a successful reattach previously retained the old volume node in `StorageDecision.Scope` and discarded the requested target node. Attach decisions now override only the scope's node and authorized writer epoch with the requested values. Detach and every unrelated decision continue to identify the current volume node. This is an intentional accepted-output correctness change with no public signature change; consumers that incorrectly inferred the attach target was the old node now receive the actual requested target.

Deletion and reattachment also previously interpreted undefined proof enum values as an unproven step, which could emit `Delete` or `Detach`. After authority and evidence-scope validation, every reattach/deletion proof is now closed: undefined values produce `InvalidInput`, defined `Contradicted` values produce `StepContradicted`, and only `Unknown` advances the legitimate next-step state machine. Permanent-retention and wrong-scope precedence remain unchanged.

## Boundaries and non-claims

This shard neither selects unresolved storage SLO, retention, RPO/RTO, or owner decisions nor claims the 100,000-case full-domain threshold, mutation target, provider conformance, destructive storage acceptance, L0 completion, or deployment authority. It starts no storage, cloud, NATS, network, process, filesystem, or VM activity.
