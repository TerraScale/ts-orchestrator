# Phase 1 deterministic adversarial model core handoff

- Work package: `docs/work-packages/phase1-adversarial-model-core.md`
- Branch starting point: `d8532f8`
- Scope changed: model-test simulation and regression-corpus paths, the model-test project reference, and this handoff only
- External or destructive actions: none

## Result

The model-test project now has a deterministic, bounded three-node simulator with an explicit virtual clock and identity source, immutable event evidence plus separate delivery scheduling metadata, stable failure-kind ordering, visited-state deduplication, deterministic replay, and replay-validated delta shrinking. The closed schedule catalog covers loss, duplicate, reorder, delay, crash, restart, leader change, partition, and heal. Exploration includes baseline progression and applicable node failures across `n1`, `n2`, and `n3`; a depth-pruned pending state returns `NonConvergent`, not `Completed`.

Inputs are materialized through explicit bounds before execution. Invalid events, arithmetic overflow, and exhausted step or schedule bounds produce typed results. Initial duplicate event IDs, malformed identities and enums, negative scalar values, more than three nodes, duplicate state identities, and caller collection mutation are rejected or isolated. Canonical model state uses length-prefixed strings before SHA-256 hashing so delimiter-shaped identities cannot create ambiguous state encodings.

The reducer fences authorization and create requests to the current active writer, accepts successful mutation only from the active leader at the current epoch, preserves exact operation/generation/epoch/idempotency/resource bindings, records bounded accepted-action evidence independently of gates, makes exact-operation mutation completion terminal/idempotent, prevents a second create after outcome-unknown, rejects critical-node termination, and deduplicates delivery by event ID. Accepted authorization/action evidence records the leader, node writer epoch, crash/partition state, generation, idempotency key, and resource identity observed at acceptance. Invariants inspect those facts independently, so mutation-style stale, unauthorized, unsafe-termination, repeated-create, and duplicate-terminal-success evidence fails audit if an individual reducer gate is removed. Passive provider and delivery observations cannot expose authorization, permit, intent, filesystem, socket, process, random, environment, or mutation capabilities.

Direct probes exercise the existing Authority, Operation, Provider, Compute, and Delivery pure cores. They establish that mutation authority requires an observed CAS, an unprepared operation cannot dispatch, missing regional provider authority cannot mutate, an outcome-unknown create is observed rather than repeated, duplicate delivery is idempotent, and an untrusted product-validation job cannot acquire production-release authority.

The versioned regression corpus is a checked-in JSON file compiled as an embedded resource and loaded only by its fixed logical resource name. Source bytes, entry count, and schedule length are bounded. Loading is strict and deterministic: unknown or duplicate fields, unsupported versions, malformed or mismatched digests, duplicate IDs, invalid schedules, and traversal-shaped IDs are rejected. A saved stale-leader/late-completion schedule is content-addressed, replayed, and checked against its expected invariant by the ordinary test suite.

## Validation

```text
dotnet test tests/TerraScale.Orchestrator.ModelTests/TerraScale.Orchestrator.ModelTests.csproj --no-restore --verbosity minimal
dotnet test TerraScale.Orchestrator.slnx --no-restore --verbosity minimal
git diff --check
```

The focused run passed 38 tests: 17 existing contract/model tests and 21 new adversarial simulator/corpus tests. The full solution run passed 371 tests. It starts no service, VM, container, adapter, network client, provider SDK, or deployment.

## Evidence boundary

The ordinary suite runs only the explicitly named `SmokeShard`. `FeatureMinimum` exposes the required 10,000-schedule floor and `FullMinimum` exposes the 1,000,000-schedule floor for later evidence lanes. This handoff does **not** claim that either threshold ran, does not mint pre-deployment evidence, and does not claim exhaustive coverage of every control-plane domain. Storage, TerraBase, runtime, and other domain engines remain independently tested and are candidates for projection into later aggregate cross-core models.
