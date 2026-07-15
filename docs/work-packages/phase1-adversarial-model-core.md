# Phase 1 deterministic adversarial model core

## Predecessor

- Contract steward commit: `3e2f747` plus the reviewed compute, networking, and observability pure-core commits.
- Production policies, timeouts, retry budgets, topology defaults, and qualification thresholds remain explicit inputs.

## Goal

Implement the deterministic L0 model simulator, reusable failure schedules, and replay corpus required by `ORCHESTRATOR.md:1114-1180` and the Phase 1 exit gate. The lane exercises existing pure cores and never executes an adapter or performs deployment.

## Allowed paths

- `tests/TerraScale.Orchestrator.ModelTests/Simulation/**`
- `tests/TerraScale.Orchestrator.ModelTests/RegressionCorpus/**`
- `tests/TerraScale.Orchestrator.ModelTests/TerraScale.Orchestrator.ModelTests.csproj`
- `docs/work-packages/handoffs/phase1-adversarial-model-core.md`

## Required behavior

- A deterministic virtual clock, deterministic identity/epoch source, immutable event queue, and closed loss/duplicate/reorder/delay/crash/restart/leader-change/partition/heal schedule catalog. No wall clock, random global, thread timing, callback, socket, file mutation, NATS client, provider SDK, or production adapter.
- A bounded three-node state-space runner with canonical state digests, stable schedule ordering, visited-state deduplication, explicit step/schedule bounds, and deterministic shrinking/replay of a failing seed. Overflow, exhausted bounds, invalid events, and non-convergence are typed failures rather than exceptions or free text.
- Reusable fake delivery/provider observations that preserve exact operation, generation, epoch, idempotency key, resource identity, and observation sequence. They may model outcome-unknown and late completion but cannot authorize an action or forge accepted domain output types.
- Cross-core adversarial scenarios prove no two accepted writers, no stale successful mutation, no unauthorized action, no unsafe deletion/termination, no quorum-floor violation, no second create after outcome-unknown, and identical digest after snapshot/replay under explored schedules.
- Every saved failure case is a canonical, culture-independent, content-addressed checked-in corpus entry with a versioned schema and expected invariant/error. Corpus loading is deterministic and rejects unknown fields, duplicate IDs, malformed digests, unsupported versions, and path traversal.
- Tests cover permutation/culture/replay, canonical digest stability, queue ordering, bound enforcement, schedule shrinking, all failure-event kinds, stale leader and late provider completion, duplicate delivery, partition/heal, crash/restart, corpus tamper/unknown-field rejection, and reflection/architecture proof that the simulator cannot acquire mutation capabilities.
- The feature-branch suite runs a deterministic bounded shard suitable for ordinary tests. The implementation exposes explicit larger bounds for later evidence lanes but does not falsely claim the required 10,000/1,000,000 schedule evidence unless those executions actually occur.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ModelTests/TerraScale.Orchestrator.ModelTests.csproj`
