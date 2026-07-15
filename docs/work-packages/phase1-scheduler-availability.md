# Phase 1 scheduler availability policy

## Goal

Implement pure scheduler hard-policy evaluators for quorum floors, disruption budgets, critical replica anti-affinity/topology spread, and caller-supplied N+1 reserve from `ORCHESTRATOR.md:307-323,619`.

## Allowed paths

- `src/TerraScale.Orchestrator.Scheduler/Availability/**`
- `tests/TerraScale.Orchestrator.Scheduler.Tests/Availability*.cs`
- `docs/work-packages/handoffs/phase1-scheduler-availability.md`

## Required behavior

- Immutable service/replica/node/failure-domain identities and explicit policy inputs for desired/min-available/quorum/disruption counts, criticality, one-per-host, required distinct domains, and reserve resource vector.
- Evaluate placement, drain, and maintenance admission without choosing numeric defaults. Reject co-location/domain collapse, quorum/min-available violation, concurrent disruption over budget, and consumption of caller-supplied reserve.
- Quorum arithmetic is checked and exact; ambiguous/missing/duplicate observations hold. Never infer stateful move safety or project/database geography.
- Return closed reason codes and stable ordered traces without free-form caller text. Decisions must be invariant to input permutations and culture.
- Tests cover 3-node quorum, 2-of-3 loss, one-at-a-time maintenance, last failure-domain margin, zero/maximum/overflow counts, reserve exact boundary, duplicate/conflicting replicas, permutations, and secret-safe output.
- No runtime/provider/NATS/filesystem/time access and no SLO/topology/cost defaults.

## Verification

`dotnet test tests/TerraScale.Orchestrator.Scheduler.Tests/TerraScale.Orchestrator.Scheduler.Tests.csproj`
