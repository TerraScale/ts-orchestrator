# Phase 1 budget and cost decision core

## Predecessor

- Contract steward commit: `85db082`
- Draft Phase 1 contracts; no owner cost target or provider price is selected.

## Goal

Implement the pure budget authorization and anomaly decision core from `ORCHESTRATOR.md:746-756`. It classifies typed resource/spend changes without estimating prices or performing provider actions.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Budgets/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Budget*.cs`
- `docs/work-packages/handoffs/phase1-budget-core.md`

## Required behavior

- Immutable bounded cell, node-class, cost-center, resource, price-evidence, and approval identities; checked non-negative fixed-point quantities only—no floating point.
- Explicit caller policy for per-node-class min/max/warm counts; per-cell and global CPU, memory, storage, IOPS/throughput, public-IP, LB-backend, hourly and daily spend ceilings; automatic, approval-required, and forbidden bands; emergency posture; evidence freshness; and safety purpose.
- Authorize or hold/reject a proposed delta against complete current cell/global usage. Unknown, stale, incomplete, duplicated, conflicting, negative, overflowed, or wrong-scope observations fail closed.
- Emergency budget may reject non-safety growth but may not authorize termination and may not block an explicitly classified data-loss-prevention storage expansion inside hard provider/account limits.
- Emit closed `Automatic`, `ApprovalRequired`, `Forbidden`, or `Held` decisions and a complete stable numeric trace. Approval-required output contains typed approval scope only; no callback, command, arbitrary text, price lookup, or provider behavior.
- Detect orphan/unattached resource and desired-vs-owned-vs-billing discrepancies as typed anomaly findings without deciding deletion.
- Defensive copies, culture/input permutation determinism, exact-boundary and every-dimension tests, maximum/overflow tests, missing/duplicate/conflicting evidence tests, emergency safety tests, and secret-safe output.
- No cost/SLO defaults, wall clock, provider SDK, billing API, filesystem, NATS, or mutation.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`

