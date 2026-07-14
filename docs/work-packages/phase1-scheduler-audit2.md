# Phase 1 scheduler capacity/completeness audit

## Goal

Adversarially audit the existing pure scheduler policy against the hard-resource,
quorum, disruption-budget, anti-affinity, topology-spread, reserve, deterministic
tie-break, and explainable-rejection requirements in `ORCHESTRATOR.md`.

## Allowed paths

- `src/TerraScale.Orchestrator.Scheduler/Availability/**`
- `tests/TerraScale.Orchestrator.Scheduler.Tests/**`
- `docs/work-packages/phase1-scheduler-audit2.md`
- `docs/work-packages/handoffs/phase1-scheduler-audit2.md`

## Required behavior

- Prove every accepted placement fits the caller-observed resources even when an
  explicitly supplied N+1 reserve may be consumed.
- Preserve the existing twenty availability trace rows and numeric reason IDs as an
  exact prefix, then append explicit capacity reasons for all eight resource
  dimensions.
- Keep reserve preservation independent from fundamental capacity admission:
  `MayConsume` disables only the reserve floor, never the capacity floor.
- Emit one stable, complete reason-code order for placement, maintenance, drain,
  invalid-target, and held-evidence paths.
- Exercise every closed caller-veto value, including volume-locality holds, and all
  eight capacity dimensions with deterministic 1,000-case properties.

## Boundaries

This lane changes no scheduler default, topology number, critical-service policy,
provider/runtime behavior, package, or external system. Caller-owned stateful vetoes,
product placement, and capacities/reservations remain outside the pure evaluator.

## Verification

Run locked restore, warnings-as-errors Release build, the focused scheduler suite,
the full solution suite, and `git diff --check` on the final rebased tree.
