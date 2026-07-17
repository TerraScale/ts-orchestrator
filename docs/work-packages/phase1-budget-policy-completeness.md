# Phase 1 budget policy completeness

## Scope

- Base: integration commit `621c37d` or its final reviewed successor.
- Production: `src/TerraScale.Orchestrator.ControlPlane/Budgets/BudgetEvidence.cs` only.
- Tests: `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/BudgetPolicyCompletenessPropertyTests.cs`.
- Handoff: `docs/work-packages/handoffs/phase1-budget-policy-completeness.md`.

## Goal

Close the budget proposal's open enum boundary and add deterministic completeness evidence for the pure budget/cost policy. A proposal may use only the three explicitly declared nonzero safety purposes. `Unspecified` and every undefined underlying enum value fail before evidence collection and cannot emit an authorizing trace or approval scope.

The property shard pins the exact purpose inventory, all nine budget dimensions, provider/account-limit then budget-ceiling then forbidden-band then approval-band precedence, exact trace and approval-scope fields, and undefined usage-status/scope/resource-attachment handling.

## Boundaries

This shard selects no owner cost target, price, currency, unit, SLO, provider, or emergency default. Price evidence remains an explicit caller-supplied current/unknown/stale identity; the shard performs no price lookup or estimation. It uses no provider/cloud API, billing export, NATS, filesystem, network, process, VM, systemd, containerd, rootless container, deployment, or sibling-repository operation.

The result is L0 pure-policy evidence only. It does not claim mutation completeness, NATS L0C, real billing reconciliation, a measured cost gate, deployment qualification, or deployment authority.
