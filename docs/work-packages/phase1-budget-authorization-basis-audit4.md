# Phase 1 budget authorization basis audit 4

## Goal

Close the proven budget-to-compute accepted-output collision where distinct selected policy/evidence provenance produced the same typed automatic authorization output.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Budgets/BudgetDecision.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/BudgetFourthAuditRegressionTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/BudgetDecisionSubjectCompletenessPropertyTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/BudgetProviderPropertyTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/BudgetProviderReplayCorpus.v1.json`
- `docs/work-packages/phase1-budget-authorization-basis-audit4.md`
- `docs/work-packages/handoffs/phase1-budget-authorization-basis-audit4.md`

## Contract

Every `BudgetDecision` produced after successful evidence selection and trace construction retains a construction-closed `BudgetDecisionBasis`. The basis holds exact references to the validated `BudgetPolicy` and selected cell-usage, global-usage, node-class-usage, and price-evidence observations. This phase boundary applies to automatic, approval-required, forbidden, and traced emergency-held decisions; it does not depend on authorization alone.

Early decisions that do not construct a trace or establish selected evidence retain `Basis = null`, in lockstep with their existing null trace and subject. The existing proposal-bound `BudgetDecisionSubject`, approval scope, policy arithmetic, decision kinds/reasons, precedence, trace fields, and enum numerics do not change.

`BudgetDecisionBasis` has no public constructor, setter, deconstructor, clone path, or alternate public factory. Its string representation is opaque and redacted.

## Validation matrix

- Distinct selected usage evidence IDs with otherwise identical accepted input: basis fingerprints differ.
- Automatic, approval-required, forbidden, provider-limit, emergency-held, and emergency-safety decisions: exact policy and four evidence references retained.
- Invalid policy/proposal/scope/class, missing/unknown/stale/duplicate/conflicting/over-limit evidence, and arithmetic failure before trace creation: basis remains absent.
- Independent evidence identity, value, age, status, price, and policy changes: accepted basis follows the exact selected objects or fails closed under existing rules.
- Reordered usage evidence, repeated evaluation, and `en-US`, `tr-TR`, `ar-SA`, and `ja-JP`: deterministic basis over 1,000 cases.
- Strict whole-file SHA-256 corpus: original and substituted evidence-identity failure seeds replay exactly.
- Reflection: construction closure, getter-only surface, no record-clone/deconstruct/factory path, and redacted output.

## Boundary

This is a pure in-memory authorization-output provenance correction. It does not authenticate evidence producers, prove billing exports or price accuracy, add a policy generation, choose a provider, establish a cost target, or grant provider mutation authority. It performs no provider SDK, billing, network, filesystem, process, VM, cloud, deployment, or other external side effect.
