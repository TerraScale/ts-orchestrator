# Phase 1 budget policy completeness handoff

## Defect and correction

`BudgetProposal.IsWellFormed` previously rejected only `BudgetSafetyPurpose.Unspecified`. Undefined values such as `4` were treated as well formed and, under the normal budget posture, could return `Automatic` with a complete authorization trace. The predicate now admits only `OrdinaryCapacity`, `AvailabilityRepair`, and `DataLossPreventionStorageExpansion`.

The pre-fix regression executed against the same source base with only the first property test present: 486 tests ran, 485 passed, and the undefined-purpose property failed because the decision was `Automatic` instead of `Held/MalformedProposal`.

## Deterministic evidence added

- The exact four-value purpose enum inventory and names are pinned; `Unspecified` fails before evidence is enumerated.
- One thousand positive and negative undefined purpose values produce the exact held, non-authorizing, trace-free result.
- One thousand defined-purpose cases cover normal and emergency semantics with exact kind, reason, authorization, trace, delta, binding, and scope nullability.
- Every one of the nine dimensions independently covers provider/account hard limit, budget ceiling, forbidden band, approval band, and inclusive automatic boundary. The shard checks the complete numeric projection, node bounds, evidence ages, binding dimension, and typed approval scope.
- One thousand undefined status/scope/attachment values fail closed with exact budget/anomaly errors and no findings or authorizing outputs.

## Verification

After rebasing onto integration commit `81ad934`:

- Locked solution restore succeeded.
- Warnings-as-errors Release build succeeded with 0 warnings and 0 errors.
- Focused budget completeness shard: 5 passed, 0 failed.
- Complete ControlPlane Release executable: 493 passed, 0 failed.
- All five Release test executables: 692 passed, 0 failed, 0 skipped.
- `git diff --check` passed.

No provider/cloud/billing/price lookup, network, NATS, filesystem, process, VM, deployment, mutation run, or sibling repository was used. This handoff does not claim a current price, measured bill, approved cost target, L0C, real-system evidence, or deployment authority.
