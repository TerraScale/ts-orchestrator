# Phase 1 mutation-evidence foundation

## Goal

Create a deterministic, fail-closed mutation project inventory, exclusion
policy, and zero-claim report while the mutation tool remains unselected. Do
not choose, install, restore, or run a candidate tool and do not claim a score.

## Allowed paths

- `tools/mutation/**`
- `docs/audits/mutation/**`
- `docs/work-packages/phase1-mutation-foundation.md`
- `docs/work-packages/handoffs/phase1-mutation-foundation.md`

## Required behavior

- Cross-check the mutation candidate/version/status against the existing Phase
  0 supply-chain audit and reject selection or execution claims while that
  source remains `candidate-unselected`.
- Inventory every production project and fail on additions, removals, duplicate
  entries, unsafe paths, and symlinks.
- Require mutation testing for every current correctness-critical project.
- Permit exclusions only for generated code, immutable DTO accessors, or proven
  trivial composition wiring; bind excluded source by exact path and SHA-256.
- Never permit exclusions for state transitions, validators, authority,
  fencing, deletion, retry, compensation, or adapter result classification.
- Preserve the specification's 85% score and zero safety-survivor thresholds
  without claiming either has passed.
- Validate exact schemas, bounded collections, policy/source digests, review
  freshness, and explicit null/false zero-claim results.
- Exercise adversarial fixtures for fabricated results, weakened policy,
  forbidden exclusions, drift, staleness, duplicate keys, and unsafe paths.

## Verification

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- mutation-evidence --as-of 2026-07-13
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format tools/mutation/mutation-policy.json
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format tools/mutation/mutation-evidence.json
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format tools/mutation/fixtures/negative-cases.json
```
