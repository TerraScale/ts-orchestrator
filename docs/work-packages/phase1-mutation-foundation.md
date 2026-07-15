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
python3 tools/mutation/validate_mutation_evidence.py --as-of 2026-07-13
python3 -m unittest discover -s tools/mutation -p 'test_*.py' -v
python3 -m json.tool tools/mutation/mutation-policy.json
python3 -m json.tool tools/mutation/mutation-evidence.json
python3 -m json.tool tools/mutation/fixtures/negative-cases.json
```
