# Phase 1 TerraBase accepted-output audit 2 handoff

## Result

The audit found and closed three accepted-output classes plus an adjacent expected-parameter hole:

- All seven entrypoints now reject a runtime-null or structurally invalid expected scope as `InvalidInput` before
  constructing a trace. Valid caller intent paired with null, malformed, or mismatched evidence remains
  `WrongEvidenceScope` and cannot emit a subject.
- Upgrade current/target releases and restore ID, terminal backup, and target generation are validated as caller
  intent before evidence matching. Null evidence identities cannot enter an authorizing subject.
- Add/remove intents require a positive replication position. Removal requires exact `CaughtUp` replication before
  leadership transfer or topology removal; unknown, lagging, conflicting, and future observations hold.
- Add, remove, upgrade, rollback, and restore checkpoints reject downstream proof that appears before its producing
  operation. Conflicting/future replication retains safety precedence, and contradiction after an applicable
  checkpoint remains a non-mutating observation or typed safety hold.

No enum member or numeric ID changed. Existing exact subject/trace closure remains intact.

## Evidence

Three new deterministic 1,000-case property families cover:

1. ten malformed scope dimensions, runtime-null expected scope, ten valid mismatches, and all seven entrypoints;
2. twenty topology modes spanning add/catch-up/transfer/remove/observe/verify, replication states, position validity,
   future proofs, role ordering, exact actions/codes/targets/traces, and authorizing topology subjects;
3. twenty-one upgrade/rollback/restore modes spanning every ordered checkpoint outcome used by the planners.

The families replay under `en-US` and `tr-TR` or `ar-SA`. Focused regressions additionally pin invalid expected
release/restore parameters and exact error precedence. Existing 44-field undefined-enum and 65-mode exact
scope/authorizing-output properties continue to pass.

## Verification

```text
Focused TerraBase second-audit shard: 8 passed, 0 failed, 0 skipped
ControlPlane tests: 518 passed, 0 failed, 0 skipped
Contract tests: 24 passed
Model tests: 38 passed
Protocol tests: 65 passed
Scheduler tests: 72 passed
Whole repository: 717 passed, 0 failed, 0 skipped
Solution build: 0 warnings, 0 errors
git diff --check: passed
```

## Remaining contract RFCs

- There is no explicit clean bootstrap-once/join-twice planner.
- The surface has no elastic tag/rank inventory from which reverse-order `3 -> 4 -> 3` removal can be proven.
- Six directed replication routes, placement generations, conflict reconciliation, and empty-cell recovery have no
  dedicated TerraBase decision surface.
- Restore has no explicit conflicting-operation proof.
- A contradicted post-rollback health proof can only remain an observation; there is no distinct terminal
  rollback-failure code/state.

These are implementation-readiness gaps, not claims satisfied by this pure bugfix/property shard.

## Non-claims

This is pure L0-style decision evidence only. It does not run TerraBase, storage, NATS, Linux, a VM, cloud APIs, or
deployment infrastructure and does not satisfy L0 aggregation, L3S, L4, or production acceptance.
