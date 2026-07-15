# Phase 1 scheduler observation-generation audit

## Goal

Close the availability evaluator's accepted-observation replay gap without changing
placement defaults or moving persistence into the pure scheduler. An authorization
must be bound to the exact generation of the observation snapshot already accepted
by its caller.

## Allowed paths

- `src/TerraScale.Orchestrator.Scheduler/Availability/**`
- `tests/TerraScale.Orchestrator.Scheduler.Tests/**`
- `docs/work-packages/phase1-scheduler-audit3.md`
- `docs/work-packages/handoffs/phase1-scheduler-audit3.md`

## Required behavior

- Require positive candidate and current-accepted observation generations on every
  availability evaluation request.
- Hold a lower candidate generation as rollback evidence and a higher candidate
  generation as not-yet-accepted evidence; equal generations preserve policy
  behavior and retry determinism.
- Preserve the existing reason IDs and trace rows 1 through 28 exactly, then append
  explicit rollback and future-generation reasons as numeric IDs 29 and 30.
- Let either generation hold participate in evidence precedence before target and
  policy evaluation even though the two compatibility rows are appended to the
  trace after the established 28-row prefix.
- Pin exact enum values, trace order, observed/required values, output signatures,
  constructor validation, and lower/equal/higher properties.

## Boundaries

This is a pure L0 policy correction. The caller remains responsible for accepting
and durably storing an observation generation. This lane adds no signature,
timestamp, persistence, NATS, provider, runtime, filesystem, process, or network
behavior and selects no topology or availability default.

## Verification

Run locked restore, warnings-as-errors Release build, focused scheduler tests, the
complete solution test set, and `git diff --check` on the final rebased tree.
