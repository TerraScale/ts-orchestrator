# Phase 1 operations work-request continuity audit

## Scope

- Predecessor: `5b05f4b70dca888dda9ee665f6164345419c31c1` after the final central rebase.
- Requirements: `INV-005` command replay identity and `INV-006` stale/conflicting provider observation rejection.
- Allowed production path: `src/TerraScale.Orchestrator.ControlPlane/Operations/OperationEngine.cs`.
- Allowed test path: `tests/TerraScale.Orchestrator.ControlPlane.Tests/OperationWorkRequestContinuityCounterexampleTests.cs`.
- Allowed documentation paths: this manifest and `docs/work-packages/handoffs/phase1-operations-audit3.md`.

## Counterexample and acceptance

After a provider operation records an `InProgress` observation for work request `provider-work-1`,
the prior policy accepted a later success observation for `provider-work-2`. The accepted event could
therefore complete the frozen operation from a different provider request.

Once a non-null provider work-request identity is observed, later observations must retain it exactly.
A missing identity may remain missing or establish the first non-null identity. Exact observation replay
is evaluated first, observation-ID rebinding second, work-request continuity third, and prior-final
conflict fourth. Commands and journal replay use the same precedence and the existing
`ConflictingTerminalObservation` error.

## Boundaries

This package changes no public shape, enum, digest domain, solution/package file, registry, schema,
composition root, adapter, or external system. It performs no provider, NATS, filesystem mutation,
process-control, lab, VM, or deployment action. It does not claim provider adapter conformance, L0C,
mutation score, model completeness, or deployment qualification.

## Verification

- Release build with warnings as errors.
- Focused work-request regressions.
- Full ControlPlane suite and all five solution test suites.
- `git diff --check` and clean branch status.
