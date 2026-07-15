# Phase 1 TerraBase accepted-output audit 2

## Predecessor and scope

- Integration predecessor: `1eac098`.
- Allowed production paths: `src/TerraScale.Orchestrator.ControlPlane/TerraBase/**`.
- Allowed evidence paths: TerraBase tests under `tests/TerraScale.Orchestrator.ControlPlane.Tests/**`
  and this package/handoff.
- No database, process, filesystem, network, NATS, provider, sibling-repository, or deployment activity.

## Goal

Audit all seven public TerraBase decision entrypoints for malformed caller expectations, exact evidence scope,
topology replication safety, valid intent parameters, and ordered upgrade/rollback/restore evidence. Prove any
accepted-output defect with a failing pre-fix regression before changing production behavior.

## Required evidence

- All ten `TerraBaseEvidenceScope` validity dimensions and runtime-null expectations across all seven entrypoints.
- Valid-but-mismatched evidence remains distinct from malformed caller intent.
- Add/remove/catch-up/transfer/observe/verify transition and precedence coverage, including every replication state.
- Upgrade, rollback, and restore future-proof coherence for `Unknown`, `Proven`, and `Contradicted` checkpoints.
- Exact mutation subject and trace closure, 1,000 deterministic cases per new property family, and non-English culture replay.
- Focused, full control-plane, whole-solution build, and all executable test projects.

## Explicit exclusions

This audit does not invent absent bootstrap/join, elastic member ordering, multi-region replication placement,
restore-conflict, or terminal rollback-failure contracts. Those require a steward-owned compatible contract tranche.
