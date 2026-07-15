# Phase 1 structured traceability foundation

## Predecessor and boundary

- Base branch: `origin/chore/phase0-bootstrap`.
- The Phase 0 lexical trace report is retained as a non-acceptance gap aid.
- No production, registry, build, package, solution, specification, or sibling-repository changes are authorized.
- `claimsAcceptanceEvidence` must remain false; this tranche cannot satisfy or promote any registry acceptance layer.

## Allowed paths

- `requirements/trace-links.yaml`
- `tools/traceability/**`
- `docs/audits/traceability/**`
- `docs/work-packages/phase1-structured-trace-foundation.md`
- `docs/work-packages/handoffs/phase1-structured-trace-foundation.md`

## Deliverable

Replace lexical-only traceability with a strict structured manifest and dependency-free validator. Every one of the 43 registry IDs has exactly one entry whose owner and ordered acceptance layers match the registry, whose status is exactly `gap` or `linked`, and whose production, test, and evidence links use closed typed shapes.

Gap entries are first-class and have no orphan links. Linked entries require all three link classes, but remain non-acceptance associations. Do not invent links for unimplemented or inadequately evidenced items.

The validator must reject missing, duplicate, or unknown IDs; owner/layer drift; unbounded or malformed input; unknown fields; path traversal, absolute paths, symlinks, non-regular or outside-root files; missing or ambiguous identifiers; comment/string-only C# references; test-only, production-only, or evidence-free promotion; duplicate/reused links; invalid evidence kinds/layers; identifier substitution; stale output; and any acceptance-evidence claim.

It emits a deterministic canonical report and input digest. The lexical report remains separate and explicitly cannot promote structured or acceptance status.

## Verification

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- traceability-validate --check
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- traceability-generate --check
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

Run relevant registry/audit tests discovered in the repository. Pre-commit review is required.
