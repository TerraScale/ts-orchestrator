# Structured traceability foundation

The `traceability-validate` C# command validates `requirements/trace-links.yaml`, a strict
JSON-compatible YAML manifest. Every canonical registry ID must occur exactly
once with the registry owner and ordered acceptance layers copied exactly. An
entry is either an explicit `gap` with no links, or `linked` with bounded,
unique production-symbol, test-identifier, and typed evidence links.

Linked paths must be canonical repository-relative regular files. Traversal,
absolute paths, symbolic links, missing files, ambiguous identifiers, comment-
or string-only C# occurrences, evidence kind/layer substitutions, partial link
sets, unknown fields, and acceptance claims fail closed. The canonical report
always has `claimsAcceptanceEvidence: false` and `acceptanceSatisfied: 0` in
this tranche; structured links are trace associations, not acceptance proof.
Report generation/checking is confined to one regular JSON file directly below
`docs/audits/traceability`; existing symlinked parents or outputs are rejected.

Generate and verify the structured report:

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- traceability-validate
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- traceability-validate --check
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

The `traceability-generate` C# command remains available solely as a lexical gap-discovery
aid. Its `linked`, `test-only`, and similar labels describe text occurrence and
must never promote a structured entry or acceptance state:

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- traceability-generate
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- traceability-generate --check
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

The checked manifest intentionally begins with all 43 entries as first-class
gaps. Existing comments and requirement-ID strings were not converted into
links because they do not establish a complete typed production/test/evidence
chain.
