# Structured traceability foundation

The `traceability-validate` C# command validates the checked-in structured
traceability artifacts under `docs/audits/traceability`. The former
`requirements/trace-links.yaml` manifest was removed; validation no longer
depends on a requirements registry tree.

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
