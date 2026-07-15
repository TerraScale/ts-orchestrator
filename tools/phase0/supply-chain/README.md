# Supply-chain candidate validator

This standard-library-only validator checks the Phase 0 candidate manifest without downloading or executing any candidate tool.

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- supply-chain
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

It fails closed on floating versions, non-primary or non-versioned sources, missing Linux architecture coverage, absent mirrors/gaps, any production-qualification claim, or any artifact/evidence/attestation signing selection. It also binds the current `global.json`, central TUnit declaration, TUnit/Microsoft.Testing.Platform lock resolution and content hashes, and every checked-in NuGet lock-file SHA-256. The negative fixture corpus is data-driven and contains only synthetic markers.
