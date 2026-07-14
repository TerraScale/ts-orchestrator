# Phase 1 deterministic protocol fuzz shard

## Base

- `origin/chore/phase0-bootstrap`

## Allowed paths

- `tests/TerraScale.Orchestrator.Protocol.Tests/Fuzz/**`
- `tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj`
- `test-corpus/protocol/**`
- narrow review-approved expansion: `src/TerraScale.Orchestrator.Protocol/Subjects/SubjectPermissionPolicy.cs`
- this work package and `docs/work-packages/handoffs/phase1-protocol-fuzz-shard.md`

## Goal

Exercise every public parser and validator currently exposed by `TerraScale.Orchestrator.Protocol` with deterministic generated valid and malformed cases. Each target family executes at least 10,000 cases from an explicit seed and proves replay determinism, fail-closed output, enforcement of currently declared bounds, secret-safe diagnostics, and absence of forged accepted output.

The opaque payload, digest, and signature factories currently declare no maximum byte length. This shard samples deterministic lengths from 0 through 256 and proves copy, empty-input, truncation, extension, equality, and redaction behavior; it does not claim a production size ceiling. Selecting cryptographic and payload byte limits requires a separate caller-policy/API work package.

The shard uses no external fuzz package, random global, clock, filesystem mutation, network, process, NATS server, or adapter. Checked-in corpus resources are bounded, content-addressed, and loaded from embedded resources. This package does not claim the ORCHESTRATOR time-based fuzz budget, full fuzz evidence, L0C, or deployment qualification.

## Verification

```text
dotnet test tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj
```
