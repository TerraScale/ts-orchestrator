# Phase 1 protocol-negotiation completeness audit

## Scope and base

- Base: central `chore/phase0-bootstrap` at `1eac098`.
- Pure N/N-1 compatibility policy and accepted-output evidence only.
- Allowed implementation paths: `src/TerraScale.Orchestrator.ControlPlane/Messaging/MessagingContracts.cs` and `MessagingPolicyEngine.cs`.
- Allowed evidence paths: the messaging/negotiation tests in `tests/TerraScale.Orchestrator.ControlPlane.Tests/**`, this work package, and its handoff.
- No serializer, wire codec, canonical byte representation, byte cap, signing algorithm, transport, network, process, NATS server, VM, container, provider, or deployment work is in scope.

## Proven defect and correction

`DecideCompatibility` already required the exact adjacent positive version window and the exhaustive four-feature by three-direction compatibility matrix. Its successful public output, however, contained only the generic `CompatibilityAccepted` trace. Compatibility for versions `2/1` and `1000/999` therefore produced identical complete public outputs, so a caller could not persist or audit which exact window and matrix had been accepted.

The accepted decision now carries a construction-closed `CompatibilityAcceptance`. It contains the exact current and previous versions plus a defensive, immutable matrix ordered by numeric feature and direction. Rejected compatibility decisions and all topology, replacement, and partition decisions carry no compatibility acceptance. Existing trace and enum values are unchanged.

## Deterministic properties

- 1,000 distinct positive adjacent windows include `long.MaxValue / (long.MaxValue - 1)` and prove exact receipt scope.
- Every accepted receipt contains exactly the closed four `CompatibilityFeature` values crossed with the three `CompatibilityPair` values, in numeric feature-then-pair order.
- Caller ordering, culture, and source-array mutation do not affect the receipt or output signature.
- 1,000 rejected cases cover non-positive and non-adjacent windows, the impossible `current=1` window, undefined/missing/duplicate/unavailable evidence, and incomplete/duplicate/undefined feature catalogs with exact existing error precedence. No rejection emits an acceptance.
- Reflection proves that the acceptance type is sealed and has no public constructor, setter, factory, deconstructor, or record clone.
- Existing 1,000-case topology, replacement, and partition properties prove their decisions remain compatibility-unscoped.

## Verification

```text
dotnet build tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-restore --verbosity minimal
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build
dotnet test --solution TerraScale.Orchestrator.slnx --no-build --output Normal
git diff --check
```

This pure audit is not NATS conformance, time-based fuzzing, mutation evidence, N/N-1 process interoperability, serialized schema compatibility, or deployment qualification.
