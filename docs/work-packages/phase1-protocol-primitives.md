# Phase 1 protocol primitives

## Goal

Implement provider-neutral, immutable protocol value objects and command validation for `INV-005`, following the envelope at `ORCHESTRATOR.md:580`. This is a pure L0 tranche, not a frozen wire contract.

## Allowed paths

- `src/TerraScale.Orchestrator.Contracts/**`
- `src/TerraScale.Orchestrator.Protocol/**`
- `tests/TerraScale.Orchestrator.Protocol.Tests/**`
- `docs/work-packages/handoffs/phase1-protocol-primitives.md`

## Required behavior

- Strong non-empty identifiers for cell, aggregate, operation, and idempotency identity; positive generation/epoch/attempt types.
- An immutable command envelope carrying every field named by the specification, with payload and signature represented only as digests/opaque bytes and never rendered by `ToString`.
- A pure validator using an explicit validation context and supplied `now`; reject malformed, expired/not-yet-valid, wrong-cell, wrong-identity, stale generation, stale epoch, digest mismatch, and invalid signature. Return a typed closed error catalog, never exception text.
- Validation order must be deterministic and tests must cover boundaries, replay of an identical envelope, and secret-safe formatting.
- Do not choose signing algorithms, clock-skew tolerances, serialization formats, NATS subjects, or owner-decision defaults. These are caller inputs or remain absent.

## Verification

`dotnet test tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj`
