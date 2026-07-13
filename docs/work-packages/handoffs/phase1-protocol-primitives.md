# Phase 1 protocol primitives handoff

- Branch: `phase1/protocol-primitives`
- Work package: `docs/work-packages/phase1-protocol-primitives.md`
- Scope: pure immutable contracts, protocol validation, and TUnit tests only
- Infrastructure, serialization, signing algorithm, wall clock, NATS, registry, build/package, and composition-root changes: none

## Implemented behavior

The tranche implements the draft `INV-005` command-admission model from `ORCHESTRATOR.md:580` without freezing a wire contract:

- Strong non-empty `CellId`, `AggregateId`, `OperationId`, and `IdempotencyKey` values reject null, empty, whitespace-only, and embedded-NUL identities while preserving caller spelling exactly.
- `ProtocolRevision`, `DesiredGeneration`, `WriterEpoch`, and `DeliveryAttempt` accept only positive `long` values; their default value remains invalid.
- `OpaquePayload`, `PayloadDigest`, and `OpaqueSignature` defensively copy source bytes, expose only read-only spans, compare by content, and never render contents. Digest and signature factories reject empty input without selecting an algorithm-specific width.
- `CommandEnvelope` is immutable and carries protocol version, cell, aggregate, desired generation, writer epoch, operation, idempotency identity, issued/expiry timestamps, attempt, opaque payload, payload digest, and opaque signature. Its formatting redacts payload, digest, and signature.
- `CommandSignedMaterial` exposes the complete signature-covered field set except the signature itself. The caller-supplied verifier owns canonical serialization, algorithm, trust roots, and signer-identity policy and must authenticate every field.
- `CommandValidationContext` explicitly supplies expected cell/aggregate, minimum generation/epoch, accepted protocol revisions, clock-skew tolerance, digest verifier, and signature verifier. Accepted revisions are defensively copied; there is no default tolerance or verifier.
- `CommandEnvelopeValidator` takes `now` explicitly and returns only `CommandValidationResult` plus the closed `CommandValidationError` catalog. Verifier exceptions are collapsed into typed verification-failure errors; exception messages are never returned.

## Deterministic order and boundaries

Validation is fail-fast in this order:

1. validation context
2. envelope structure/non-empty digest and signature
3. accepted protocol revision
4. `IssuedAt <= ExpiresAt`
5. not-yet-valid time bound
6. expiry time bound
7. expected cell
8. expected aggregate identity
9. minimum desired generation
10. minimum writer epoch
11. payload digest
12. signature

Clock skew is caller-supplied. Equality at `now + skew` for issue time and `now - skew` for expiry is accepted; one tick beyond is rejected. Subtraction-based comparisons avoid `DateTimeOffset` addition/subtraction overflow at extreme timestamps. Equal issue and expiry timestamps are structurally valid, while a reversed interval is rejected before skew evaluation. Generation and epoch equal to the context minimum pass; lower values are stale.

Validation is intentionally stateless. Replaying the identical envelope returns the same accepted result and re-runs digest/signature verification. Durable operation idempotency and completion re-read belong to the future operation journal/coordinator, not this value-object validator.

## Signer identity

This tranche does not invent a signer identifier, algorithm, trust store, or key format. Wrong-signer rejection is enforced by the concrete `ICommandSignatureVerifier` injected into the validation context for the expected authority. It receives `CommandSignedMaterial` containing protocol, cell, aggregate, generation, epoch, operation/idempotency identities, timestamps, attempt, payload, and payload digest plus the opaque signature separately. An identity/trust-policy mismatch returns `VerificationOutcome.Invalid`, which becomes `InvalidSignature`.

## Tests

The TUnit suite covers:

- invalid/default and positive-boundary value objects;
- defensive copying, content equality, empty digest/signature rejection, and secret-safe formatting;
- all envelope fields and redacted envelope formatting;
- malformed envelopes and contexts before verifier invocation;
- accepted-revision collection mutation after context construction;
- deterministic error precedence;
- equal/reversed validity windows, inclusive skew boundaries, one-tick failures, and extreme timestamp arithmetic;
- wrong cell/aggregate, lower versus equal generation/epoch, digest mismatch, wrong signer/invalid signature, and typed verifier failures;
- complete signed-material projection; and
- identical-envelope replay.

Verification commands:

```text
dotnet restore src/TerraScale.Orchestrator.Contracts/TerraScale.Orchestrator.Contracts.csproj --locked-mode
dotnet restore src/TerraScale.Orchestrator.Protocol/TerraScale.Orchestrator.Protocol.csproj --locked-mode
dotnet restore tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj --locked-mode
dotnet build tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj --no-restore
dotnet test tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj --no-build --no-restore
git diff --check
```

## Deliberate limitations

- This is not a serializer or frozen wire schema. Canonical bytes, unknown-field preservation, compatibility fixtures, and N/N-1 serialization remain steward-owned follow-up work.
- Digest/signature algorithms and widths remain verifier policy; this layer enforces only non-empty opaque values.
- Clock-skew tolerance and accepted protocol revisions remain mandatory caller inputs.
- Aggregate identity is the admission target. Operation and idempotency identities are strongly valid but their durable uniqueness/replay result is operation-journal state.
- The validator accepts generations/epochs above the supplied minimum. Authoritative generation re-read and future-epoch acquisition proof belong to coordinators and fenced journal state.
- No payload/identifier size ceiling is selected here; the future wire/transport contract must impose reviewed resource bounds before accepting untrusted serialized input.
- No production signing, serialization, transport, or deployment evidence is claimed by these L0 unit tests.
