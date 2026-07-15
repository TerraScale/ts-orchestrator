# Phase 1 Protocol accepted-command receipt audit

## Scope and base

- Base: central `chore/phase0-bootstrap` at `8e90364c960cee44ebeacb4c8e0dbdfb5ac5da43`.
- Allowed paths: `src/TerraScale.Orchestrator.Protocol/CommandValidation.cs`, Protocol tests, and this work package.
- Pure in-memory command validation only. No serializer, NATS process, socket, filesystem, clock API, secret retrieval, VM, provider, or deployment operation is introduced.

## Proven gap

Before this audit, every accepted command returned the same complete public value: `CommandValidationResult { Error = None, IsValid = True }`. A valid protocol N command and a different valid N-1 command therefore produced equal accepted results even when their generations, operation identities, idempotency identities, and signatures differed. A durable caller could not persist which signed envelope validation accepted without rejoining the caller-controlled input.

## Contract correction

Successful validation now emits a construction-closed immutable `CommandAcceptance`. It retains the exact protocol revision, cell, aggregate, desired generation, writer epoch, operation, idempotency key, issued/expires times, delivery attempt, payload digest, signature, and explicit validation time. Its value equality makes identical replay equal and makes every retained-field substitution unequal.

The receipt deliberately does not retain the raw opaque payload. The accepted digest and signature bind that payload without encouraging a durable audit projection to duplicate possibly secret bytes. Receipt formatting redacts the digest and signature. The type exposes no public constructor, setter, deconstructor, clone, or public factory.

Every rejection and the default result retain `Acceptance = null`. The existing error numbers and exact precedence remain unchanged:

```text
InvalidValidationContext -> MalformedEnvelope -> UnsupportedProtocolVersion
-> InvalidValidityWindow -> NotYetValid -> Expired -> WrongCell
-> WrongAggregateIdentity -> StaleGeneration -> StaleWriterEpoch
-> PayloadDigestMismatch/VerificationFailed
-> InvalidSignature/SignatureVerificationFailed
```

Only the final valid-signature branch constructs the receipt.

## Evidence boundary

This is an accepted-envelope receipt. It is not a receipt for the digest/signature verifier implementation or for the complete validation-context policy. In particular, it does not retain the accepted-version set, minimum generation/epoch, allowed skew, or verifier identities. Callers that require complete authorization provenance must persist that policy evidence separately; this audit makes no wire-codec, serialization, canonical-byte, NATS-conformance, or deployment-readiness claim.

## Verification

The focused regression covers N versus N-1 output inequality, exact receipt fields, identical replay equality, per-field inequality, receipt absence on every generated rejection/default, construction closure, payload omission, and redacted formatting. Existing 1,000-case and 10,000-case validators now include input-sensitive accepted-result fingerprints and require acceptance scope to match success under multiple cultures.

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore -warnaserror
dotnet run --project tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj -c Release --no-build --no-restore -- --no-progress
git diff --check
```

Recorded on this exact branch: Release solution build succeeded with zero warnings and zero errors; Protocol passed 70/70; all five repository executables passed 771/771 (ControlPlane 562, Contract 24, Model 38, Protocol 70, Scheduler 77).
