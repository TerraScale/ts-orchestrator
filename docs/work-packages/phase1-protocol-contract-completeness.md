# Phase 1 protocol contract-completeness property shard

## Scope and base

- Base: central `chore/phase0-bootstrap` at `7d960ecebb654a6fdcb4cc451e0bf98892097ba1`.
- Narrow production hardening is limited to accepted-version input capture and fatal-exception propagation in existing command-verifier and permission-policy wrappers.
- It starts no process, socket, NATS server, VM, container, systemd unit, cloud/provider operation, or deployment and makes no L0/L0C or production-readiness claim.

## Properties

- 1,000 materially distinct command-admission cases use exact independent error oracles, deterministic replay, culture changes, unique identities/generations/epochs/timestamps/payloads, and secret-safe result checks.
- 1,000 distinct unknown positive protocol revisions are rejected before digest or signature verification.
- 1,000 distinct envelopes prove every in-memory `CommandSignedMaterial` field remains bound to its source envelope.
- 1,000 distinct binary values prove defensive copy, equality, truncation/extension distinction, and redacted formatting without inventing a byte ceiling.
- 1,000 distinct Unicode subjects pin the accepted UTF-16 code-unit limit semantics and exact boundary behavior.
- 1,000 distinct corpus mutations cover oversize, truncation, malformed UTF-8, unknown and duplicate fields, unknown family/error vocabulary, invalid seed, and digest tampering.
- The embedded corpus is read from seekable or non-seekable streams within a byte bound, decoded as strict UTF-8, checked against a whole-file SHA-256 pin, and validated against closed family/error vocabularies.

## Proven production hardening

- `CommandValidationContext` now captures at most 4,096 caller items before deduplication. This public technical ceiling is intentionally far above the ordinary N/N-1 set; it is an acquisition/denial-of-service bound, not permission to accept 4,096 wire versions. The implementation checks maximum+1 after `MoveNext` and before the extra `Current`, ignores lying collection counts, snapshots defensively, bounds endless duplicate sequences, translates ordinary failures from every iterator phase to `ArgumentException` with no inner exception or iterator text, and propagates `OutOfMemoryException`, `StackOverflowException`, and `AccessViolationException`.
- Command digest/signature verifier wrappers retain their existing typed failures for ordinary exceptions but propagate those three fatal runtime exceptions.
- Subject permission allow/deny enumeration retains the caller-supplied `MaximumPermissionPatternCount`; no second pattern business cap was invented. Ordinary acquisition failures remain `EnumerationFailed`, while fatal runtime failures now propagate from `GetEnumerator`, `MoveNext`, `Current`, and `Dispose`.

## Explicit deferred gaps

The accepted `phase1-protocol-fuzz-shard` and subject-grammar handoffs intentionally leave these transport decisions open. This shard does not silently close them:

- There is no public command/event/header/snapshot wire codec, canonical serialized form, schema conversion, or unknown-optional-field preservation surface. Therefore canonical encoding, serialized truncation, duplicate/unknown wire fields, malformed wire UTF-8, and N/N-1 schema round-trip remain unimplemented production requirements.
- Opaque payload, digest, signature, and command identifiers have no reviewed serialized byte ceilings. Selecting limits is an owner/API compatibility decision.
- Subject limits count .NET UTF-16 code units. A future transport adapter must separately bound encoded UTF-8 bytes.
- Subject-pattern count remains a caller-policy trust boundary: `SubjectGrammarLimits.MaximumPermissionPatternCount` must be selected by the caller before untrusted policy material is collected. This shard preserves that accepted contract and adds no global pattern-count policy.

These are audit findings, not acceptance claims. A future production work package must select compatibility behavior and add transport-byte/fuzz fixtures before any untrusted serialized input is admitted.

## Verification

```text
dotnet test tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj --no-restore --verbosity minimal
git diff --check
```
