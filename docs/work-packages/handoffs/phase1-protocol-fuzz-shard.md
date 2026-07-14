# Phase 1 deterministic protocol fuzz shard handoff

- Base: `origin/chore/phase0-bootstrap` at `366c145`
- Branch: `phase1/protocol-fuzz-shard`
- External or destructive actions: none

## Result

The protocol test project now runs deterministic generated valid and malformed inputs from explicit SplitMix-style seeds across every current public protocol parsing/validation family: positive numeric factories, opaque byte factories, concrete subjects, permission patterns and matching, grammar limits, permission-policy construction and authorization, and command-envelope validation. A reflection inventory closes the current surface and confirms that no public header or snapshot parser/validator exists on this base; future additions make the inventory test fail until registered.

Every target family executes at least 10,000 cases. Generated categories have exact acceptance/error oracles, explicit branch/error-hit counts, randomized identities/byte shapes within each category, replay digests, culture-independent reruns, and permutation checks. The shard covers malformed/default/unknown numeric and enum values, unknown protocol versions and corpus fields, validity windows, stale generations/epochs, digest/signature failures, truncation/extension, subject size/token/count/unicode/wildcard boundaries, permission count limits, null/duplicate/cross-set patterns, redacted output, and construction-closed default results.

`SubjectPermissionPolicy.TryCreate` now totalizes caller enumerables through the review-approved narrow production expansion. `EnumerationFailed` closes exceptions from `GetEnumerator`, `MoveNext`, `Current`, and `Dispose`, discards partial values, and exposes no exception text. Tests cover failures before and after a valid item, current/dispose failure, exact maximum, finite maximum+1, and infinite unique prefixes for both allow and deny inputs.

Three minimal malformed seeds are checked in under `test-corpus/protocol` and compiled as a fixed-name embedded resource. The loader bounds bytes, JSON depth, entry count, and field lengths; rejects unknown/duplicate fields, versions, malformed content, duplicate identities, and digest tampering; and uses invariant UTF-8 byte-length prefixes for every string in its canonical digest. Each typed mutation is parsed and replayed from its recorded input with its explicit seed controlling the deterministic replay count.

## Validation

```text
dotnet test tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj --no-restore --verbosity minimal
dotnet test TerraScale.Orchestrator.slnx --no-restore --verbosity minimal
git diff --check
```

The focused protocol run passed 50 tests, including eight new fuzz/corpus/iterator-boundary tests. The full solution run passed 422 tests.

## Evidence boundary

This is deterministic generated-case replay, not a time-based fuzz campaign. It does not claim the ORCHESTRATOR 60-second feature budget, full fuzz budget, L0C, NATS conformance, or deployment evidence. It starts no network, process, NATS server, VM, container, or adapter.

Opaque payload, digest, and signature factories currently declare no maximum byte length. The shard samples lengths 0 through 256 and proves copy, empty-input, equality, truncation, extension, and redaction semantics; it does not invent or claim a production size ceiling. A separate caller-policy/API decision must select payload and cryptographic material limits.
