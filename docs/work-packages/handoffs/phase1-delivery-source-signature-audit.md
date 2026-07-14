# Phase 1 Delivery source-signature audit

## Finding and correction

Source verification previously compared the proposed and observed opaque
`SignatureId`, but `SourceEvidence` had no result or attestation proving that the
signature was checked. An exact evidence record could mark schema and dependency
verification successful while the source signature was invalid or unchecked, and
the engine emitted `PlanApplyIntent`.

`SourceEvidence` now requires a signature-verification attestation and result.
`DecideSource` emits `VerifySourceIntent` unless signature, schema, and dependency
verification all succeed. An accepted `PlanApplyIntent` retains the exact signature
attestation alongside the existing signature, schema attestation, dependency
attestation, and ordered dependency proofs.

Evidence subject equality still precedes verification-state evaluation. A replay
or mismatched source field remains `EvidenceInvalidated`; an exact but incomplete
or failed verification remains the existing `VerificationRequired` path. No error,
action, trace, or other enum member or numeric value changed.

## Evidence

- The regression counterexample uses an exact proposed and observed forged
  signature ID with successful schema and dependency checks. `SignatureValid=false`
  now produces only `VerifySourceIntent` and never plan/apply authority.
- Null, empty, and overlength signature-attestation identities fail closed as
  invalidated evidence.
- Signature, schema, and dependency verification results are independently gated.
- The plan/apply public-shape inventory and 1,000-case culture-stable output
  fingerprint retain the exact signature attestation.
- The Delivery/TerraBase replay property includes failed signature verification as
  a deterministic source outcome.

## Boundary

This is pure Delivery decision evidence only. It does not implement or qualify a
signature verifier, trust root, signing policy, Git/Forgejo adapter, persistence,
NATS transport, deployment credential, VM, provider, or production acceptance
evidence. It proves only that the pure authorizing boundary can represent and
requires the caller-supplied verification result and retains its attestation.
