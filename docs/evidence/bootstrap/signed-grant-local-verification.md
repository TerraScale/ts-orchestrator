# System Project cold-bootstrap signed grant: local verification lane

Status: implemented and lane-tested on `develop`, 2026-08-29. This note is the
honest evidence record for the Orchestrator side of qualification gap sweep
row 31 (`/home/mariogk/Projects/TerraScale/TerraBaseV2/docs/evidence/qualification-gap-sweep.md`,
"system Project cold bootstrap and complete recovery"). It does not close the
row: the row also requires the Database API wiring, which lives in another
repository.

## What exists now

`src/TerraScale.Orchestrator/Bootstrap/` implements the signed-grant half of
the bootstrap trust contract in `AGENTS.md` ("Bootstrap trust") and the
workspace `GOAL.md` ("Dashboard system Project and bootstrap"):

- `BootstrapGrantCanonical.cs` — deterministic length-prefixed canonical
  encoding (`length:value;` records, the same scheme as the CreateNode handoff
  receipt codec) with a strict parser that rejects reordered, resized, padded,
  or trailing content.
- `BootstrapGrantPayload.cs` — the typed, canonically encodable grant payload:
  payload version, grant ULID (26-character Crockford base 32 per ADR 0027),
  64-hex nonce, trust-bundle key id/version/purpose code, fixed system
  Organization/Project/database ULIDs, audience, certificate fingerprint,
  UTC-tick validity window, and the sorted distinct allowed-operation list.
  Persisted operation codes are fixed strings (`ensure-system-organization`,
  `ensure-system-project`, `ensure-system-database`,
  `ensure-system-project-configuration`); only that idempotent set is
  admissible.
- `BootstrapTrustBundle.cs` — the versioned, rotated local trust bundle with
  key purpose separation (`bootstrap-grant-signing-v1` vs
  `bootstrap-workload-attestation-v1`). Keys resolve by exact
  (key id, key version); every retained grant-signing key must be older than
  the current one and pins an `AcceptedUntil` deadline, which is the rotation
  window.
- `SignedBootstrapGrant.cs` — the wire form (canonical payload text + one
  ECDSA-P256-SHA256 signature, the repository's pinned signing algorithm), the
  `BootstrapGrantIssuer` (refuses to sign with a non-grant-signing key), and
  `BootstrapWorkloadIdentity`, which mints the short-lived self-signed ECDSA
  P-256 X.509 development workload certificate and derives the binding value:
  the lowercase SHA-256 hex digest of the SubjectPublicKeyInfo.
- `BootstrapReplayJournal.cs` — in-memory and durable file-backed replay
  journals. The file journal appends the consume record before acknowledging
  it, survives the restart shape, prunes entries for already-expired grants on
  load, and skips a torn trailing line (crash during append, when no answer
  was returned).
- `SignedBootstrapGrantVerifier.cs` — local verification from the bundle only:
  canonical form, algorithm, key presence, key purpose, signature, audience
  binding (fixed-time compare for the certificate fingerprint), validity
  window and maximum lifetime, pinned rotation window, fixed system Project
  identity, operation allowlist plus idempotence, and one-time replay
  consumption. Every failure is a typed decision; no denial distinguishes
  which signature byte failed; the result carries no grant id, nonce,
  audience, or fingerprint value.

The cryptographic layer composes with the landed policy decision engine in
`src/TerraScale.Orchestrator/Security/SystemProjectBootstrap/`
(`a72f315`, `5a9bfd2`): `SignedBootstrapGrantVerification.ToSignatureEvidence()`
bridges into `BootstrapGrantVerifier`, and the journals implement its
`IBootstrapGrantReplayConsumer`.

## Evidence

Focused check, run on this host 2026-08-29:

    dotnet build TerraScale.Orchestrator.slnx            # 0 warnings, 0 errors
    ./tests/TerraScale.Orchestrator.ControlPlane.Tests/bin/Debug/net10.0/linux-x64/TerraScale.Orchestrator.ControlPlane.Tests
    # total: 872, failed: 0, succeeded: 872

The 20 new lanes in
`tests/TerraScale.Orchestrator.ControlPlane.Tests/Bootstrap/SignedBootstrapGrantVerificationTests.cs`
cover: valid grant verifies from the local bundle only; wrong audience, wrong
workload certificate, expired, not-yet-valid, over-long, wrong system Project,
non-granted operation, and non-idempotent operation each fail typed; replay
consumes the nonce exactly once and the second attempt fails typed; the file
journal survives the restart shape (including the torn trailing line) and
prunes expired entries on load; unknown key id and unknown key version fail
typed; a tampered payload fails as an invalid signature and non-canonical
payload text fails before signature work; a previous-bundle-version grant
still verifies inside the pinned rotation window while a grant whose validity
exceeds the window fails typed, and the retired key becomes unknown once
rotation advances; key purpose separation is enforced at issuance (throw) and
at verification (`KeyPurposeMismatch`); issuance refuses reversed windows,
lowercase ULIDs, and malformed nonces; the canonical payload is deterministic
and round-trips; the cryptographic layer composes with the landed policy
engine to an `Authorized` decision; and the serialized verification result
redacts every bound value.

## Honest limits

- **Not wired into `TerraScale.Database`.** The Database API does not yet
  consume this verifier or bundle. Wiring it in — including how the Database
  API obtains the presented certificate fingerprint from its TLS terminator —
  is a later cross-repository packet. Until that lands, gap sweep row 31
  remains open; this note supplies its Orchestrator half.
- The workload certificate here is a self-signed development shape. Production
  issuance stays with the Orchestrator provider adapter, which is not part of
  this packet.
- Bundle construction, persistence, and distribution to Database API
  instances (versioning on disk, how a rotation is pushed and pinned across
  Regions) are not implemented; the bundle is a typed in-memory contract plus
  tests.
- No steady-state rotated workload-credential path (`@terrascale/sdk`
  credential-provider) exists here; this packet covers the bootstrap grant
  only.
- The file replay journal is single-process, single-file, and not concurrent
  across multiple Database API instances; a shared-durable journal is part of
  the Database API wiring packet.
- No performance claim is made; the lanes are functional correctness lanes on
  this shared development host.
