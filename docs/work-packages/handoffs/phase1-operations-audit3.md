# Phase 1 operations work-request continuity handoff

## Result

The pure operation engine now preserves a provider work-request identity once an `Unknown` or
`InProgress` observation establishes one. A later observation with a different or missing identity is
rejected with `ConflictingTerminalObservation`; the engine emits no event or intent. If no identity was
previously supplied, a later observation may keep it absent or establish it once.

Command handling and journal replay share the conflict order: exact observation replay, same
observation-ID rebinding, established work-request continuity, then replacement of final provider truth.
This keeps the more specific observation-identity error ahead of the new continuity check and preserves
the prior final-observation rule.

## Deterministic evidence

The focused regression fixture covers:

- established non-null identity changed or removed;
- absent identity remaining absent or becoming established;
- immutability after first establishment;
- one work request progressing from pending to success;
- same observation-ID rebound precedence;
- forged journal events changing or removing the identity while preserving prior state;
- event and decision digests changing with the provider work-request identity.

`OperationDigest` already encoded `ProviderWorkRequestId` in observation events and reconciliation
intents, so no digest-domain or accepted-output shape change was necessary.

## Evidence boundary

This closes only the proven pure-policy replay gap. It does not establish that a provider adapter returns
an authentic work-request identity, does not add cryptographic verification, and does not claim L0C,
provider conformance, mutation coverage, VM/cloud execution, or deployment readiness.
