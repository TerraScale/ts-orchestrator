# Phase 1 security authorization output audit 3 handoff

## Proven gap and correction

Two exact accepted capability requests could use the same operation, principal ID, capability, resource scope, and generation numbers while proving different principal kinds and roles with different matching grants. Their traces and `AuthorizeCapabilityIntent` values were equal because the intent retained none of the selected evidence or grant provenance.

Accepted authorization intents now retain the exact selected `PrincipalAuthorizationEvidence`, exact selected matching `AuthorizationGrant`, and the accepted expected/current principal, policy/current-policy, and current-revocation generation objects. Existing operation, principal ID, capability, and resource-scope projections remain unchanged. The engine passes the already selected evidence and grant only after every existing gate; no enum, code, trace, policy, or precedence changed. The intent uses a redacted string representation.

Tests pin exact reference retention, semantic replay equality/hash stability, independent principal-kind, role, and generation-group sensitivity, nested evidence/principal/grant fingerprints, hold-only denial paths, construction closure, redaction, and strict corpus/checksum replay.

## Honest boundary

This closes only accepted authorization-intent provenance. The intent retains the selected matching grant, not the full candidate grant set, and neither selection nor identifiers prove external grant or identity authenticity. This work does not perform or qualify cryptography, secret handling, immediate connection termination, certificate/vault adapters, runtime enforcement, deployment, L3S, L4, or production behavior. No external I/O occurs.
