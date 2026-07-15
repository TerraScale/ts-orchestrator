# Phase 1 evidence accepted-scope audit handoff

## Proven gap and correction

Two otherwise valid evidence-gate calls could use different manifest identities and different matching verified signer identities while retaining the same payload digest, generation, expiry, and numeric counts. Both calls authorized, but their `EvidenceDecision` values compared equal because the accepted output retained only action, code, payload digest, and numeric trace.

Accepted decisions now carry a construction-closed `EvidenceAuthorizationScope` with the exact manifest identity, lane, gate target, signing profile, signing identity, signature identity, generation, and expiry sequence. Hold decisions carry no authorization scope. Subject, policy, signature, generation, expiry, verifier, lane, and action precedence is unchanged, and no error code was added.

Tests pin every retained scope field, exact independently reconstructed replay equality, distinct accepted outputs when any retained field changes, exact retained identity instances and numeric values, null scope on denials, construction closure, and redacted formatting. The existing 1,000-case evidence decision oracle and snapshot/evidence property suite also inspect the accepted scope.

## Honest boundary

This scope retains the signature identity, not opaque signature bytes, verifier implementation identity, or full policy and threshold provenance. It must not be described as complete cryptographic authorization provenance. The change does not qualify a signer, verifier, evidence lane, architecture artifact, credential release, deployment, or production environment, and it performs no external I/O.
