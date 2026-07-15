# Phase 1 security policy property shard

## Scope

This shard strengthens the pure `SecurityDecisionEngine` contract for enrollment, certificate lifecycle, capability authorization, secret leases, and regional survival-secret references. It is primarily property/replay evidence and includes one narrow certificate-scope policy correction. It does not exercise a real issuer, KMS/Vault, NATS, network, process, filesystem, cloud resource, or deployment boundary and therefore makes no L0C or production-readiness claim.

Allowed paths for the shard are the security property tests and embedded replay corpus, the ControlPlane test project resource declaration, and this handoff. Reconciliation and cross-domain construction-closure files are excluded.

## Independent properties

- 1,000 materially distinct enrollment cases cover exact bootstrap/attestation identity, operation, cell, role, generation, issuer hierarchy, issuer generation, revocation generation, single-use status, duplicate/conflicting evidence, and the separately authorized attestation intent.
- 1,000 certificate cases cover issue, renew, rotate, and compromise-backed revoke; exact operation/principal/cell/key/usage/scope/issuer evidence; principal, issuer, policy, certificate, and revocation generations; expiry/action state; and exact intent subjects.
- 1,000 capability-authorization cases cover evidence completeness, duplicate/conflicting principal evidence, principal and generation binding, revocation, policy generation, exact grant cardinality, cell-bounded privilege, default denial, and the exact accepted authorization subject.
- 1,000 lease cases cover grant, renew, revoke, retained versions, availability, expiry evidence, duration, principal/policy/revocation/lease generations, exact grant and existing-lease binding, and the intentional revoke precedence that makes availability, retention, and current-policy checks not applicable.
- 1,000 survival-secret cases cover reference/metadata/policy uniqueness, cell/environment/purpose/version/digest equality, availability, policy generation, retention, expiry evidence, missing material, and exact accepted operation/request subjects.
- Another 1,000 cases replay conflicting authorization and multi-secret survival inputs across permutations and `en-US`, `tr-TR`, `ar-SA`, and `ja-JP` cultures.

`SecurityEpoch` currently exists as a primitive but none of these five request contracts carries an epoch. This shard therefore makes no epoch-coverage claim and does not invent a public contract expansion. Whether and where an epoch belongs in the security request bindings remains an explicit future contract decision; all generations currently modeled by the requests are covered here.

## Input and output safety

The audit found that all caller-controlled security enumerables already pass through `SecurityInputSnapshot.Copy`. The public `SecurityTechnicalLimits.MaximumCapturedItems` cap is a technical denial-of-service limit distinct from certificate, lease-duration, or retention policy. Tests prove the maximum-plus-one element is rejected before reading its `Current`, disposal occurs, ordinary failures in `GetEnumerator`, `MoveNext`, `Current`, and `Dispose` become opaque `ArgumentException`, and `OutOfMemoryException`, `StackOverflowException`, and `AccessViolationException` propagate from every enumerator phase.

Construction-closure assertions cover the immutable public-constructor boundary for `SecurityDecision` and every `SecurityIntent` subtype; the central architecture guard owns the exported factory inventory. A bounded strict JSON replay reader pins the whole-file SHA-256, exact schema and object fields, canonical lowercase ASCII IDs, unique IDs and case tuples, per-family variant vocabulary, complete seed-sensitive input/evidence fingerprints, and full authorized/intent/subject/ordered-trace output fingerprints. Parse accepts only the exact input fingerprint and engine-replayed output fingerprint for the recorded `(kind, variant, seed)` tuple; the generated property families separately provide independent trace and subject oracles. Unknown, duplicate, zero, out-of-range, noncanonical, wrong-nonempty fingerprint, commented, trailing-comma, and trailing-content inputs fail closed.

## Compatibility and production changes

The audit found one production policy defect: the global-administrative issuer branch validated the issuer's own scope but not the requested certificate scope, allowing that capability to sign a cell-scoped certificate. `EvaluateCertificate` now requires a `GlobalAdministrativeIntermediate` request to carry `TrustScope.GlobalAdministration`. This is a deliberate behavior correction for callers that previously attempted the cross-scope combination; it changes no public type or signature. The embedded test resource declaration is the only project-file change.

## Verification

Run the ControlPlane test executable serially in Release mode. The shard requires all five 1,000-case policy families, the 1,000-case culture/permutation family, enumerable safety, construction closure, corpus replay, and parser rejection tests to pass alongside the existing ControlPlane suite.
