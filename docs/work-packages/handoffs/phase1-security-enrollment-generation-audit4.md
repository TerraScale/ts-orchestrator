# Phase 1 security enrollment generation audit 4 handoff

## Proven gap and correction

Enrollment previously compared the expected principal generation only with the selected bootstrap and attestation generations. A request whose three values were coherently generation 4 could therefore authorize issuance even when the authoritative current principal generation was 5. The same gap allowed the missing-attestation branch to authorize an attestation intent for a stale principal, and a coherently future generation had the same request-local consistency problem.

`EnrollmentRequest` now requires a non-null, get-only `CurrentPrincipalGeneration`. The existing `GenerationCurrent` gate requires the expected principal, bootstrap, attestation, and current-principal high-water to agree before either accepted intent can be constructed. The trace keeps its established code number and order and now records principal generation as observed and the high-water as required. Exact accepted issue and attestation outputs retain the request and high-water by reference.

The executable proof covers exact acceptance, coherent lower and future denial, stale missing-attestation denial, null construction, `ulong.MaxValue`, stable reason order and culture-independent replay. Reflection pins exactly one public ten-parameter constructor in the declared order, no optional/default parameters, and no public static factory returning `EnrollmentRequest`. The completeness model adds all three adversarial variants, exercises them across 1,000 cases, updates accepted-output and input fingerprints, and saves variants 16, 17, and 18 in the strict whole-file SHA-256 replay corpus.

## Honest boundary

This closes only request-to-current-principal generation closure inside the pure enrollment decision model. Callers remain responsible for obtaining an authoritative current generation; supplying a dishonest or stale high-water is outside this model. `SecurityGeneration` is not the deferred `SecurityEpoch`. Nothing here performs identity verification, cryptographic attestation, certificate issuance, vault/KMS access, durable replay storage, distributed consensus, immediate connection termination, external I/O, or production deployment.
