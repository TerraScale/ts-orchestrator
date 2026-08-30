# Deploy to Orchestrator candidate evidence v2

Status: verifier and evidence consumer implemented. This contract is candidate admission input, not rollout authority or production qualification.

## Version boundary

Deploy handoff mapping v1 stays byte-for-byte frozen. V2 uses a separate namespace, schema, media type, signing domain, corpus, verifier, and consumer. No v2 field is accepted by the v1 mapper, and the v2 consumer does not reinterpret a v1 document.

| Identity | Value |
| --- | --- |
| Schema | `2` |
| Media type | `application/vnd.terrascale.candidate-evidence-handoff.v2+json` |
| Signing domain | `terrascale.deploy/candidate-evidence-handoff/v2` |
| Signature | Established `TSCS` envelope using ECDSA P-256 and SHA-256 |
| Maximum document | 256 KiB, depth 16 |
| Shared corpus SHA-256 | `7296415226db0919d1bac3bdfc287dbdede74bacd1a4342944cecda52220137c` |
| Canonical signing material SHA-256 | `9c2dce7f498dfa9647f1e2f6aa2ab9acebfef3807952d1ed5b54147103090a45` |

## Consumption sequence

```text
bounded v2 JSON
  -> strict case, duplicate, and unknown-field rejection
  -> signed direct-delivery command-envelope verification
  -> exact startup policy lookup by operationId and artifact digest
  -> declared artifact digest lookup
  -> existing DirectDeliveryArtifactEvidenceJournal read
  -> existing CI signature verification
  -> exact source and artifact match
  -> pure v2 signature, evidence, freshness, and policy verification
  -> non-executable DeliveryRequest with authority fields set to zero
  -> typed admission-only receipt with authority fields set to zero
```

The durable journal remains the source-to-artifact authority. V2 adds no evidence store, promotion state machine, approval authority, lease authority, or rollout controller.

## Required bindings

The verifier requires all of these exact values:

- source repository, commit, tree, clean status digest, proof digest, and inspection time;
- Deploy CLI package, version, package digest, and executable digest;
- every dependency lock path, package-manager kind, and digest;
- artifact digest, evidence manifest digest, OCI config digest, kind, architecture, OCI repository, and digest-only reference;
- configuration and optional migration digests;
- exact passed schema-version-2 `SupplyChainReceipt` digest and its artifact, SBOM, provenance, policy, scan, trust-policy, and workload-signature proof digests;
- passed security status, matching policy and scan digests, scan time, vulnerability count, and license count;
- schema-version-1 `firstPartyLicense` evidence with resolved status, all-first-party-component scope, complete private-component coverage, exact source repository and tree, component-inventory, disposition, and distinct evidence digests, and its UTC decision time;
- candidate-bound test names, required flags, outcomes, evidence digests, and times;
- exact reviewed approval evidence digests and expiry;
- service, environment, ordered Region scope, and matching active handoff lease evidence;
- exact retained rollback artifact, manifest, OCI config, configuration, kind, architecture, repository, and digest-only reference;
- explicit known gaps, with no blocking entry; and
- issued time, expiry, audience, requested actor, and redacted reason.

The admission policy supplies current time and explicit freshness limits, the expected operation identity, handoff signing identity, CLI and artifact observations, exact dependency-lock set, configuration, target, lease, rollback, receipt digest, first-party schema, resolved status, scope, private-component coverage and three evidence digests, approval digest set, and required test set. Missing expectations make the policy invalid. A trusted startup catalog selects policy by the exact pair of `operationId` and artifact digest. Duplicate keys, unknown fields, mixed-case fields, and ambiguous documents fail startup. The handoff never supplies or widens its own expected values.

`TS_ORCH_CANDIDATE_HANDOFF_V2_POLICY_FILE` names the bounded startup catalog for `run` and `check`. The catalog has schema version 1 and a `policies` array. Each entry contains the expected fields above, a `firstPartyLicense` expectation, and literal freshness limits in seconds including `maximumFirstPartyLicenseAgeSeconds`. Composition loads the file once. An absent catalog leaves v2 admission closed while preserving v1 behavior.

## Authority separation

Approval evidence proves that a reviewed record with an exact digest exists. It does not authorize catalog publication, rollout, routing, provider mutation, rollback, or target access. Lease evidence proves that Deploy held the scoped handoff boundary. It does not replace a global or regional Orchestrator authority term.

The verifier therefore returns a `DeliveryRequest` with `authorityGeneration = 0`, `writerEpoch = 0`, and `attempt = 0`. The production v2 path keeps those values and returns media type `application/vnd.terrascale.candidate-evidence-admission-receipt.v2+json`. It does not call `DirectDeliveryCoordinator`, stamp a live lease, write a delivery operation, or mutate a target. A separate future Orchestrator-owned authorization step must combine admitted evidence with current fenced authority before execution.

Verification is intentionally pure and repeatable. It binds `operationId` to the exact startup admission-policy entry but does not consume that operation or submit a rollout. The existing direct-delivery operation journal owns idempotent submission, attempt allocation, and replay handling after a future authorization step stamps current fenced authority.

Benchmark results cannot appear in the envelope and cannot authorize delivery. Unknown-field rejection denies any attempted benchmark authorization field.

## Rejection policy

The consumer returns no admission data on rejection. It fails closed for malformed, duplicate, noncanonical-case, unknown, oversized, unredacted, mutable, missing, stale, failed, skipped-required, blocking, expired, signing-identity-mismatched, signature-mismatched, audience-mismatched, source-mismatched, dependency-lock-mismatched, artifact-mismatched, configuration-mismatched, target-mismatched, lease-mismatched, rollback-mismatched, approval-mismatched, or test-set-mismatched evidence. Missing reviewer identities, receipt schemas other than 2, unresolved or incomplete first-party dispositions, candidate/tree mismatch, generic evidence substitution, future decisions, stale dispositions, and policy-digest mismatch all fail closed. Security scans, first-party decisions, test completion, approval decisions, and lease acquisition after `issuedAt` are invalid even when they are earlier than the admission clock.

Pure verification performs no filesystem, NATS, OCI, registry, socket, environment, or wall-clock I/O. The consumer adapter performs the one existing durable journal read and supplies typed observations to the pure decision. Clean-worktree inspection, security scans, first-party dispositions, test completion, approval decisions, and lease acquisition after `issuedAt` are rejected.
