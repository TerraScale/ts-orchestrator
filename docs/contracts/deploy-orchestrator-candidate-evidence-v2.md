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
| Shared corpus SHA-256 | `3470dc4a72474def7c04bb65ffe625047fe56d82e08cc2e97a76e21f9f63b702` |
| Canonical signing material SHA-256 | `ec544be2f4cd1d71ece4d83af4966bb505f41acd852788897fa2e81970661412` |

## Consumption sequence

```text
bounded v2 JSON
  -> strict duplicate and unknown-field rejection
  -> declared artifact digest lookup
  -> existing DirectDeliveryArtifactEvidenceJournal read
  -> existing CI signature verification
  -> exact source and artifact match
  -> pure v2 signature, evidence, freshness, and policy verification
  -> non-executable DeliveryRequest with authority fields set to zero
```

The durable journal remains the source-to-artifact authority. V2 adds no evidence store, promotion state machine, approval authority, lease authority, or rollout controller.

## Required bindings

The verifier requires all of these exact values:

- source repository, commit, tree, clean status digest, proof digest, and inspection time;
- Deploy CLI package, version, package digest, and executable digest;
- every dependency lock path, package-manager kind, and digest;
- artifact digest, evidence manifest digest, OCI config digest, kind, architecture, OCI repository, and digest-only reference;
- configuration and optional migration digests;
- exact passed `SupplyChainReceipt` digest and its artifact, SBOM, provenance, policy, scan, trust-policy, and workload-signature proof digests;
- passed security status, matching policy and scan digests, scan time, vulnerability count, and license count;
- candidate-bound test names, required flags, outcomes, evidence digests, and times;
- exact reviewed approval evidence digests and expiry;
- service, environment, ordered Region scope, and matching active handoff lease evidence;
- exact retained rollback artifact, manifest, OCI config, configuration, kind, architecture, repository, and digest-only reference;
- explicit known gaps, with no blocking entry; and
- issued time, expiry, audience, requested actor, and redacted reason.

The admission policy supplies current time and explicit freshness limits, the expected operation identity, CLI and artifact observations, configuration, target, lease, rollback, receipt digest, approval digest set, and required test set. Missing expectations make the policy invalid.

## Authority separation

Approval evidence proves that a reviewed record with an exact digest exists. It does not authorize catalog publication, rollout, routing, provider mutation, rollback, or target access. Lease evidence proves that Deploy held the scoped handoff boundary. It does not replace a global or regional Orchestrator authority term.

The verifier therefore returns a `DeliveryRequest` with `authorityGeneration = 0`, `writerEpoch = 0`, and `attempt = 0`. Those values are deliberately unusable by the direct-delivery execution gate. Only the Orchestrator runtime may stamp a current fenced authority and attempt after its own authorization and durable operation admission.

Verification is intentionally pure and repeatable. It binds `operationId` to the durable admitted intent but does not consume that operation or submit a rollout. The existing direct-delivery operation journal owns idempotent submission, attempt allocation, and replay handling after the runtime stamps current fenced authority.

Benchmark results cannot appear in the envelope and cannot authorize delivery. Unknown-field rejection denies any attempted benchmark authorization field.

## Rejection policy

The consumer returns no admission data on rejection. It fails closed for malformed, duplicate, unknown, oversized, unredacted, mutable, missing, stale, failed, skipped-required, blocking, expired, signature-mismatched, audience-mismatched, source-mismatched, artifact-mismatched, configuration-mismatched, target-mismatched, lease-mismatched, rollback-mismatched, approval-mismatched, or test-set-mismatched evidence.

Pure verification performs no filesystem, NATS, OCI, registry, socket, environment, or wall-clock I/O. The consumer adapter performs the one existing durable journal read and supplies typed observations to the pure decision.
