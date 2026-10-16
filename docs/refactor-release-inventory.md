# Release trust and delivery inventory

REL source inspection, 2026-10-16. This records implementation boundaries and
remaining work; it does not establish live rollout qualification.

## Producer and apply boundaries

| Responsibility | Current owner/callers | Required follow-up |
| --- | --- | --- |
| Exact CI/source/job/log verification | `internal/release/cli/admission.go`, `internal/githubapi`, `scripts/ci/publish-qualification.sh` | Keep source/run ID/run number/attempt/job/manifest proof at publication. Missing historical source/fixtures remain producer failures. |
| Source ancestry and leaf signing | `internal/release/cli/update_delegation.go`, `internal/release/cli/deploy.go`, `internal/release/update_delegation.go` | Producer-only Git/GitHub dependencies. Do not rewrite historical signed lineage. |
| Signed orchestrator application | `internal/release/cli/apply.go`, `internal/releasechannel/channel.go` | Bundle targets no longer require Atlas. Local signatures/bytes are validated before remote writes; scope/transfer/channel/observation run independently with four active regions. |
| Generic service signing/publication | `internal/release/cli/service_deploy.go`, `internal/delivery/codec.go`, `internal/releasechannel/service.go` | Still combined producer/apply; add signed service-bundle consumption through the existing claim admission boundary. No source-independent service apply is claimed. |
| Production admission | `internal/release/production.go`, `internal/release/cli/production.go` | Separate root/scoped qualification authority and retained proof hashes; integrate before signing/mutation. A qualification producer and actual RUNTIME/HA/workload evidence are still required. |

## Ordering migration remains open

Orchestrator receipts sign `SourceLineage.QualificationRunNum`, copied from the
producer CI run number. `Channel.Verify` binds that value to `Channel.RunNumber`.
`Channel.Publish` preserves the regional floor by compare-and-swap, rejects a
lower number and rejects another source under the same number. These fields
remain historical build provenance, not a durable cross-producer allocator.

Service publication currently orders claims by their signed envelope `IssuedAt`.
It does not share the orchestrator channel's numeric order. A global producer
change cannot safely substitute a new repository's CI counter or wall clock.

The replacement must add an explicitly signed signer-owned sequence, allocate
it durably under fenced authority, and initialize its migration floor above all
retained regional floors. Consumers must verify a signed migration binding old
ordering to the new floor without resetting anti-rollback state. Preserve
historical run IDs/numbers/signatures unchanged. No allocator or migration proof
is implemented by this slice.

## Integration and deletion ledger

| Boundary evidence | State |
| --- | --- |
| `TestSignedApplyRegionalHTTPRecovery` | Actual Go executables, Git lineage, signatures, filesystem and OCI SDK/loopback HTTP. Scope outage/missing/stale/wrong environment/architecture, denied writes, retry reuse and local tampering exercised. Not live OCI or workload rollout. |
| `TestProductionAdmissionRetainedArtifactBoundary` | Actual retained binary inspection, CLI, signed root/delegation records and hashed filesystem evidence. Exact candidate/scope, gate absence, expiry, signer/capability, proof timestamp and tampering rejections exercised. Test-only evidence never certifies production. |
| Existing `deploy_test.go` fixture | Retains real signed qualification files so old deployment safety checks are not silently bypassed during integration. Mock-centric tests still require boundary migration before deletion. |
| Unit-only inventory | `internal/release`, `internal/release/cli`, `internal/releasechannel`, `internal/delivery` still contain unit tests and shared unit helpers. None are claimed integration-only or removed prematurely. |
| Service roles, signer sequence, durable operation IDs | Remain open work. This slice preserves current CAS/digest retry behavior; it does not add a durable fleet operation store or claim restart-safe fleet orchestration. |

Production credential permissions and GitHub environment protection are recorded
separately in [the startup inspection](refactor-start-deploy.md). No paid
capacity, IAM mutation, credential installation or production publication ran in
this stream.
