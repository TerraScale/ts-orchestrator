# Capacity runtime integration handoff, 2026-09-06

Dynamic scale-out and host replacement are unfinished. The changes below are prerequisites, not production capacity qualification. No live OCI mutation was performed.

## Completed bounded corrections

- `cmd/orchestrator/runtime_host_removal.go` retains SPIFFE placement identity separately from exact OCI ResourceID and original provider ETag. Per-invocation callbacks prevent concurrent removal target crossover. It loads retained operation before provider observation and does not reread a completed operation's provider state.
- `src/orchestrator/hostremoval/journal.go` resumes retained inventory/stage; rejects rebound ResourceID/generation/ETag; does not replay replacement/fence after fencing; disallows skipped stages; requires terminal observation even after nil termination acknowledgement. Terminal reconciliation completes the provider journal before the removal journal.
- `src/orchestrator/ocireconcile/oci_reconcile_compute.go` exact observation has typed terminal evidence only from a successful GET returning exact ID, provider ETag, declared compartment and TERMINATED state. OCI 404 remains ambiguous. `TerminateMember(id, ifMatch)` now invokes `OCIComputeAdapter.TerminateInstance`, replacing direct DELETE.
- `src/orchestrator/provider/oci_automation.go` GET uses response ETag header and actual compartment; termination journals its immutable conditional request, leaves 202/204 pending, never repeats DELETE for Submitted/Unknown, and confirms TERMINATED before provider success. Host removal retains the original ETag through restart and authority epoch change.
- `hostsecrets` now admits only enumerated engine, receipt, placement, database and observer credential destinations in addition to original bootstrap destinations (24 entry maximum). Separate persisted TerraBase/orchestrator ownership records must bind the same signed manifest. Node credentials remain root-owned. Actual `hostagent.OpenLocalBootstrap` hands off both signed service users before any service starts; ts-node calls renamed `AdmitServiceOwnershipFile`.
- `keyrotation.OCICapabilityVault.PublishEnrollmentCredential` publishes immutable credential bytes to the existing OCI Vault authority and returns a pinned public `hostsecrets.Entry`. It recovers unknown create by deterministic name, validates provider metadata and exact version bytes, rejects changed retry content, and checks authority at each OCI call. **It currently has no runtime caller.**

## Verified tests

Passed:

```
go test ./src/orchestrator/provider ./src/orchestrator/hostremoval ./src/orchestrator/ocireconcile ./cmd/orchestrator -run 'TestOCIComputeTermination|TestRemoval|TestExactMemberTerminal' -count=1
go test ./src/orchestrator/hostremoval -run TestRemoval -count=1
go test ./src/orchestrator/hostsecrets ./src/orchestrator/hostbootstrap -run 'TestEnrollmentCredentials|TestCredentialHandoff|TestOwnership|TestRecordedOwnership|TestMissingHanded' -count=1
go test ./src/orchestrator/keyrotation -run TestOCIEnrollmentCredential -count=1
```

`TestRemovalRuntimeUsesDurableConditionalProviderTermination` executes runtime -> actual gateway -> actual OCI adapter -> local HTTP transport and CAS provider journal. It covers asynchronous 202 and lost response, successor epoch while TERMINATING with changed ETag, one conditional DELETE, then terminal completion. Additional tests reject 404-like lookup failure and rebound provider generation. Local fakes supply provider responses; these are not live OCI evidence.

## Next vertical slice: durable GRU host enrollment

1. Reconcile currently has two disconnected declarations. `ociRegionController.computeDeclared` in `cmd/orchestrator/reconcile.go` carries autoscale target but supplies neither MemberBindings nor per-slot bootstrap. `buildProductionGlobalConfig` ComputeApply builds static slots 1/2 from database writer/follower and ignores autoscale target. Connect the same durable target/enrollment inventory to both real callers, rather than only filling a standalone map.
2. Reserve stable MemberID/Region/slot/generation/operation and immutable credential issue times in `authorityjournal` under exact GRU lease before effects. Do not derive readiness from enrollment or OCI RUNNING. Preserve original provider generation across lease turnover.
3. Existing certificate issuer is `keyrotation.OCIIdentityIssuer` with admitted OCI CA and CapabilityVault, not `authbootstrap`. Its `Issue` returns transient WorkloadTLS/ControlTLS JSON maps plus trust bundle; `Fetch` recovers exact provider reference. Add dynamic principals under this existing authority, generate independent NATS and receipt credentials, publish private values through `PublishEnrollmentCredential`, and retain only public references in GRU state/cloud-init. Never put private PEM/NKey material into productionGlobalComputeFile.HostFiles.
4. `nodebootstrap.SignBootstrapGrant` signs full manifest with existing P256 owner provisioning signer. GRU has no configured delegated bootstrap signer in current productionGlobalFile; add an explicit validated signer/pin input. Private signer must never reach a host. Public per-slot seed/manifest/grant plus Vault references flow through TSNodeCloudInit and actual ts-node consumer.
5. Broker authorization is currently startup-only: `bootstrap.NatsServerConfig.PlacementHosts/DatabaseHosts` -> `placementpublisher.ApplyBrokerGrants` / `databaseadmission.ApplyBrokerGrants`. Add authenticated lease-bound durable public enrollment inventory, R3 broker update acknowledgements and restart replay before launch/admission. No current live reload path. NATS operator/JWT adoption is not a substitute for existing selected NKey policy.
6. Update dynamic placement/readiness transport and key inventories: productionPlacement.publishers, productionPlacementTransition targets/config.Issuer.MemberKeys, production readiness keys/remote targets, database host inventory, service identity rotation trusted endpoints/roster. `serviceidentityrotation.Coordinator.Enroll` exists, but independently trusted endpoints are currently static. `authbootstrap` installs auth-domain grants and does not issue host identities.
7. Global factory still ends with ErrProductionGlobalDependency for lifecycle reaper database/key and estate snapshot adapters. Do not claim production constructor succeeds until its actual dependency graph is completed.

## Subsequent slice: host replacement successor plan

- `runtime_host_removal_inventory.go` Capture currently passes supplied replacement references unchanged; Owner supplies nil. No candidate planner exists.
- It compares target.AcceptedGeneration with provider ownership generation. These are separate domains: provider launch currently sets generation to session epoch, while placement generation comes from PlacementProposal.Generation. Preserve provider generation for exact resource identity and bind placement generation/proof independently in replacement inventory.
- `databaseadmission.Save` intentionally forbids changed Targets/PlacementTargets and ready evidence in original creation records. Do not weaken create immutability. Use separate durable placement successor records and explicit references; wire accepted successor state into inventory/readiness/runtime consumers.
- Current `runtime_host_removal_replacement.go` loads original admission operation by replacement IssuerOperationID, stages existing proposal, activates transition, and expects signedDigest known before Replace. A real plan must reserve the successor before effects and distinguish proposal/request digest from subsequently issued accepted proof digest.
- Select authenticated admitted spare member in same selected Region, preserve RF2 for every database and all selected Regions, provision keys/state through existing database pipeline, stage and collect authentic catch-up/readiness before old member removal. Scope-wide placement proposals include multiple databases; successor generation cannot accidentally discard unrelated assignments.
- `productionPlacementTransition.activate` provides real prepare/drain/issue/deliver/acceptance machinery. Reuse it with successor persistence callbacks and actual host readiness. Fencing validates signed old-member drain receipts. Inventory revalidation must allow the planned successor changes while rejecting concurrent unrelated/new assignments; a raw hash of immutable original records alone cannot establish that.

## R4: unresolved pre-send termination window

The accepted termination correction deliberately favors safety over automatic
recovery in one remaining window: process failure after durable MarkSubmitted
but before the HTTP DELETE is sent. Its retained state is indistinguishable
from a sent request whose response was lost. A later RUNNING response, even
with the original ETag, does not prove the earlier DELETE was never accepted
or cannot still take effect.

Source evidence: the pinned OCI SDK's
`core/terminate_instance_request_response.go` documents IfMatch as optimistic
concurrency against the current resource ETag (lines 24–27). It offers
OpcRequestId for request correlation (lines 43–45), but no OpcRetryToken or
operation-status lookup for this DELETE. `core/core_compute_client.go` starts
TerminateInstance with NoRetryPolicy (lines 7790–7798). This is not a provider
guarantee of deduplication or a negative acknowledgement. The current adapter
therefore retains Submitted/Unknown and returns ErrComputeTerminationPending;
it must not reset the journal, declare success, or repeat DELETE merely because
GET still returns RUNNING/unchanged ETag. There is no implemented provider
no-effect proof permitting such a reset.

Operational resolution for this condition remains necessary: inspect the
retained exact OCID, original ETag and operation identity; keep the old member
fenced; establish the provider outcome through authoritative OCI operation
support/audit evidence. If no conclusive outcome is available, leave the
operation unresolved. An explicitly authorized operator may instead complete
the intended termination of that exact retained resource through OCI; the
existing reconciler can then observe TERMINATED and complete both journals.
This is an operator action, not an automated retry or an instruction to edit
journal state. No operator action was performed during this task.

Bounded follow-up for the runtime integration owner: expose this unresolved
condition with those non-secret operation identifiers and an intervention
status in the existing operations surface. Any future automatic retry must
first add and test a provider-backed no-effect/deduplication contract; a local
send marker, elapsed time, RUNNING, unchanged ETag, or 404 is insufficient.
