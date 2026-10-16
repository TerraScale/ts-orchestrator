# Release trust and delivery inventory

REL source inspection, 2026-10-16. Implementation and retained integration
checks below do not establish live runtime or workload qualification.

## Producer and apply boundaries

| Responsibility | Implementation | Remaining boundary |
| --- | --- | --- |
| Exact CI/source/job/log verification | `internal/release/cli/admission.go`, `internal/githubapi`, `scripts/ci/publish-qualification.sh` | Producer retains source/run/attempt/job/manifest proof. Missing historical artifacts remain failures. |
| Orchestrator producer and apply | `internal/release/cli/bundle.go`, `apply.go`, `internal/releasechannel/channel.go` | Signed bundle creation checks exact retained bytes and qualification before leaf-key access. Apply consumes local signed artifacts without Git, CI, a signing key or allocator; bounded regions progress independently. |
| Native service producer and apply | `internal/release/cli/service_bundle.go`, `service_apply.go`, `internal/releasechannel/service.go` | `service-bundle` and `service-apply` replace direct `service-deploy`. This format is a native artifact contract, not an OCI container manifest. Runtime native-service enforcement is owned by CORE. |
| Production admission | `internal/release/production.go`, `production_receipt.go`, `internal/release/cli/production.go` | Independent qualification authority binds exact candidate/scope and retained evidence. Current channel/selfupdate admission requires the embedded proof. Actual RUNTIME/HA/workload evidence and a production qualification producer remain required. |
| OCI container admission | `internal/release/container.go` | Typed canonical child-manifest digest, signer sequence/migration and independent qualification are verified at current time and operation deadline. The actual authenticated container producer and app delivery wiring remain integration work. |
| Portable function admission | `internal/release/function.go` | Exact module bytes, ABI, tenant/function/revision, capability restriction and admitted sequence floor are checked. Durable intent/producer wiring is owned by WASM; this does not qualify the runtime host or isolation. |

The narrow QA startup gate additionally makes `ImageReceipt.Production`
mandatory for current image admission, bound to the **final QCOW2 digest**, not
just its embedded binary. `verify-image-production` verifies retained evidence
before import/signing; image promotion, attempt callers and privileged startup
ordering are being integrated separately on the QA branch.

## Signer-owned ordering

`internal/release/sequence.go` and `sequence_store.go` implement root-signed
migration and durable signed CAS reservations, scoped by role and environment.
The initial grant binds the online signer, canonical GRU Object Storage
location, all three retained regional floors and their evidence hashes. A
consumer authenticates that grant before accepting the new sequence floor.
Historical CI run numbers/timestamps remain immutable provenance.

Concurrent producers importing the same grant reconcile a lost create CAS by
authenticated reread. Repeating the latest identical content identity reuses its
reservation; failed reservations leave safe gaps. Qualification renewal for the
same content preserves its ordering identity. Channel/service publication
verifies authority before writes and preserves regional anti-rollback floors.

Signer replacement or allocator relocation requires a linked successor migration;
that transition is not implemented. Replaying the exact established initial grant
continues to work after its initial import validity interval.

## Retained boundary checks

| Evidence | Recorded result and limit |
| --- | --- |
| `TestSignedApplyRegionalHTTPRecovery` | Real Go executables, Git lineage, signatures, filesystem and OCI SDK/HTTP; regional refusal/retry and local tampering. Not live OCI or runtime rollout. |
| `TestSignedServiceApplyHTTPRecovery` | PASS 6.859s on isolated final service branch. Both native roles across FRA/GRU/SFO; pre-key qualification, signer allocation, regional failures/retries, source/key-free apply and consumer evidence tampering. Recovery reruns in one process; no process-kill claim. |
| `TestSequence*` | PASS across release/channel/CLI on final sequence branch. Real signed filesystem/HTTP CAS allocation, concurrent initialization/reservation, migration/floor identity and renewal cases. Not live OCI. |
| Qualified channel/selfupdate SDK gate | Race PASS on narrow QA-base commit `987f7ed8`: actual unreachable HTTP cancellation and blocking interface clients. Separate OCI mutation-cancellation helper race PASS on `2b0211b9`. |
| Bundle producer and final image followups | Source committed; exact final focused checks are tracked by QA. No unexecuted producer scenario is claimed passing. |

Unit infrastructure remains until its behavior is replaced at integration
boundaries. Durable fleet process restart recovery, actual container producer
integration, live capacity qualification and live rollout remain outside the
recorded passing checks.

Production credential permissions and GitHub environment protection are recorded
in [the startup inspection](refactor-start-deploy.md). This stream performed no
paid-capacity/IAM mutation, credential installation or live rollout.
