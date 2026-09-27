# Shared goal acceptance ledger — 2026-09-26

**Overall: IN PROGRESS.** No milestone is complete. This ledger records the
workspace goal against the current shared worktrees; it does not qualify a
deployed candidate. Historical reports and component tests retain only their
stated scope.

**Acceptance completion: 0/16 gates verified (0%).** The fixed denominator is
the M0 exit gate plus D01–D15. A gate counts only when every required child
check passes on the required environment and immutable artifacts. This is
verified acceptance, not effort or source completion.

## Source identity

The workspace root has no Git revision (`git rev-parse` fails because it is
not a repository). The source snapshot used for this ledger is:

| Source | Revision or SHA-256 | Worktree |
| --- | --- | --- |
| Workspace [`GOAL.md`](../../../GOAL.md) | `c9933171fba8c997a91ed48e4fae62f6d9f8932ee7d3b62aa6abd8c0c820291b` | Frozen by doc owner for this evidence snapshot |
| Root [`AGENTS.md`](../../../AGENTS.md) | `6d0e45ba183117ef522ab321831b28971d5b1a45575cab45314acdef2909653a` | Human-owned; unchanged |
| `ts-orchestrator` | HEAD `c845e6ca2c04f5cd435c9c3039d731f8a453ebfa` | Dirty |
| `terrabase` | HEAD `7930f774552034cbb5d5ad1cae2d1bd28d254ccd` | Dirty |
| `terrabase/crates/turso` | submodule `64b8ef5742fc18937f9c89806c81e3f6475dc7a3` | Dirty patch/worktree |
| Isolated `ts-orchestrator` M0 integration worktree | branch `integration/shared-m0-20260926`, HEAD `c845e6ca2c04f5cd435c9c3039d731f8a453ebfa` | Clean at latest status check; not frozen into a candidate manifest |
| Isolated `terrabase` M0 integration worktree | branch `integration/shared-m0-20260926`, commit `ce9f1deece4042adfb5b3f9cab9f5c4d017dc655`, tree `7a59cecce16509f83cf0415e9a20c7907991f5e5` | Dirty pinned Turso submodule; canonical SHA-256 of `git -c core.abbrev=9 -C crates/turso diff --binary --no-ext-diff` is `3860cb7bb959179a6e651e1b00ca17f647787d2f4c35d2974ecd23274fe7c55b` and matches the tracked patch |

Relevant document hashes at the latest source refresh: `ts-orchestrator/docs/production-readiness-plan.md`
`5f6555fa95155d69958bb7032c34a31e367f4b1fb8ef9eb72510069df3e7a578`;
`ts-orchestrator/docs/qualification-status-20260926.md`
`fcb3e92413c93affe04f490505f95cfcee5c10f8f4ea3bd2143168056cd79403`;
`ts-orchestrator/docs/terrabase-runtime-contract.md`
`75d049a749e63daa9b8ed5eb9461ec8ab51eabfc1e98d337b868a7fcbe751111`;
`terrabase/docs/acceptance.md`
`601d9b3e74fdc3bac3bce0955d68bbfe6bbba585f7833e59d932fb6c5247b77e`;
`terrabase/docs/evidence-ledger.md`
`4808ad6f6deaf37d5dda1c384e41ce7f2104d086f190c21004275ae7deb5d4fa`;
read-only OCI inventory [`oci-preview-20260926.json`](oci-preview-20260926.json)
`f06b0670627770f341407d1aafed83a26a912510e88b4fa1c9d0525ac95b048b`
(captured 2026-09-26 23:54:04 UTC).

Selected source hashes: `ts-orchestrator/internal/placement/controller.go`
`9023fe51715c00493e53f673022c01604db81c6fc26d8e46ee650e1236753a8f`;
`internal/placement/terrabase.go`
`f0684f92379dd2db42b2f6a87f617df8c5bb4962787de28aa8392a6da09bfa00`;
`internal/host/managed_runtime.go`
`290123f5d14e94f31ea71b40a18c7b5e4c3115720cdfc6edb6320b383471c17a`;
`internal/app/controller.go`
`1e98c2213d8d216a4944873895c6480b860fda92cf8026b18d1c2162eafbadae`;
`internal/oci/fleet.go`
`6eb941c42d49d6fe957693ea9e5f67678a816a38a33616256f1c9756a1e2be0b`;
`tests/firecracker/managedmember/qualify.py`
`a7c99c49dafaf862b12c99cd96e47574c0455525bffbfc5adc59299cfa92446e`;
`terrabase/crates/tb-server/src/client_http.rs`
`1309674bea92dfd460302ff20ad99746c2aae069cf750e2604e2f2228c117fb2`;
`client_reference.rs` `e9b0815e5a7b0fba190e800e91e262fa0cb661726e06eb7a9babadf7741ab878`;
`http.rs` `f20f5130f2d523f5048ae1777214443da7e0b4b74a27b0fd6f91cca1d763acd1`;
`s3_runtime.rs` `fc90f88cd60dbc0dd673de9d433164cc99947413726c045e2b2877ca6e33760b`;
`member_control.rs` `9f2121ca9adf0367e34d7c10330ff9e237985c37de8d7d453fe6cb0595d91d72`;
`replication_sender.rs` `268f34a0edd695802691c8250a702a34299d09ed4e6a86f92832923a58d1b058`;
`main.rs` `fc055c880067e91819058e5311b869d7ea7ddd9bec322bc44061e1155ad1de52`;
`assets/client-openapi.json` `3ec4f15998b042b7f7bf8e37bc7ecfaf4505f4a2fac7c95fee220fd9acfdaca3`;
`assets/admin-openapi.json`
`161135c737f5392867e7de6063565d831261e126628c5415e8d90b4ac2364b20`;
`tests/client_process.rs` `947587237e5290ffa3b0bad5133b69472fd66e1ea3d198524db70cba14bdd714`;
`tests/replication_process.rs` `d6139c6383cc7fb88a5bc0e4d36ecff64c9a346f5f8ce6bf6b1cd502bc6b8cb3`.

D15 inputs were refreshed after the resource-boundary audit: controller unit
`e97c0c8348c04a99ac3a18224e4acacc2dc40792dd2f033c607178b8fcb76fbb`, host
unit `96398ecfb8d6a7ad4d49f117461c63243fa69ca638c7b487d65961a9ac83c729`,
`internal/host/native_boundary.go`
`261f5b7959e10d1453cb7a93ad23afe0e23f8ce2d89aab2464504bcfb3c8a969`,
`native_exec.go` `4bb53f613356699e811eb45e3fdef0fecf6e15114344e3be9c16a559c8e1cbeb`,
`runner.go` `6e28fb1cdf32024e10550f19dd17dc29c6ee8fabe4386a1355064d04549731fb`,
and `tests/runtime_priority/qualify.py`
`297c2ffc8bdb5bc7b31ef41a4c52b9214c248ac54719bed577a407be6b34db46`;
`internal/host/native_boundary_test.go`
`e932b9b257707037a28be864ea16368971d35d15c33ea1a2262581e4e3883d66`;
`tests/runtime_priority/README.md`
`f395daeb16b94fe473b0a1688b0af84b2ab275be462776ac13803cb91f9c1f2c`; and
`deploy/image/build-offline.sh`
`bb9015d147150b7ccaef3df32fd2d7a827f4e01e9a95fc8fc19e2c89b9eb4210`.

These are hashes of individual working-tree files, not a lock on a complete
source pair. The OCI inventory is captured at 23:54 UTC. The separate TerraBase
integration commit is not a qualified candidate: its Turso submodule has a
dirty patch, the orchestrator pair is not frozen into a manifest, and no
candidate binaries or signed acceptance packet are evidenced. Inventory and
source worktrees changed during preparation. Any changed source or
configuration invalidates the affected evidence; refresh these identities
when the candidate is frozen. During
preparation the operational docs changed to add the $100 cap, D15, the
five-instance R3 ARM topology, and the fixed 16-gate reporting denominator;
the root Goal and qualification status were rehashed after those edits.
Historical cleanup was confirmed intentional.
No historical files were restored. No build, test, deployment, or external
mutation was run as part of preparing this ledger; the separate candidate
build report is recorded under M0-02.

## Status rules and milestone snapshot

Use only **NOT STARTED**, **IN PROGRESS**, **BLOCKED**, or **VERIFIED**. A
`VERIFIED` entry requires the real caller, identified immutable artifacts and
configuration, required environment, reproducible command, and retained
behavioral evidence. None of the M1 scenarios below currently meets that bar.

| Milestone | Status | Current gate |
| --- | --- | --- |
| M0 — reproducible integration candidate | **BLOCKED** | Both source worktrees are dirty; there is no immutable candidate manifest/artifact set or signed two-member acceptance packet. |
| M1 — deployed preview | **BLOCKED** | No current OCI deployment or live API result. Exact production object-storage profile/provider, qualified artifacts, host image/preparation, and executable deployment command are still open. |
| M2 — complete supported APIs | **NOT STARTED** | The current HTTPS document API has point-read and transaction operations. SQL, user queries/indexes, schema provisioning APIs, relationships, and reactive delivery lack complete runtime callers. |
| M3 — operation and regional automation | **NOT STARTED** | Independent backup/PITR, safe member lifecycle, regional replication, and live OCI exhaustion/cleanup acceptance remain open. |

The 16-gate acceptance denominator is `{M0 exit, D01, D02, …, D15}`.
**Completed: none. Remaining:** M0 exit; D01 fresh deployment; D02 document
lifecycle/retry; D03 authorization/isolation; D04 replication; D05
persistence/S3 recovery; D06 update/failed rollout; D07 SQL; D08
queries/schemas/relationships; D09 reactive delivery; D10 backup/restore; D11
member lifecycle; D12 regional formation; D13 exhaustion/cleanup; D14 Scalar;
D15 management resource protection. M0 is blocked, and there is no immutable
M1 candidate deployed to the required OCI ARM environment. Recalculate only
when a whole top-level gate closes; source edits, component-suite passes,
historical receipts, and partial subchecks do not increase the numerator.

The single ordered critical path is: freeze candidate and signed fixture;
verify release admission and retained artifacts; settle and implement the
selected two-member S3 acknowledgment/serving contract; qualify the ARM host
image and exact R3 five-instance cost/inventory; then run D01–D06, D14, and D15
on those artifacts. M2/M3 work remains recorded below and must not silently
become an M1 prerequisite.

## M0 — integration candidate boundaries

| ID | Producer / consumer and acceptance | Status | Evidence and blocker / next check |
| --- | --- | --- | --- |
| M0-01 | Candidate lock: pin both repositories, Turso source and patch, toolchain/lockfiles, runtime configuration, artifact digests, and contract versions. | **BLOCKED** | The workspace main worktrees `ts-orchestrator@c845e6c` and `terrabase@7930f77` are dirty. A separate `ts-orchestrator` integration worktree at `c845e6c` is clean, and TerraBase integration commit `ce9f1de` exists, but its pinned Turso submodule carries a dirty patch (canonical diff SHA-256 recorded above; `make prepare-turso` was reported passing). No manifest binds the paired revisions, submodule patch, toolchain, runtime configuration, and binary digests. CI corrections remain pending. Produce the manifest only after the owners freeze the pair; verify every digest from a clean checkout. |
| M0-02 | Go host → packaged TerraBase: launch two managed members from signed, identity-bound material and complete authenticated document write/read through the real host path. | **IN PROGRESS** | `internal/host/managed_runtime.go` and `tests/firecracker/managedmember/qualify.py` implement the driver boundary; the driver consumes a separately generated exporter manifest and does not build binaries or generate/sign the fixture. The exporter source's source-digest/revision fields are shape-checked claims, not bound to binary digests; no signed two-member packet exists. The coordinator reports that the isolated `ce9f1de` local Fast build succeeded, but CI corrections remain pending and no two-member process packet closes this gate. Complete the exporter plus Rust decoder oracle, then run the manifest-bound driver. |
| M0-03 | Go placement/runtime ↔ TerraBase: preserve tenant/database/shard/member identity, incarnation, authority generation, volume/mount layout, process args, config and credential digest through the actual caller. | **IN PROGRESS** | Relevant fields flow through `internal/placement/terrabase.go`, `internal/placement/controller.go`, `internal/host/managed_runtime.go`, and TerraBase `main.rs`. This is source evidence only; candidate packet and process acceptance are absent. |
| M0-04 | TerraBase serving evidence → Go placement: selected durability profile, client admission, catch-up, exact serving predicate; distinguish signed host observation from database-owned serving proof; reject stale/mismatched reports. | **BLOCKED** | `crates/tb-server/src/member_control.rs` still reports serving/drain unavailable, and routes return 501. Existing Go controller holds at `awaiting-healthy`; no TerraBase-owned signed serving receipt or peer-ACK packet is evidenced. Select the two-member acknowledgment/failure-domain contract and connect its actual receipt consumer. |
| M0-05 | Go/TerraBase update boundary: safe stop/update, admitted and uncertain write outcomes, authority fencing, restart recovery. | **BLOCKED** | No deployed changed-artifact or interrupted-operation scenario exists. There is no evidenced operation that binds the stop/update result to a durable member receipt and recovers uncertainty through restart. Define the exact behavior in the selected contract and exercise it through the real caller. |
| M0-06 | Forgejo → release admission → deployment: required checks qualify and retain exact immutable artifacts; admission rejects anything unqualified. | **IN PROGRESS** | Release-admission and CI source changes are in progress, but no final workflow run, retained artifact set, or deployed digest exists. Verify the configured `fj` run and exact candidate; do not treat source code or a successful build as release evidence. |

Known M0 driver checks (placeholders are required inputs; the exporter manifest
does not yet exist):

```bash
cd ts-orchestrator
go test -c -o <absolute-path>/host.test ./internal/host
python3 tests/firecracker/managedmember/qualify.py check --manifest <exporter-manifest>
python3 tests/firecracker/managedmember/qualify.py run --manifest <exporter-manifest> --run-dir <new-absolute-evidence-dir>
```

M0 exit evidence must come from a clean pinned pair and the orchestrator's real
host launch path, not from a manually started Rust process or a fixture that
does not bind the actual binary digests.

## M1 — deployed preview and operational protection

Root GOAL §5 selects one GRU (`sa-saopaulo-1`) R3 regional cell: three
`VM.Standard.A1.Flex` controller instances and two separate orchestrator-managed
A1 TerraBase hosts, each initially planned at 1 OCPU / 6 GB, subject to the
combined budget and capacity gates. The database has two fixed members. The
control-plane claim is controller restart and recovery; it is not continuous
management through loss of a controller. JetStream quorum and database-member
replication are independent facts.

| ID | Acceptance and real caller | Status | Current evidence, exact gap, and completion check |
| --- | --- | --- | --- |
| D01 / M1 | One-time bootstrap of the initial controller/foundation and credentials, followed by identity/authority handoff; ts-orchestrator creates the two remaining controller peers and two DB hosts, provisions/enrolls hosts, creates/attaches volumes, verifies mounts, and deploys TerraBase through signed desired state; external authenticated write/read and idempotent setup. | **BLOCKED** | The read-only inventory captured at 2026-09-26 23:54:04 UTC records no preview compartment/resources; only unrelated Forgejo resources are present. No deployable qualified ARM image, bootstrap IAM/network material, managed production member material, or deployed-client receipt exists. Complete after immutable candidate, image/preparation owner, scoped credentials and refreshed cost inventory. Record the first controller identity/authority handoff, then verify that the founder creates all remaining runtime resources and deploys only through signed desired state. Manual CLI loops for remaining hosts or direct-SSH TerraBase deployment do not qualify. |
| D02 / M1 | Document lifecycle and retry: create/read/update/delete and supported upsert/transactions, expected values/errors, idempotent replay and identity-mismatch rejection. | **IN PROGRESS** | Current client route exposes `readDocument` and `commitDocuments`; mutations/tombstones share the transaction path. Local and signed-distributed process cases exist in `tests/client_process.rs` and `tests/distributed_client_process.rs`, but the recorded Fast/Slow aggregate is from an older 153-input packet and no current OCI artifact was exercised. Run the current checks, then the same walkthrough against deployed artifacts with retry and restart evidence. |
| D03 / M1 | TLS/scoped-key auth, tenant isolation, denied missing/invalid/revoked/wrong-scope requests, private control listeners, and secret-free errors/logs. | **IN PROGRESS** | `client_auth.rs` checks tenant/database/shard, permission, and collection; the request path authorizes before body parsing and at the worker boundary. Current process coverage includes malformed credentials, but managed key rotation/provisioning has no production writer/restart path; NATS bridge ACL and signing-key installation provenance lack live OCI evidence. Complete on the deployed path, including rotated/revoked material and listener reachability. |
| D04 / M1 | Two real members replicate writes/deletes through declared visibility frontier, survive disconnect/reconnect/repeated delivery, converge supported concurrent writes, and report received/durable/applied progress correctly. | **BLOCKED** | Replication process tests and authenticated gRPC/LZ4 path exist, but no candidate-bound two-member OCI acknowledgment/profile receipt exists. Local cold recovery uses local-v1, one publisher, and an empty inbox and cannot qualify the required replicated profile. Freeze profile/failure-domain semantics, then run on both deployed members and preserve per-frontier receipts. |
| D05 / M1 | Acknowledged writes survive restart under selected profile; interrupted publish is atomic; cold reads/cache loss recover from the actual production object tier and independently checked bytes. | **BLOCKED** | Existing local cold-open work is read-only after recovery and is not the signed-v2 two-member service. `terrabase/docs/m1-signed-v2-object-durable-contract.md` states the signed-v2 S3 ObjectDurable path is not yet implemented/qualified. No production-provider two-member cold-open/cache-loss receipt exists. Define and exercise the actual selected profile; backup uploads or warm restart do not count. |
| D06 / M1 | Deploy a second changed artifact; preserve data/identity; pass health gates; inject failure and recover without unsafe format rollback. | **NOT STARTED** | No first deployment or changed-artifact OCI rollout is evidenced. Completion requires two retained artifact digests, update operation identity, failure injection, health-gate rejection, and observed qualified rollback/recovery. |
| D14 / M1 onward | Deployed `/docs` and `/openapi.json` load in a real browser; expected operations, scoped auth, examples, live success/error responses, correct TLS/CORS/server URL, and CI path coverage. | **IN PROGRESS** | Client/admin OpenAPI assets and static routes exist. Current data operation IDs are `readDocument` and `commitDocuments`; public API-reference assets are separate, and Unix-socket/root-only member routes are intentionally outside that browser reference. `client_process.rs::packaged_reference_matches_client_and_admin_routes` checks packaged route coverage; `scripts/client-document-walkthrough.sh` accepts environment-supplied inputs. No current deployed URL, scoped live credential, browser result, or candidate-bound Fast run exists. Run `cd terrabase && make test-fast` for the current release-critical suite and then the browser/walkthrough against the deployed origin. Exact deploy/browser invocation depends on the yet-unset preview manifest and endpoint. |
| D15 / M1 | On the exact qualified ARM64 image, prove management CPU/memory reservations, workload CPU/memory caps, I/O weights and OOM policy; use highest configured normal scheduler priority (no RT); apply concurrent CPU/memory/I/O pressure; verify management still reconciles or reports a truthful hold and verify process/OOM restart recovery. Record effective systemd/cgroup values. | **BLOCKED** | Controller/host units set normal scheduling (`CPUSchedulingPolicy=other`), `Nice=-20`, `CPUWeight=10000`, `IOWeight=10000`, best-effort I/O priority 0, `OOMScoreAdjust=-1000`, `ManagedOOMPreference=omit`, and restart-on-failure. `ManagedOOMPreference=omit` marks only the unit cgroup; it is nonrecursive. `internal/host/native_boundary.go` explicitly sets and reads back `user.oomd_omit=1` on the host `supervisor` subgroup, clears OOM preference from the native runner and workload roles, and `tests/runtime_priority/qualify.py` checks protected unit/supervisor cgroups against runner/role eligibility. This is source-level policy evidence only. Native supervisor cgroups get CPU/I/O weight 10000 vs 1000 for workload; workload roles receive `cpu.max` derived at 75% of effective ancestor/affinity CPU, leaving one quarter for the manager, and per-role `memory.max`. The 25% CPU headroom is a source policy choice without a measured management CPU need or pressure qualification. The host unit says an image/profile drop-in supplies `MemoryMin/MemoryLow`; `tests/runtime_priority/qualify.py render-drop-ins` can render profile-bound drop-ins into a staging root, but `deploy/image/build-offline.sh` does not call or package that renderer. Native Apply requires `0 < MemoryMin <= MemoryLow <=` the signed reserve and ancestor propagation, so absent drop-in/profile values cause a fail-closed launch. The signed memory profile is operator-supplied; source validation requires process memory >=4 GiB, headroom >=max(1 GiB, 25% of process memory), cgroup cap between process memory and allocatable memory, and reserve plus allocatable <= nominal compute memory. No accepted memory values/RSS basis, OCI image systemd version, pressure/OOM exercise, or process/OOM recovery receipt exists. A prior isolated guest passed only a cgroup-accounting/status boundary check (2 vCPU/6 GiB, no guest NIC), which does not qualify D15. The documented target checks are `python3 tests/runtime_priority/qualify.py render-drop-ins ...` against the image staging root, then `python3 tests/runtime_priority/qualify.py qualify ...` twice on the booted guest (before and after TerraBase launch), with the exact artifact/config/profile, memory-profile and evidence-directory arguments in `tests/runtime_priority/README.md`. The image owner must wire and hash the generated drop-ins; follow with bounded CPU/memory/I/O pressure and process/OOM restart cases on the exact ARM image. |

### Current preliminary cost and inventory evidence

A read-only OCI preflight at 23:39 UTC estimated **about US$89.55/month**,
leaving about **US$10.45** under the goal's combined US$100/month
testing-plus-preview cap. The 23:54 UTC inventory refresh shows approximately
1 GB more existing Forgejo object data than the estimate used; refresh the
itemized cost before resource creation, rather than carrying the old total
forward as an exact current estimate.
The estimate uses five preview instances at 1 OCPU / 6 GB plus the existing
Forgejo VM (7 OCPU / 34 GB total), 450 GB block volumes (200 GB free allowance
deducted), a 72-hour 1/6 GB replacement and 100 GB of volumes, 10 GB Object
Storage, 1 million extra requests, 100 GB egress, a provisional 350 GB snapshot
reserve, existing Forgejo Object Storage, and a US$5 miscellaneous reserve.
It uses the lower Always Free documentation values (1,500 A1 OCPU-hours and
9,000 GB-hours); the 2026-09-23 price catalog lists higher values (3,000 and
18,000), while the tenancy reports `is-free-tier: null`. The lower values still
fit the estimate; the $5 reserve and snapshot price are estimates, not verified
line items. The assumptions come from Oracle's [Always Free resources page](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)
and [price list catalog](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/)
(SKUs B93297/98, B91961/62, B91628/27 and B93455); their A1 free-hour values
conflict, so the lower published allowance was used. A separate full-month 1/6 GB stress host with 100 GB volumes would
exceed the remaining margin. The estimate conservatively includes unrelated
Forgejo object costs. The resource inventory is retained as
[`oci-preview-20260926.json`](oci-preview-20260926.json), SHA-256
`f06b0670627770f341407d1aafed83a26a912510e88b4fa1c9d0525ac95b048b`; it
contains the capture time, existing resources/buckets, and a null preview
compartment. The price calculation and live command output have no separate
retained receipt yet. This JSON is inventory evidence only, not proof of a
deployed preview.

Before creating/enlarging preview resources, retain the itemized estimate and
resource IDs in the deployment manifest, refresh live inventory and capacity,
reconcile free-allowance assumptions, and demonstrate the combined cap. Use the
existing common-infrastructure workflow for `ts-infra`; do not create competing
resources for infrastructure it owns. No live deployment is verified by this
preflight.

## M2 — supported API backlog

TerraBase is the workspace GOAL's database producer. The canonical detailed
database requirement/decision tracking remains
[`terrabase/docs/evidence-ledger.md`](../../../terrabase/docs/evidence-ledger.md);
this shared ledger maps product acceptance to real callers. API names below are
stable ledger IDs, not claims that current endpoints exist.

| ID | Required caller behavior | Status | Source-backed boundary and completion evidence |
| --- | --- | --- | --- |
| D07 / M2 | Secured PostgreSQL protocol used by real `psql`: documented TLS/credentials, scoped grants/session isolation, reads and supported DML, transaction commit/rollback, retry identity, atomic capture/outbox, replicated application, fail-closed unsupported SQL. | **BLOCKED** | `tb-server/src/main.rs` starts HTTP/admin, replication gRPC and Unix member control; there is no SQL listener or runtime `SqlSession` caller. The Fast SQL fixtures cover admission/preparation, CDC probing and key codecs only; the listener, grants, server transactions/outbox and SQL replication are absent. `DEC-011` selects auth design; `DEC-010` leaves exact DML/effect/constraint semantics open. Keep this M2; do not make it an M1 prerequisite. |
| D07-SQL-01 | TLS PostgreSQL listener and documented `psql` connection string. | **BLOCKED** | No listener exists. Complete with real `psql` process test over TLS against the supported service. |
| D07-SQL-02 | Scoped SQL authentication, database/table grants, revocation and key rotation. | **BLOCKED** | No SQL listener/grant caller; test allow/deny, cross-scope isolation, rotation and restart against runtime. |
| D07-SQL-03 | Per-client SQL session isolation and supported transaction lifecycle. | **BLOCKED** | No runtime session. Verify distinct sessions, rollback, commit, cancellation and restart. |
| D07-SQL-04 | Supported `SELECT` result/parameter behavior. | **BLOCKED** | One single-table primary-key admission/preparation fixture is not a SQL server result. Prove through `psql`. |
| D07-SQL-05 | Administrative table/schema provisioning and immutable supported key types. | **BLOCKED** | Key codec and internal Turso/schema work have no public provisioner. Decide exact schema/DML surface before advertising it. |
| D07-SQL-06 | Supported `INSERT`/`UPDATE`/`DELETE`/`UPSERT` row effects. | **BLOCKED** | No service path from SQL session to write transactions. Verify effects and invalid operations through `psql`. |
| D07-SQL-07 | Transaction and retry atomicity: local row effects, outbox and idempotency receipt commit together. | **BLOCKED** | In-process CDC probe does not prove atomic service effects. Inject rollback/crash/uncertain result and prove no partial effect or second effect. |
| D07-SQL-08 | Replicate SQL changes and atomically apply event identity before acknowledgment. | **BLOCKED** | No SQL change stream/outbox runtime caller. Verify source and peer state plus accurate durable/applied frontier on two members. |
| D07-SQL-09 | Retry, transaction conflict and commit/rollback response semantics. | **BLOCKED** | No SQL real caller or published result contract. Specify idempotency and uncertain-outcome behavior, then test with `psql`. |
| D07-SQL-10 | Reject unsupported original SQL/translated plans before side effects. | **IN PROGRESS** | Admission helpers reject a bounded subset in Fast fixtures, but are not wired to a PostgreSQL service. Keep unsupported syntax fail-closed through the eventual real listener. |
| D08 / M2 | User filters, projections, ordering, pagination and indexed queries; schema provisioning/validation and relationships/deletion policy; correct results across restart/replication. | **NOT STARTED** | Current HTTP data IDs are only `readDocument` and `commitDocuments`. Parser rejects query strings; worker has only `PointRead` and `Commit`. Internal immutable schema/catalog and primary-key lookup do not supply public query/schema routes; no relationship or referential-policy caller exists. Set supported operators and ordering (`DEC-006` partly open), relationship constraints/delete policy and coordination/fencing requirements before implementation. Add route/spec/example and real-client coverage with each supported operation. |
| D09 / M2 | Reactive snapshot plus tail, resumable opaque checkpoints, auth/revocation, retention reset and bounded slow-consumer behavior. | **BLOCKED** | No reactive producer in TerraBase server/document/protocol runtime. SDK/stub/snippet artifacts are not the matching database caller; the live browser test is optional-input gated and does not cover cross-member resume or all D09 cases. Root GOAL assigns TerraBase as producer; older SDK ownership text does not override it. Missing runtime source and server semantics (snapshot cut, checkpoint portability, retention, revoke-during-stream, slow-consumer result) block a concrete implementation contract. Complete through two actual members and the real SDK caller. |

The ten SQL children are M2 acceptance splits under D07. They do not turn
internal admission, CDC or codec fixtures into service evidence. M2 exit still
requires every chosen supported operation to pass success, invalid input,
permission, retry, restart and replication cases through the real client.

## M3 — operation, backups, lifecycle and regions

| ID | Required caller behavior | Status | Source-backed boundary and completion evidence |
| --- | --- | --- | --- |
| D10 / M3 | Independently retained backup; clean-destination restore; PITR; compare data/schema/index/replication metadata; accept valid writes after restore. | **BLOCKED** | No TerraBase backup/PITR producer or restore route was found. Warm object-tier recovery and caller-supplied cold-open fixtures are not independent retained backup or clean restore. Missing scenario decisions: on-demand vs scheduled capture, PITR `at` cutoff semantics, and acknowledgment/failure-domain profile to preserve. Root GOAL owns the DB functionality; route/client wiring and these semantics must be made concrete before claiming this gate. |
| D11 / M3 | Real OCI member addition/replacement/drain/scale-in with named-survivor durable/applied proof, writer fencing, restart/uncertain-operation recovery and cleanup. | **BLOCKED** | Controller creates two fixed seats in one region, reaches `awaiting-healthy`, and holds serving/retirement. TerraBase serving/drain are false/501; no caller converts stream-local ACK state into survivor receipts. Production fleet has nil drain/writer-stop providers; ambiguous detach/termination lack full journal replay/reconciliation. Complete producer receipt, consumer, OCI reconciliation, and real-provider restart/failure scenarios; fake-provider tests alone do not close D11. |
| D12 / M3 | Form independent regional R3 cells; recover controller/quorum state; prove cross-region DB behavior under selected profile with stale-authority fencing and residency preserved. | **NOT STARTED** | The selected initial M1 scope is a single R3 cell. `founder_plan.go`/`founder_runtime.go` require three controller slots; current topology does not prove a second region, cross-region replication, or controller loss recovery beyond restart. Build a second region and verify the declared cross-region contract; do not infer continuous operation through controller loss. |
| D13 / M3 | Bounded admission and storage/provider exhaustion, retry/cancellation, correct pending/failure result, no partial effects/lost acknowledged data, and no leaked resources/active writers/credentials. | **BLOCKED** | No real OCI exhaustion/cleanup acceptance. Source has a four-job S3 publisher queue acquired before writes, disk quotas that reject before allocation, and bounded provider/read timeouts; these are component-level evidence. `BODY_TIMEOUT` currently shares the malformed-body path and returns `400 invalid_request`; no slow-body expiry case or agreed timeout result was found, so document/qualify its expected caller behavior. Storage stats calculate disk bytes but no server metrics caller exports them. Create/attach calls use durable intents, while ambiguous detach/termination lack equivalent replay/reconciliation; fake-provider tests and current inventories do not prove billable-resource cleanup. Exercise bounded failures and cancellation through real callers, then real OCI owned resources, and retain before/after inventory plus data-integrity evidence. D15 is the separate management-path pressure gate. |

## Deferred scope and unresolved decisions

- Comparative benchmarks, performance thresholds, speed targets, and tuning are
  deferred until functional completion. Resource bounds, deadlines,
  backpressure, and capacity checks remain correctness safeguards.
- Optional model-assisted index advice and optimization studies are deferred;
  ordinary index correctness remains in scope when indexed queries are
  implemented.
- Regional Raft remains a separate proposal and is not an M1 dependency.
- The existing leaderless first-release profile is selected, but the precise
  two-member acknowledgment profile, failure-domain guarantee and supported
  production object-storage provider still require a concrete M1 decision and
  enforcement proof.
- D15 has no numeric reserve/cap thresholds in GOAL. The ARM image and service
  configuration must declare measurable values; acceptance is effective
  settings plus successful pressure/OOM/restart behavior.
- The current SQL DML/constraint/effect subset remains open (`DEC-010`). Query
  ordering/cross-scope semantics remain partly open (`DEC-006`). Relationship
  coordination and delete policy need an explicit contract (`DEC-003` and
  document schema/API work).
- D09's endpoint/runtime must be integrated under TerraBase's root-goal
  ownership; the previously referenced C# service is absent from this runtime.
  Define snapshot/checkpoint, revocation and slow-consumer server outcomes.
- D10 needs backup trigger policy, PITR cutoff semantics and a restore profile.
- Initial resource accounting is preliminary: the exact OCI compartment/resource
  IDs, selected image, production object provider, current free-allowance basis,
  and retained raw CLI/cost receipt must be bound into the candidate manifest.

## Verification commands and evidence policy

No check was executed for this ledger. Known repository entrypoints for the
later candidate are:

```bash
cd ts-orchestrator && make test
cd terrabase && make fmt-check
cd terrabase && make test-fast
cd terrabase && make test-slow
```

TerraBase keeps exactly Fast and Slow integration suites; Fast is release
critical and Slow remains independent. Use `fj` for Forgejo status/logs as
required by the repository. The commands above alone do not satisfy OCI or
browser gates. No reproducible M1 deploy command has yet been identified. The
M1 browser check must use the live preview, and resource-pressure evidence must
name the exact ARM image, service/cgroup settings, load profile, outcomes and
recovery receipts. Retain raw reports by immutable candidate digest; refresh
file hashes and relevant ledger rows whenever the shared worktree changes.
