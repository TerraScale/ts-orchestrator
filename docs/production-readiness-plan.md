# Production readiness plan

## Objective and current decision

The production objective is one Go orchestrator binary that can form and
maintain an independent embedded-NATS control cell in every admitted OCI
region, enroll hosts without manual secret copying, and safely place, scale,
recover, and retire TerraBase members on retained OCI storage. A placement is
serving only after the exact member identity, durable storage, local process,
and replication state have been independently verified.

**Status: NOT PRODUCTION READY. No production deployment, image publication,
secret distribution, or OCI mutation is authorized by this plan.** This work
does not authorize or perform OCI uploads, console captures, secret writes, or
an apply. The current Go placement path can create a region-bound host and
retained volume, then holds at `awaiting-runtime-contract`. No acceptance gate
below is closed.

This plan records a source and runtime audit, not an approval to deploy. It
does not turn archived C# guidance or historical evidence into Go acceptance.
The local Firecracker evidence is useful but does not qualify OCI images,
production IAM, the full bootstrap path, or sustained availability.

## Baseline and evidence boundaries

The original audit baseline is repository commit
`90b7ea1f4402967d2cc09b00a50d0e2d9c33c369`; the reviewed OCI create-retry
slice was later committed as `997498bff9a9c1e6aed29622796515b753ca7b69`.
The current committed checkpoint is `a54c8b1344af941c277aed2b22b274a6beb1b0b2`:
`043e8f47` contains the local JWT/fencing operator caller and R6 leader-read
changes, and `a54c8b1` contains the eight-file R7 JWT/NTP Firecracker harness.
The clean detached R7 source is `/tmp/ts-orch-r7-qualification-a54c8b1`;
its binary builds passed, but the R7 run failed at host Chrony readiness before
any VM boot. Guest qualification still needs a rerun. New bootstrap integration,
host cgroup and Chrony harness changes in the shared tree are separate,
unreviewed work and do not close their gates. `AGENTS.md` is human-owned and is not an
implementation target.

The OCI SDK uses instance-principal authentication and launches from a pinned
region configuration. Its launch request supplies the configured image,
shape, subnet, network security groups, and a host-node metadata field; it
does not install the binary, provide cloud-init, or distribute host identity
material. Managed placement explicitly stops before TerraBase serving. Host
configuration requires local key material, a pinned controller public key,
NATS settings, install root, and state root, but the repository has no
production host first-boot or enrollment delivery path. A separate controller
bootstrap admission path is present but unreviewed and unqualified in guests.
The host runner writes
under the cgroup-v2 root and needs a qualified privilege and lifecycle
contract.

The Firecracker harness writes systemd units into temporary test guests. It
does not provide production image or unit assets. The active release workflow
builds static amd64 and arm64 binaries and prints checksums in job logs; it
does not retain, sign, or publish release assets. Controller JetStream data is
written under configured `store_dir`; no active durable-volume, backup,
restore, or quorum-recovery procedure is supplied.

The latest completed four-VM attempt is R6 at
`/tmp/ts4vm-20260925-r6/summary.json`: it passed initial guest execution and
host restart recovery, then failed the same-process renewal check after a
controller loss. It is partial recovery evidence, not uninterrupted
availability. The local R7 attempt exercising the production JWT/NTP path
failed before VM boot, so a guest rerun is pending; the recorded
arm64 artifact was cross-compiled and ELF-checked, not executed.

Read-only OCI SDK inventory for the active `TerraScale` parent compartment
returned HTTP 200 in São Paulo, San Jose, and Frankfurt, with zero Compute
instances, VCNs, block volumes, or boot volumes in those regions. No existing
regional foundation can be assumed during rollout. The zero counts are a
point-in-time resource inventory, not a cost estimate. Quotas and total monthly
cost remain unknown; any future estimate must separate unit-priced resources
with explicit quantity and duration assumptions from unpriced services and
usage such as Vault, logging, and data transfer. Any eventual cloud apply must
pass through the reviewed `ts-infra` workflow after target and budget
authorization.

Relevant source: [`internal/oci/sdk.go`](../internal/oci/sdk.go),
[`internal/app/config.go`](../internal/app/config.go),
[`internal/host/runner.go`](../internal/host/runner.go),
[`internal/placement/controller.go`](../internal/placement/controller.go),
[`docs/architecture.md`](architecture.md),
[`docs/local-development.md`](local-development.md), and
[`docs/releases.md`](releases.md).

## Plan-only GRU qualification envelope

This is a bounded estimate and a gated sequence, not authorization. No OCI plan,
apply, resource creation, upload, console capture, secret write, or image import
has been run or authorized. In the committed `ts-infra` defaults,
`oci_estate_enabled = false` and `oci_seed_enabled = false`; both remain false.
OCI budgets are soft alerts evaluated about once every 24 hours, not spend caps
or an automatic shutdown mechanism.

The only cost candidate is one disposable private GRU run in
`sa-saopaulo-1`, using one selected availability domain. The observed GRU AD is
`YDvv:SA-SAOPAULO-1-AD-1`, but quotas do not reserve physical capacity. The
maximum candidate is four concurrent VMs: three controllers and one host,
each at 1 OCPU and 6 GB memory. The architecture branches are exclusive:
`VM.Standard.E4.Flex` for AMD64, or `VM.Standard.A1.Flex` for ARM64. The E4
branch would require a separately reviewed `ts-infra` profile change because
its current initial-controller validation accepts A1 only. The ARM64 branch
is not guest-qualified; present evidence is cross-compilation and ELF checking.
SFO (`us-sanjose-1`) and FRA (`eu-frankfurt-1`) are excluded from this first
budget and would need separate decisions and plans.

The storage scenario assumes four 50 GB boot volumes and one 50 GB retained
data volume, five volumes total, using the balanced 10 VPU/GB tier. The
50 GB seed boot-volume size is present in `ts-infra`; the other boot-volume
sizes, retained-volume size, and billing proration for a short run are not
confirmed. These assumptions must be replaced by exact planned values before
any approved spend.

The following public PAYG list-price snapshot uses the OCI pricing data updated
`2026-09-23T13:10:59.012Z`; it is not a quote. The totals cover only the four
VMs and the five-volume scenario for 30 full days. They exclude all services
and usage listed as unknown below.

| Candidate line item | SKU and rate | 30-day calculation |
| --- | --- | --- |
| E4 compute: OCPU | `B93113`, $0.025/OCPU-hour | 4 × 1 × 720 × $0.025 = $72.00 |
| E4 compute: memory | `B93114`, $0.0015/GB-hour | 4 × 6 × 720 × $0.0015 = $25.92 |
| E4 compute subtotal | E4 branch only | $97.92; $0.136/hour for four VMs |
| A1 compute: OCPU | `B93297`, $0.01/OCPU-hour after the first 3,000 monthly OCPU-hours | 4 × 1 × 720 × $0.01 = $28.80 list-tier amount |
| A1 compute: memory | `B93298`, $0.0015/GB-hour after the first 18,000 monthly GB-hours | 4 × 6 × 720 × $0.0015 = $25.92 list-tier amount |
| A1 compute subtotal | A1 branch only | $54.72 list-tier amount; $0.076/hour for four VMs |
| Block-volume capacity | `B91961`, $0.0255/GB-month | 250 × $0.0255 = $6.375/month |
| Balanced performance | `B91962`, $0.0017/VPU-GB-month × 10 VPU/GB | 250 × $0.017 = $4.25/month |
| Five-volume scenario | Capacity plus balanced performance | $10.625/month |
| E4 priced subtotal | E4 compute plus volume scenario | $108.545 for 30 full days |
| A1 priced subtotal | A1 list-tier compute plus volume scenario | $65.345 for 30 full days |

The A1 branch consumes 2,880 OCPU-hours and 17,280 GB-hours in 30 days. Both
fall below the stated 3,000 OCPU-hour and 18,000 GB-hour free ranges only if
those ranges are entirely unused by the rest of the tenancy. The A1 priced
subtotal therefore remains $65.345; $10.625 is only the compute-free scenario,
not a promised price. Neither subtotal is an all-in ceiling.

Other known list rates are recorded without inventing workload quantities:
Object Storage Standard `B91628` is free for the first 10 GB, then $0.0255 per
GB-month; requests `B91627` are free for the first 50,000, then $0.0034 per
10,000 requests-month. Logging `B92593` is free for the first 10 GB, then
$0.05 per GB-month. Monitoring ingestion `B90925` is free for the first 500M
datapoints, then $0.0025 per million; retrieval `B90926` is free for the first
1B, then $0.0015 per million. Software Vault key versions `B92092` are free;
HSM key versions are free for the first 20, then $0.5334 per key-version-month.
No dedicated or private Vault tier is selected. Private Vault `B90328` is
$3.724/hour; dedicated KMS `B99597` is $1.75 per HSM-partition-hour with a
three-partition minimum. Those are unselected alternatives, not part of the
priced subtotal.

The unpriced or quantity-unknown items are actual VM and block-volume
availability, final disk sizes and short-run billing, tenancy/contract/tax
price differences, custom-image storage and licensing, VCN and gateway needs,
public IP and NAT choices, NTP and service egress, data transfer and any
cross-region traffic, object retention and version-history growth, API request
volume, logs and metrics volume, Vault tier and shared free-range consumption,
and backup storage/lifecycle. A later estimate must show priced quantities and
durations separately from these unknowns; it must not label the priced
subtotals a total monthly bill.

Candidate quota limits for a future, separately authorized qualification
compartment and selected AD are resource bounds, not dollar limits:

| Exclusive candidate | AD-scoped quota proposal |
| --- | --- |
| E4 / AMD64 | `compute-core standard-e4-core-count=4`; `compute-memory standard-e4-memory-count=24` |
| A1 / ARM64 | `compute-core standard-a1-core-count=4`; `compute-memory standard-a1-memory-count=24` |
| Five 50 GB volumes | `block-storage total-storage-gb=250` |
| Isolated network, if selected | Regional `vcn vcn-count=1` |

Use `where request.ad=<actual-AD>` only after confirming the target AD in the
selected tenancy. Compute and block-storage quotas are AD-scoped; VCN quota is
regional. Nested-compartment use counts at the parent, and service limits take
precedence. These quotas constrain resource count/capacity, do not cap cost,
VM lifetime, or role count, and do not reserve capacity. Never allocate both
architecture branches concurrently. A 2026-09-20 read-only quota snapshot
reported 249 A1 cores, 1,662 GB A1 memory, and 61,340 GB block storage available
in GRU AD-1; it is stale evidence for planning only, not reservation. The
scoped parent-compartment inventory found no existing Compute instances, VCN,
block volumes, or boot volumes in the three regions, but it was not
tenancy-wide.

Before any future resource action, all of these gates must be met:

1. A decision owner names the exact tenancy, parent and target compartments,
   GRU AD, one architecture branch, run window, dollar ceiling, and approved
   resource inventory. A budget alert is not that ceiling.
2. The pinned base and custom image, signer/delegation, root-signed manifest,
   first-boot delivery, production NTP, and the image receipt consumer are
   verified on the exact source and image. The signed manifest policy is now
   bounded to 365 days, defaults to 30 days, allows one minute clock skew, and
   requires at least 24 hours of current remaining validity for mutation. The
   image receipt and delegation wire are carried publicly in the root-signed
   manifest after image import and remain bound by its exact envelope digest.
3. The durable intent and instance receipt bind the original manifest digest.
   Uploading or re-signing a new manifest does not renew that authority.
   Historical restarts are read-only for cloud mutations and cannot refetch
   Vault material. A reviewed durable rollover/current-admission grant is
   still required for ongoing OCI mutation after expiry; a new release signer
   or longer delegation does not solve that dependency.
4. A separate read-only bucket auditor, authorized only for `BUCKET_READ`,
   checks `GetBucket`, `ListRetentionRules`, and `GetRetentionRule` in the
   pinned region. It verifies a private, exact-KMS, nonversioned, locked-WORM
   immutable ledger bucket and a separate private, exact-KMS, versioned CAS
   `HEAD` bucket without WORM retention. Conditional writes alone are not
   WORM. The minimum lock/retention duration must be explicitly selected by
   the decision owner; the runtime must not guess or inspect bucket policy.
5. The offline CLI, focused receipt tests, production broker/JWT/clock gate,
   and no-live-secret/image delivery paths pass review. R6's static-TLS
   fixture is not evidence for active JWT/ClockCheck or production NTP; R7's
   JWT/NTP attempt failed before VM boot and has no guest outcome.
6. The qualification operator accepts inventory, stop criteria, teardown
   ownership, exact-OCID cleanup, and post-run verification before an apply
   is even considered.

No command below has been executed; this is the future sequence only:

1. Run only read-only inventory, quota, capacity, and bucket-property checks.
   Record returned regions, ADs, OCIDs, ETags, and evidence timestamps.
2. Select one architecture and revise the price sheet with exact AD, image,
   boot/data sizes, run duration, network and service usage. Keep the other
   architecture, SFO, and FRA out of this run.
3. If separately authorized, use two reviewed `ts-infra` revisions: first
   create only the GRU foundation with estate enabled and seed disabled; then
   populate exact version-pinned Vault references and sign the public
   manifest; finally enable the one seed in a separate reviewed apply. The
   current gates and their plan remain disabled in this task.
4. Prove exact seed identity, current image receipt, private networking,
   synchronized clock, broker authorization, and bootstrap-ledger properties
   before workload admission. No local `tofu apply`, manual ownership transfer,
   or overlapping `ts-infra`/orchestrator reconciliation is allowed.
5. Stop on any missing precondition, ambiguous OCI result, unexpected OCID,
   missing quorum, stale clock, or unknown ownership. Hold the operation for
   OCID-specific reconciliation; do not retry a stale or ambiguous create.

The qualification operator who creates a resource owns its stop and cleanup.
Before any future run, record a run ID, owner, expiration, every expected OCID,
and the exact resource tags. At the deadline, stop the test workloads, verify
writer shutdown, terminate only the four exact run-owned instances, and verify
their terminal states. Preserve normal retained TerraBase data and the
immutable ledger/HEAD evidence; do not delete a bucket or volume just to make
cleanup appear complete. Remove only clearly disposable run-owned network or
test resources after exact-OCID/tag checks, then repeat read-only listings and
record any residual resource for its named owner. Ambiguous ownership or
attachment means stop and escalate; never broaden cleanup by compartment.

## Latest local qualification limits (2026-09-25)

R6 is the latest completed four-VM run. Its clean source revision was
`10970344f53afe246b787177c1f439aa9efb2620`, with Go source manifest
`11dc97ca8af8c106179630ae8d590d871595603109d0982eb8bbc7e0fb07da77` and
harness hash `b166c78851c9b7e7204aa9d38d6330801065d341d4eeb4199eeccc6618cd58f3`.
It reached initial v1 execution, host reboot recovery and 2/3 controller
readiness, then failed the 25-second same-process host-session renewal check.
The operator `hosts` attempts timed out; the required current session, report,
and unchanged process proof was not obtained. R6 therefore did not reach v2
deployment, signed-expiry fencing or rollback. Its `cleanup_errors` were empty.
Evidence: `/tmp/ts4vm-20260925-r6/summary.json` and
`logs/nats-live-diagnostics.jsonl`. The post-run parser correction narrows
renewal evidence to the verified guest log format. The later leader-read fix
addresses a diagnostic direct-KV read that took the 2-second timeout while
the equivalent leader read took about 6 ms. Neither correction retroactively
passes R6 or proves its 25-second renewal requirement.

The older R5 attempt is preserved at `/tmp/ts4vm-20260925-r5/summary.json`.
Both R5 and R6 used static TLS and manual pre-start guest clock setting, so
neither tests production JWT admission or the kernel NTP predicate. The
accepted R7 harness at commit `a54c8b1` instead builds the frozen JWT fixture
and a probe calling the production `KernelClockProbe.Measure()` predicate,
starts bridge-only Chrony with a real selected upstream, waits for guest
timesyncd before releasing services, and tests pinned c1 admission closure
and recovery. Its clean detached source and four static binary builds are
recorded under `/tmp/ts-orch-r7-qualification-a54c8b1` and
`/tmp/ts-orch-r7-qualification-binaries-a54c8b1`. The R7 attempt **FAILED
BEFORE VM BOOT** at host Chrony readiness: root `chronyd` refused its command
socket beneath the user-owned run directory, although it selected a real
upstream. The bridge UDP listener was configured, but the `chronyc` readiness
probe could not connect and the harness never reached listener observation.
Evidence is
`/tmp/ts-orch-r7-qualification-run-20260925T160720Z/summary.json` and
`logs/chronyd.log`. The shared-tree harness now creates a root-owned mode-0700
socket directory under `/run`; its 33 focused tests and a pinned Chrony 4.8
foreground no-NTP-port socket probe passed. This fix has not been used for an
R7 guest rerun. The four-guest result remains **PENDING**; build, fixture,
bridge and socket tests do not substitute for guest evidence.

The corrected local JWT R3 tests now exercise the signed operator
`broker-claim-apply` caller and real TLS-first broker bridge. Both focused
tests passed: `TestRunControllerOperatorBrokerClaimApply` covers the CLI/caller,
and `TestBrokerGateR3TicketRevocationAndOfflineFence` covers the gate/fence
directly; see `/tmp/ts-broker-jwt-r3-final-caller-focused.log`.
The frozen fixture's 6 GiB cell quota passed a three-broker R3 store test
with a finite 2 GiB store limit per broker; see `/tmp/oci-jwtsetup-test.log`.
These tests resolve the earlier helper-only and invalid-fence-floor review
findings in their local scope. They do not prove OCI bootstrap, external
credential delivery, production NTP, image deployment or regional operation.

A separate one-guest Unix-socket member-status attempt **FAILED**: systemd
recorded `ts-member-boundary.service` exiting status 1 after 5.745 seconds.
The Rust result and Go marker were not captured because the service wrote to
`ttyS0` while serial-getty also ran. The outer 240-second watcher saw no exit
marker; this is a monitor/output failure, not evidence that the service kept
running for 240 seconds or that the member boundary passed. See
`/tmp/ts-member-boundary-vmrun-20260925T1220Z/attempt-outcome.txt` and
`guest-systemd.journal`. A corrected guest run and the full systemd
main-process-death boundary remain open.

## Proposed trust and bootstrap contract

These are the planner's preferred interfaces for implementation and
qualification. They are design inputs, not accepted production behavior.

1. Keep the long-lived root private key offline and outside ordinary build
   jobs and OCI runtime. Its public trust anchor is baked into the pinned
   image. A protected release signer holds a root-signed delegation with an
   explicit key ID, expiry, and scope. Build jobs may produce hashes and
   unsigned candidates; a separate protected promotion step signs binary,
   image, and public bootstrap receipts. No ordinary CI secret is described
   as an offline key.
2. Build the static binary for each supported architecture from one clean,
   exact source revision. A signed binary receipt binds the revision,
   toolchain, ELF architecture, binary size and digest, and delegated signer.
   Bake that verified binary, its signed artifact receipt, the public trust
   anchor and delegation, and production service assets into a pinned OCI
   custom image. After import, sign a separate image receipt binding the same
   source and binary digest to the image-file digest, architecture, OCI image
   OCID, and OCI region. Keeping the image receipt external avoids a
   self-referential image digest. Release tags and artifact names are
   no-overwrite; signatures and digests are verified before an image or
   instance is accepted.
3. Cloud-init contains only role and public signed-manifest references. It
   carries no private key, Vault secret, NATS seed, or installer credential.
   The image's trusted binary verifies the receipt; a network download is
   never trusted to verify itself.
4. The proposed first-region bootstrap uses an immutable pre-quorum ledger in
   a planned GRU Object Storage bucket, with conditional create
   (`If-None-Match: *`), exact reads and ETags, and no mutable pointer. A
   signed public manifest identifies the bootstrap generation. It is verified
   through the pinned root and a currently valid delegated signer. Private,
   per-node material is version-pinned in Vault and fetched through
   instance-principal access. Exact seed ownership transfers only after the
   prior OpenTofu state relinquishes it without destroying the resource.
   Each slot needs immutable intent and result records plus a separate
   protected mutable `HEAD` object updated with compare-and-swap. Reserve a
   slot once; advance it only after a signed result and retirement fence or
   seed-handoff proof, then read back every write before OCI launch. A mutable
   head cannot use the WORM ledger bucket, so it needs a separately authorized
   CAS-capable store and IAM policy.
5. `ts-infra` must separate foundation from seed creation: first create the
   Vault and ledger foundation with no seed, then populate and pin the Vault
   material and signed manifest, and only then create the seed from the
   verified image. The reviewed two-phase change is committed in `ts-infra` as
   `3fff4df2d3f92c0343cd11c633fc0ba36a82f3e8` and available on draft PR #16;
   no apply was run. Both gates remain false by default. An existing seed stays
   OpenTofu-owned and protected until explicit handoff. Disabling future
   ledger archiving does not restore records already archived.
6. TerraBase admission should use native v2 ULID database/member identities,
   numeric shard and incarnation values, and reject legacy v1 labels without
   an alias shim. This remains blocked on a frozen TerraBase producer
   contract; the current producer API lacks the required sender, status, and
   drain semantics.

## Acceptance ledger

No gate is **CLOSED**. Evidence must be collected from the exact code and image
being qualified; a design document or isolated unit test does not close an
integration gate.

| Gate / ownership | Required implementation and acceptance evidence | State |
| --- | --- | --- |
| OCI operation recovery — `internal/oci/**` | Use the persisted original operation time and stop replaying OCI create requests before the provider retry-token window expires. Hold expired unknown outcomes and disappeared confirmed resources for explicit, authority-fenced, OCID-specific reconciliation. Preserve the immutable create receipt and use the currently observed ETag for the next fenced operation. Real JetStream KV integration tests must prove no additional provider create at the expiry boundary and safe recovery after lost acknowledgements. | IN PROGRESS; implementation committed as `997498bff9a9c1e6aed29622796515b753ca7b69`; fake-journal unit/race tests passed. Real JetStream KV boundary tests, final review, and reconciliation tooling remain open. |
| Signed release and pinned image — `.forgejo/workflows/**`, `deploy/image/**`, `deploy/systemd/**`, `deploy/release/**`, `docs/releases.md` | Retain exact static artifacts and signed manifests; bind source revision, architecture, binary and image digests, signer, OCI image OCID, and region. Build from a pinned and qualified base image. Install one binary for controller and host roles with explicit service, filesystem, cgroup, and privilege contracts. Require the Linux realtime clock gate before NATS opens: `adjtimex` must report `TIME_OK`, with `STA_UNSYNC` and `STA_CLOCKERR` clear and `maxerror <= 250 ms`; production images need working chrony or systemd-timesyncd. A manually set wall clock is not proof and there is no bypass. Verify an offline image build, installed-binary receipt, and a staged systemd restart/health-check/rollback path. Missing signing keys must fail closed. No live publication or image mutation is part of this work. | IN PROGRESS; `cmd/ts-release` creates/verifies canonical receipts and conditionally publishes exact OCI objects, but no image or release was signed, imported, published, or run. `internal/bootstrapstart` and `internal/app/bootstrap_controller.go` now contain the intended current/historical image-receipt and running-binary consumer path; this integration is still under review and has no OCI or guest proof. The public receipt/delegation wire remains pinned by the root-signed manifest's exact envelope digest. Controller/host units and an offline installer exist, but first-boot config/enrollment and the corrected host cgroup service layout remain unqualified. The R7 amd64 build passed, but its attempt failed at host Chrony readiness before VM boot; the guest result needs a rerun, and arm64 execution has not been tested. Base-image pinning, installed-binary runtime verification, staged restart/rollback, signer environment review, and OCI IAM/cost authorization remain OPEN. |
| Durable pre-quorum bootstrap and region formation — bootstrap slice, `internal/app/controller.go`, `internal/natscell/**`; `ts-infra` separately | Implement the signed immutable bootstrap ledger and exact seed handoff before regional JetStream exists. Prove a cold three-peer GRU cell can form, restart, survive one-node loss, and refuse mutations without quorum. Then prove admitted SFO and FRA cells form automatically with pinned routes, TLS, and trust material. No first-region or cross-region mutation may depend on an already formed JetStream cluster. | IN PROGRESS; root-to-service admission, anchor/ledger and current/historical restart checks have source and focused tests in `internal/bootstrapstart` and `internal/app/bootstrap_controller.go`, but the current integration is unreviewed and has no guest proof. The founder launcher that reserves a slot and creates the first OCI seed is absent. `ts-infra` foundation/seed gating is committed on draft PR #16 without apply. Exact seed handoff, cold GRU formation and SFO/FRA formation remain OPEN. |
| Instance identity and host enrollment — NATS authorization/enrollment, host image/runtime owners | Use least-privilege OCI policies and version-pinned Vault material to issue per-host NATS identity and Ed25519 identity, pin the controller response key, and complete signed registration and rotation for the exact OCI instance. Demonstrate denied foreign-region, stale-generation, revoked, and tag-only identities through the real boot path. The preferred proof is a private HTTPS begin/complete exchange, fresh nonce, and public-only serial-console response; the controller reads console history, verifies exact instance ID and both signatures, and issues a durable one-time grant before NATS JWT issuance. Fail closed on 1 MiB history truncation or missing/replayed proof; do not grant console-connection IAM to the validator. | IN PROGRESS; local signed operator `broker-claim-apply` and R3 JWT/fence caller tests passed at the committed checkpoint, addressing the earlier helper-only review findings. The R7 fixture generates private JWT identities but is not a production issuer. Live OCI console-history/IAM denial, first-boot credential issuance and delivery, retry cleanup, and broker-revocation convergence in guests remain OPEN. |
| Host runtime contract — host image/runtime slice, `internal/host/**` | Qualify the exact pinned kernel and image for writable cgroup v2, execution, cancellation, restart recovery, and safe child cleanup. Define the service user, cgroup delegation, state/install directory ownership, read/write mounts, stop timeout, and restart policy. Prove workload privilege boundaries before accepting untrusted workloads; a native process and a startup probe alone are not a tenant sandbox. | IN PROGRESS; the earlier 8/8 native security run covered nested-supervisor death and child cleanup, but full systemd main-process death and writable-cgroup guest qualification remain OPEN. The one-guest Unix-socket attempt exited status 1 without a captured application result. Root-to-service credential handoff has source but its real privileged subprocess and restart caller still require review and qualification. A process-free delegated supervisor leaf is being prepared in the shared tree and is not a guest pass. R7 failed before VM boot, so JWT/NTP host evidence still needs a rerun. |
| TerraBase member and retained-volume contract — TerraBase producer first; then `internal/placement/**` and host member runtime | Freeze canonical database/member IDs, shard/incarnation semantics, desired-state fields, mTLS, durable directories, readiness, replication evidence, shutdown, and writer-lease semantics. Prove the exact attached retained OCI volume is mounted by the intended process before serving. Serving requires fresh identity-bound local readiness plus independent replication/quorum evidence. | OPEN; placement deliberately holds at `awaiting-runtime-contract` after OCI attachment. Guest block-device discovery, safe format/adoption, filesystem identity, exclusive mount and mount-bound member launch/report are absent. The bounded receiver-only member-status surface has no serving proof; sender, applied visibility and independent replication evidence remain producer dependencies. |
| Healing, autoscale, and retirement — `internal/placement/**`, followed by OCI drain integration | Choose and approve capacity signals, replica floor, min/max, hysteresis, anti-affinity, budget ceiling, and scale-in policy. Implement durable drain, graceful database shutdown, fresh writer-stop proof, retained-volume detach and re-observation, and only then termination. Exercise interrupted and ambiguous lifecycle operations without data loss or duplicate members. | OPEN; the TerraBase producer has no durable drain or writer-fence receipt, and the real OCI controller has no member-serving/drain/writer-stop verifier wired. Fixed seats do not establish autoscaling or safe scale-in. |
| Recovery, operations, and production approval — operations slice | Set RPO/RTO and retention. Back up and restore JetStream authority, OCI journal, and TerraBase data to a tested point; exercise controller quorum loss, host replacement, image upgrade/rollback, scale-in, and recovery. Expose capacity, cost, replication, backup age, and held operations. Review tenancy IAM, regional quotas, network, image OCIDs, and monthly cost before approving even a private OCI canary. | OPEN; no restore procedure or live OCI qualification exists. |

## Required implementation order

1. Close and review OCI operation recovery so the controller cannot replay
   ambiguous creates beyond the provider's safe retry window.
2. Produce retained signed release artifacts and image receipts, then qualify
   systemd and cgroup behavior on a pinned custom image. Keep image creation
   offline until the base image, signer, tenancy, and cost target are approved.
3. Implement the pre-quorum immutable ledger and split foundation/seed
   provisioning. Prove seed relinquishment before controller ownership.
4. Add automatic R3 regional cell formation and least-privilege identity
   enrollment. Prove cold boot and restart paths before TerraBase serving.
5. Freeze the TerraBase producer contract, then integrate one real member on
   its exact retained volume and verify serving from independent evidence.
6. Add safe healing, autoscaling, retirement, backup, restore, and operational
   signals. Set policy and cost limits before enabling automatic scale-in.
7. Run the private GRU canary with reboot and replacement receipts. Only then
   consider automatic SFO/FRA formation. Production readiness still requires
   all regional, failure, restore, upgrade, and cost gates above.

The first bounded deployment candidate is a **disposable private GRU canary**
with a pinned signed image, secure R3 NATS, automatic host enrollment, exact
volume mount, and one real TerraBase member with verified health. It remains
non-production until the remaining gates pass. The private canary itself
requires a separately reviewed target tenancy, image OCID, IAM, quota, and
cost envelope before any cloud mutation.

## Unresolved authority decisions

- Select the OCI tenancy, base operating-system image and kernel, architecture
  support, image-builder identity, regional image OCIDs, IAM policies,
  network rules, quotas, and monthly cost limit.
- Provision the offline release signer, publish its trust anchor into the
  image, and decide signer rotation and revocation behavior. A missing signer
  key cannot be replaced by an unsigned build or test key.
- Confirm the immutable pre-quorum ledger bucket, conditional-write and
  retention behavior, KMS authority, Vault path/version policy, and exact
  seed ownership handoff between `ts-infra` and the Go controller.
- Freeze TerraBase v2 identity, readiness, replication, drain, and writer-stop
  contracts with its producer team.
- Set availability targets for controller loss and host session loss, replica
  floor, scale policy, cost ceiling, RPO, RTO, and backup retention.

Until those decisions and the acceptance ledger are complete, this document
must not be read as an operating runbook or a production approval.
