# Production readiness plan

## Current workspace delivery scope

The [workspace GOAL](../../GOAL.md) is the current delivery authority and
supersedes earlier plan-only and AMD-only restrictions in this dated plan.
Current Go orchestration work belongs to `ts-orchestrator`; TerraBase is the
database service. The former `ts-deploy`-era guidance is historical. See the
[current orchestrator overview](../README.md).

The current regional bootstrap flow is the operator-run
[manual regional bootstrap](region-bootstrap.md): the operator provisions the
foundation and starts only controller A for one mapped cell; admitted A
provisions controller B/C, and `ts-orchestrator` owns managed workload hosts
and volumes after the cell-specific host-enrollment bundle is available.
`ts-infra` manages shared Email Delivery only (four resource identities);
regional networking, IAM, and bootstrap inputs remain operator-prepared. The
OpenTofu seed candidate described later in this dated plan is historical and
is superseded for current operation by the runbook.
The material generator and first-seed verifier accept only the fixed GRU /
`sa-saopaulo-1`, SFO / `us-sanjose-1`, and FRA / `eu-frankfurt-1` mappings.
The checked-in regional plan is populated for GRU. The host-enrollment public
bundle renderer accepts matching reviewed material for all three mappings;
the mapped CLI support and its tests are not evidence of a live deployment in
any cell.

Prioritize correct APIs and end-to-end integration, then an early deployed
preview before full product completion. Use the existing leaderless profile
for the first milestone; regional Raft remains a separate proposal. The goal
authorizes OCI inspection and task-owned preview resources for both services
on low-cost ARM64, preferring `VM.Standard.A1.Flex` where capacity and cost
permit and starting in GRU when feasible. Combined recurring costs for
qualification testing and preview are capped at **US$200/month**, including
every required compute, storage, networking, object-storage, and retained
resource. Record the itemized estimate and resource inventory before creating
resources.

The selected preview topology is one regional R3 cell with three A1
controllers and two separate orchestrator-managed A1 TerraBase hosts. Its
control-plane claim is controller restart and recovery, not uninterrupted
management through controller loss. Confirm the combined cost estimate and
capacity before creating resources.

Benchmarks, comparative performance targets, performance tuning, and optional
model-assisted index advice are deferred until functional completion.
Correctness, authorization, durability, resource limits, and ordinary index
behavior remain in scope.

Protect the Go controller and embedded NATS management path with reserved CPU
and memory, workload CPU and memory caps, I/O weights, and OOM handling. The
orchestrator must use the highest normal scheduling priority supported by its
pinned host, without real-time scheduling guarantees. Verify pressure and
restart/recovery behavior against effective systemd/cgroup settings; host or
kernel failure remains a separate recovery case.

This authorization does not show that a preview has been deployed or that an
API scenario has passed. The current inventory and execution status are in the
[OCI preview record](evidence/oci-preview-20260926.json); milestone gates are in
the [shared-goal acceptance ledger](evidence/shared-goal-acceptance-20260926.md).
This production-readiness plan remains a dated audit, not deployment evidence.

## Objective and current decision

The production objective is one Go orchestrator binary that can form and
maintain an independent embedded-NATS control cell in every admitted OCI
region, enroll hosts without manual secret copying, and safely place, scale,
recover, and retire TerraBase members on retained OCI storage. A placement is
serving only after the exact member identity, durable storage, local process,
and replication state have been independently verified.

**Status: NOT PRODUCTION READY.** This plan does not approve production use.
The bounded preview authorization in the workspace GOAL supersedes the former
plan-only restriction recorded below; it does not establish that preview
resources or a deployed artifact exist. At the `d5fc307` checkpoint, the Go
placement path could create a region-bound host and retained volume, then held
at `awaiting-runtime-contract`; later commits publish TerraBase desired state
and hold at `awaiting-healthy` without a serving claim. No production
acceptance gate below is closed.

This plan records a source and runtime audit, not an approval to deploy.
The local Firecracker evidence is useful but does not qualify OCI images,
production IAM, the full bootstrap path, or sustained availability.

## Baseline and evidence boundaries

The accepted source checkpoint for this readiness pass is commit
`d5fc307f31ae825a664d99897a80a2219c058c3f` (tree
`647ffbcf601942d5bf4b15e558f1b457332f7168`). It includes the signed founder
plan, current-selection reader and rollback floor, and the OCI launch adapter.
Later shared-tree changes are outside this checkpoint and are not covered by
the findings below. `AGENTS.md` is human-owned and is not an
implementation target.

Qualification results are revision- and scope-specific. The broad Go
suite/vet check recorded Go 1.27.1, `go test -count=1 ./...`, and `go vet ./...`
passing on its frozen pre-founder snapshot: archive base `93ca72c6` plus 13
overlays whose hashes match every tracked path changed through the preceding
`4c284550` enrollment checkpoint. It excludes untracked files and the nested
`third_party/nats-server` module, and does not cover the later founder commits.
Focused founder bootstrap tests and vet, the selection package with a
focused race test and vet, and the current-reader/floor and OCI adapter checks
passed separately. Those checks are bounded package tests, not a later
full-suite run or a live OCI qualification.

The OCI SDK now sends Flex OCPU and memory dimensions in `ShapeConfig`, and
`sdk_test.go` checks that request and response dimensions round-trip. The
founder OCI adapter likewise receives the signed launch profile. These tests
do not show that OCI launched or re-observed the proposed E4 dimensions. No
production `internal/app` caller connects the founder selection reader and
OCI launch adapter at this checkpoint; founder formation remains an
unqualified integration path.

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
usage such as Vault, logging, and data transfer. The statement that a future
production apply would use the reviewed `ts-infra` workflow records the
assumption in this dated checkpoint. The current ownership boundary assigns
regional foundation and seed setup to the operator through controller A, then
same-cell peers to `ts-orchestrator`; `ts-infra` manages shared Email Delivery
only. Its approved state-only handoff subsequently completed without resource
additions, changes, or destruction; 25 regional state entries were removed,
and post-apply checks verified the four email resources. This state transition
does not establish regional resource health or a live controller. The regional
Terraform definitions and workflow were later removed from `ts-infra` main
commit `e347f13a313ebb2b9d0a0b631ba0aed56af65126`. See the
[manual regional bootstrap runbook](region-bootstrap.md).

Relevant source: [`internal/oci/sdk.go`](../internal/oci/sdk.go),
[`internal/app/config.go`](../internal/app/config.go),
[`internal/host/runner.go`](../internal/host/runner.go),
[`internal/placement/controller.go`](../internal/placement/controller.go),
[`docs/architecture.md`](architecture.md),
[`docs/local-development.md`](local-development.md), and
[`docs/releases.md`](releases.md).

## Historical GRU E4 canary proposal (superseded)

This section preserves the estimate and gates from the earlier E4 plan-only
proposal. Its E4 target, A1 exclusion, and separate-authorization statements
are historical and are superseded by the current workspace GOAL above. They do
not define the current preview target or its authorization. At the proposal's
source checkpoint, no OCI plan, apply, resource creation, upload, console
capture, secret write, or image import had been run or authorized. The
committed `ts-infra` defaults then had `oci_estate_enabled = false` and
`oci_seed_enabled = false`. OCI budgets were soft alerts, not spend caps or an
automatic shutdown mechanism.

**Historical scope at that checkpoint: plan preparation only.** The current
preview authorization comes from the workspace GOAL. This old E4 proposal is
not a current operator runbook; the linked preview record and acceptance ledger
hold the current evidence and open prerequisites. Production remains **NOT
PRODUCTION READY**.

The only concrete candidate is one private control-plane canary in GRU
`sa-saopaulo-1`, using one selected availability domain and a planned two-hour
active compute target. The previously observed GRU AD is
`YDvv:SA-SAOPAULO-1-AD-1`, but its capacity and service endpoints must be
re-observed. The run contains exactly four AMD64 `VM.Standard.E4.Flex` VMs:
three controllers and one host, each exactly 1 OCPU and 6 GB, with private IPs
only. A1, SFO and FRA are excluded. A1 has cross-build and ELF evidence only;
its price rows below are comparison arithmetic, not this candidate.
Normal TerraBase placement intent and reconciliation must remain inactive:
current placement has two fixed member seats per selected region and could
create a second host outside this four-VM inventory. The one-host run qualifies
control-plane and host boundaries, not normal placement or autoscaling.

The candidate resource inventory is four AMD64 E4 Flex VMs at 1 OCPU/6 GB
each, four 50 GB boot volumes, one protected 50 GB member-data volume, and one
private VCN with a private subnet. No exact VCN, subnet, route-table, NSG, or
volume OCIDs are recorded for this plan. The five-volume count is a planning
assumption; the member-data volume is retained after the run, and boot-volume
disposition still needs an owner and decision.

Still unselected or unverified are the target tenancy and canary compartments,
the pinned image OCID, exact network and service-gateway identifiers and
effective routes, current GRU AD capacity and E4 quota, the volume performance
tier, boot-volume dispositions and named retention owners, and an itemized
first-period estimate. There is no approved dollar ceiling.

Use a separately reviewed canary OpenTofu root/state and run-owned namespace or
compartment, disjoint from production `ts-infra` state and resources. It may
own only the exact canary foundation and seed, with an explicit controller
handoff and disposal policy; it must not reuse or destroy the protected
production seed. The existing `ts-infra` initial-controller validator accepts
only A1 and the seed has `prevent_destroy`; an E4 seed needs a reviewed canary
profile/validation path. OpenTofu and the orchestrator must never reconcile
the same resource concurrently. The two-hour target is not a hard runtime or
spend cap: a safety/ownership hold can leave compute billable beyond T+120.
It does not bound the lifetime or cost of retained data, boot volumes,
ledger/HEAD or keys; each retained resource needs a named owner and retention
decision.

The storage candidate is four 50 GB boot volumes and one 50 GB retained data
volume. Price arithmetic below assumes the balanced 10 VPU/GB tier, but this
is not a selected or requested tier: the Go volume-create request sets size and
does not set performance, and the volume read-back mapping does not expose the
performance tier. Set and read back the intended tier in a separately reviewed
path before treating that price as the canary estimate. The seed boot profile
is already 50 GB; other exact launch and volume settings still need review. At
this source checkpoint, instance termination explicitly preserves boot and
launch-created data volumes, and the OCI provider has no volume-delete
operation. The protected member-data volume remains retained; every preserved
boot volume needs a named owner and retention decision.

The network candidate is one reviewed private GRU VCN/subnet in the selected
AD, with private east-west NATS and health traffic. A GRU service gateway may
route only to [eligible same-region OCI services](https://docs.oracle.com/en-us/iaas/Content/Network/Tasks/servicegateway.htm),
pending the exact service ID/CIDR and per-endpoint eligibility check. Prove
effective route, NSG and security-list rules for Compute, Object Storage,
Vault/Secrets, instance-principal federation/Identity, IMDS and the required
NATS ports. The current `ts-infra` NSG chiefly defines private ingress; it
does not prove all of that egress. No public IP, Internet gateway, default NAT
or cross-region route belongs in this run. A service gateway does not provide
arbitrary public OS patch/artifact or operator endpoints. The candidate NTP
source is [Oracle's VCN-local managed service](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/configuringntpservice.htm)
at `169.254.169.254` UDP/123; it needs guest chrony/timesyncd configuration
and an effective route/firewall audit, but no service-gateway or NAT route.
Stage signed artifacts in the pinned offline image and separately review the
private operator path; the GRU path is the
[operator gateway](region-bootstrap.md#operator-gateway-peering). Guest clocks must pass the production `adjtimex`
predicate (`TIME_OK`, no `STA_UNSYNC` or `STA_CLOCKERR`, maxerror at most
250 ms), and actual service reachability must be demonstrated before workload
admission.

The `ts-infra` snapshot inspected for this plan is commit
`32bd267c0f64e74634667c113e13880c1147fd14`: both OCI gates are false and
`oci_estate_regions` is empty. Its current initial-seed validator accepts only
`VM.Standard.A1.Flex`, not this E4 candidate. Therefore the existing
configuration supplies no reviewed GRU CIDRs, subnet key, service-gateway
service ID/CIDR, or NSG rules for this run. Exact network IDs and effective
routes remain lookup and review gates; do not infer them from the candidate
diagram or from the provider's region defaults.

The signed placement profile carries OCPU and memory dimensions through the
launch request. At this checkpoint the OCI SDK sets Flex `ShapeConfig`, and
`internal/oci/sdk_test.go` verifies request values and normalized response
values. The test uses a 2-OCPU/12-GB fixture; it is not a live launch. Recheck
the proposed 1-OCPU/6-GB E4 dimensions on all four actual instances before
workload admission. A shape name, unit test, or quota arithmetic alone does
not prove the launched VM size.

The following public PAYG list-price snapshot was captured on
2026-09-25T18:12:17Z. The snapshot is
`/tmp/oci-public-pricing-20260925T181217+0000.json` (SHA-256
`d9311eeb05bae5e7e6434586deb3d7ff0479787be639b9c55617241d0b4041be`).
The [Oracle product catalog](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?partNumber=B93113)
reports the E4 SKUs below with `lastUpdated=2026-09-23T13:10:59.012Z`;
the [volume capacity](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?partNumber=B91961)
and [performance](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?partNumber=B91962)
SKU endpoints supplied the storage rates. This is neither a tenancy quote nor
an all-in estimate. The table's 30-day arithmetic covers only compute and the
five-volume scenario; its A1 rows are excluded from the concrete E4 canary.
The block-volume performance rows use the balanced 10 VPU/GB rate only as an
illustrative assumption; the current Go create/read-back path neither selects
nor confirms that tier.

| Candidate line item | SKU and rate | 30-day calculation |
| --- | --- | --- |
| E4 compute: OCPU | `B93113`, $0.025/OCPU-hour | 4 × 1 × 720 × $0.025 = $72.00 |
| E4 compute: memory | `B93114`, $0.0015/GB-hour | 4 × 6 × 720 × $0.0015 = $25.92 |
| E4 compute subtotal | E4 branch only | $97.92; $0.136/hour for four VMs |
| A1 compute: OCPU | `B93297`, $0.01/OCPU-hour after the first 3,000 monthly OCPU-hours | 4 × 1 × 720 × $0.01 = $28.80 list-tier amount |
| A1 compute: memory | `B93298`, $0.0015/GB-hour after the first 18,000 monthly GB-hours | 4 × 6 × 720 × $0.0015 = $25.92 list-tier amount |
| A1 compute subtotal | A1 branch only | $54.72 list-tier amount; $0.076/hour for four VMs |
| Block-volume capacity | `B91961`, $0.0255/GB-month | 250 × $0.0255 = $6.375/month |
| Assumed balanced performance | `B91962`, $0.0017/VPU-GB-month × assumed 10 VPU/GB | 250 × $0.017 = $4.25/month, if read-back confirms this tier |
| Five-volume scenario | Capacity plus assumed balanced performance | $10.625/month, conditional on that tier |
| E4 priced scenario | E4 compute plus assumed five-volume tier | $108.545 for 30 full days, not an approved estimate |
| A1 priced subtotal | A1 list-tier compute plus volume scenario | $65.345 for 30 full days |

The A1 branch consumes 2,880 OCPU-hours and 17,280 GB-hours in 30 days. Both
fall below the stated 3,000 OCPU-hour and 18,000 GB-hour free ranges only if
those ranges are entirely unused by the rest of the tenancy. The A1 priced
subtotal therefore remains $65.345; $10.625 is only the compute-free scenario,
not a promised price. These historical subtotals are not an all-in preview
estimate and do not establish that an A1 deployment fits the current
$200/month combined testing-and-preview cap. Recalculate with the current
tenancy inventory and all required charges.

For the E4 canary, four VMs cost 4 × (1 × $0.025 + 6 × $0.0015) = $0.136 per
hour at these list rates, or **$0.272 for the planned two active hours**. A
safety hold that extends billable VM time increases this compute charge. Under
the unverified balanced-tier assumption, capacity and performance cost
$0.0425/GB-month: five 50 GB volumes exposed for a full month would be
**$10.625**, while the retained 50 GB data volume alone would continue at
**$2.125/month** if boot deletion were separately approved and performed via a
separately reviewed path. Oracle's [public price list](https://www.oracle.com/cloud/price-list/)
says block capacity/performance meter until deletion, with a one-minute
minimum then per-second proration across the calendar month. The hypothetical
two-hour charge if **all five** volumes were deleted then is about $0.029514,
but that is not the current preserve behavior in the Go provider and cannot be
used as a run cost. At the time of this proposal, no dollar ceiling was
recorded and a prior draft's **$50 first-billing-period example was unapproved
and illustrative only**: under the two-hour compute scenario, $0.272 plus a
full month of five volumes at that assumed tier leaves $39.103 before every
other itemized charge. That arithmetic is not an all-in estimate for the
current authorized $200/month combined testing-and-preview recurring-cost cap,
and a safety hold can extend
billable compute beyond the planned duration.
Image/Object Storage, network/transfer, logs, Vault and continued retention
must be priced with named owners before any authorization.

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
availability, exact volume retention and boot disposition, tenancy/contract/tax
price differences, custom-image storage and licensing, VCN/gateway charges,
private NTP and operator paths (the GRU
[operator gateway](region-bootstrap.md#operator-gateway-peering) adds no priced
OCI resource), eligible service traffic, data transfer and
any cross-region traffic, object retention and version-history growth, API
request volume, logs and metrics volume, Vault tier and shared free-range
consumption, and backup storage/lifecycle. The public catalog showing no
gateway SKU is not a zero-cost guarantee. A later estimate must show priced
quantities and durations separately from these unknowns; it must not label
the priced subtotals a total monthly bill.

Candidate quota limits for a future, separately authorized qualification
compartment and selected AD are resource bounds, not dollar limits:

| Exclusive candidate | AD-scoped quota proposal |
| --- | --- |
| E4 / AMD64 | `compute-core standard-e4-core-count=4`; `compute-memory standard-e4-memory-count=24` |
| Five 50 GB volumes | `block-storage total-storage-gb=250` |
| One private GRU VCN | Regional `vcn vcn-count=1` |

Use `where request.ad=<actual-AD>` only after confirming the target AD in the
selected tenancy. Compute and block-storage quotas are AD-scoped; VCN quota is
regional. Nested-compartment use counts at the parent, and service limits take
precedence. These quotas constrain resource count/capacity, do not cap cost,
VM lifetime, or role count, and do not reserve capacity. A 2026-09-20 read-only
quota snapshot reported 249 A1 cores, 1,662 GB A1 memory, and 61,340 GB
block storage available in GRU AD-1; it is stale planning evidence and the A1
limits say nothing about E4 availability or capacity. The scoped
parent-compartment inventory found no existing Compute instances, VCN,
block volumes, or boot volumes in the three regions, but it was not
tenancy-wide.

The following sequence was written for the historical E4 canary. For the
current preview, follow the workspace GOAL's resource-ownership boundaries and
recorded cost/inventory prerequisite; the root GOAL supplies the preview
authorization. Decisions, inventory, state isolation, cost and stop ownership
still precede resource creation. Image/ledger checks that require created
resources block seed launch, and live network/clock checks block workload
admission. A passed check does not substitute for these prerequisites.

1. A decision owner names the exact tenancy, parent and canary compartments,
   GRU AD, run ID and owner, a planned two-hour active-compute target with
   explicit safety-hold ownership, and the exact inventory:
   three controller and one host `VM.Standard.E4.Flex` AMD64 VMs at 1 OCPU and
   6 GB each, four 50 GB boot volumes, one protected 50 GB data volume, and
   one private GRU VCN/subnet. The owner reviews E4 service limits and live
   capacity, boot-volume preservation versus OCID-specific deletion authority,
   every residual resource's retention owner, and an itemized first-period
   estimate including unpriced usage. No approved dollar ceiling exists; a
   budget alert is not a dollar ceiling or a stop mechanism.
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
5. A separately reviewed canary OpenTofu root/state, E4 Flex sizing and
   launch/intent contract, pinned image OCID, exact planned instance tags and
   post-create OCID inventory, and explicit seed handoff are ready. Its state
   owns only canary resources and is disjoint from the protected production
   `ts-infra` seed; no OpenTofu and orchestrator controller may own the same
   resource at once. Prove managed TerraBase placement intent/reconciliation
   stays inactive so it cannot request a second host.
6. The private service-gateway endpoint eligibility, planned effective
   routes, NSG/security-list ingress and egress, artifact staging, private
   Oracle VCN-local NTP UDP/123 and private operator paths, and production
   clock predicate are reviewed for the
   selected subnet. A runtime reachability and clock check is required before
   workload admission. No public IP, Internet gateway, default NAT or
   cross-region route is in scope.
7. The offline CLI, focused receipt tests, production broker/JWT/clock gate,
   and no-live-secret/image delivery paths pass review. R6's static-TLS
   fixture is not evidence for active JWT/ClockCheck or production NTP; R7's
   JWT/NTP attempt failed before VM boot and has no guest outcome.
8. The qualification operator accepts inventory, stop criteria, teardown
   ownership, exact-OCID cleanup, retained-volume/ledger/HEAD protection,
   and post-run verification before an apply is even considered.

At the historical proposal checkpoint, none of the commands below had been
executed; this was a future sequence for that E4 candidate. Later OCI
inventory and preview work are recorded separately in the linked current
evidence.

1. Run only read-only inventory, E4 quota/capacity, service-endpoint, and
   bucket-property checks. Record returned regions, ADs, OCIDs, ETags, E4
   limits, and evidence timestamps.
2. Review the separate canary root/state, exact Flex dimensions, selected AD
   and pinned image, five volume sizes/tiers and boot disposition, private
   routes and service/NTP/operator reachability, run duration, itemized cost,
   owners and stop automation. Keep A1, SFO, FRA and production `ts-infra`
   state/resources out of this run.
3. If separately authorized, use staged, reviewed canary applies: create only
   its GRU foundation with seed disabled; populate exact version-pinned Vault
   references and signed public manifest; then enable only its one E4 seed in
   a separately reviewed apply. Verify the exact seed OCID and formally
   relinquish canary OpenTofu ownership before controller adoption. The
   production `ts-infra` gates remain disabled.
4. Prove exact seed identity and 1-OCPU/6-GB launch dimensions on each VM,
   current image receipt, private networking, synchronized clock, broker
   authorization, and bootstrap-ledger properties before workload admission.
   No local `tofu apply`, manual ownership transfer, or overlapping
   `ts-infra`/orchestrator reconciliation is allowed.
5. Stop on any missing precondition, ambiguous OCI result, unexpected OCID,
   missing quorum, stale clock, or unknown ownership. Hold the operation for
   OCID-specific reconciliation; do not retry a stale or ambiguous create.

The qualification operator who creates a resource owns its stop and cleanup.
Before any future run, record a run ID, owner, start/expiry times, every
expected OCID, exact tags, and the owner and disposition of each retained
resource. At T+90 minutes, stop new creates and begin the controlled stop.
Target T+105 minutes to stop test workloads and capture fresh, identity-bound
writer-stop proof or evidence that no writer was admitted; absent that proof,
hold detach and termination for explicit reconciliation. Target T+120 minutes to
detach the protected data volume only after writer-stop, host stop/unmount and
exact attachment checks, and re-observe its detached state. Terminate only the
four exact run-owned VMs when those safety
conditions hold, then verify their terminal states and inventory of preserved
boot/data volumes, immutable ledger, CAS `HEAD`, and any other retained items.
Termination alone does not delete the boot or data volumes. The current Go
provider has no volume-delete operation; any separately approved volume
disposition therefore needs a reviewed mechanism outside that provider, an
exact-OCID scope, and read-back proof. Otherwise record each preserved boot
volume and its owner.
Remove only clearly disposable run-owned network or test resources after
exact-OCID/tag checks, then repeat read-only listings and record any residual
resource for its named owner. Ambiguous ownership or attachment means stop
and escalate; never broaden cleanup by compartment. These milestones do not
authorize unsafe detach, termination, or deletion when proof is missing. A
safety/ownership hold may extend billable compute beyond T+120; the named owner
must track and resolve the resulting charges. There is no approved spend cap.
The T+90/T+105/T+120 milestones are targets, not an implemented expiry timer or
spend cutoff. Before any separately authorized execution, review and test a
run-scoped enforcement and operator-response plan that blocks new creates by
T+90, starts the controlled stop by T+105, and defines escalation when safety
evidence prevents detach or termination. Verify the stop against the exact
run-owned OCIDs and confirm terminal instance states, volume attachments, and
the residual-resource inventory. No such enforcement path is qualified here;
because a safety hold can keep compute billable, the two-hour target is not a
hard runtime or spend cap.

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
`guest-systemd.journal`.

The later delegated one-guest attempt **FAILED** with a captured and verified
systemd journal. The guest reached the `/supervisor` service subgroup, reported
the expected `0x1e1` effective and bounding capability mask, and showed a
5 GiB service `MemoryMax`. During native runner `Apply`, the Go execution
helper logged `epollwait on fd 5 failed with 9` (`EBADF`) and
`fatal error: runtime: netpoll failed`; the runner reported that the native
target exited before verification. The Rust test failed;
`ts-member-boundary.service` exited status 101, while Firecracker exited 0. The role
`memory.max`, workload capability drop and Unix-socket member-status checks
were not verified. The cause remains under runtime investigation; this is no
member-status or production-readiness pass. Journal extraction and verification
worked; the Firecracker process, socket, mount and loop attachment were quiescent after
cleanup, with the guest image retained for forensics. Evidence is
`/tmp/ts-member-boundary-vmrun-delegated-20260925T1659Z/summary.json`,
`guest-systemd-unit.log`, and `runtime-evidence.sha256` (SHA-256
`ebc56d0e7c4707ca04e02b50444ee5e087b93becfbd6eca7decc67aa21e12e78`).
The full systemd main-process-death boundary remains open. This guest failure
is separate from R7's pre-VM Chrony failure. Commit `3aef6fba` later changed
native helper FD preservation, but it has no guest requalification result.

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
5. **Historical proposal, superseded for current operation.** The earlier
   two-phase `ts-infra` proposal put foundation and seed creation in OpenTofu
   and is replaced by the operator-run [regional bootstrap
   runbook](region-bootstrap.md). At its recorded candidate (`ts-infra`
   `3fff4df2d3f92c0343cd11c633fc0ba36a82f3e8`, draft PR #16), no apply had run
   and both gates were false. Regional source/state migration still requires
   its own reviewed, non-destructive plan identifying the exact resources;
   this historical proposal does not show that migration has completed.
   Disabling future ledger archiving does not restore records already archived.
6. TerraBase admission should use native v2 ULID database/member identities,
   numeric shard and incarnation values, and reject legacy v1 labels without
   an alias shim. This remains blocked on a frozen TerraBase producer
   contract; later mutable producer source includes an outbound sender and
   `AppliedAck`, but current-source real-peer acceptance, serving proof and
   durable drain semantics are still missing.

## Production-readiness gates

No production gate in this table is **CLOSED**. Evidence must be collected
from the exact code and image being qualified; a design document or isolated
unit test does not close an integration gate. The current M0/M1 delivery gates
are tracked separately in the [shared-goal acceptance ledger](evidence/shared-goal-acceptance-20260926.md).

| Gate / ownership | Required implementation and acceptance evidence | State |
| --- | --- | --- |
| OCI operation recovery — `internal/oci/**` | Use the persisted original operation time and stop replaying OCI create requests before the provider retry-token window expires. Hold expired unknown outcomes and disappeared confirmed resources for explicit, authority-fenced, OCID-specific reconciliation. Preserve the immutable create receipt and use the currently observed ETag for the next fenced operation. Real JetStream KV integration tests must prove no additional provider create at the expiry boundary and safe recovery after lost acknowledgements. | IN PROGRESS; implementation committed as `997498bff9a9c1e6aed29622796515b753ca7b69`; fake-journal unit/race tests passed. Real JetStream KV boundary tests, final review, and reconciliation tooling remain open. |
| Signed release and pinned image — `.forgejo/workflows/**`, `deploy/image/**`, `deploy/systemd/**`, `deploy/release/**`, `docs/releases.md` | Retain exact static artifacts and signed manifests; bind source revision, architecture, binary and image digests, signer, OCI image OCID, and region. Build from a pinned and qualified base image. Install one binary for controller and host roles with explicit service, filesystem, cgroup, and privilege contracts. Require the Linux realtime clock gate before NATS opens: `adjtimex` must report `TIME_OK`, with `STA_UNSYNC` and `STA_CLOCKERR` clear and `maxerror <= 250 ms`; production images need working chrony or systemd-timesyncd. A manually set wall clock is not proof and there is no bypass. Verify an offline image build, installed-binary receipt, and a staged systemd restart/health-check/rollback path. Missing signing keys must fail closed. | IN PROGRESS; this row tracks production image/release qualification. The root GOAL separately authorizes publishing qualified preview artifacts; the OCI preview record currently reports no deployed artifact. `internal/release/cli` creates/verifies canonical receipts and conditionally publishes exact OCI objects, but the production image and release gates remain open. `internal/bootstrapstart` and `internal/app/bootstrap_controller.go` contain the intended image-receipt and running-binary consumer path; this integration is still under review and has no OCI or guest proof. Controller/host units and an offline installer exist, but first-boot config/enrollment and the corrected host cgroup service layout remain unqualified. The R7 amd64 build passed, but its attempt failed at host Chrony readiness before VM boot; the guest result needs a rerun, and arm64 execution has not been tested. Base-image pinning, installed-binary runtime verification, staged restart/rollback, and signer-environment review remain OPEN. |
| Durable pre-quorum bootstrap and region formation — bootstrap slice, `internal/app/controller.go`, `internal/natscell/**` | Connect the signed immutable bootstrap ledger, current founder selection/floor, and OCI launch adapter through a reviewed caller. Prove a cold three-peer GRU cell can form, restart, survive one-node loss, and refuse mutations without quorum. Then prove admitted SFO and FRA cells form automatically with pinned routes, TLS, and trust material. No first-region or cross-region mutation may depend on an already formed JetStream cluster. | IN PROGRESS; founder plan verification, signed current-selection reading, rollback-floor checks, and an offline-testable OCI seed launch adapter have focused package evidence at their recorded source checkpoints. At `d5fc307`, no production `internal/app` caller connects the current-selection reader to the OCI adapter, and no live seed launch or cold-cell qualification exists. At that same historical checkpoint, `ts-infra` gates were false and its GRU seed validator accepted A1 only. Current ownership is operator-provisioned foundation and controller A, followed by Go-managed same-cell B/C after handoff; that boundary does not prove live launch or formation. Cold GRU formation and SFO/FRA formation remain OPEN. |
| Instance identity and host enrollment — NATS authorization/enrollment, host image/runtime owners | Use least-privilege OCI policies and version-pinned Vault material to issue per-host NATS identity and Ed25519 identity, pin the controller response key, and complete signed registration and rotation for the exact OCI instance. Demonstrate denied foreign-region, stale-generation, revoked, and tag-only identities through the real boot path. The preferred proof is a private HTTPS begin/complete exchange, fresh nonce, and public-only serial-console response; the controller reads console history, verifies exact instance ID and both signatures, and issues a durable one-time grant before NATS JWT issuance. Fail closed on 1 MiB history truncation or missing/replayed proof; do not grant console-connection IAM to the validator. | IN PROGRESS; local signed operator `broker-claim-apply` and R3 JWT/fence caller tests passed at the committed checkpoint, addressing the earlier helper-only review findings. The R7 fixture generates private JWT identities but is not a production issuer. Live OCI console-history/IAM denial, first-boot credential issuance and delivery, retry cleanup, and broker-revocation convergence in guests remain OPEN. |
| Host runtime contract — host image/runtime slice, `internal/host/**` | Qualify the exact pinned kernel and image for writable cgroup v2, execution, cancellation, restart recovery, and safe child cleanup. Define the service user, cgroup delegation, state/install directory ownership, read/write mounts, stop timeout, and restart policy. Prove workload privilege boundaries before accepting untrusted workloads; a native process and a startup probe alone are not a tenant sandbox. | IN PROGRESS; the earlier 8/8 native security run covered nested-supervisor death and child cleanup, but full systemd main-process death and writable-cgroup guest qualification remain OPEN. The earlier one-guest Unix-socket attempt exited status 1 without a captured application result; the later delegated attempt captured a verified journal but failed during native Apply with a Go netpoll fatal error before role and Unix-socket verification. The cause is under runtime investigation. Root-to-service credential handoff has source but its real privileged subprocess and restart caller still require review and qualification. The delegated supervisor leaf reached guest startup, but native workload verification failed. R7 failed before VM boot, so JWT/NTP host evidence still needs a rerun. |
| TerraBase member and retained-volume contract — TerraBase producer first; then `internal/placement/**` and host member runtime | Freeze canonical database/member IDs, shard/incarnation semantics, desired-state fields, mTLS, durable directories, readiness, replication evidence, shutdown, and writer-lease semantics. Prove the exact attached retained OCI volume is mounted by the intended process before serving. Serving requires fresh identity-bound local readiness plus independent replication/quorum evidence. | OPEN; at `d5fc307`, placement held at `awaiting-runtime-contract` after OCI attachment. Later commits (`ccfe2566` host bridge, `c0a4d639` placement) publish signed TerraBase desired state, verify a pinned exclusive mount and volume claim on the host, launch the member and report local process/mount status, then hold at `awaiting-healthy`; this path is not qualified here. Guest block-device discovery and safe format/adoption remain absent. The bounded receiver-only member-status surface has no serving proof. Later mutable producer source includes an outbound sender and `AppliedAck`, but current-source real-peer acceptance, independently observed applied frontiers and a durable serving/drain receipt remain open. |
| Healing, autoscale, and retirement — `internal/placement/**`, followed by OCI drain integration | Choose and approve capacity signals, replica floor, min/max, hysteresis, anti-affinity, budget ceiling, and scale-in policy. Implement durable drain, graceful database shutdown, fresh writer-stop proof, retained-volume detach and re-observation, and only then termination. Exercise interrupted and ambiguous lifecycle operations without data loss or duplicate members. | OPEN; the TerraBase producer has no durable drain or writer-fence receipt, and the real OCI controller has no member-serving/drain/writer-stop verifier wired. Fixed seats do not establish autoscaling or safe scale-in. |
| Recovery, operations, and production approval — operations slice | Set RPO/RTO and retention. Back up and restore JetStream authority, OCI journal, and TerraBase data to a tested point; exercise controller quorum loss, host replacement, image upgrade/rollback, scale-in, and recovery. Expose capacity, cost, replication, backup age, and held operations. Review tenancy IAM, regional quotas, network, image OCIDs, and monthly cost before production approval. Qualification testing and preview share the authorized US$200/month recurring cap above. | OPEN; no production restore procedure or production qualification exists. |

## Production-readiness follow-on

The API-first preview sequence and M0/M1 exit criteria are defined in the
[workspace GOAL](../../GOAL.md#5-delivery-sequence) and tracked in the
[shared-goal acceptance ledger](evidence/shared-goal-acceptance-20260926.md).
After that milestone, close the production gates above: signed release and
pinned-image qualification, host enrollment and runtime recovery, durable
TerraBase serving and drain evidence, safe scale-in, backup and restore, and
regional failure testing. Regional Raft remains a separate proposal and is not
a prerequisite for the first preview.

The first bounded deployment target is now the workspace GOAL's API-first,
low-cost ARM64 preview with both services and the existing leaderless profile.
The E4 control-plane-only canary above is historical and is not the current
target. Preview progress and open acceptance gates are recorded in the linked
OCI preview record and shared-goal acceptance ledger. A preview result does
not imply production readiness.

## Unresolved authority decisions

- Select and verify the OCI tenancy, base operating-system image and kernel,
  architecture support, image-builder identity, regional image OCIDs, IAM
  policies, network rules, and quotas. Record an itemized preview estimate
  within the authorized US$200/month combined testing-and-preview recurring-cost cap before resource
  creation; production cost approval remains separate.
- Provision the offline release signer, publish its trust anchor into the
  image, and decide signer rotation and revocation behavior. A missing signer
  key cannot be replaced by an unsigned build or test key.
- Qualify the immutable pre-quorum ledger bucket, conditional-write and
  retention behavior, KMS authority, Vault path/version policy, and the
  operator-A to Go-controller identity/authority handoff. The current boundary
  keeps regional foundation and the first seed with the operator until explicit
  handoff, then assigns same-cell B/C to `ts-orchestrator`. The completed
  `ts-infra` state-only handoff is a separate state operation; it does not
  establish regional resource health, a live controller, or the required
  operator-to-orchestrator identity, authority, and inventory handoff. Source
  cleanup is separate. See the
  [manual regional bootstrap runbook](region-bootstrap.md).
- Freeze TerraBase v2 identity, readiness, replication, drain, and writer-stop
  contracts with its producer team.
- Set availability targets for controller loss and host session loss, replica
  floor, scale policy, RPO, RTO, and backup retention. Apply the authorized
  preview cap to recurring preview resources; define production limits
  separately.

Until those decisions and the acceptance ledger are complete, this document
must not be read as an operating runbook or a production approval.
