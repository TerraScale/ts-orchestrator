# OCI deployment readiness — 2026-09-20

**Do not start OCI deployment yet.** Local tests cover useful components, but
the production first-boot, resource ownership handoff, automatic regional
formation, and complete runtime qualification are not finished. No OCI
mutation or local OpenTofu apply was performed for this readiness work.

## Required ownership model

`ts-infra` is authoritative for supported regions and starts the first GRU
orchestrator. Orchestrator must then own the OCI resource lifecycle and create
autonomous regional orchestrator/NATS clusters, whose admitted hosts pick up
work automatically. `ts-auth` and TerraBase scale independently. Status and
metrics must expose needs, actions, and progress across these lifecycles.

Current `ts-infra` code emits generation-versioned region intent and contains
an explicitly disabled GRU-only seed estate and one private ARM64 controller.
It does not create SFO/FRA infrastructure. Runtime OCI fleet startup consumes
`TS_ORCH_REGION_INTENT_FILE` and rejects unsupported cells or mismatched OCI
endpoints/templates. This is startup validation; it neither distributes intent
updates nor creates regional clusters. OpenTofu still owns the seed resources.

The [bootstrap contract](../operations/control-bootstrap.md) defines the
required first boot and exact-resource handoff. A tag or output does not
transfer ownership. A signed adoption request, CI relinquishment without
destruction, durable state publication, and signed release receipt are still
needed before the controller may mutate the seed foundation.

The executable now includes a pinned OCI Vault delivery command,
[`oci-bootstrap-secrets`](../operations/oci-vault-bootstrap.md). It verifies
exact secret versions/digests and publishes private files atomically before
normal runtime startup. This closes the materialization component; live
Instance Principal checks, bootstrap supervisor composition, enrollment
renewal and admission remain open.

The bounded [`oci-founding-peers`](../operations/oci-founding-peers.md) command
now creates the seed's two signed GRU peers before NATS exists. Its offline
`oci-sign-founding` companion keeps the signing key in CI. Retry/restart and
expiry behavior are covered locally; `peers-running` still explicitly requires
regional NATS quorum, admission and seed handoff. Expired partial bootstraps
have no signed renewal/recovery protocol yet.

The real SDK launch test exposed an endpoint-routing bug: the OCI client
retained the credential region's template after receiving an explicit
endpoint. The compute, network, block-storage, work-request and Vault factories
now clear that template, preserving the reviewed explicit regional endpoint.
Five signed loopback HTTP tests cover those service clients. These checks
use synthetic test credentials and do not qualify Instance Principal.

## Verification evidence

These are working-tree results, not qualification of an immutable release.
Other changes are present in the shared checkouts. Rerun the final gates against
the exact release revision before deployment.

| Check | Result | Evidence/limit |
| --- | --- | --- |
| Founding peer grant and reconciliation | **27 passed**, 0 failed/skipped | `/tmp/ts-oci-founding-tests-final.log`; offline signing, exact bounds, retries/lost responses and receipts, restart, drift, expiry, lock and redaction; includes real SDK signed launch serialization against loopback |
| Explicit OCI SDK endpoint routing | **5 passed**, 0 failed/skipped | `/tmp/ts-oci-sdk-endpoint-tests.log`; compute, network, block storage, work requests and Vault use the supplied endpoint despite a stale template |
| Founding Release/style and publish | Pass; build 0 warnings/errors; x64 and ARM64 ELF verified | `/tmp/ts-oci-founding-release-build-final.log`, `/tmp/ts-oci-founding-style.log`, `/tmp/ts-oci-founding-{x64,arm64}-publish.log` |
| Published founding CLI | Pass, offline x64 process | `/tmp/ts-oci-founding-cli-receipt.json`; actual signing verified by OpenSSL, existing grant preserved, invalid signature rejected before provider/state; ARM64 built but not executed |
| Vault delivery after SDK endpoint correction | **18 passed**, 0 failed/skipped | `/tmp/ts-oci-founding-vault-regression.log`; no live Vault calls |
| Full orchestrator main suite including founding and endpoint changes | **1032 passed, 0 failed, 5 live-lane skips** | `/tmp/ts-oci-founding-main-suite.log`; revision `80f9356d`, 9m56s; before the subsequent R3 assertion correction |
| R3 authority conformance after read assertion correction | **1 passed**, 0 failed/skipped; style passed | `/tmp/ts-oci-r3-read-regression.log`, `/tmp/ts-oci-r3-read-style.log`; 33.8s, real three-server NATS with the existing account-denial checks |
| Stateful enrollment/readiness, host producer, configuration | **51 passed**, 0 failed/skipped | `/tmp/ts-oci-member-admission-runtime-tests.log`; real NATS, exact identity/artifact/time binding, report before service startup, admission withdrawal and schema-2 fleet environment |
| OCI member fleet after readiness binding | **21 passed**, 0 failed/skipped | `/tmp/ts-oci-member-admission-provider-tests.log`; stopped-instance and owner/member/bootstrap/image drift rejection; fake OCI transport |
| Placement with missing drain evidence | **6 passed**, 0 failed/skipped | `/tmp/ts-oci-member-admission-placement-tests.log`; missing health holds the real-NATS placement ladder before detach/retire |
| Broader placement regression after readiness binding | **16 passed**, 0 failed/skipped | `/tmp/ts-oci-member-admission-placement-regression.log`; final Release build and style verification also passed |
| Restricted host report producer and relay | **26 passed**, 0 failed/skipped | `/tmp/ts-host-report-relay-tests.log`; real NATS, multiple manifest-pinned hosts/controllers, explicit denial, malformed/replayed reports, bounded retention, reserved-key collision rejection and persistence retry |
| Report permission model | **165 passed**, 0 failed/skipped | `/tmp/ts-host-report-protocol-tests.log`; regional agent wildcard remains region/direction bounded, host scopes retain exact hashes, publisher kinds remain disjoint |
| Status, telemetry, endpoint/security and R3 regressions | **29 passed**, 0 failed/skipped | `/tmp/ts-host-report-regression-tests.log`; authenticated three-server NATS plus bounded status/metrics assertions |
| Report persistence with the controller's own R3 credentials | **1 passed**, 0 failed/skipped | `/tmp/ts-host-report-r3-relay-test.log`; real JWT/mTLS host, private store opened by restricted controller, withdrawal/order preserved across relay restart; not full `NatsRuntime.StartAsync` qualification |
| Report relay Release build and style | Pass; **0 warnings/errors** | `/tmp/ts-host-report-relay-build.log`, `/tmp/ts-host-report-relay-style.log` |
| OCI data-volume identity and attachment boundary | **33 passed**, 0 failed/skipped | `/tmp/ts-oci-data-volume-provider-tests-final.log`; current attachment/ETag, boot/logical ID denial, access/identity drift, ambiguity, wrong host, repeated pagination, timeout/404 reobservation; fake OCI transport |
| Placement with exact retained-volume evidence | **20 passed**, 0 failed/skipped | `/tmp/ts-oci-data-volume-placement-tests-final.log`; real NATS plus scripted fleet; missing/different disks hold serving and removal; Release build 0 warnings/errors |
| Vault bootstrap component | 18 passed; Release build 0 warnings/errors; locked restore and dependency audit passed | `/tmp/ts-oci-vault-tests-sdk.log`, `/tmp/ts-oci-vault-final-build.log`, `/tmp/ts-oci-vault-audit.log`; includes real OCI SDK signing/version serialization/response decoding against loopback HTTP, no live OCI access |
| Real containerd lifecycle and isolation | **2 passed, no skips**; cleanup verified | `/tmp/ts-oci-containerd-rehearsal-final.log`, `/tmp/ts-oci-containerd-f9l1t9em/receipt.json`; real pinned pull/create/start/restart/delete, kernel security/resource checks, forged-label rejection; synthetic x64 image, no ts-auth application or OCI VM |
| Containerd adapter, runtime plans, host convergence | 8 + 7 + 18 passed | `/tmp/ts-oci-containerd-adapter-tests.log`, `/tmp/ts-oci-containerd-plan-tests.log`, `/tmp/ts-oci-containerd-host-tests.log` |
| Published Vault bootstrap CLI | Existing private bundle verified; modified bundle rejected without overwrite | `/tmp/ts-oci-bootstrap-cli-probe.json`; actual single-file x64 process, no OCI calls |
| Orchestrator single-file publish | x64 and ARM64 passed, including Vault delivery | `/tmp/ts-oci-bootstrap-cli-publish.log`, `/tmp/ts-oci-bootstrap-arm64-publish.log`; ELF architecture checked; ARM64 was not executed on OCI |
| Orchestrator runtime/main-test dependency audit | Pass | `/tmp/ts-oci-nuget-audit.log`; exit 0 |
| Orchestrator Release solution build, latest edits | Pass, 0 warnings/errors | `/tmp/ts-readiness-build-final3.log` |
| Region-intent authorization tests | 19 passed | `/tmp/ts-region-intent-tests.log`; strict shape, mappings, endpoints, bounded/private file |
| Operator-status projection and desired-artifact tests | 7 passed | `/tmp/ts-oci-readiness-binding-status.log`; exact report key, cell, artifact and time; independent policy bounds; conflicting desired digests rejected |
| OCI workload fleet tests after readiness correction | 19 passed | `/tmp/ts-oci-readiness-binding-tests.log`; real NATS readiness binding; non-ready VMs count as pending, expired authority prevents launch; invalid demand and unsafe TerraBase retirement denied |
| Live local TerraBase fleet | 1 passed, no skip | `/tmp/ts-oci-local-fleet-live.log`; fresh TerraBase.Host publish, scale-out, loss/heal, drain safety and scale-in |
| Live single-region and three-region VM lanes | **2 passed, no skips** | `/tmp/ts-oci-vm-live.log`; 2m22s; fresh self-contained host with prepared kernel/rootfs; no remaining Firecracker processes or br-fc/tap-fc devices for lanes 77/78/79 |
| Scheduler suite, latest edits | 106 passed, 0 failed | `/tmp/ts-scheduler-final.log`; provider failure isolation, cancellation, confirmation reset |
| OpenTofu format, validation, mocked plans | Pass; 7 tests passed | `/tmp/ts-infra-bootstrap-tests-final.log`; all test runs use mocked providers and `command = plan` |
| OpenTofu Vault tier configuration | Pass; 9 mocked plan tests passed | `/tmp/ts-infra-vault-tier-validation.log`, `/tmp/ts-infra-vault-tier-tests.log`; shared HSM default, explicit dedicated tier and invalid-tier rejection; estate remains disabled |
| Refreshed plan after Vault tier selection | Pass; **zero resource changes**, outputs only | `/tmp/ts-infra-vault-tier-plan-receipt.json`; no apply; saved plan remains private |
| Refreshed read-only OCI plan, estate disabled | Pass; outputs only, no resource changes | `/tmp/ts-infra-region-plan-final.log`; passphrase available locally, never printed |
| Auth browser context cleanup regression | 1 passed | `/tmp/ts-auth-browser-cleanup.log`; page disposal now closes its isolated context |
| Auth admin authorization test after cleanup fix | 1 passed | `/tmp/ts-auth-admin-focused.log`; isolated pass does not establish the full-run timeout's cause |
| Full auth CI-equivalent run before cleanup fix | Incomplete, interrupted after approximately 29 minutes | `/tmp/tsauth-ci-equivalent.log`; one admin browser timeout recorded; exit 1, no completed totals |
| Full auth run after browser cleanup fix | 380 passed, 1 failed | `/tmp/tsauth-ci-cleanup-rerun.log`; completed in 3 minutes; same admin navigation timeout |
| Admin portal after navigation assertion fix | 5 passed | `/tmp/ts-auth-admin-navigation.log`; observes navigation before submit and checks the rendered account heading |
| Full auth run after navigation assertion fix | **381 passed, 0 failed, 0 skipped** | `/tmp/tsauth-ci-navigation-rerun.log`; 2m40s, CI-equivalent serial execution |
| Full orchestrator main suite after region/status/scaler changes | 974 passed, 0 failed, 3 skipped | `/tmp/ts-orchestrator-main-final.log`; 10m14s; final provider demand/drain correction was then verified by the 17 focused fleet tests |

The [founding component receipt](oci-founding-local-2026-09-20.json) records
source file hashes, local log hashes, test totals and both published artifacts.

Earlier completed orchestrator results, before the latest region/status/scaler
edits: main **952 passed, 3 live-test skips**; control plane **949 passed**;
protocol **165 passed**; scheduler **102 passed**; model **59 passed**. Focused
host convergence had 18 passes and admission 2 passes. These are component
results, not proof of a fresh OCI VM booting and serving work.

Earlier auth log `/tmp/tsauth-final-run2.log` completed with 325 passes and
49 failures (44 browser target-closed errors and five webhook/magic-link
failures). It is distinct from the later interrupted runs. Focused reruns of
webhooks (9 tests) and atomic magic-link consumption (1 test) passed. The
subsequent session 49559 was terminated with exit 137 and has no passing suite
result. Do not combine these runs into a green full-suite claim.

Prior focused service telemetry results: auth authenticated metrics 1 pass;
TerraBase metrics/readiness 2 passes. Real local containerd execution now passes the synthetic x64 rehearsal in
[containerd-qualification.md](../operations/containerd-qualification.md). The final
ARM64 service images and external TerraBase/auth deployment remain unqualified. The VM host single-file
publish succeeded with SDK warning NETSDK1236 about exclusion of the referenced
TerraBase runtimeconfig file; the resulting guest binary passed both VM lanes.
This warning must still be assessed for release packaging.

## OCI inventory and configuration

Read-only OCI CLI 3.82.0 queries confirm READY subscriptions:

| Cell | OCI region | OCI key |
| --- | --- | --- |
| GRU | `sa-saopaulo-1` (home) | GRU |
| SFO | `us-sanjose-1` | SJC |
| FRA | `eu-frankfurt-1` | FRA |

Read-only resource-availability queries completed for all five regional
availability domains (`/tmp/ts-oci-quota-readiness.json`):

| Region/AD | Available A1 cores | Available A1 memory (GB) | Available block storage (GB) |
| --- | ---: | ---: | ---: |
| GRU AD-1 | 249 | 1662 | 61340 |
| SFO/SJC AD-1 | 250 | 1666 | 61440 |
| FRA AD-1 | 250 | 1666 | 61440 |
| FRA AD-2 | 250 | 1666 | 61440 |
| FRA AD-3 | 249 | 1660 | 61440 |

The service counters reported zero usage except FRA AD-3's one A1 core and
6 GB memory. Direct instance listings of the recorded compartment still
returned no entries in the three regions; that does not establish the scope
or freshness of those usage counters. These are quota results, not reservations
or evidence of physical host availability. Additional network, Vault and
service-specific quotas and the enabled plan's cost still need review.

The GRU availability domain is `YDvv:SA-SAOPAULO-1-AD-1`. The recorded TerraScale
compartment is `ocid1.compartment.oc1..aaaaaaaangcm4a4gp4epa2jec7mizqkomvgjnymdrxecimlroa42ozvk7cna`.
Earlier direct listings found no compute instances in that compartment in
these three regions, and no GRU VCN. Vault listing returned no entries in that
compartment. These observations are scoped to the queried compartment and do
not prove the whole tenancy is empty. Dynamic-group listing was denied, so
controller dynamic-group absence is **unconfirmed**.

OpenTofu is 1.12.6 with OCI provider 6.37.0. The private local state passphrase
exists and enabled the refreshed read-only plan. No state was edited manually.
Saved plan files are private local artifacts; state encryption alone does not
ensure saved plans are encrypted. The enabled configuration has been checked
with mocks only. It still needs actual pinned artifacts/images, bootstrap,
least-privilege IAM, private egress, quotas, Vault bindings, and cost review.

The estate now separates the TerraScale parent compartment from the tenancy
root used for dynamic groups and the Email Delivery compartment. Its retained
buckets disable versioning: Oracle explicitly disallows retention rules on
versioned buckets ([OCI retention documentation](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingretentionrules.htm)).
The Vault tier is now explicit in `infra.tfvars`: `DEFAULT` uses shared HSM
capacity and keys retain HSM protection. A dedicated `VIRTUAL_PRIVATE`
partition requires an explicit configuration change and cost review. The
complete enabled resource plan still needs review. Infra commits `1ac160f`
(controller compartment binding) and `4c237a9` (Vault tier) remain local after
Forgejo rejected the push to protected `main`; publication is pending the
repository's main-only push rule being resolved.

## Authentication required before deployment

- **OCI controller:** Instance Principal. The dynamic group must match only
  controller instances; workload hosts need separately scoped permissions.
  Workstation API keys must not be installed on controllers. Prove allowed
  operations and denial outside the owned compartments/resources from OCI.
- **Regional NATS:** distinct controller, operator, infrastructure journal
  provisioner, journal writer, and host identities, with private NKey/mTLS
  material and exact regional subject permissions. The production regional
  runtime uses NKey files; existing JWT-based test fixtures do not by
  themselves prove its first-boot connection configuration.
  Separate Unix users on a VM share its Instance Principal. The controller
  principal must be denied the journal writer key, including self-granted
  access; first boot still needs an enforceable OCI identity boundary for
  the writer. Separate credential directories alone do not establish it.
- **Command and enrollment trust:** pinned signing keys, grant audience,
  certificate/node/region binding, fixed system project, and durable replay
  records. Production admission currently accepts a generation once and
  caches it for the process lifetime. Restart and credential renewal need a
  complete protocol; do not weaken the replay fence to bypass this gap.
- **Vault and workloads:** fetch pinned secret versions through scoped
  Instance Principals, verify digests, write restricted files, rotate and
  revoke credentials. Compose this path for NATS, TerraBase and auth secrets.
  The new `oci-bootstrap-secrets` CLI materializes pinned Vault references
  through the OCI SDK and Instance Principal into private generation
  directories. Its local transport tests and published-binary probe are not
  live Vault qualification. The supervisor still needs to compose it with
  signed host admission, rotation and renewal.
- **Operator:** use authenticated
  `ts.orch.v2.<cell>.query.operator-status` through a read-only operator
  identity. Auth `/metrics` uses its dedicated `TS_AUTH_METRICS_KEY` in
  `X-TerraScale-Metrics-Key`, with no operator-key fallback.

## Blocking implementation and qualification

1. Complete the seed first boot: artifact verification, Instance Principal,
   scoped Vault retrieval, NATS startup, isolated journal, controller admission,
   and recovery after interruption at each stage.
   The initial controller must create its founding peers before an R3 authority
   quorum exists; the current normal runtime depends on that quorum. The new
   signed founding path creates only two peers without downgrading production
   stores. Its supervisor, peer artifact delivery, authenticated NATS quorum,
   isolated journal identity and partial-bootstrap grant recovery are still
   required.
2. Implement and qualify the CI/controller seed ownership transfer. The
   dynamic-group rule now binds to the newly created controller compartment
   automatically. Bootstrap policies must still be reviewed and must not
   allow the controller to widen its own tenancy permissions.
3. Compose regional network/storage/Vault/IAM and controller formation from
   supported-region intent, with durable generation fencing, resource ownership,
   idempotent retries, rollback, drain, and retained-data protections.
4. Prove fresh host enrollment and automatic admitted task pickup, then restart,
   credential renewal, node loss and replacement. Region support alone must
   never authorize work or confer membership. The host-agent manifest grants
   hashed observation/ack/command subjects. Host reports now use an acknowledged
   controller relay; the controller's agent grants cover all hosts only in its
   fixed region. Desired state, artifact retrieval, backoff, replacement leases
   and enrollment still need restricted-host protocols and dedicated host startup.
   The report tests inject separate controller store handles and are not proof
   of a complete host runtime under host credentials.
5. Qualify generic auth scaling alongside stateful TerraBase placement. The
   status projection now uses configured fleet limits, absent/suspended desired
   state blocks allocation, and one workload's provider failure does not stop
   the other. Generic provider readiness now binds the node, cell, accepted artifact,
   report time and OCI running state. Unready VMs count as pending capacity,
   preventing repeated launches while bootstrap is incomplete. Stateful member
   readiness now binds exact enrollment evidence to its delivery environment,
   node, cell, artifact and time, separately from serving health. Generic TerraBase scale-in is explicitly denied until the stateful
   placement fleet supplies drain and data-safety proof.
   Preserve the distinction between host readiness and service health when
   tightening the member path: placement attaches a retained volume after
   `ProvisionAsync` returns. Requiring a healthy member before that attachment
   would prevent recovery. Bind host readiness to the exact admitted artifact
   used by host convergence, then qualify service health after volume recovery.
   The storage audit's boot/data-volume mismatch is corrected: the fleet now
   reads current data-volume attachments and ETags, rejects ambiguous/access
   drift, and never substitutes boot-volume IDs. Placement no longer fabricates
   a missing provider volume or accepts a different retained identity. Data
   volume creation, resource ownership and guest mount/use proof still need
   implementation. The drain command also has no
   composed production host consumer/acknowledgement. Missing health now holds
   draining, but explicit writer-stop, volume ownership/mount/retention and
   retirement proofs are still required. Details are in
   [oci-member-readiness.md](../operations/oci-member-readiness.md).
6. Finish status and telemetry for foundation, handoff, regional enrollment,
   Vault rotation and every provider operation. Current workload aggregates and
   needs/actions/progress are useful but are not complete OCI lifecycle coverage.
7. Retain the completed green auth, orchestrator, live fleet and VM results,
   then qualify the ARM64 container runtime and external TerraBase/auth on the
   final immutable artifacts. The local synthetic x64 containerd lane passes. Local VM fleet tests do not exercise the unimplemented
   OCI Instance Principal/Vault/bootstrap handoff.

## Final local gate

Run at reduced local priority; CI keeps normal priority. Use TUnit, not
`dotnet test`. Retain command, revision, exit code and test totals.

- Locked restore, format, Release build, architecture-specific single-file
  publish and vulnerability audit for orchestrator, TerraBase, and auth.
- Full TUnit suites including real NATS, authenticated operator query and
  permission denial, auth browser/security tests, and external TerraBase use.
- Local provider-to-first-boot rehearsal with deterministic OCI transports:
  lost responses, retry-token reuse, restart, ownership mismatch, IAM denial,
  polling timeout, partial failure and cleanup. Prove no duplicate VM.
- Real containerd pull/create/start/readiness/stop/delete on a disposable host;
  verify pinned digest, isolation, wrong-image rejection and secret redaction.
- Live local TerraBase fleet scale/heal, one-region and three-region VM
  formation/loss/heal; verify no leaked guests, taps, bridges or listeners.
- Independent auth/TerraBase target changes, cooldown, pending operations,
  drain, failure isolation and status/metric agreement. Exercise key rotation,
  backup/restore and the controller restart path.
- Mocked OpenTofu tests and a reviewed enabled **plan**, with an exact bootstrap
  artifact and least-privilege resource inventory. Applies remain CI-only.

The provider demand/drain correction is `5b4da8f2`, pinned Vault delivery is
`7e7ba778`, and readiness binding is `c2e3ae16`; all are committed and pushed.
Forgejo tasks 493, 494 and 495 were cancelled by subsequent pushes. Task 496 for
`04c0b09a` failed: control plane **949**, model **59**, protocol **165**, and
scheduler **106** tests passed; main had **999 passed, 1 failed, 5 live-lane
skips**. The failure was an immediate R3 KV read of a just-acknowledged runner
job (`NatsControlR3L0cTests`, line 265). The correction uses the existing bounded
read retry, retaining the exact revision assertion and all permission-denial
checks. Its qualification is recorded separately; this CI run remains failed.
The private job log is `/tmp/ts-orchestrator-ci496-job-21991.log`.

Task **497**, revision `2ea613dc9f`, passed all five test projects: control
plane **949**, model **59**, protocol **165**, scheduler **106**, and main
**1032** (main has **5 live-lane skips**). The job failed afterward because
the checksum glob included its own newly created `SHA256SUMS`. The workflow
now hashes only the log, HTML reports and source receipt, then verifies that
manifest. Local fresh/repeated packaging passed and receipt tampering failed
verification. This corrects the packaging bug; remote upload and artifact
jobs still need a successful run. Log:
`/tmp/ts-orchestrator-ci497-job-21993.log`.

Task **498**, revision `5cfd56552c`, passed control plane **966**, model
**59**, protocol **165**, scheduler **106**, and main **1063**, with **5
live-lane skips**. Its checksum packaging and verification passed. The job
then failed in `upload-artifact` on the runner's known `include-hidden-files`
boolean-input handling bug. The test step now writes its source receipt and
checksums to the retained job log, matching the existing binary-artifact
fallback; HTML reports are not uploaded or durably retained by that fallback.
The unsupported upload step is removed without changing test failure handling.
Log: `/tmp/ts-orchestrator-ci498-job-21995.log`. A successful pipeline and a
working immutable artifact-delivery path are still required.

## First live OCI qualification, after local readiness

Start with disposable GRU staging. Prove Instance Principal allow/deny behavior,
private connectivity, Vault access/denial, seed handoff, fresh node joining,
automatic task pickup, lost-create response recovery, controller restart, drain,
backup/restore and complete cleanup. Run auth security and tenant-isolation
probes over real TerraBase. Do not enable customer traffic or form SFO/FRA
clusters until the GRU receipt is reviewed. Live OCI checks cannot be marked
passed by mocked plans, transport tests, or local VM tests.
