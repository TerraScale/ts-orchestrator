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

Host enrollment now signs the exact workload roles and environment, with
scope mismatches rejected before replay consumption or runtime connection.
The [host session request component](../operations/host-session-authentication.md)
also verifies possession of the enrolled NATS user key on bounded, exactly
routed acquire/renew requests. A controller-owned R3 session authority and
restricted NATS host client/service now implement renewable process leases,
durable revocation and generation/replay fencing. Their component tests pass.
Controller startup now loads a public enrollment policy and starts the service
with status/metrics. An independent renewable host execution lease now exposes
terminal cancellation and an immutable current session signer. Core convergence
links work to that cancellation, including stalled desired-state reads.
Lease-backed convergence now requires exclusive local ownership and a durable
canonical workload inventory. It discovers both native drivers and stops
recorded work before new reconciliation, independently of desired state and
report acknowledgements. Late starts, stops and recovery probes retain the
owner lock until they actually settle.
Convergence now takes a typed desired source. The controller's separate signed
desired service derives role/environment from enrollment, checks current sessions
before and after storage access, confirms positive reads through CAS, and binds
replies to the exact request and expiry. Missing desired state is distinct from
malformed or unavailable storage. Status and metrics expose its retry needs.
Native artifact retrieval now uses independently signed, current-session chunk
requests with exact role/environment target checks. The controller streams from
a bounded verified cache; the host checks the complete digest before installing.
The [artifact protocol](../operations/host-artifact-delivery.md) documents its
limits, status and metrics. [Durable cycle/backoff](../operations/host-convergence-cycles.md)
now uses signed requests, non-expiring controller-owned records and replay-safe
outcomes. Regional replacement leases still require a restricted protocol; this
does not enable the production host entry. The
[artifact publisher](../operations/artifact-publication.md) now snapshots input,
conditionally resumes a digest's verified chunk prefix and creates metadata
once. It does not require purge authority. Safe abandoned-upload and artifact
retention/reclamation remain open; the 8 GiB store cap rejects new writes at
capacity rather than evicting active artifacts.
Protected credential validation now supplies fixed certificate/JWT/trust expiry
to a nonrenewable monotonic material budget. The restricted R3 test composes
these checks with session renewal and actual owned-process shutdown. The
dedicated host entry, external-command cgroup quiescence and writer fencing
still need composition, so remote host admission/startup remains a blocker. A local stopped observation is not storage writer fencing.
Current lease retries now confirm replica reads through an unchanged CAS;
report proof and current-session authorization components use the same fence.
TerraBase recovery/health, OCI workload readiness and operator ready counts
now require a signed report and current session, with an unchanged CAS for
both the session and report. The publisher and relay now require signed
session-bound envelopes and persist each proof atomically with its observation.
Ready counts also require matching current admission, so withdrawal invalidates
an older converged report. Plain reports fail closed. Controller run/check
rejects mixed host roles; the dedicated host path remains a deployment blocker.

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

### Final candidate evidence — 2026-09-21

The final local candidate is based on `ts-orchestrator@503bb363`, with the
qualification harness and evidence changes recorded by this document's commit,
and `ts-auth@5075c89`. The clean orchestrator rerun passed **1,459 tests**, with
zero failures and seven expected live-lane skips; its supporting suites passed
**969 control-plane**, **59 model**, **165 protocol**, and **106 scheduler**
tests. Locked restore, required format, Release build (zero warnings/errors),
and dependency audit also passed. The main-suite log is
`/tmp/ts-goal-orchestrator-main-after-gateway-20260921.log`.

The auth release run at `ts-auth@2e98d0e` passed **381/381 tests**, with zero
failures or skips. The current `ts-auth@5075c89` member-mode gateway change was
then used in the Firecracker lane below. The release payload's
single-file payload SHA-256 is
`f3f3d877b5f9a339064e035a7947f0bbd7c435a5d0cc27086f8980001e189171`.
The locally built image is
`localhost/terrascale/ts-auth:a82c42474804bcd6922e75fb388f2106c1fb285d`,
with image digest
`sha256:d8fe574566629aaae4db34f79a3837cbcdf7b1c739da2511cc4106e2f5dea75a`.
The green test log is `/tmp/ts-goal-auth-full-20260921.log`; the corrected
restore, publish, and image gate is `/tmp/ts-goal-auth-publish-fixed-20260921.log`.

The external auth smoke exercised the real process against the local
`TerraBaseDevMember` and passed **22/22 checks**, including account/session,
management API, OIDC, SCIM, webhook, billing, passcode, and audit behavior:
`/tmp/ts-goal-auth-external-devmember-smoke-20260921.log`. This is dev-member
integration evidence only. The raw TerraBase production host has no composed
public API-key authentication and tenant authorizer for document requests, so
it fails closed; the dev member supplies a local stand-in for this boundary.

The serialized Firecracker run passed the existing one-region and three-region
lanes (**2 passed**). The auth lane failed at instance creation because the raw
host returned HTTP **503 Service Unavailable**; it is a deployment blocker, not
a passing VM result. The failure and cleanup evidence are in
`/tmp/ts-goal-orchestrator-vm-auth-live-serialized-20260921.log`.

A follow-up serialized auth lane passed **1/1 test** after the VM harness was
given an explicitly local `TerraBaseDevMember` payload in member mode. That
payload composes the dev API-key middleware and allow-all tenant hook with the
real TerraBase engine, and the test covered readiness, instance creation,
duplicate rejection after a hard VM restart, graceful drain, and retirement.
The complete serialized Firecracker run then passed **3/3 tests**: the
single-region boot/heal/drain lane, this auth/restart lane, and the three-region
GRU/SFO/FRA loss-and-replacement lane. Its log is
`/tmp/ts-goal-orchestrator-vm-all-live-20260921.log`; the focused auth log is
`/tmp/ts-goal-orchestrator-vm-auth-live-local-gateway-20260921.log`.
This is local gateway qualification only; it does not qualify the production
project-key gateway, durable credential issuance, tenant policy service, or
the raw `TerraBase.Host` deployment path. The raw-host failure above remains a
production blocker.

The current TerraBase Release build was exercised with **1,192 API tests**,
**480 core tests plus four expected Windows skips**, **20 schema-generator
tests**, **73 full-text tests**, **28 ZoneTree tests**, and **14 recovery tests
with two expected Windows skips**; every executed test passed. Replication and
transport evidence includes the three-member leaderless convergence test,
SIGKILL crash-resume, MagicOnion resumable/partition/network-fault suites,
native gRPC, durable Q3 integration, and the two upstream-derived replicator
tests; all passed. The API log is
`/tmp/ts-goal-terrabase-api-full-20260921.log`, with focused evidence in the
other `/tmp/ts-goal-terrabase-*20260921.log` files. The complete upstream
ZoneTree stress project remains time-prohibitive locally: its WAL-heavy atomic
update cases were stopped after more than 40 minutes without a failure, so it
is not represented as a green deployment gate.

The current `ts-infra` working tree also passed its **28** encrypted-state
publication tests, OpenTofu formatting, configuration validation, and **9**
mocked plan tests. A local `tofu init` cannot refresh the checked-in encrypted
state without the deployment state's passphrase; no cloud credentials or
apply were used.

These results are local release and integration evidence only. They do **not**
qualify OCI deployment, production first boot, raw-host TerraBase/auth
composition, native ARM64 service execution, ownership handoff, or regional
formation.

The [restricted desired-state receipt](host-desired-local-2026-09-21.json)
records **2,638 passed** across all five projects, zero failures and five expected
opt-in skips. It covers signed desired selection, controller and convergence
callers, stale-read/revocation fences, bounded stalled storage, and status/metrics.
Release build and required style passed. This receipt does not qualify the
remaining host protocols, production first boot, native ARM64 services or OCI.

The [host session authentication receipt](host-session-authentication-local-2026-09-21.json)
records source hashes, dependency and test evidence, native-library bundle
hashes and the scope of local single-file execution.
The [durable session authority receipt](host-session-authority-local-2026-09-21.json)
records the subsequent authority, broker and request-deadline checks with
separate source and local-log hashes.
The [controller session composition receipt](host-session-controller-local-2026-09-21.json)
records the policy loader, runtime service, status and telemetry checks.
The [report authorization receipt](host-report-authorization-local-2026-09-21.json)
records the signed report and current-session primitives. The subsequent
[readiness-reader receipt](host-report-readiness-local-2026-09-21.json) records
current-session/report CAS barriers, controller composition and the populated
store permission correction, including the full local regression.
The [signed report transport receipt](host-report-transport-local-2026-09-21.json)
records the real host publisher/relay path, admission/runtime pairing and the
subsequent complete local regression.
The [host execution lease receipt](host-execution-lease-local-2026-09-21.json)
records independent renewal/watchdog, cancellation, authenticated R3 and
response-deadline checks. It does not qualify physical workload shutdown.
The [tracked workload shutdown receipt](host-workload-shutdown-local-2026-09-21.json)
records the subsequent full regression, including actual child-process exit
after authenticated R3 revocation and independent cleanup before report ACK.
The [ARM64 emulation receipt](host-arm64-emulation-local-2026-09-21.json)
records AArch64 application startup and bundled cryptography execution under
QEMU, with exact artifact/loader hashes and isolated test-harness limitations.
The [credential material receipt](host-credential-material-local-2026-09-21.json)
records manifest, certificate-chain/key/usage and JWT validation, the immutable
material deadline, synchronous-block cancellation and the composed R3 path.
The five local suites passed **2564** tests with **5 expected opt-in skips**;
the main suite passed **1268** in 13m45s. Its separate ARM64 run executes 67
signing/authentication/material checks under QEMU. Neither receipt qualifies native ARM64 workloads or OCI deployment.

The [durable recovery receipt](host-recovery-local-2026-09-21.json) records
**2616 passing tests** across the five projects (main1320, five expected skips),
plus **111 focused checks** on the final source and **26 ARM64 inventory checks**
under QEMU. The full suites preceded the final ARM64 directory-open flag
correction; its x64 values are unchanged, and the corrected source passed the
focused x64 and emulated ARM64 checks. The ARM64 run caught and verified that
correction. A killed supervisor's actual child process was recovered without
NATS. This is local recovery qualification; production host startup and physical
execution/storage fencing remain blocked.

| Check | Result | Evidence/limit |
| --- | --- | --- |
| Native command cleanup | **78 runtime/recovery + one live systemd + two live containerd tests passed**, zero failures/skips; Release build and required style passed | [Receipt](host-command-cleanup-local-2026-09-21.json); four regressions failed on the old runners. Pre-cancelled calls do not dispatch; container output overflow cancels the process wait and joins both readers. Synthetic live workloads only; durable containment and writer fencing remain open |
| Systemd queued-job and process evidence | **61 adapter/recovery + 62 convergence/inventory + 22 lifecycle checks passed; one live systemd test passed**, zero failures/skips | [Receipt](systemd-queued-recovery-local-2026-09-21.json), source `1ad279446e`; nine regressions failed on the old adapter. Real inactive queued start cancelled before dependency release. Manager evidence does not establish command containment, cgroup emptiness or writer fencing |
| Live NATS startup diagnostics | **30 focused passed**, 0 failed/skipped; Release build and required style passed | [Receipt](nats-startup-diagnostics-local-2026-09-21.json); fixed failure-category counters are available while each server is alive, with bounded input buffering and no raw logs. Startup attempts/deadlines and production code are unchanged. CI startup cause remains unconfirmed |
| Encrypted infrastructure state publication PR #14 | **28 local tests passed**, nine mocked plans; **CI #37 passed** at `66625a482a` | [PR](https://git.terrascale.tech/TerraScale/ts-infra/pulls/14), sibling `ts-infra/docs/evidence/state-publication-local-2026-09-21.json`; refreshed disabled-estate OCI plan changes only outputs. Durable pre-apply reservation and atomic state/recovery publication tested against local Git remotes. PR remains unmerged; production publication and reviewed CI recovery are still gates |
| Orchestrator CI #519 at `78037327b4` | Four smaller suites passed; main suite still running at this update | `/tmp/ts-orchestrator-ci519-job-22093.log`; includes bounded startup diagnostics and the queued-systemd correction. No full main/artifact success recorded yet. Subsequent native command cleanup is a separate candidate |
| Orchestrator CI #516 at `5e490e0017` | Broker-startup failure observed; subsequently cancelled | `/tmp/ts-orchestrator-ci516-job-22058.log`; `CellDirectoryPublisherJwtIsEnforcedByAuthenticatedR3Servers` fails before its assertions while the R3 fixture connects. This repeats the unresolved startup failure class from CI514; scheduling qualification does not establish its cause |
| Shared local NATS fixture scheduling correction | **55 focused passed**, 0 failed/skipped; Release **0 warnings/errors**, required style passed | [Source and log receipt](nats-fixture-scheduling-local-2026-09-21.json); all identified shared fixture callers use one TUnit constraint or existing global exclusion, so deadlines begin after scheduling. Production source and operation deadlines are unchanged. Full CI rerun required; the separate CI514 broker-startup failure remains unconfirmed |
| Restricted durable host cycle/backoff | **2734 passed**, 0 failed, 5 expected skips across five suites; focused **144 passed** | [Source and log receipt](host-cycle-local-2026-09-21.json); main1438/control966/protocol165/model59/scheduler106; final main18m27s506ms, Release0warnings/errors and required style passed. Restricted R3 replay/restart/stall/role isolation and actual controller status; replacement lease, production startup and native fencing remain open |
| CI #514 at `0568af028b` | **Failed**: main1401 passed, 3 failed, 5 expected skips; four smaller suites passed | `/tmp/ts-orchestrator-ci514-job-22029.log`; two artifact tests expired while waiting for the shared fixture slot; one report-authorization test failed during broker startup. Main51m14s532ms; artifact job did not run. This is the previous artifact-publication revision, not the locally qualified cycle candidate; fixture scheduling/startup needs correction |
| Immutable artifact publisher and delivery regression | **65 passed**, 0 failed/skipped; Release **0 warnings/errors**, required style passed | [Source and log receipt](artifact-publication-local-2026-09-21.json); actual restricted JWT/mTLS R3 CLI, concurrent/repeated uploads, injected lost acknowledgements, member restart, SDK/cache interoperability, poisoned data, bounded snapshots and metadata conflicts. Focused qualification only; abandoned-digest reclamation and release-sized renewing-session delivery remain open |
| Restricted native artifact delivery | **2680 passed**, 0 failed, 5 expected skips across five suites; focused **109 passed** | [Source and log receipt](host-artifact-local-2026-09-21.json); main1384/control966/protocol165/model59/scheduler106; main16m05s527ms; Release0warnings/errors and required style passed. Real restricted R3 chunks and core convergence; backoff/replace remain controller-supplied test seams, and native ARM64 service execution is not established |
| CI #512 at `88dec4466a` | **2638 passed**, 0 failed, 5 expected skips; x64/ARM64 artifact job **passed** | Published orphan-recovery fixture correction and signed desired protocol, before the artifact-delivery change; `/tmp/ts-orchestrator-ci512-job-{22025,22026}.log` |
| Durable host ownership and recovery | **2616 passed**, 0 failed, 5 expected opt-in skips across five suites; final focused **111 passed**; ARM64 inventory **26 passed** | `/tmp/ts-host-recovery-{full-main,control,protocol,model,scheduler,abi-qualified,arm64-tests-corrected}.log`; main13m53s315ms; final Release0warnings/errors and required style passed; source chronology and native qualification limits in the receipt |
| CI #510 at `857e57de` | **2564 passed**, 0 failed, 5 expected skips; x64/ARM64 artifact job **passed** | Main1268/control966/protocol165/model59/scheduler106; `/tmp/ts-orchestrator-ci510-job-{22021,22022}.log`; main37m42s665ms; published credential-expiry checkpoint before the durable recovery batch |
| Tracked workload shutdown and complete regression | **2513 passed**, 0 failed, 5 expected opt-in skips across five suites | Main1217/control966/protocol165/model59/scheduler106; `/tmp/ts-host-shutdown-{full-main,control-tests,protocol-tests,model-tests,scheduler-tests}.log`; main13m45s021ms; Release0warnings/errors, required style passed; local inventory does not establish crash recovery or writer fencing |
| ARM64 application and bundled signing under QEMU | Offline application plan **passed**; **24 tests passed**, 0 failed/skipped | `/tmp/ts-host-shutdown-arm64-{plan.json,crypto-tests.log,loader.log}`; guest loaded the extracted bundled AArch64 libsodium; application publish had no warnings; isolated test harness retained IL3000/NETSDK1236 limitations; native ARM64 services remain unqualified |
| CI #508 at `52276b1e` | **2499 passed**, 0 failed, 5 expected skips; x64/ARM64 artifact job **passed** | Main1203/control966/protocol165/model59/scheduler106; `/tmp/ts-orchestrator-ci508-job-{22017,22018}.log`; lease checkpoint before tracked-shutdown integration; verification46m3s, artifact1m37s; native ARM64 workloads were not executed |
| Independent host execution lease and report regression | **60 passed**, 0 failed/skipped; control-plane **966 passed**; Release **0 warnings/errors**; required style passed | `/tmp/ts-host-lease-corrected-{targeted,build,style}.log`, `/tmp/ts-host-lease-control-tests.log`; prior 47-case convergence/authority/signer run also passed; see receipt for exact source chronology; no new full-main or ARM64 execution claim |
| Signed host transport and admission/readiness regression | **2482 passed**, 0 failed, 5 expected opt-in skips across all five suites | Main1186/control966/protocol165/model59/scheduler106; `/tmp/ts-signed-host-report-{full-main,control-final,protocol-tests,model-tests,scheduler-tests}.log`; main13m43s984ms; final source, Release0warnings/errors and required style passed |
| Real runtime, relay restart, retention correction and lease signer | **5 passed**, 0 failed/skipped | `/tmp/ts-signed-host-report-runtime-tests.log`; actual restricted JWT/mTLS host → controller relay → reader → authenticated operator status; independent current-session signing and retained ordering |
| CI #506 at `6c2b58f8` | **Failed**; artifact job skipped | Delivery namespace contract rejected `HostReportSession.Process`; renamed to `SessionId` in the signed-transport batch. Final local control-plane966 and all other suites now pass. `/tmp/ts-orchestrator-ci506-job-22011.log` |
| Previous signed-report readiness reader regression | **1180 passed**, 0 failed, 5 expected opt-in live-lane skips | `/tmp/ts-host-report-reader-full-main.log`; 12m19s909ms; final source; no running owned test containers remained |
| Reader, populated-store permission correction and actual runtime | **8 focused passed**, **2 actual R3 runtime tests passed**, 0 failed/skipped; **165 protocol passed**, build **0 warnings/errors**, required style passed | `/tmp/ts-host-report-reader-permissions-{tests,build,style,protocol}.log`, `/tmp/ts-host-report-reader-runtime-r3.log`; signed controller-written reports, revocation, stale report reads, strict storage, bounded read, and real operator query; publisher/relay was still unsigned in that batch |
| CI #505 at `d2fc8e94823ae7753e7cb48964bf2b029d0753bc` | **2471 passed**, 0 failed, 5 expected skips; x64/ARM64 artifact job passed | Main1175/control966/model59/protocol165/scheduler106; `/tmp/ts-orchestrator-ci505-job-{22009,22010}.log`; predates readiness-reader integration; ARM64 binaries were built, not executed |
| Final controller startup timeout correction | **51 focused passed**, **2 real R3 runtime tests passed**, 0 failed/skipped; build **0 warnings/errors**; CI style passed | `/tmp/ts-host-session-composition-timeout-{tests,r3,build,style}.log`; internal startup deadlines report failure while explicit caller cancellation retains shutdown semantics; final source |
| Full main regression with controller session composition | **1160 passed**, 0 failed, 5 expected live-lane skips | `/tmp/ts-host-session-composition-main-suite.log`; 12m03s304ms; before the final internal-timeout classification correction, whose checks are recorded separately |
| Controller policy, status/metrics and actual regional runtime | **49 focused passed**, **2 real R3 runtime tests passed**, 0 failed/skipped | `/tmp/ts-host-session-composition-tests2.log`, `/tmp/ts-host-session-runtime-r3-tests.log`; strict policy/permissions/key admission, real restricted host acquisition through `NatsRuntime`, authenticated operator query and runtime-attached acquisition metric |
| Controller composition Release, required style, protocol and CLI | **165 protocol passed**; build **0 warnings/errors**; CI style passed; expected CLI policy denial | `/tmp/ts-host-session-composition-final-build.log`, `/tmp/ts-host-session-composition-required-style.log`, `/tmp/ts-host-session-composition-protocol.log`, `/tmp/ts-host-session-composition-cli-policy.log`; actual CLI exits 1 before NATS on invalid policy |
| Full main regression with durable host sessions | **1140 passed**, 0 failed, 5 expected live-lane skips | `/tmp/ts-host-session-main-suite.log`; 12m04s708ms; final source for that batch, no NATS test servers remained; an infra-only pod from the aborted attempt was removed during subsequent controller qualification |
| Durable host session authority and authenticated broker | **57 passed**, 0 failed/skipped; final wall-clock broker test **1 passed** | `/tmp/ts-host-session-qualified-tests3.log`, `/tmp/ts-host-session-wall-clock-r3.log`; R3 races, lost response, epochs, restart, expired-grant continuation, revocation after actual stream-leader kill/restart, trust/scope/lease deadline, replay capacity, restricted JWT/mTLS and private-KV denial; before the subsequent controller composition |
| Session request PONG deadline | **1 passed**, 0 failed/skipped | `/tmp/ts-host-session-ping-deadline-test.log`; loopback server withholds PONG after handshake; explicit `WaitAsync` bounds the upstream NATS.Net 2.7.2 cancellation gap; original `/tmp/ts-host-session-authority-tests.log` was aborted, not green |
| Session authority Release/style and protocol | **165 passed**, 0 failed/skipped; build **0 warnings/errors**; style passed | `/tmp/ts-host-session-protocol-tests.log`, `/tmp/ts-host-session-final-build4.log`, `/tmp/ts-host-session-final-style2.log`; no new dependencies or new single-file packaging claims |
| Full main regression with signed scope and session request authentication | **1132 passed**, 0 failed, 5 expected live-lane skips | `/tmp/ts-host-request-main-suite.log`; 11m02s; real regional JWT/mTLS R3 startup and gateway regressions included; no owned test containers remained |
| Signed role/environment scope and NKey session request proof | **49 passed**, 0 failed/skipped | `/tmp/ts-host-request-tests2.log`; scope tampering, pre-connection execution mismatch, RFC 8032, actual seed/JWT signing, noncanonical/small-order rejection, replaced-key denial, routing/freshness/wire bounds; no remote session authority |
| Same focused checks from an isolated single-file test executable | **49 passed**, 0 failed/skipped | `/tmp/ts-host-proof-bundle-tests.log`, `/tmp/ts-host-proof-bundle-receipt.json`, `/tmp/ts-host-proof-bundle-loader.log`; loader used the bundled libsodium; test-harness publish emitted NETSDK1236 for its runtimeconfig/coverage configuration |
| Host request dependency, Release/style and protocol checks | **165 protocol tests passed**, 0 failed/skipped; solution build **0 warnings/errors**; locked restore/style/audit passed | `/tmp/ts-host-request-protocol-tests.log`, `/tmp/ts-host-request-final-build.log`, `/tmp/ts-host-request-final-style.log`, `/tmp/ts-host-request-locked-restore.log`, `/tmp/ts-host-proof-audit.log`; NSec 26.4.0 and libsodium 1.0.22 locked |
| Application publish with host request crypto | **x64/ARM64 passed**, no publish warnings; offline x64 runtime plan passed | `/tmp/ts-host-request-publish-{x64,arm64}.log`, `/tmp/ts-host-proof-app-receipt.json`; ELF architectures and exact embedded libsodium bytes checked; ARM64 was not executed |
| Regional JWT, configuration, admission, OCI node allocation, R3 grants and host convergence | **113 passed**, 0 failed/skipped | `/tmp/ts-regional-jwt-qualified-tests.log`; actual controller startup against restricted JWT/mTLS R3; before the operator CLI addition |
| Full main regression with regional JWT and operator CLI | **1106 passed, 2 failed, 5 live-lane skips** | `/tmp/ts-regional-jwt-main-suite.log`; 13m07s; actual regional startup and CLI passed; failures were the duplicated source-subject literals and immediate directory freshness assertion after gateway reconnection; correction evidence recorded separately |
| Corrections after the regional JWT main run | **8 passed**, 0 failed/skipped | `/tmp/ts-regional-jwt-corrections-tests.log`; canonical subject source checks plus real gateway heal requiring a fresh advertisement, advancing sequence and unchanged epoch; 42.7s; publisher cleanup also runs on assertion failure |
| Final regional JWT protocol, Release and style | **165 passed**, 0 failed/skipped; build **0 warnings/errors**; style passed | `/tmp/ts-regional-jwt-final-protocol-tests.log`, `/tmp/ts-regional-jwt-corrections-build.log`, `/tmp/ts-regional-jwt-corrections-style.log`; includes explicit shared read-only query cases and mutation-owner invariants; no owned test containers remained |
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
| Full orchestrator main suite with report relay | **1074 passed, 0 failed, 5 live-lane skips** | `/tmp/ts-host-report-main-suite.log`; compiled revision `f29b19ae`, 10m56s; before the subsequent replacement-lease correction |
| Replacement lease restart/release races | **28 host tests passed**, 0 failed/skipped; Release build 0 warnings/errors; style passed | `/tmp/ts-lease-fixed-host-tests.log`, `/tmp/ts-lease-fixed-build.log`, `/tmp/ts-lease-fixed-style.log`; both new real-NATS regressions first failed against the old implementation with deletion of the newer lease (`/tmp/ts-lease-regression-red.log`) |
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
| Live Firecracker VM qualification, including ts-auth with local gateway stand-in | **3 passed, 0 failed** | `/tmp/ts-goal-orchestrator-vm-all-live-20260921.log`; single-region boot/heal/drain, auth hard-restart/duplicate/drain, and GRU/SFO/FRA loss/replacement; local gateway stand-in only for auth |
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

Read-only OCI CLI 3.82.0 queries confirm READY subscriptions. The local API-key
authentication check was repeated on 2026-09-21; see the
[region subscription receipt](oci-region-subscriptions-local-2026-09-21.json).
This does not qualify a guest Instance Principal or permission to mutate resources.

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
(controller compartment binding) and `4c237a9` (Vault tier) are published in
[ts-infra PR #13](https://git.terrascale.tech/TerraScale/ts-infra/pulls/13) under
the user's explicit pull-request authorization. The PR remains separate from
deployment enablement; no apply or state edit was performed.

## Authentication required before deployment

- **OCI controller:** Instance Principal. The dynamic group must match only
  controller instances; workload hosts need separately scoped permissions.
  Workstation API keys must not be installed on controllers. Prove allowed
  operations and denial outside the owned compartments/resources from OCI.
- **Regional NATS:** distinct controller, operator, infrastructure journal
  provisioner, journal writer, and host identities, with private NKey/JWT and
  mTLS material and exact regional subject permissions. Regional runtime and
  operator CLI now accept JWT credentials, bind the JWT to its actual user
  seed, and reject reused regional/global identities. The actual regional
  startup has passed against restricted JWT/mTLS R3 NATS using the shared
  runtime permission plan. First-boot issuance and rotation remain open; see
  [regional-nats-authentication.md](../operations/regional-nats-authentication.md).
  Separate Unix users on a VM share its Instance Principal. The controller
  principal must be denied the journal writer key, including self-granted
  access; first boot still needs an enforceable OCI identity boundary for
  the writer. Separate credential directories alone do not establish it.
- **Command and enrollment trust:** pinned signing keys, grant audience,
  certificate/node/region binding, fixed system project, and durable replay
  records. Version-2 node enrollment now signs and enforces the exact workload
  roles and environment. Session request proofs bind the enrolled user key to
  that document, process session, operation, nonce, epoch and timestamp;
  the controller session authority separately checks enrollment trust and
  durable replay state. Its 30-second leases support process restart and
  renewal without reauthorizing expired bootstrap operations. The independent
  host execution lease now renews remotely and triggers stop/observation of
  tracked local workloads. The obsolete cached one-use admission gate has been removed; host material
  validation does not access controller replay stores. Controller startup rejects mixed host roles; the dedicated
  host entry and physical execution fencing remain open. Local durable ownership
  and recovery now have component coverage. The new material
  validator binds protected credential files to signed enrollment, checks
  certificate chain/key/usage and JWT validity, and supplies a fixed expiry to
  the lease. A separate monotonic material deadline cannot be renewed, even
  with frozen UTC. The restricted R3 test composes this validator; production
  host startup, immutable credential delivery and rotation are still required.
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
   fixed region. Desired selection now has a signed restricted-host protocol and
   core-convergence caller coverage. Native artifact retrieval now has a separate
   signed protocol, bounded cache and core-convergence coverage. Durable cycle/backoff
   now has its own signed protocol and controller-owned non-expiring state.
   Regional replacement leases still need a restricted protocol, expiry/watchdog
   handling and exact quiescence evidence. Session enrollment exists; its dedicated
   host startup composition remains incomplete.
   The report tests inject separate controller store handles and are not proof
   of a complete host runtime under host credentials. The controller report
   relay now requires signed session-bound ingress and atomic persistence.
   Generic OCI/operator serving readiness also pairs current admission with
   runtime evidence, so a withdrawal invalidates an older converged report.
   Independent renewal, durable ownership, native discovery, restart recovery
   and workload shutdown now have component and core-convergence coverage.
   They do not yet compose the production restricted host runtime, external
   command cgroup quiescence or physical writer fencing. Controller run/check
   rejects mixed host roles.
   The controller instance-name parser rejects full OCI node IDs, while admission and fleet
   reporting require that exact identity. Host allocation names now use a
   stable cell/node/artifact hash and preserve full OCIDs in report bodies;
   a real NATS convergence/upgrade test covers this component. Finish the
   dedicated host entry point without widening the controller/subject grammar.
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

Task **500**, revision `4ebda9caec`, passed both jobs. All five test projects
passed: control plane **966**, model **59**, protocol **165**, scheduler **106**,
and main **1076**, with **5 live-lane skips** (**2372 passed** total). The job
retained the source receipt and checksums in its logs. The artifact job verified
both x64 and ARM64 single-file binaries and their source-bound SHA-256 digests.
This confirms the CI fallback works; it does not provide durable binary/HTML
artifact storage or OCI deployment evidence. Logs:
`/tmp/ts-orchestrator-ci500-job-21999.log` and
`/tmp/ts-orchestrator-ci500-job-22000.log`.

Task **502**, revision `7923e82bf1`, also passed both jobs. All five test
projects passed: control plane **966**, model **59**, protocol **165**,
scheduler **106**, and main **1132**, with **5 expected live-lane skips**
(**2428 passed** total). The artifact job verified both single-file ELF
architectures and source-bound hashes: x64
`874f59a7328b7ffdb2082b0a1e31f3bfbbc0cab1d32fdc464b9be258a284ec2f`, ARM64
`bff3ad20b7555fe608b940bea3b0fd406bd0053b95cfd5014a19b52612d46dee`.
Logs: `/tmp/ts-orchestrator-ci502-job-22003.log` and
`/tmp/ts-orchestrator-ci502-job-22004.log`. These checks cover the published
request-authentication batch, before the durable session authority/service.
The same artifact-retention and ARM64 execution limits still apply.

Task **511**, revision `b3b9133998`, failed one recovery-process fixture:
control plane **966**, model **59**, protocol **165**, scheduler **106**, and
main **1,319** passed; main had **1 failure and 5 expected skips**. The artifact
job was skipped. The stopped orphan was retained as a zombie by the runner's
PID 1, causing the fixture's non-child `WaitForExitAsync` to time out. This was
reproduced in a local private PID namespace. The test-only correction uses
kernel state and stable start identity for the single-threaded orphan while
preserving full supervisor exit/lock-release waiting. Its separate
[receipt](host-recovery-orphan-local-2026-09-21.json) records final qualification;
the failed CI result remains failed and requires a new run. Full log:
`/tmp/ts-orchestrator-ci511-job-22023.log`.

Task **512**, revision `88dec4466a`, passed both jobs: **2,638 tests passed**
(main **1,342**, control plane **966**, model **59**, protocol **165**,
scheduler **106**), with **5 expected live-lane skips**. Verification took
**51m1s**; the x64/ARM64 single-file artifact job passed in **1m39s**. This
confirms the published orphan-recovery fixture correction and signed desired
protocol in CI. It precedes the restricted artifact-delivery change and does
not prove native ARM64 service execution. Logs:
`/tmp/ts-orchestrator-ci512-job-22025.log` and
`/tmp/ts-orchestrator-ci512-job-22026.log`.

## First live OCI qualification, after local readiness

Start with disposable GRU staging. Prove Instance Principal allow/deny behavior,
private connectivity, Vault access/denial, seed handoff, fresh node joining,
automatic task pickup, lost-create response recovery, controller restart, drain,
backup/restore and complete cleanup. Run auth security and tenant-isolation
probes over real TerraBase. Do not enable customer traffic or form SFO/FRA
clusters until the GRU receipt is reviewed. Live OCI checks cannot be marked
passed by mocked plans, transport tests, or local VM tests.
