# Production operation and dependency inventory

This is the PR-01 implementation inventory required by [GOAL.md](../../../GOAL.md#ts-orchestrator).
It records entry points and the proof each operation still needs. A package,
constructor, or passing unit test does not establish an executable production
path. PR-01 remains open while published contracts, operational limits, or
required mappings below are missing.

Paths below are relative to the repository root. Test paths identify tests to
inspect and run, not passing results for this document. Retained evidence is
listed separately so source coverage cannot be mistaken for qualification.

## Authority and persistence shared by operations

GRU owns accepted global desired state, Region admission, cross-Region policy,
and release ordering. Regional controllers execute admitted regional work.
Each member host must have a local orchestrator, with `ts-node` as the only
runtime file/systemd mutator. TerraBase decides membership acceptance, catch-up,
RF=2 and permission to serve. NATS storage leadership does not confer master
authority.

Each mutation needs an operation ID, desired revision, Region/host scope,
fencing epoch and live lease identity. Before an external effect, reread the
required authority and ownership; after an uncertain result, observe actual
state before retrying the same operation. A caller-side lease check alone
cannot prove fencing at a remote provider or engine boundary. An unavailable
journal or stale authority stops new mutations. Existing admitted customer
service must continue under TerraBase's consistency contract.

| Record or dependency | Current contract and owner | Recovery or unresolved obligation |
| --- | --- | --- |
| Global desired state, leases, Region directory, delivery fanout | `GLOBAL_SPEC`, `KV_ORCH_LEADERS`, `KV_GLOBAL_CELLS`, `KV_GLOBAL_DELIVERIES`; [global storage](global-control-storage.md) | Permanent R3 in GRU/SFO/FRA; only pre-customer bootstrap permits R1. Operational rotation/reaper/restore records share the authority stream and require quorum/CAS barriers. |
| Regional desired state, operations, membership and observations | `src/orchestrator/protocol/durable_work_inventory.go`, [durable work](durable-work-inventory.md), [membership](controller-membership.md) | The durable-work contract distinguishes required shared global R3 placement from the existing separate regional/global profiles. The per-Region stream/bucket/consumer isolation, naming, permissions and production reader mapping onto that R3 remain unwired and unqualified; do not infer a regional quorum from host count. |
| Provider intent, ownership and receipts | `src/orchestrator/provider/durable_journal.go`, `nats_ownership.go`, `ownership.go` | Provision durable journal and exact Region/compartment/bucket scopes. Readback must distinguish absent, pending, failed and unknown; an ownership tag alone is insufficient deletion authority. |
| Host commands and installed versions | `src/orchestrator/hostagent`, `hostmanifest`, `initialgrant`, `nodeauthority`; [initial R1](initial-gru-r1.md) | Persist signed admission before effects; reconcile pending commands on restart; retire bootstrap grants durably; restore exact prior binary and launch configuration on rollback. |
| Rotation, Free lifecycle, restore state | [rotation state](rotation-state.md), [reaper authority](reaper-state-authority.md), `src/orchestrator/restoredrill/nats_journal.go` | Root binds candidate, epoch and LeaseID after global election. Reaper checkpoint sharding/retention is still required. Concrete effect adapters and their durable receipts remain incomplete. |
| Published estate and telemetry | Public control-plane database API; Workers KV; Grafana agent/Cloud | `estate.*` documents belong to the database, usage facts to TerraBase, collected telemetry to Grafana. None becomes authoritative control state merely by being published. |

## Operation map

`run` below means the executable command in `cmd/orchestrator/main.go`.
Its production path calls `admitProductionRuntime` in
`cmd/orchestrator/runtime_composition.go`, whose default unconditionally returns
`ErrProductionCompositionMissing`. Rows reached through that composition are
blocked in the executable even where their domain/adapters have tests.

| ID and required operation | Entry point, controller and adapters | Durable intent, authority and recovery | Failure coverage and missing proof |
| --- | --- | --- | --- |
| OP-01 Empty-tenancy GRU bootstrap and credential handoff | `bootstrap`; `cmd/orchestrator/bootstrap_cmd.go`; `bootstrap/greenfield.go`, `provider_control_plane.go`, OCI adapters and cloud-init/ts-node | Owner API key creates IAM, network, storage and two failure-domain hosts; signed finite grants seed R1 and local identities; journal handoff and key retirement | `cmd/orchestrator/bootstrap_cmd_test.go`, bootstrap package tests. Real empty-tenancy bootstrap, installed same-host processes, engine admission and key retirement together are unverified. |
| OP-02 Initial GRU broker and second local controller | `initial-gru-r1 --config FILE`; `cmd/orchestrator/main.go`, `src/orchestrator/initialcontrolcli`, `src/orchestrator/initialcontrol`, embedded NATS | Signed root-owned admission; provision regional/global profiles; separate peer identity without broker/provisioning/global credentials; expiry and retirement stop mutations | `cmd/orchestrator/initial_r1_test.go`, `bootstrap_control_seed_test.go`; first-guest process startup evidence exists, but full authority and engine readiness do not. |
| OP-03 Add SFO/FRA, synchronize and promote R1 to R3 | `add-region`; `cmd/orchestrator/add_region.go`, bootstrap control runtime | GRU authority and journaled transition; preserve records/checkpoints and accepted epoch; prove exact stream and consumer replicas, post-transition snapshot, then retire bootstrap authority | Bootstrap NATS mutation/transition tests; [snapshot experiment](../evidence/nats-snapshot-promotion-audit-2026-09-05.md). Signed successor preparation, authority-source cutover and all-host retirement remain unintegrated; [snapshot transition design](control-snapshot-transition.md) specifies the required phases, without claiming executable completion. |
| OP-04 Admit later Regions and their local orchestrators | `add-region`; admitted typed `estate.Spec`, regional dispatch and host install | GRU admits Region and host identities; two hosts minimum; Regions 4–20 use global R3 without becoming replicas or masters | `cmd/orchestrator/add_region_test.go`; actual later-Region engine contract and guest lifecycle unproven. No remote-only substitute satisfies same-machine management. |
| OP-05 Global election, regional lease and restart/takeover | `run`; control authority/membership, `runtime_global_session.go`, globalclient | Signed pinned identities; quorum-read candidate/epoch/LeaseID; cancel and join workers before successor; reject stale, duplicate/conflicting lineage | `runtime_global_session_test.go`, `runtime_global_cluster_test.go`, authority tests; isolated tests do not prove every provider/TBEP mutation is fenced. |
| OP-06 Observe/dry-run/apply estate and repair drift | `reconcile` and `cmd/orchestrator/reconcile_supervision.go`; reconcile, ocireconcile, provider, cloudflare | Accepted estate revision and scoped lease; deterministic dependency plan, provider journal and idempotency; unknown effect requires observation; foreign resources survive | `reconcile/loop_test.go`, provider/ocireconcile/cloudflare tests. Need executable supervision and real OCI/Cloudflare pagination, throttling, work-request and lost-reply qualification. |
| OP-07 Install/activate/restart/rollback host services | `cmd/ts-node/main.go`; hostagent, hostmanifest, runtime/systemd adapter; authenticated hostcontrol | Host-bound signed command, durable command receipts, staged verified slots, atomic current link and immutable arguments/configuration; ts-node bootstrap self-service rules | Hostagent and command tests plus failed guest records. Need independent service restarts, reboot recovery, actual TerraBase catch-up, security-update reboot and exact rollback on every touched host. |
| OP-08 Create/admit/scale out TerraBase members | Intended regional `run` lifecycle; scheduling, provider/create_node.go, same-host TBEP | GRU placement/residency intent and regional/host authority; provision both services, admit identity, obtain engine catch-up and RF=2 evidence before traffic | Scheduling tests and TBEP observation tests exist. No complete production mutation adapter/entry path to engine admission is established. |
| OP-09 Drain/scale in/safe removal | Intended regional lifecycle/CLI; scheduling, residency, hostcontrol and engine lifecycle | Fresh member and placement records; drain and RF=2 proof; at least two hosts per Region; journal unknown outcomes before deleting resources | Policy tests exist. Concrete CLI-to-TBEP mutation/status contract and guest failure-during-drain proof are missing. |
| OP-10 Host/Region loss, replacement and rejoin | Intended regional repair under `run`; OCI compute/volume, host install, TBEP | Re-observe ownership and surviving copies; replacement installs local orchestrator and TerraBase; regain RF=2 before routing; no ambiguous last-copy removal | Provider and scheduling tests; full joint-host-loss, Region-loss/rejoin and stale-controller execution remain unqualified. |
| OP-11 A1 shortage, disk repair and clock repair | `reconcile`, ts-node observations, provider and observability/clock | Declared A1→E5 fallback; journal expansion/replacement; drain bad disk, preserve proven copy; engine must enforce 500 ms write fence | Provider/volume and `observability/clock_test.go`; tests of policy or host clock observation do not establish actual engine write fencing or recovery. |
| OP-12 Receive signed candidate, mirror and dispatch | `run`; global `ts.orch.v1.global.release.delivery`; delivery/master_preparation.go, provider/delivery_region_store.go | `GLOBAL_DELIVERIES` retains original envelope/signature and deterministic children; global plus regional lease checks; verify every Region mirror before rollout; resume lineage after lost reply | Delivery tests and `runtime_delivery_composition_test.go`; [master delivery](master-delivery.md). Root must supply registry fetcher, trust/signers, routes, scoped stores and ownership callbacks. |
| OP-13 TerraBase/orchestrator rolling upgrade and rollback | Regional delivery runtime; delivery/rollout.go, hostcontrol and engine gates | Durable per-host prior digest and receipt; GRU canary then one host at a time; preserve RF=2; rollback every touched host on failed gate; restart never revives old authority | Rollout tests; real six-host upgrade, lost-master recovery, catch-up and per-Region rollback missing. Supported mixed-version window is undeclared. |
| OP-14 Worker/Snippet release and edge configuration | Delivery edge adapters, cloudflare; estate reconciliation for DNS, Cache Rules, tiered cache, routes, WAF/rate rules, KV | Shared-zone authority, signed candidate and provider-ID/version receipts; health-gated promotion and exact prior version restore; uncertain update needs readback | Cloudflare HTTP/rollout tests. Real Pro/Workers Paid behavior, propagation, concurrent rule updates and rollback remain unqualified. |
| OP-15 Identity/certificate/capability rotation and revocation | Global `run` workers; keyrotation.NewProduction, security coordinator | Lease-bound rotation checkpoint; staged trust, provider IDs and consumer-generation receipts; overlap before old material retirement; resumable rollback | Keyrotation R3/CAS tests; concrete issuer, vault, member distribution/reloader and complete Secrets Store activation/verification are missing. See [Cloudflare effects](cloudflare-rotation-effects.md). |
| OP-16 Backup, restore, export and branch lifecycle | Intended regional engine lifecycle; residency/operations.go; global restoredrill composition | Placement/residency records and DEK/KEK references; engine owns backup correctness; scratch branch stays within residency; checksum/row-count facts and owned cleanup receipts | Residency and restoredrill tests; executable production backup/branch/restore/export mutation/status adapters and authoritative facts producer missing. |
| OP-17 Daily database restore drill and durability page | Global `run`; `cmd/orchestrator/restore_drill.go`, restoredrill scheduler/production adapters | Global fenced run/item journal; enumerate real eligible databases including control-plane database; sample, restore scratch, verify facts, delete and acknowledge page on failure | Restoredrill scheduler and NATS journal tests; concrete backup/branch/catalog/facts/pager ports and 14 consecutive production daily drills missing. |
| OP-18 Snapshot/restore full control state and master recovery | Global restoredrill snapshotter, restoresnapshot, bootstrap control runtime | Daily signed snapshots mirrored to every Region; verify bytes and complete inventory; no accepted epoch regression; journal restore and ownership | Snapshot/provider tests and pinned snapshot experiment; executable disaster recovery, post-promotion snapshot and measured acknowledged-state loss/RTO unproven. |
| OP-19 Publish member health, capacity and placement to ts-proxy | Regional observations plus global edge publication; cloudflare, memberobserve, tbep | Fresh exact Worker KV consumer schema; health before placement; delete stale keys; host liveness cannot grant readiness; retained accepted placement remains residency-bound | Cloudflare/publication and TBEP tests; actual engine-gated publication, high-load redistribution, probation and stale-map guest scenarios missing. |
| OP-20 Publish estate, metrics/logs, SLO and cost observations | Global `run`; estatepublisher.NewProduction/public database client; observability and Grafana agent | Coherent authority-bound snapshot, ordinary scoped database credential; bounded dimensions/redaction; external probes own availability facts; only SLO burn and failed restore page | Estatepublisher/observability tests; concrete snapshot source, endpoint/credential, effect fencing, live probes and acknowledged paging missing. |
| OP-21 Free pause/reactivate/reap and key destruction | Global `run`; reaper.NewProduction | Fenced state, current product eligibility/notices and authoritative activity; 30-day pause, request reactivation, eligible 90-day deletion; never reap paid data; explicit owner authority for ambiguous data loss | Reaper policy/R3 tests; actual database/key/mail adapters, product eligibility contract, checkpoint scaling and transport-boundary authority missing. |
| OP-22 Qualify real composition and clean owned test resources | `make check`, `make vm-doctor`, `make vm-smoke`, `make vm-test`; cmd/vm-qualify and vmqual packages | Persist resource cleanup journal before effects; exact artifacts, config/contract pins, faults, receipts and raw measurements; preserve first failure when diagnostics/cleanup fail | VM suite source and retained failed runs exist. Complete six-guest suite, workload-through-outage results, idle budget and all required scenarios remain unproven. |

## External contracts and dependency admission

| Dependency | Existing pin or contract | Admission and unresolved evidence |
| --- | --- | --- |
| TerraBase private TBEP and launch configuration | `src/orchestrator/tbep/CONTRACT_VERSION` is `terrabase-v1`; producer contract source is pinned to commit `0fd27ca01685f60c46384f95e320beb9256d10aa`; [provenance](../../src/orchestrator/tbep/README.md) records both protobuf digests | This pins the published terrabase v1 contract snapshot. Observation exposes SupervisionHealth, TopologyRead and AdminStatus, not lifecycle mutations. Require production configuration schema, lifecycle operation/status/errors, durable membership source and producer/consumer drift checks. |
| ts-deploy candidate and signed artifact | `src/orchestrator/delivery/contract.go`, Request/Receipt v1, golden JSON in delivery/testdata; [master delegation](master-delivery.md) | Local copied schemas/goldens do not establish a published cross-repository release pin. Bind exact ts-deploy artifact/protocol provenance and verify submission through the real ingress. Detached ed25519 signature authenticates binary bytes; signed host manifest must separately bind launch configuration. |
| OCI | Go provider HTTP adapters, instance principals, typed estate, provider mutation journal | Require tenancy/home Region, compartments, credentials/scopes, namespace/buckets, Vault/certificate access and ownership admission. Real API behavior, A1 capacity, E5 fallback, quotas, prices and terms need G1/G4 review and real-provider qualification. |
| Cloudflare/ts-proxy | cloudflare package; [Secrets Store contract](cloudflare-rotation-effects.md); typed edge estate | Require scoped account/zone tokens and exact consumer KV/Worker/Snippet contracts. Secrets Store CRUD does not provide atomic current/previous activation. Reverify Pro plus Workers Paid limits and supported features. |
| Public control-plane database and product lifecycle facts | estate.ControlPlaneClient, estatepublisher.SnapshotSource, reaper database/mail ports | Require public endpoint/scoped credential, schema/version and coherent estate source; product supplies notices/eligibility, TerraBase supplies activity/usage truth. Missing producers cannot be replaced with empty snapshots or invented eligibility. |
| Identity, secrets and signing | SPIFFE TLS 1.3, persistent membership pins, P-256 command signatures, NATS NKeys, release trust and finite bootstrap grant | Admit bounded credential references before listeners; concrete issue/fetch/retire/distribute/reload providers and propagation proof are unfinished. NATS may persist validated BYOK provider references and wrapped ciphertext. Credentials, plaintext key material, and other secret material remain prohibited in declarations, arguments, NATS, metrics, fixtures, and audit output. |
| Grafana and external probe/pager | observability export/SLO packages and restore PagerPort | Require actual per-host agent deployment, destination credential references, probe region mapping and acknowledged notification adapters. Local metric formatting is insufficient. |
| Host OS and qualification artifacts | Hardened systemd, cgroup v2, chrony, Firecracker/jailer/kernel/root disk pins | Ubuntu LTS minimal and signed linux/amd64 + linux/arm64 releases. Full VM qualification must run intended immutable artifacts, retain all pins and prove cleanup. Native amd64 results do not qualify A1/arm64. |

## Declared limits and missing decisions

| Limit | Current declaration | Acceptance gap |
| --- | --- | --- |
| Launch topology/capacity | GRU/SFO/FRA; two A1 hosts each, 2 OCPU/12 GiB, E5 fallback; support 20 Regions; permanent global R3 | Prove same-host management, exact replica placement and failure-domain separation. Sustained scaling thresholds, hysteresis, cooldowns and per-estate max capacity must be admitted typed configuration. |
| Global storage | 1,352 MiB limits per replica, 4,056 MiB aggregate before overhead; initial combined R1 profile 3,952.25 MiB | Storage limits are not RSS/allocation measurements. Full regional/global journal retention and overflow safety must match final topology and required recovery history. |
| Durable transport | Inventory declares 2-minute duplicate window, 5 deliveries, 1/5/15/30-second backoff and bounded pull/pending settings | Operation idempotency must survive the transport window. The incomplete regional storage mapping above must be resolved; terminal evidence and exhaustion cannot silently lose accepted work. |
| Provider retries | reconcile.Config exposes attempt/backoff/interval; OCI work-request validation bounds polls to 1–10,000 and interval to at most one minute | These API validation bounds are not a declared production reconciliation deadline. Pin per-operation retry/deadline/re-observation budgets and prove timeout-after-accept behavior. |
| TBEP observation | Positive deadline at most one minute, covering all three RPCs | Lifecycle deadlines/status polling, unknown-outcome recovery and contract version skew remain unspecified. |
| Delivery | Request/receipt 1 MiB, artifact 512 MiB; master intent 256 KiB/envelope 512 KiB; green-to-serving target <15 minutes TerraBase, <5 minutes Workers | Enforce tighter nested envelope limits before effects; qualify end-to-end times and rollback duration. Mixed-version compatibility and maximum skew duration remain undeclared. |
| Publication and telemetry | Health KV every 10 seconds/on transition; placement on change; estate on change/at least 10 seconds; 100 log lines/s/host sampling, 14-day retention; no tenant/database/view metric labels | Bound coherent snapshot size, batching, backlog and stale evidence age in final production adapters; prove correct deletes and correctness writes despite KV budget warnings. |
| Rotation and Free lifecycle | Capability rotation 24 hours plus one expiry-bucket overlap; root rotation loop 1 minute/15-minute lead; reaper loop 24 hours, pause day 30/delete eligible day 90 | Declare concrete propagation/expiry safety and retry bounds; prove consumer generations and eligibility races before destructive effects. |
| Data/control recovery | Daily restore drills and daily control snapshots; accepted epoch cannot regress | Control RPO/RTO, regional recovery targets, acknowledged-state loss limits, restore deadlines and destructive-recovery owner procedure are missing. Daily cadence alone does not specify RPO or RTO. |
| Availability and warnings | 99.9% monthly API availability per Region; egress warning at 8 TiB/Region/month pace; 500 ms clock write fence | Live probe/paging and engine enforcement evidence required. Cause alerts cannot become general pages. |
| VM resources | Six baseline guests, 512 MiB configured memory each; aggregate idle host RSS <=4 GiB and average CPU <=1 core | Declare warm-up/sample interval and include every required worker/helper. Record peaks separately. Current startup failures provide no steady-state budget proof. |
| Release qualification | make check then full make vm-test on every develop push; 7-day exact-digest soak, per-Region rollback, 14 daily restore successes, no critical security findings and owner sign-off | ts-deploy CI enforcement and all G2/G3/G4 real-provider/launch records must be inspected; neither this inventory nor local tests closes those gates. |

## Evidence binding

[Production readiness](../guides/production-readiness.md) and
[qualification status](../guides/qualification-status.md) retain the broader
history. Current evidence relevant to this inventory includes:

- [Receiver VM run](../evidence/vm-test-receiver-authority-2026-09-05.json)
  and [human report](../evidence/vm-test-receiver-authority-2026-09-05.txt)
  observed ts-node and orchestrator processes, but TerraBase startup failed.
  They do not prove guest authority, six-host readiness or any workload scenario.
- [Integrated receiver checks](../evidence/receiver-promotion-gates-2026-09-05.txt)
  report portable/tagged and isolated receiver results, not live R3 promotion.
- [Snapshot promotion audit](../evidence/nats-snapshot-promotion-audit-2026-09-05.md)
  records public snapshot/restore behavior and metadata limits; direct retained
  standalone-store restart did not establish clustered streams.
- [TerraBase configuration audit](../evidence/terrabase-production-config-audit-2026-09-05.md)
  and [contract audit](../evidence/terrabase-contract-audit-2026-09-05.txt)
  identify missing production launch/membership contracts. Worktree inspection
  does not attest a published binary's schema.

Every OP ID needs a future immutable evidence record identifying source and
artifact digests, contract/configuration pins, exact executable command,
authority/operation receipts, injected failure, expected/observed result,
deadline, recovery measurement and cleanup outcome. For rows without that
record, qualification is missing. Passing a narrower row never qualifies an
unexecuted dependency or a different release candidate.
