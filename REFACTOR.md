# OCI-native orchestrator: A1-first capacity and mixed Wasm, ARM, and x86

Start with a disposable OCI regional prototype on A1 Flex: automatic cluster
formation, one containerd executor, and a healthy rolling container deployment.
Prove ARM/x86 placement and OCI host replacement before migrating production
workloads. Qualify customer Wasm on that same capacity model.

## Status and decisions

Planning revision, 2026-10-16. Code baseline: `5fbe42a8`; original plan: `7a65ad45`.
This document records the reviewed direction; it does not claim an implemented
runtime, measured savings, production readiness, or deployment authorization.

| Decision | Direction |
| --- | --- |
| Infrastructure owner | `ts-orch` reconciles the platform's complete OCI lifecycle through the existing Go SDK clients. |
| Capacity | Prefer `VM.Standard.A1.Flex`; qualify other ARM families and x86 without changing workload identity. |
| Control plane | Keep `ts-orch` in Go; qualify embedded upstream SwarmKit before committing to migration. |
| First-party workloads | OCI containers through containerd and runc; no Docker Engine. |
| Customer workloads | Short-lived Wasm functions on isolated worker hosts. |
| Mixed execution | Native `linux/arm64`, native `linux/amd64`, and portable Wasm coexist in each region as demand requires. |
| Security and joining | Substantially simplify custom protocols; automatic discovery and worker admission using OCI identity and Vault-delivered bootstrap material. |
| First regional milestone | A small, working GRU / San Francisco Bay Area / FRA deployment, communicating through orchestrator-managed NetBird. |
| NetBird control plane | One dedicated A1 Flex VM in GRU, owned and recovered by `ts-orch`. |
| Build and release provider | GitHub-hosted Actions, GitHub artifacts/releases, and GitHub source/run verification; no Forgejo server, runner, token, CLI, or package-fetch requirement. |

Wasmtime is the proposed first function runtime, subject to the compatibility
prototype below. The user selected customer Wasm, not a particular WASI version
or runtime implementation. Do not present Wasmtime or WASI Components as an
already qualified dependency. Use wazero instead if the actual function contract
fits its supported interfaces and its simpler Go integration wins the comparison.

OCI-native means OCI Compute, networking, storage, IAM, Vault, and registry APIs
are the infrastructure primitives, with `ts-orch` owning their reconciliation.
It does not require OKE, Kubernetes, Docker Engine, or a second infrastructure
controller. Keep embedded regional NATS for orchestrator communication.

This decision scopes the orchestrator-managed platform; it does not move other
TerraScale services off Fly or Cloudflare. Keep the existing external service
hosting boundaries. No new paid capacity, IAM permission, credential, or secret
installation is authorized by this planning document.

## Review verdict and required corrections

The original direction makes sense as a compatibility spike, not yet as a
production migration commitment. Preserve its rollout, isolation, and database
safety requirements. Close these gaps before implementing the replacement:

1. **Complete OCI ownership.** Existing resource reconcilers manage selected
   rules and backends; creating infrastructure once is not continuous lifecycle
   management. Join provisioning, repair, upgrades, backups, and safe retirement.
2. **Remove the A1-only model.** Pool recipes, regional validation, bootstrap,
   and cost estimation contain A1/ARM assumptions. An x86 container cannot run
   on an ARM host just because both hosts joined the same scheduler.
3. **Qualify SwarmKit's value.** It adds regional Raft beside NATS/JetStream and
   still needs a containerd executor, OCI capacity controller, and routing.
   Compare the adapter's total maintenance against the existing control path.
4. **Close bootstrap and identity gaps.** NetBird admission must lead to serving
   automatically, while OCI permissions come from verified host identity.
   Workers cannot create a new regional cluster after an empty discovery result.
5. **Make migrations explicit.** A newer ARM family, ARM-to-x86 move, database
   relocation, and Wasm recompilation have different compatibility requirements.

## First desired state: three regions that actually communicate

| Display location | OCI region | Existing product token |
| --- | --- | --- |
| GRU / São Paulo | `sa-saopaulo-1` | `gru` |
| San Francisco Bay Area (OCI San Jose) | `us-sanjose-1` | `sfo` |
| FRA / Frankfurt | `eu-frankfurt-1` | `fra` |

Keep the existing `sfo` product token; OCI's region key is `SJC`. Fly's `sjc`
identifier is a different provider's naming convention. Do not substitute
Phoenix or rename stored identities to make the display name match.

Start with four disposable A1 VMs: one regional controller per region and one
dedicated GRU NetBird server. Each regional controller runs its own embedded
NATS and a bounded, trusted smoke workload. This is a connectivity milestone,
not a highly available deployment or a customer execution environment. The
qualification topology belongs in test tooling, never a production singleton
switch. Before HA claims, qualify three managers per region: ten VMs including
NetBird, plus any isolated workload/function hosts required by later slices.

Acceptance requires real OCI hosts and the exact qualified source/artifacts:

1. **Automatic formation.** All three controllers infer their regions, join
   NetBird, discover the other regions, and expose authenticated readiness with
   observed commit/digests. Restart one without manual enrollment or enable flags.
2. **Working communication.** Exercise authenticated request/reply in all six
   directed regional pairs and verify replies identify the intended region.
   Use a loop-free NATS leaf tree rooted in GRU; a request may traverse GRU.
   Prove required overlay paths and DNS; a ping or peer count alone is not enough.
3. **Working rollout.** Deploy the trusted smoke workload in every region, serve
   requests for 30 minutes, update it by digest, and recover an unhealthy release.
   Record failures and recovery time; an unavailable region cannot count as passed.
4. **Failure and recovery.** Restart the central server, test a relay-dependent
   peer, and restore NetBird from an off-host backup onto a replacement GRU VM.
   Existing direct tunnels may survive; new joins and relayed paths may not.
   Separately interrupt the GRU NATS hub and prove other regions keep serving
   locally while unavailable cross-region operations are reported honestly.
5. **Publish evidence.** Retain redacted inventories/OCIDs, peer and link health,
   six-direction results, boot/join/rollout/recovery timings, resource use, and
   the actual regional bill under `benchmark/bench/`. Add separate ARM/x86/Wasm
   workload hosts before claiming the mixed-runtime milestone is complete.

These are desired acceptance results, not a report that the fleet exists.
Provisioning and destructive recovery exercises retain their authorization gates.

## NetBird: a managed GRU foundation service

Provision one dedicated `VM.Standard.A1.Flex` host in `sa-saopaulo-1` for the
pinned ARM64 NetBird management, signal, relay/STUN, and required identity/TLS
components. Preserve `netbird.terrascale.tech` and existing account/peer identity
where recoverable. Inspect current resources and backups before choosing
restoration or fresh bootstrap; the historical ts-ops bundle is not live evidence.

`ts-orch` owns the VM/image, network/firewall, persistent data, DNS/certificates,
upstream component installation, health/restart, updates, setup keys, scoped API
credential rotation, groups/policies, peer cleanup, backups, and restore. Use
upstream NetBird components managed by the Go executable; do not reimplement
the VPN server or require a second operator deployment tool. The target has no
Forgejo cohosting, `ts-ops` hostname guard, pinned ts-ops private address, manual
PAT file, or dashboard-only setup step. Preserve the existing mesh address plan.

Bootstrap/recovery must work before NetBird and regional scheduler admission.
Use a narrowly authorized foundation path on OCI networking, the host supervisor,
and instance-principal Vault access. Create the initial owner/service identity
over a private local bootstrap channel, deliver its credentials into Vault
without stdout/file handoffs, and close initial setup before public exposure.
Do not schedule the sole manager through the network that it must create.
This bootstrap authority does not grant serving admission or customer privileges.

Every private regional subnet needs a verified path to the manager, DNS, OCI
identity/Vault, and artifact endpoints before enrollment. Declare and test the
chosen egress/private routing; a public hostname alone supplies no route.
Restrict public exposure to the pinned upstream version's required TLS and
STUN/relay ports, with the appropriate DNS-only endpoint for UDP. Derive least-
privilege policies from the required traffic graph, preserving scoped NATS mTLS.
NetBird's central coordination server does not imply that all peer traffic
passes through GRU. Do not create cyclic NATS links to obtain pairwise reachability.

Use one GRU authority for account-wide writes; other regions report inventory
and request scoped changes. Check authority before each write and cancel a
cycle on leadership loss. Recover partially applied operations before retrying.
Back up a consistent store together with the required encryption/identity
material to protected OCI Object Storage outside the VM; copy recovery material
outside GRU for regional disaster recovery. Prove restore preserves peer identity
and access policy. Measure and publish recovery time and recoverable data age.

The single GRU server is an accepted initial failure domain. Its loss can stop
joins, policy changes, authentication, and relay-dependent traffic. A GRU-wide
outage needs separately approved alternate-region recovery; a backup alone does
not supply that capacity. Local regional serving must not require a live manager.

## What the current code establishes

| Evidence | Implication |
| --- | --- |
| `internal/app/workload_autoscale.go` starts `workload.Reconciler`. | An established native-workload control path already exists. |
| `internal/machines/schedule.go` has a pure planner, with no production caller found. | The generic Machines API is not an end-to-end execution implementation. |
| The generic schema accepts rolling updates, dependencies, and stateful policy, but that planner does not enforce them. | Do not wire it into production as though those policies work. |
| `internal/placement/controller.go` verifies serving reports; `internal/app/artifact_store.go` collects artifacts. | Older README/architecture statements that these are absent are stale. |
| `internal/host/agent.go` stops execution after host-session loss. | Availability and database fencing must be separated deliberately during migration. |
| `internal/ociclient/factory.go` provides shared SDK clients and instance principals; `internal/ociregion/foundation/` creates regional foundations. | Extend these paths rather than adding a parallel cloud provisioner. |
| `internal/ociresource/` and `docs/oci-reconcile.md` cover selected rules, backend sets, and bucket protection. | Full creation, repair, and retirement still need an explicit owner for each resource. |
| `internal/nodescale/pool.go` fixes one pool and `VM.Standard.A1.Flex`; `internal/ociregion/plan.go` rejects other shapes. | Mixed roles, shapes, and architectures require changing the provisioning model, not just scheduler labels. |
| `internal/ociregion/seed.go` requires `linux-arm64`; `internal/ocicost/node.go` prices A1 SKUs. | Bootstrap images and pricing must become architecture- and shape-aware together. |

Existing `enabled`, telemetry, report/enforce, and per-region activation paths are
legacy inventory, not the target API. Remove their switches as their slices
migrate; every feature and every admitted region serves automatically. Discover
NetBird members, region inventory, placement, and qualified releases without
operator-maintained host lists or shape-selection knobs.

The original plan identified historical [#352: deployment lag exceeds 30 minutes](https://git.mariogk.com/TerraScale-Old/ts-orchestrator/issues/352).
It reports unavailable serving-region discovery and qualified-main history.
SwarmKit cannot repair missing build retention, region inventory, or deployment
evidence by itself. Inspect those paths independently.

Historical [#27: WASI tenant compute](https://git.mariogk.com/TerraScale-Old/ts-orchestrator/issues/27)
and its child issues contain useful HTTP/queue, credential-hiding, and isolation
requirements. They are closed with unchecked acceptance criteria; no first-party
Wasm runtime was found in the reviewed Go tree. Reconcile their historical C#
and runtime assumptions rather than treating closure as delivery evidence.

## Ownership: one scheduler and one task authority

```text
CI -> immutable images/components -> regional deployment admission
                                      |
                              ts-orch platform controller
                              /                        \
                  embedded SwarmKit              OCI provisioning
                  regional Raft state            and database lifecycle
                           |
                  custom containerd executor
                   /                     \
         TerraScale containers      Wasm worker containers
                                           |
                                  bounded function invocations

NATS: regional events, queues, and observations; not a second task scheduler.
```

SwarmKit owns regional nodes, generic service replicas, task assignment, task
reconciliation, and rollout progression. Keep its Raft quorum inside one region;
do not form one latency-sensitive quorum across regions. The initial production
design uses three managers per region; measure its real capacity cost.

Place managers across availability domains where offered, otherwise across
fault domains. Managers may use different qualified CPU architectures; replace
one at a time without losing quorum. Regional embedded NATS/JetStream must also
form automatically with persistent identities and recoverable storage. The same
three trusted hosts may run managers and NATS if measured resource reservations
protect both quorums; exclude customer execution from those hosts.

`ts-orch` owns app intent, artifact selection, regional deployment aggregation,
OCI capacity, traffic readiness, and TerraBase's database-specific lifecycle.
It translates accepted app intent into SwarmKit services with stable identities
and retry-safe updates. `ts-orch` decides desired replica counts and required
host capacity; SwarmKit assigns generic tasks to admitted hosts. OCI instance
pools realize those host counts; do not attach an independent OCI autoscaler
that competes with this decision. NATS carries events and queues; existing
JetStream state is retained where a remaining platform feature needs it. Avoid storing two
authoritative copies of generic task placement or adding a third state store.

Containerd is a runtime, not a SwarmKit executor. Implement the adapter using
SwarmKit's `exec.Executor`, task `Controller`, and generic runtime payload.
It must prepare, start, observe, wait, drain, terminate, and remove tasks, recover
after agent restart, and expose bounded logs and resource usage. Identify tasks
by their durable SwarmKit identity so retries never launch duplicate containers.

SwarmKit does not supply containerd networking or the product's public routing.
Start with the existing private network and explicit host-port reservations;
keep containerd's socket local and privileged. Qualify port conflicts, private
service discovery, and readiness-based gateway registration. Do not add a new
overlay, service mesh, or network allocator unless this path demonstrably needs it.

The control executable remains one Go binary. Host images also contain managed,
pinned containerd/runc dependencies, and the proposed function runtime is a
container artifact. This is one control binary, not one executable for the whole
host. Reuse feature-sliced packages rather than introducing generic frameworks.

`ts-orch` installs, verifies, supervises, and upgrades these host dependencies
through its managed image/release path. Publish one controller binary per Linux
architecture from the same source revision; do not require per-host operator
installation of containerd, runc, NetBird, or a function runtime.

## OCI resources: one complete lifecycle owner

Reuse `internal/ociclient`, `internal/ociregion`, `internal/ociresource`,
`internal/nodescale`, `internal/oci`, and the existing storage/release slices.
`ts-orch` owns only platform resources within the authorized tenancy footprint,
not unrelated workloads in the tenancy. Its ownership inventory must cover:

| Resource group | Controller responsibility |
| --- | --- |
| Foundation and identity | Compartments, ownership tags, dynamic groups, scoped IAM policies, Vault keys/secrets, and regional discovery records. Serialize tenancy-wide IAM writes through one authority in the home region. |
| Network and ingress | VCNs, subnets, NSGs, routes, required gateways, private discovery, and the chosen OCI LB/NLB with readiness-based backends and certificate renewal. Use existing NetBird membership across regions. |
| Compute and runtime | Architecture-specific host images, instance configurations/pools, domain placement, capacity acquisition, dependency updates, draining, replacement, and orphan cleanup. |
| Durable data and artifacts | Block/boot volumes, attachment/fencing, Object Storage backups and restore verification, OCIR container images and retention, and digest-addressed Wasm artifacts. OCI API permissions use instance principals where supported; automate any registry-specific credentials through Vault. |
| Operations | Capacity/quota observations, actual usage and cost, runtime health, logs/metrics, OCI work-request failures, secret rotation, and recovery evidence exposed through the existing dashboard/insights. |

Use the required services, not every OCI product: for example, choose the
balancer the traffic contract needs rather than deploying both by default.
Cloudflare DNS/certificates and vendor-issued credentials retain their existing
provider boundary; orchestrate needed records/renewal with the established path,
and keep vendor keys once in OCI Vault. No separate Terraform/OKE control loop.

Observe live resources, compute a desired diff, persist an operation identity,
apply with OCI retry tokens/ETags where supported, and wait for the observed
result before dependent operations. Reconcile after process/leader loss without
duplicating instances, secrets, pools, or volume attachments. Check authority
before writes; after failover, recover in-flight OCI operations before starting
conflicting work. A regional outage must not stop healthy regions from serving.

Names/tags locate candidates; verify recorded OCIDs, compartment, and ownership
before adoption or mutation. Never infer permission from a mutable worker tag.
Retain data volumes, backups, and encryption material through host replacement;
retirement needs proven drain and retention safety. A discovery miss never means
delete a region or its data. Do not automatically add or remove serving regions
or buy capacity outside the approved footprint merely because it appears in OCI.

The first tenancy authorization is a real prerequisite: an unprivileged binary
cannot grant itself IAM access. Once that scoped foundation authority exists,
`ts-orch` creates and delivers first-party credentials and configures services
automatically; vendor keys are supplied once. No per-node enrollment, copied
secrets, per-region enable flag, or ongoing manual infrastructure recipe.

## A1-first capacity without an A1-only architecture

Oracle's Compute Shapes reference checked on 2026-10-16 lists A1, A2, and A4
Flex. It does not list `VM.Standard.A3.Flex`; do not invent that identifier or
assume a numeric upgrade sequence. Treat any later family, including a possible
A3, as a discovered candidate requiring the same image/runtime qualification.

| Candidate | Architecture | Selection rule |
| --- | --- | --- |
| `VM.Standard.A1.Flex` | `linux/arm64` | Default for compatible workloads because cost efficiency is the initial goal. |
| `VM.Standard.A2.Flex`, `VM.Standard.A4.Flex` | `linux/arm64` | Use when available and qualified, and measured performance/capacity or price justifies replacing A1. |
| Available, qualified AMD/Intel Flex shapes | `linux/amd64` | Use for x86-only artifacts or a measured workload advantage; coexist with ARM capacity. |
| Other discovered families | Verify from OCI and the running host | Admit after qualification; family names alone establish neither architecture nor compatibility. |

Discover subscribed regions, domains, image-compatible shapes (`ListShapes` with
the image OCID), service limits, remaining quota, and capacity reports. A shape
listing is not spare capacity; a capacity report is not a reservation. Handle
allocation failure, refresh observations, and try the next qualified candidate
within the authorized cost envelope. Unknown price is not zero. If none fits,
leave demand pending with a concrete reason and preserve healthy capacity.

Use a fixed selection policy in code: satisfy runtime/architecture, isolation,
memory/CPU, storage/network, and failure-domain requirements first; prefer A1
among viable candidates until measured evidence justifies another family. Avoid
shape churn with a fixed stabilization policy. No operator shape lists, ordered
fallback configuration, CPU emulation, or manual per-node architecture flags.

Track OCI billing OCPUs separately from guest schedulable CPU and measured
throughput. Oracle currently documents A1 as one core/vCPU per OCPU, A2/A4 as
two cores/vCPUs per OCPU, and x86 as two vCPUs per OCPU. These do not promise
equal useful work. Measure actual CPU topology/cgroup capacity and reserve CPU,
memory, disk, and bandwidth for the OS, controller, NATS, and runtime.

Keep separate pool/configuration identities for isolation role, architecture,
and selected shape where required. Allow old and new pools to coexist during
replacement. Updating a pool's instance configuration does not itself migrate
existing instances. Include shape/image identity in recipe digests and scope
configuration pruning to the owning pool so migration cannot delete another
pool's active recipe. Trusted service, manager, and function hosts have distinct
identity and isolation requirements even when they use the same shape.

Price each candidate using its actual CPU/memory SKUs, storage/performance,
network, registry/artifact storage, backup, and required spare capacity. Compare
cost per useful workload at equal availability. Do not extend A1-only SKU logic
to another family or treat Always Free capacity as a production availability
guarantee. Three managers in every region plus isolated function hosts may cost
more than A1 worker savings; publish the whole regional bill.

## Mixed workloads and safe architecture migration

An execution kind and a CPU architecture are different fields. Wasm is an
artifact/runtime contract; its worker still runs native ARM or x86 code.

| Artifact | Eligible host |
| --- | --- |
| Native ARM binary or ARM-only container | Qualified `linux/arm64` with required CPU features. |
| Native x86 binary or x86-only container | Qualified `linux/amd64` with required CPU features. |
| Multi-platform container image | Resolve its pinned index to the matching ARM/x86 child manifest; record both digests. |
| Portable Wasm module/component | Qualified worker on either architecture implementing the declared WASI/host capabilities. |
| Compiled Wasm cache/native sidecar | Exact compatible architecture, CPU features, runtime version, and compilation settings. |

Verify host architecture and capabilities through OCI inventory plus admitted
agent observations; propagate trusted constraints to SwarmKit placement. Build
controller images, containerd/runc, service images, and function workers for
both architectures. Admission refuses missing artifact variants or unsupported
capabilities before rollout. Show missing compatible capacity as pending, never
as a successful deployment or an instruction to run x86 code on ARM.

Retain portable Wasm bytes as the authoritative artifact. Compile on the target
worker and key caches by module digest, runtime/version, CPU target/features,
and relevant compilation settings. An A1-optimized cache may be invalid on a
different ARM family, even though both report `arm64`. Keep portable native
baselines or explicit CPU-feature requirements; avoid accidental `-march=native`
artifacts that only run on their build host.

For A1-to-other-ARM or ARM-to-x86 moves, acquire and admit replacement capacity,
pre-pull the matching artifacts, gate traffic on readiness, drain old tasks, and
retire old instances only after their replacements serve. Keep rollback capacity
until the release succeeds. Compatible OCI shape resizing can reboot a host;
treat it as a planned drain operation, not a live CPU upgrade. ARM-to-x86 always
requires an architecture-matching boot image and replacement host.

TerraBase and JetStream data movement require explicit storage/on-disk format
compatibility in addition to binary compatibility. Keep database membership,
replication catch-up, writer fencing, and volume ownership authoritative. OCI
block volumes are availability-domain scoped; cross-domain/region moves need
replication or backup/restore to a new volume, not an assumed reattachment.
Preserve object data and workload identity across CPU changes. Stop new writes
and complete a final catch-up/fence before transferring a database writer; a
generic readiness-based stateless replacement is insufficient. If cross-CPU
database compatibility is unproven, retain its current architecture until a
same-commit restore/replication exercise proves the migration.

## Automatic joining without manual enrollment

1. A prepared OCI instance boots `ts-orch`, discovers its OCI region and intended
   pool, and establishes its existing private-network/NetBird membership. Do not
   require an operator to paste addresses, tokens, or certificates per host.
2. OCI instance-principal access retrieves only that pool's regional bootstrap
   material from OCI Vault. Use separate permissions for trusted service hosts,
   function hosts, and managers; a self-reported tag alone grants no privilege.
3. The node discovers the region's stable private manager endpoint, validates its
   TLS identity, and exchanges the regional bootstrap secret for worker-join
   material. Reuse the same path for replacements; reconnect using persisted
   SwarmKit identity on normal restarts.
4. SwarmKit performs its existing certificate issuance and rotation. Workers join
   automatically. Manager promotion follows the controller placement plan and
   separate manager admission; a worker secret never grants manager membership.
5. Retry transient discovery/Vault/manager failures with bounded backoff. Expose
   the current blocked stage. Region creation initializes exactly one first
   manager, then joins its peers; workers must never initialize competing swarms
   merely because discovery returned no answer.

Use the existing region-provisioning operation under a single durable bootstrap
authority to select the first manager and publish its endpoint. An admitted
region forms and serves automatically within its authorized footprint; an
initial tenancy/IAM authorization is not a per-region enable step. Persist
identity and container inventory across agent restarts; do not kill healthy
stateless containers merely to rebuild the supervisor's in-memory state.

Record boot-to-ready separately from agent-start-to-admitted, and break out
network join, discovery, Vault fetch, certificate exchange, image pull, and health
checks. Cache non-secret discovery and existing identity where safe. Joining
must not wait for release publication or function compilation. Set the p95 target
after measuring the baseline; do not promise a seconds-level result beforehand.

## Less custom security, with a small clear boundary

Use a Vault-delivered regional shared secret over verified TLS for the trusted
management/bootstrap API. Remove redundant custom per-message signatures,
per-host application key ceremonies, and repeated proof chains when the new
transport and upstream mechanisms cover their purpose. Keep SwarmKit's built-in
mTLS: replacing it with a custom shared-secret protocol would require more work.

Separate bootstrap access from ongoing management access. Function hosts get
worker-join access, not deployment-admin access; customer modules get neither.
Keep secrets out of images, launch metadata payloads, CLI arguments, logs, and
customer environment variables. Fetch through workload identity; rotate with a
bounded overlap so changing a secret does not require rebuilding the fleet.

Keep TLS verification, authentication, basic authorization and input validation,
non-root execution, resource limits, and digest-pinned artifacts. Keep the normal
CI/registry release boundary; avoid rebuilding a parallel attestation framework.
Audit existing signature checks before deleting them so a remaining build,
cross-region, or database trust boundary is not accidentally left unauthenticated.

Private-network membership reduces exposure; it does not isolate customer code
or make a shared secret harmless. Compromising it grants its regional scope.
Do not expose control-plane endpoints or OCI instance metadata to customer code.
Prefer upstream defaults and a few fixed policies over new security switches.

Database writer fencing, exclusive volume attachment, serving/catch-up checks,
and durable drain protect data correctness. Preserve those even while deleting
custom authentication complexity. SwarmKit node loss or task `RUNNING` is not
proof that an old database writer stopped or that its replacement is current.

## Customer functions: Wasmtime versus wazero

SwarmKit schedules long-lived function workers; workers dispatch short-lived
invocations. Do not create a SwarmKit task or pull an image for every request.
Keep workers warm and reuse compiled code, while resetting guest state between
invocations and never sharing mutable tenant memory or capabilities accidentally.

| Option | Use when | Cost to account for |
| --- | --- | --- |
| Wasmtime in a worker container | The selected contract needs its WASI/Component interfaces or other demonstrated capabilities. | Worker image, host integration, compilation cache, and runtime lifecycle. |
| Embedded wazero in a Go worker | Required module/WASI interfaces are supported and a pure-Go host is sufficient. | Custom host functions and any missing higher-level interfaces. |
| Wasmtime embedded directly in the controller | Not the proposed design. | CGO/Rust linkage changes the existing `CGO_ENABLED=0` builds and couples untrusted execution to control-plane availability. |

Prototype one bounded HTTP handler and one queue handler before freezing the
artifact/WIT contract. WASI Preview 2 from historical #27 is a candidate, not a
reason to assume current Go bindings provide every required interface. Do not
support both engines in production initially; choose the smallest one that
passes the required contract and measurements.

Use dedicated function hosts, separate from managers and TerraBase. Apply bounded
memory, execution deadlines/interruption, output, concurrency, temporary storage,
and network capabilities. A worker may share an engine/compiled-code cache;
guest instances and host-call identity remain tenant-scoped. Keep process/cgroup
boundaries between tenants initially; only pool guest instances when reset and
cross-tenant tests establish the boundary. Wasm is not a full-Linux compatibility
layer, and a container alone is not a VM-equivalent isolation guarantee.

Block function sandboxes' access to OCI metadata/instance-principal endpoints,
host sockets, and private control networks, including through host calls, SSRF,
and redirects. A container network rule alone is insufficient when a trusted
HTTP capability can fetch on its behalf. Function-host instance principals must
also lack infrastructure mutation and general Vault privileges; host compromise
must not yield controller authority. Admission requires isolation tests on both
ARM and x86, not an assumption that Wasm or private networking supplies them.

The platform owns HTTP listeners and NATS queue consumers. Functions receive
typed input and restricted host capabilities, never raw cluster/NATS credentials
or general OCI Vault access. TerraBase calls use a tenant/project-scoped host
capability or gateway. Queue delivery can repeat; preserve acknowledgement,
retry, and idempotency semantics instead of promising exactly-once execution.

## Deployments: define success beyond task start

CI retains a digest-pinned image/component and qualification record for its exact
source commit. The region controller selects that digest, updates the SwarmKit
service, waits for application readiness, and only then registers traffic.
Configure bounded rolling updates and explicit failure/rollback behavior; do not
inherit an all-at-once default accidentally. Preserve the last healthy release.

For TerraBase, the platform controller authorizes each member update only after
the required serving, replication, drain, and volume evidence is present. The
executor must refuse unsafe replacement even if a generic task is rescheduled.
Do not rely on stop-first/start-first settings alone to establish single-writer
safety or on container health alone to establish replication catch-up.

Publish the requested digest, observed running digest, readiness, and rollout
outcome for each region. Mark an unavailable region as unknown, not successful.
Retain durable failure/rollback evidence so the deployment-lag guard can separate
missing observations from a real rollout exceeding its deadline.

## Migration sequence and acceptance

1. **Baseline, OCI capacity, and compatibility spike.** Inventory production
   callers and state; record present join/deployment failure stages. Run a disposable three-manager
   SwarmKit cluster with one containerd executor, pinned upstream versions, and
   ARM and x86. Discover and price compatible shapes; qualify A1 first and other
   available families. Prove the executor, network path, and mixed-architecture
   constraints without a fork. Record the SwarmKit maintenance/cost decision.
2. **Automatic joining and one stateless service.** Exercise simultaneous boot,
   replacement, persistent identity, Vault outage, manager loss, and partitions.
   Recover interrupted OCI creates and discover regions without enable flags.
   Deploy ARM-only, x86-only, and multi-platform containers by digest; gate traffic
   on readiness and prove rollback after an unhealthy update. Existing stateless
   tasks survive manager unavailability. Exercise A1 exhaustion and unavailable
   alternatives without discarding healthy hosts or exceeding authorized spend.
3. **Replace generic orchestration.** Map Machines intent to SwarmKit, assign each
   migrated workload exactly one owner, and remove its old scheduler, native
   supervisor, host-session execution lease, and redundant authentication path.
   Join foundation/resource, capacity, image, credential, and upgrade ownership
   into continuous reconciliation. Exercise mixed pools, shape replacement,
   manager/NATS quorum preservation, and safe cleanup. Use a bounded deployment
   migration, not permanent dual controllers or flags.
4. **Add functions.** Compare the required handler contract on Wasmtime/wazero;
   select one engine, then qualify HTTP/queue delivery, tenant isolation, quotas,
   cancellation, compilation caching on both CPU architectures, worker loss,
   metadata/control-network denial, and revision rollback.
5. **Migrate TerraBase last.** Re-establish storage ownership, catch-up, drain,
   fencing, backups/restores, and member-by-member updates before removing its
   previous executor. Prove cross-architecture data compatibility or keep each
   database on its qualified architecture. Require explicit authorization for
   destructive migration.

Each slice needs focused contract/failure tests and CI on the exact candidate
commit. External tests use fakes/contract fixtures; do not download or run
TerraBase from this repository's tests. Real TerraBase integration belongs in
the monorepo using its same-commit build. Local build/test/benchmark commands run
with `nice -n 19`; GitHub CI runs normally on hosted runners. No local check is
required before opening a PR. Use GitHub-hosted CI and retain exact-commit
qualification, binaries, images, logs, and rollback history in GitHub-backed
release paths. Replace Forgejo qualification/lineage checks with GitHub run,
job, repository, SHA, and artifact validation; never bypass admission to migrate.
Move SDK fetching and operational tools to their GitHub equivalents, remove
private-builder/`fj` requirements, and preserve credential and production gates.

## Measure whether it is actually cheaper

Publish pinned inputs, raw samples, correctness checks, and reports under
`benchmark/bench/`. Compare equivalent availability and isolation on the same
host classes. Include warm idle workers, dedicated function hosts, spare capacity,
three regional managers, NATS, containerd, image storage, and operational work.

| Measure | Required comparison |
| --- | --- |
| Joining and deployments | p50/p95/p99 startup, first readiness, image pulls, failed rollout recovery, manager failover. |
| Host overhead and density | CPU/RSS/disk at idle and load; safe tasks/invocations per A1/other ARM/x86 host with reserve and normalized CPU units. |
| Functions | Cold/warm latency, compilation/cache cost, throughput, timeout behavior, tenant fairness. |
| Availability and correctness | Node/manager loss, partitions, duplicate delivery, stale writers, rollback, restore. |
| Overall cost | Actual per-shape cost per useful request/job and per region, including migration surge, backups, network/registry, adapters, patching, and maintenance effort. |

Expected benefit: fewer custom scheduling and rollout mechanisms to maintain.
Unproven benefit: lower infrastructure spend or faster function execution.
If the adapter retains most existing orchestration or requires extensive upstream
patches, stop and reassess the architecture rather than maintaining two platforms.

## Project review: recommended implementation order

Review scope: the four-VM connectivity milestone, then HA and mixed workloads.
Read the control/bootstrap, NetBird, regional NATS, release/CI, OCI capacity/cost,
host execution, storage fencing, API, and artifact-retention paths. This is a
risk-based source review, not exhaustive inspection of every file or live proof.

### Must fix before claiming the first milestone

1. **Qualify GitHub release continuity.** The reviewed baseline had no GitHub
   workflows. This change migrates all seven workflows to hosted Actions, SDK
   fetching and the Go module to GitHub, and producers/consumers to native `gh`.
   Exact run ID/number, attempt, job, source, manifest and lineage checks remain.
   GitHub CI results still need to establish the new pipeline. Old standalone
   TerraBase, ts-auth and ts-libs repositories/qualified releases return 404 to
   the current account; agree their current source/artifact contract before
   generating fresh GitHub qualifications. Never relabel old signatures or
   run IDs. [Migration status](docs/github-migration.md) records remaining gates.
2. **NetBird must bootstrap and recover independently.** The manager installer
   and `setup-owner.sh` require ts-ops; `netbirdManagementLoop` also requires
   explicit PAT/peer-map inputs. Replace these assumptions with the foundation
   lifecycle above, or a fresh fleet still needs manual enrollment and setup.
3. **Fence NetBird writes through leadership changes.** `manager/loop.go` checks
   leadership before a cycle and between sync/prune; `sync.go` applies its
   planned writes without checking each one. Cancel and recheck before writes,
   and reconcile partial results. Otherwise old/new leaders can apply stale
   plans concurrently and create ambiguous objects that stop later syncs.
4. **Backups must survive host loss.** `manager/netbird-backup` writes consistent
   SQLite snapshots beside the live store on the same VM. Add protected off-host
   storage, matching key/identity recovery, and a restore exercise. Otherwise
   losing the manager's disk can lose the account and peer state with it.
5. **Prove the actual network graph.** `manager/desired.go` grants GRU-to-other-
   region fabric access; `natscell/interregion.go` requires a signed leaf tree.
   Generate compatible policies, DNS, credentials, and links automatically and
   test all six request/reply directions. Existing group/heartbeat code alone
   does not establish a reachable three-region deployment.

### Must complete before production or mixed-runtime claims

6. **Keep stateless availability separate from database fencing.** Session loss
   in `internal/host/agent.go` stops workloads. Move stateless supervision to the
   qualified executor while retaining `storage/failover` writer/volume proofs;
   removing every lease uniformly risks concurrent database writers.
7. **Migrate shape, image, pricing, and scheduling as one contract.** A1-only
   pool/seed/cost paths and the unwired generic Machines planner cannot provide
   mixed execution. Keep exactly one task owner and qualify wrong-architecture,
   missing-capacity, replacement, isolation, and rollback failures end to end.
8. **Update stale operational claims after qualification.** README still says
   artifact cleanup and serving verification are absent, but the corresponding
   code exists. Preserve that code and correct docs from retained evidence;
   do not rebuild working services or call source tests production readiness.

Verdict: establish GitHub release continuity and the managed NetBird foundation
first, then prove the three-region milestone before replacing production tasks.
Not checked: live OCI/NetBird state, credentials, real traffic, runtime benchmarks,
or every source file. No infrastructure changes are implied by this review.

## Primary references

- [OCI Compute shapes and OCPU definitions](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm), [shape changes and image compatibility](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/resizinginstances.htm), and [ListShapes API](https://docs.oracle.com/en-us/iaas/api/#/en/iaas/20160918/Shape/ListShapes)
- [OCI instance principals and dynamic groups](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/callingservicesfrominstances.htm) and [instance metadata](https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm)
- [SwarmKit architecture and features](https://github.com/moby/swarmkit)
- [SwarmKit executor](https://github.com/moby/swarmkit/blob/master/agent/exec/executor.go), [task lifecycle](https://github.com/moby/swarmkit/blob/master/agent/exec/controller.go), and [generic runtime schema](https://github.com/moby/swarmkit/blob/master/api/specs.proto)
- [Wasmtime security model](https://docs.wasmtime.dev/security.html) and [Go embedding](https://github.com/bytecodealliance/wasmtime-go)
- [wazero compatibility and Go embedding](https://github.com/tetratelabs/wazero)

Pin exact versions during the spike; upstream branch links describe moving code.
