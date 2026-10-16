# Orchestrator refactor: SwarmKit, containerd, and customer Wasm

Start with a disposable regional prototype of embedded upstream SwarmKit and
one containerd executor. Prove automatic joining and a healthy rolling container
deployment before migrating production workloads or adding function execution.

## Status and decisions

Planning baseline, 2026-10-16. Source reviewed: `main` at `5fbe42a8`.
This document records the brainstorming outcome; it does not claim an implemented
runtime, measured savings, production readiness, or deployment authorization.

| Decision | Direction |
| --- | --- |
| First deployment target | OCI hosts first; no Fly implementation in this refactor. |
| Control plane | Keep `ts-orch` in Go; embed upstream SwarmKit without an initial fork. |
| First-party workloads | OCI containers through containerd and runc; no Docker Engine. |
| Customer workloads | Short-lived Wasm functions on isolated worker hosts. |
| Security and joining | Substantially simplify custom protocols; automatic discovery and worker admission using OCI identity and Vault-delivered bootstrap material. |

Wasmtime is the proposed first function runtime, subject to the compatibility
prototype below. The user selected customer Wasm, not a particular WASI version
or runtime implementation. Do not present Wasmtime or WASI Components as an
already qualified dependency. Use wazero instead if the actual function contract
fits its supported interfaces and its simpler Go integration wins the comparison.

The OCI-first decision scopes this repository refactor; it does not move other
TerraScale services off Fly or Cloudflare. Keep the existing external service
hosting boundaries. No new paid capacity, IAM permission, credential, or secret
installation is authorized by this planning document.

## What the current code establishes

| Evidence | Implication |
| --- | --- |
| `internal/app/workload_autoscale.go` starts `workload.Reconciler`. | An established native-workload control path already exists. |
| `internal/machines/schedule.go` has a pure planner, with no production caller found. | The generic Machines API is not an end-to-end execution implementation. |
| The generic schema accepts rolling updates, dependencies, and stateful policy, but that planner does not enforce them. | Do not wire it into production as though those policies work. |
| `internal/placement/controller.go` verifies serving reports; `internal/app/artifact_store.go` collects artifacts. | Older README/architecture statements that these are absent are stale. |
| `internal/host/agent.go` stops execution after host-session loss. | Availability and database fencing must be separated deliberately during migration. |

The backup's sole open issue is [#352: deployment lag exceeds 30 minutes](https://git.mariogk.com/TerraScale-Old/ts-orchestrator/issues/352).
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

`ts-orch` owns app intent, artifact selection, regional deployment aggregation,
OCI capacity, traffic readiness, and TerraBase's database-specific lifecycle.
It translates accepted app intent into SwarmKit services with stable identities
and retry-safe updates. NATS carries events and queues; existing JetStream state
is retained only where a remaining platform feature needs it. Avoid storing two
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

Use the existing region-provisioning operation to select the first manager and
publish its endpoint. Initial provisioning can remain explicit; subsequent host
admission and region participation are automatic, without enable flags. Persist
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

1. **Baseline and compatibility spike.** Inventory production callers and state;
   record present join/deployment failure stages. Run a disposable three-manager
   SwarmKit cluster with one containerd executor, pinned upstream versions, and
   both target architectures. Prove the executor and network path without a fork.
2. **Automatic joining and one stateless service.** Exercise simultaneous boot,
   replacement, persistent identity, Vault outage, manager loss, and partitions.
   Deploy one container by digest, gate traffic on readiness, and prove rollback
   after an unhealthy update. Existing stateless tasks survive manager unavailability.
3. **Replace generic orchestration.** Map Machines intent to SwarmKit, assign each
   migrated workload exactly one owner, and remove its old scheduler, native
   supervisor, host-session execution lease, and redundant authentication path.
   Use a bounded deployment migration, not permanent dual controllers or flags.
4. **Add functions.** Compare the required handler contract on Wasmtime/wazero;
   select one engine, then qualify HTTP/queue delivery, tenant isolation, quotas,
   cancellation, compilation caching, worker loss, and revision rollback.
5. **Migrate TerraBase last.** Re-establish storage ownership, catch-up, drain,
   fencing, backups/restores, and member-by-member updates before removing its
   previous executor. Require explicit authorization for destructive migration.

Each slice needs focused contract/failure tests and CI on the exact candidate
commit. External tests use fakes/contract fixtures; do not download or run
TerraBase from this repository's tests. Real TerraBase integration belongs in
the monorepo using its same-commit build. Local build/test/benchmark commands run
with `nice -n 19`; GitHub CI runs normally on hosted runners. No local check is
required before opening a PR. Retire this backup's old Forgejo/private-builder
assumptions as part of establishing its authorized implementation repository.

## Measure whether it is actually cheaper

Publish pinned inputs, raw samples, correctness checks, and reports under
`benchmark/bench/`. Compare equivalent availability and isolation on the same
host classes. Include warm idle workers, dedicated function hosts, spare capacity,
three regional managers, NATS, containerd, image storage, and operational work.

| Measure | Required comparison |
| --- | --- |
| Joining and deployments | p50/p95/p99 startup, first readiness, image pulls, failed rollout recovery, manager failover. |
| Host overhead and density | CPU/RSS/disk at idle and load; safe tasks/invocations per host with reserve. |
| Functions | Cold/warm latency, compilation/cache cost, throughput, timeout behavior, tenant fairness. |
| Availability and correctness | Node/manager loss, partitions, duplicate delivery, stale writers, rollback, restore. |
| Overall cost | Cost per useful request/job and per region, plus adapters, patching, and maintenance effort. |

Expected benefit: fewer custom scheduling and rollout mechanisms to maintain.
Unproven benefit: lower infrastructure spend or faster function execution.
If the adapter retains most existing orchestration or requires extensive upstream
patches, stop and reassess the architecture rather than maintaining two platforms.

## Primary references

- [SwarmKit architecture and features](https://github.com/moby/swarmkit)
- [SwarmKit executor](https://github.com/moby/swarmkit/blob/master/agent/exec/executor.go), [task lifecycle](https://github.com/moby/swarmkit/blob/master/agent/exec/controller.go), and [generic runtime schema](https://github.com/moby/swarmkit/blob/master/api/specs.proto)
- [Wasmtime security model](https://docs.wasmtime.dev/security.html) and [Go embedding](https://github.com/bytecodealliance/wasmtime-go)
- [wazero compatibility and Go embedding](https://github.com/tetratelabs/wazero)

Pin exact versions during the spike; upstream branch links describe moving code.
