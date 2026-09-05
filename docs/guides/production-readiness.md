# Production readiness and refactoring inputs

The [repository goal](../../GOAL.md) defines the target. This guide records
exploration findings and the inputs needed to implement it. Code presence is
not qualification evidence. The inspected checkout includes substantial
uncommitted implementation work; recheck these findings as that work lands.

## Agreed architecture

GRU is first and hosts the single active global master. Every Region runs its
own regional orchestrator, including Regions with only two member hosts. The
master manages those orchestrators. Every TerraBase machine runs its own local
`ts-orchestrator` to manage that machine's TerraBase instance. These local
processes coordinate regional OCI work under fenced authority; only selected
processes host global control-store replicas. `ts-node` performs host mutations. TerraBase owns data
correctness and membership acceptance.

```text
GRU master: global policy, regional admission, control lifecycle, rollout order
    |
    +-- GRU regional orchestrator --> GRU OCI resources and TerraBase members
    +-- SFO regional orchestrator --> SFO OCI resources and TerraBase members
    +-- FRA regional orchestrator --> FRA OCI resources and TerraBase members
    +-- each added Region        --> its OCI resources and TerraBase members

Global control storage: embedded JetStream R3 across GRU/SFO/FRA
Bootstrap only: temporary GRU R1 before customers
```

The global R3 protects control state. It does not create three independent
masters or require every regional process to join that storage group.
Regional orchestrators use fenced authority and durable control records;
unavailable authority stops new mutations while admitted TerraBase service
continues.

## What the code establishes

| Area | Entry points inspected | Finding and next proof |
| --- | --- | --- |
| Runtime composition | `cmd/orchestrator/main.go`, `runtime_composition.go` | Production startup calls `composeProductionRuntimeConfig`. Its default returns `ErrProductionCompositionMissing`, and the search found no other assignment. Wire the concrete dependencies and prove startup through the real executable. |
| Bootstrap and control transition | `src/orchestrator/bootstrap/greenfield.go`, `control_plane.go`, `provider_control_plane.go` | Durable bootstrap and R1/R3 transition contracts exist. Prove the CLI, provider effects, host admission, synchronization, and credential retirement together under interruption. |
| Region topology | `src/orchestrator/bootstrap/control_plane.go`, `cmd/orchestrator/add_region.go` | The implementation contains `remote-managed` topology. Audit whether each path actually installs and admits a regional process. Replace remote-only behavior with the newly required per-Region orchestrator while preserving storage placement. |
| Authority | `src/orchestrator/control/authority/authority_engine.go` | Lease, epoch, replay, and fencing decisions exist. Trace their enforcement to every provider, host, and TBEP mutation; a decision engine alone does not establish single-master safety. |
| Regional resources | `src/orchestrator/estate`, `reconcile`, `provider`, `cloudflare` | Desired-estate and provider code exist. Verify global versus regional ownership and credential scopes, including duplicate and indeterminate provider operations. |
| Host lifecycle | `src/orchestrator/hostagent`, `cmd/ts-node` | Signed install, lifecycle, transport, and recovery code exist. Qualify actual systemd operations and durable receipts in guests. |
| Operational services | `src/orchestrator/estatepublisher`, `keyrotation`, `reaper`, `restoredrill`, `delivery` | Service constructors and adapters exist. Trace production scheduling, concrete clients, durable stores, error propagation, and restart recovery. |
| Qualification | `Makefile`, `cmd/vm-qualify`, `src/orchestrator/vmqual`, `vmqualruntime`, `vmqualsuite` | Portable and Firecracker targets are separate. VM code and scenario tests are present; their presence does not establish a passing full-stack or real-provider result. |

The package map in `DESIGN.md` is useful for orientation but is incomplete
relative to the working tree. Update it alongside the eventual package
refactor after the in-flight implementation is integrated.

### Guest service startup

Host manifests now carry bounded literal `arguments` and nonsecret
`configuration`. `@config` selects the immutable configuration next to the
current signed binary. `ts-node` writes the configuration and admitted launch
manifest in the same staged version directory, refuses same-version launch
changes or incomplete existing slots, and restores the prior version's arguments
and configuration on rollback. The detached artifact signature authenticates the
binary only; launch configuration relies on authenticated manifest admission.
Configuration files are readable by services and must contain secret file
references, never secret values. The private-key PEM check is not a general
secret detector. Self-service `ts-node` launch remains owned by its bootstrap
unit, with release metadata retained for authenticated self-rollback.

Qualification initial activation uses the existing journaled host drain,
deploy, and release commands, verifies the seeded manifest digest and exact host
component observations, and resumes partially activated hosts without deploying
an unexpected version. This isolated NATS transport has no GRU fencing fields or
cryptographic caller authentication; it does not qualify production authority.

The guest manifests still lack concrete TerraBase and orchestrator launch
configuration. Bare TerraBase startup fails because its process requires
`--config FILE` or `TERRABASE_CONFIG_FILE`. Even with a complete production
configuration, the inspected adjacent producer's
`crates/terrabase-server/src/runtime.rs` production path drains its opened member
and returns `Membership: no durable orchestrator membership source is configured`.
That same file maps production Regions only to GRU/SFO/FRA. These are unfinished
producer paths, not missing VM credentials. A local-development engine observation
does not satisfy production membership, RF=2, or fourth-Region acceptance.

### Immutable orchestrator launch configuration

`ts-node` can launch the orchestrator with `Arguments: "run --config @config"`
and a `Configuration` string containing a JSON object that maps admitted
`TS_ORCH_*` setting names to string values. The command resolves the installed absolute configuration path.
An explicit file replaces the process environment entirely. It requires cell,
instance, NATS URL, replica count, and `TS_ORCH_PROVIDER=oci`; production identity
and estate validation still run before any runtime starts.

The file contains nonsecret settings and absolute credential-file references.
Inline Cloudflare/Grafana tokens, URL credentials, unknown or duplicate fields,
trailing data, and local-provider bypasses are rejected. Files must be regular,
at most 64 KiB, have one link, belong to root or the service identity, and deny
group/other writes. The command rejects symlinks and FIFOs. This supports the
host agent's immutable configuration contract without embedding credentials in
release slots.

Qualification cannot yet generate the required authoritative values. It still
needs admitted NATS identities and TLS files, signed-command identity and trust,
and OCI estate/signer references. TerraBase separately needs durable membership,
admitted database placement, peer identity, and Vault bindings. The command
file reader does not supply these missing authorities or complete runtime
composition.

### Production dependency audit

The production composition root still always returns
`ErrProductionCompositionMissing`. This is unfinished implementation, not a
missing-credential or VM-environment gate. `control.OrchestratorOptions`
currently resolves NATS and signed-command identities; it does not resolve the
provider, TerraBase, catalog, notification, or durable operational-service
dependencies required by `productionRuntimeConfig`.

| Runtime input | Existing implementation and exact missing connection |
| --- | --- |
| Estate publication | `estate.ControlPlaneClient` implements public document writes. The root still needs its configured endpoint and credential, a coherent `estatepublisher.SnapshotSource`, and an `Authority` that reads the accepted epoch and rechecks its fence before each write. A constant epoch or empty snapshot cannot establish this. |
| Identity and capability rotation | `security.IdentityIssuer` requires `Issue`, `Fetch`, and `Retire`; `CapabilityVault` requires `Generate`, `Fetch`, and `Retire`. Their concrete production implementations are absent. `MemberGateway` still needs member enumeration, distribution, generation verification, activation, retirement, rollback, and fencing; `Reloader` needs reload, verification, rollback, and fencing. These require authenticated host/member transports and durable operation receipts. |
| Cloudflare rotation | `keyrotation.CloudflareSecretsStore` wraps the value API, but requires concrete `CloudflareCapabilityObserver.VerifyCapability` and `CloudflareCapabilityFencer.FenceCapability`. Secret metadata alone cannot prove the generation accepted by the Snippet. Its staged provider versions also need crash recovery before production use. |
| Rotation state | `security.FileStateStore` is local process persistence, not global R3 authority. Compose a fenced global durable store for `security.StateStore` and an audit sink; prove that an old controller cannot overwrite a resumed rotation. |
| Free database lifecycle | `reaper.DatabaseAdapter` needs the authoritative paginated catalog, snapshot and placement verification, close, Litestream stop, reactivation, CDN purge, and owned-data deletion. `KeyAdapter.DestroyDEK` and `MailAdapter.Send` have no concrete production implementation. The file/memory reaper stores do not establish global journal fencing. Notice delivery must be acknowledged before the durable lifecycle advances. |
| Daily restore | Production wrappers validate `BackupPort` and `BranchPort`; they do not implement database enumeration, restore, scratch creation, restored checksum/row-count observation, or owned scratch deletion. The root also needs `JournalPort` facts and fenced run/item persistence and an acknowledged `PagerPort`. `TickerScheduler` and `NATSJetStreamSnapshotter` exist, but still need composition with the authoritative stream, an OCI `SnapshotObjectStore` supporting verified reads, and verified per-Region snapshot mirrors. VM-local restore adapters are qualification fixtures. |
| Release mirrors | `provider.DeliveryRegionStore` is concrete. The root must bind each admitted Region's OCI `ObjectStorageProvider`, namespace, compartment and bucket to an authoritative `ProviderMutationJournal` and a live `OwnershipCheck`. The delivery and restore paths must share those same scopes and journal. |

The adjacent TerraBase checkout exposes its private contract in
`../terrabase/contracts/proto/terrabase/v1/engine.proto` and the matching crate
copy under `crates/terrabase-tbep/proto`. Its `MaintenanceService` currently
provides `TopologyRead`, `AdminStatus`, `SupervisionHealth`, and
`SupervisionShutdown`. `ReplicationService` provides `Health`, `Cursor`,
`Fenced`, `Denials`, `Conflicts`, and `Depositions`. Those RPCs can support
bounded observations; they do not provide the required database lifecycle,
backup/restore, scratch-branch, key-ring, or placement-intent mutation
contracts. `src/orchestrator/tbep` now pins the complete protobuf source and
generated Go bindings and implements scoped health, topology, and admin
observations over TLS 1.3 with exact admitted SPIFFE identity verification.
The pin records the modified producer worktree's exact file digests; it is not
a published contract release. Transport tests do not establish real-server
qualification.

The production host observation loop still needs to consume this client and
qualify it against the real server. Replication observations remain separate
from health. Lifecycle mutations additionally need TerraBase
server contracts that carry the accepted authority, operation ID, status
observation, and durable receipt; `SupervisionShutdown` is not a replacement
for database drain or safe member replacement.

Scheduled production workers now preserve operation errors through runtime
shutdown. The restore scheduler returns callback failures, including journal
read failures that occur before a run can be durably recorded or paged, to
process supervision. A restore scheduler that exits successfully while its context is
still active also fails the process. Cancellation remains a clean shutdown,
and duplicate starts are rejected. Focused race tests cover periodic and
long-running service failure, propagation through `closeRuntime`,
cancellation, and close-before-start. These tests establish service lifecycle
behavior only; production startup remains blocked by the missing graph above.

## First implementation slices

1. Define explicit master, regional, and host-local roles and their durable
   identities. Install `ts-orchestrator` beside TerraBase on every member
   machine and prove local management without duplicate regional mutations.
   Trace a global declaration through regional admission, scoped authority,
   regional reconciliation, and a receipt returned to the master. Include a
   fourth two-host Region to expose remote-only assumptions.
2. Complete first-GRU bootstrap and recovery. Exercise crashes before and
   after provider creation, journal persistence, runtime handoff, and R3
   promotion. A second bootstrap invocation must resume or refuse, and a
   retired bootstrap identity must fail at the mutation boundary.
3. Wire the production runtime dependencies. Start the actual executable with
   declared configuration and prove provider reconciliation, regional
   dispatch, estate publication, key rotation, reaping, restore scheduling,
   and delivery mirroring. Missing required configuration must name the
   dependency and prevent readiness.
4. Pin the TerraBase lifecycle contract and connect it to host operations.
   Prove placement, drain, catch-up, safe replacement, rollout, backup, and
   restore against the real TerraBase binary. A timeout must trigger status
   observation before retrying a mutation.
5. Qualify self-management. Restart a local orchestrator while TerraBase
   continues serving. Lose the whole machine and use a surviving authorized
   controller to replace both components before readmission. Upgrade global replicas one at a time. Restart the master
   during a rollout, restore control state without a running master, and prove
   that the old identity cannot resume mutations.
6. Remove superseded paths after their replacements pass. Keep policy in Go
   decision packages, provider effects in adapters, and process composition
   explicit. Replace greenfield persisted contracts and all consumers together;
   delete old readers instead of adding compatibility layers or migration shims.

These slices refine the workspace infrastructure track; they do not replace
its gates. Each slice needs a concrete input contract, operation journal,
recovery behavior, and observable acceptance test before implementation.

## Inputs still needed

| Input | Source or owner | Needed before |
| --- | --- | --- |
| Exact TBEP operations, schemas, errors, supported versions, and readiness evidence | TerraBase contract owners; start at `terrabase/contracts/proto/terrabase/v1/engine.proto` in the workspace and the published Go contract | Wiring lifecycle clients; do not invent a successful adapter for a missing RPC |
| Global-to-regional command and receipt contract, authority expiry, and disconnected behavior | Orchestrator implementation design under the goal's fencing rules | Regional mutation path |
| Mapping from regional processes to embedded NATS endpoints, accounts, and durable stores | Orchestrator control design | Adding the fourth Region; local process presence must not silently add a global replica or an authoritative R1 |
| Master recovery procedure, snapshot recovery point objective, recovery time objective, and supported version skew | Orchestrator recovery design and operating owner | Control upgrade and recovery qualification |
| Per-Region CPU, RAM, disk, queue, reconciliation, and provider retry budgets | Measured OCI workloads and orchestrator capacity tests | Production capacity acceptance |
| OCI account, Region identifiers, quotas, image IDs, failure domains, IAM scopes, and initial credentials | Owner prerequisites in workspace O-4; credentials supplied through secret references | Real bootstrap |
| Signed orchestrator, `ts-node`, and TerraBase artifacts for arm64 and amd64 | `ts-deploy` release contracts | Guest and real-host delivery qualification |
| Cloudflare/Grafana account configuration and scoped runtime secret references | Owner prerequisites and declared estate | Real routing and telemetry gates |
| Exact release evidence for portable tests, full VM suite, real-provider drills, soak, and restore history | CI and supervised qualification | Production release |

The code refactor can start with the role and bootstrap contracts. Production
readiness cannot be declared until the remaining inputs and evidence exist.
Do not infer operational targets or credential values from defaults.

## Evidence to retain

For each qualified release, record its exact artifacts, configuration revision,
scenario results, and bounded redacted diagnostics outside `GOAL.md`.
Portable `make check` verifies formatting, vet, build, and race tests. Full
Firecracker `make vm-test` proves process and guest behavior; a fourth-Region
scenario must additionally exercise its local orchestrator. Real OCI and
Cloudflare drills establish provider behavior, quotas, and performance.

Keep the goal's seven-day soak, rollback rehearsal in every Region, fourteen
consecutive daily restore drills, live external SLO probes, and security gates.
Report failed or unrun gates explicitly. A documentation update or a passing
unit suite does not make the system production ready.
