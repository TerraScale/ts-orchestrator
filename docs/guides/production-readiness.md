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
| Runtime composition | `cmd/orchestrator/main.go`, `runtime_composition.go` | Production startup calls `admitProductionRuntime`. Its default returns `ErrProductionCompositionMissing`, and the search found no other assignment. Wire the concrete dependencies and prove startup through the real executable. |
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

### Global operational worker ownership

The root now separates regional delivery from GRU global operational workers.
It constructs publisher, rotation, reaper and restore workers only after a
fresh quorum proof of the actual global lease. Rotation, restore and reaper
state bind candidate, epoch and lease ID. Followers retain regional work;
lease loss cancels and joins the old group before a replacement starts.
Client factories transfer explicit cleanup ownership, including partial or
late construction results. Cleanup failures prevent a successor from starting.
The [session contract](../contracts/global-worker-sessions.md) records these
boundaries. The default `admitProductionRuntime` still fails with
`ErrProductionCompositionMissing`; concrete external adapter resolution is
unfinished.

Initial global topology provisioning also remains unwired. Static production
admission currently rejects before the embedded broker starts, and bootstrap
activation waits for running services before inspecting control stores. The
guest broker seed declares only `GRU_CONTROL`, without the global account,
separate infrastructure identity or required global storage budget. Complete
signed R1 admission and provisioning between broker readiness and live-store
construction. Normal global runtime and operational workers remain R3-only.

The [integrated verification](../evidence/global-worker-reaper-gates-2026-09-05.txt)
records passing portable and sandboxvm-tagged race suites and a Linux arm64
cross-build. These results do not establish guest startup or provider behavior.

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

Initial activation validates the seeded full-manifest digest and component
observations, then sends the exact drain, deploy, and release commands admitted
by an independent owner-signed grant. The grant binds the host, full launch
configuration, signer, finite command set, and expiry. The node journals its
admitted manifest and signer pin before effects. A durable accepted regional
epoch permanently retires bootstrap authority. Pending commands require fresh
authorization after restart, and manifest recovery hydrates the exact verified
snapshot before restoring host state.

The qualification transport requires TLS 1.3, verified client certificates,
and per-node NKeys with node-specific permissions. Its file-backed JetStream
is a test transport, not the guest global control store; it cannot establish
GRU authority or R3. Ordinary qualification mutations still refuse to use a
bootstrap grant instead of a real regional lease. The signed-grant VM run
below activated both real component binaries through `ts-node`, but neither
component stayed active. This proves the initial grant transport boundary,
not runtime regional fencing or service readiness.

Production also has a separate local initial executor that consumes the same
finite signed grant before dialing NATS. It uses the same command journal and
epoch retirement checks and requires observed service readiness. Its tests
use actual signatures and recorded host effects; that offline path has not
passed guest qualification. It does not supply missing orchestrator runtime
composition or TerraBase membership.

The guest renderer now signs concrete GRU orchestrator launch configuration.
Only the first GRU guest embeds the initial broker; GRU peers use its guest
address and independent service credentials. It does not invent OCI estate
or signer inputs, and additional Regions require admitted allocations.
TerraBase launch configuration remains incomplete. Bare TerraBase startup fails because its process requires
`--config FILE` or `TERRABASE_CONFIG_FILE`. Even with a complete production
configuration, the inspected adjacent producer's
`crates/terrabase-server/src/runtime.rs` production path drains its opened member
and returns `Membership: no durable orchestrator membership source is configured`.
That same file maps production Regions only to GRU/SFO/FRA. These are unfinished
producer paths, not missing VM credentials. A local-development engine observation
does not satisfy production membership, RF=2, or fourth-Region acceptance.

A [direct check of the pinned binary](../evidence/terrabase-missing-config-process-2026-09-05.txt)
confirmed exit 1 with `Error: MissingConfigurationPath` when no configuration
is selected. Future guest diagnostics recognize that fixed error text. This
direct process result does not retroactively identify prior guest exits.

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

Qualification now generates disposable NATS identities and TLS files and
stages private credentials outside cloud-init UserData. Persistent membership
keys and explicit peer pins are staged for the service identity. It still needs the complete
runtime authority qualification and OCI estate/signer references. TerraBase separately needs durable membership,
admitted database placement, peer identity, and Vault bindings. The command
file reader does not supply these missing authorities or complete runtime
composition.

### Embedded server and membership identity

Selected orchestrator processes can host the NATS library through a supervised
server handle. Its lifecycle tests use real authenticated TLS connections and
cover readiness, cancellation, concurrent shutdown, and listener failure.
Configuration parsing reads immutable bytes without writing temporary files in
the release directory. The command now orders static admission, broker readiness, live adapter
construction, and command subscriptions, then shuts down clients before the
broker. Focused tests cover construction failure and broker failure exit
status. They do not establish working production composition or guest R3.

Membership startup now requires a persistent PKCS8 P-256 signing key and an
explicit map of controller instance IDs to canonical Base64 PKIX public keys.
The map must include the local identity. Membership observation cannot learn a
new trusted key from the first record or replace a pin after lease expiry.
The settings are `TS_ORCH_MEMBERSHIP_SIGNING_KEY_FILE` and
`TS_ORCH_MEMBERSHIP_PINS_FILE`. Focused race tests pass for file admission and
the control membership path; real-guest membership qualification remains open.

### Production dependency audit

The bootstrap and add-region commands now admit an owner-private declaration
before provisioning and retain those exact inputs through construction.
Per-slot cloud-init is mandatory. Initial GRU bootstrap resolves only GRU's
actual owned OCI members; later admissions extend immutable region receipts.
Private credentials are represented in user-data by version-pinned Vault
references and digests. The instance-principal fetcher checks the returned
identity and content before durable publication. These paths still require
real OCI qualification and complete runtime handoff.

Credential publication now records the authenticated manifest and exact
service UID/GID before transferring orchestrator credential ownership.
Directories remain root-owned with traversal permission; ts-node secrets stay
root-private. A [privileged temporary-directory test](../evidence/host-secrets-ownership-2026-09-05.txt)
proved service readability and restart recognition of that ownership.
The command checks the durable regional epoch under the authority lock before
initial secret loading. Once runtime authority has retired bootstrap, restart
skips the initial seed so later rotated credentials are not replaced or
rejected against initial digests. This ordering has focused race coverage;
it has not passed real-host credential rotation qualification.

The production composition root still always returns
`ErrProductionCompositionMissing`. This is unfinished implementation, not a
missing-credential or VM-environment gate. `control.OrchestratorOptions`
currently resolves NATS and signed-command identities; it does not resolve the
provider, TerraBase, catalog, notification, or durable operational-service
dependencies required by `productionRuntimeConfig`.

| Runtime input | Existing implementation and exact missing connection |
| --- | --- |
| Signed command dispatch | The master now journals original signed requests, mirrors verified artifacts, and sends signed per-Region commands through runtime-owned global NATS ingress. Regional receivers require both delegated global authority and a live regional lease. Recovery tests cover registry outage, partial mirrors, lost replies, and master takeover. The executable still needs complete root configuration and rollout dependencies; infrastructure must provision the new `GLOBAL_DELIVERIES` R3 bucket. Real-guest delivery qualification remains open. |
| Estate publication | `estate.ControlPlaneClient` implements public document writes. The root now supplies generation and admission checks from its fixed global session. It still needs the configured endpoint and credential, a coherent `estatepublisher.SnapshotSource`, and effective fencing at the external mutation boundary. An empty snapshot cannot establish readiness. |
| Identity and capability rotation | `security.IdentityIssuer` requires `Issue`, `Fetch`, and `Retire`; `CapabilityVault` requires `Generate`, `Fetch`, and `Retire`. Their concrete production implementations are absent. `MemberGateway` still needs member enumeration, distribution, generation verification, activation, retirement, rollback, and fencing; `Reloader` needs reload, verification, rollback, and fencing. These require authenticated host/member transports and durable operation receipts. |
| Cloudflare rotation | The former `CloudflareSecretsStore` adapter used unsupported version/activation endpoints and has been removed. Real CRUD operations use secret IDs and do not provide atomic current/previous activation. Production rotation still needs durable provider-ID receipts, supported consumer bindings and rollout, propagation verification, overlap/retirement proof, and rollback/fencing behavior. The [contract audit](../contracts/cloudflare-rotation-effects.md) records the API sources and remaining requirements. |
| Rotation state | Production key rotation requires `keyrotation.NATSStateStoreConfig` and a separate state session for each coordinator. The root binds the actual candidate, epoch and lease ID after election and owns the connection lifetime. State and quorum read barriers share the global R3 lease stream. Loaded-revision CAS rejects stale writers; late commits retain prior state for recovery. Three-server tests cover restart, minority loss, takeover, lost replies and conflicting sessions. Issued references and publication receipts cannot change within a rotation. The CLI resolver, audit sink and fenced provider adapters remain unfinished. |
| Free database lifecycle | Production construction requires concrete globally fenced NATS state and effect admission checks. Real R3 tests cover restart, stale writers, minority loss, lost replies, lease replacement and late commits, plus day 30/60/90 and reactivation. File persistence is removed; memory state exists only in domain tests. Database, key and mail adapters still need actual production implementations and transport-boundary authority checks. The bounded checkpoint needs [sharding and retention work](../contracts/reaper-state-authority.md) before launch-scale use. |
| Daily restore | Production wrappers validate `BackupPort` and `BranchPort`; they do not implement database enumeration, restore, scratch creation, restored checksum/row-count observation, or owned scratch deletion. The root also needs `JournalPort` facts and fenced run/item persistence and an acknowledged `PagerPort`. `restoredrill.NATSJournal` now persists runs, items, source facts, and restore epochs in the global authority stream. Stream-wide CAS barriers protect successful reads and mutations. Three-node file-backed JetStream tests cover restart, stale writers, minority outage, and late-commit recovery with history 1. Its authoritative facts producer and command wiring remain unfinished. `TickerScheduler` and `NATSJetStreamSnapshotter` exist. `restoresnapshot` now implements signed OCI snapshot writes, full-content verified reads, and per-Region mirrors with durable ownership checks and immutable object keys; its HTTP contract tests pass under race detection. These adapters still need production composition with the authoritative stream and exact regional scopes. VM-local restore adapters are qualification fixtures. |
| Release mirrors | `provider.DeliveryRegionStore` is concrete. The root must bind each admitted Region's OCI `ObjectStorageProvider`, namespace, compartment and bucket to an authoritative `ProviderMutationJournal` and a live `OwnershipCheck`. The delivery and restore paths must share those same scopes and journal. |

OCI resource list adapters now consume canonical array responses and bounded
`opc-next-page` pagination. Network, volume, attachment, Vault, bucket,
availability-domain and instance reads no longer rely on the fixture's old
`items` wrapper. The certificate API retains its canonical collection wrapper.
HTTP contract tests cover page cycles, duplicate resource identities, malformed
collections and later-page failures without returning partial results.
These tests do not replace real-provider qualification.

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

### Local authority and startup evidence, 2026-09-05

The [portable evidence](../evidence/authority-portable-gates-2026-09-05.txt)
records passing portable and sandboxvm-tagged race suites for the authority,
control, snapshot, and fixture-store changes. These results do not establish
production composition or successful guest activation.

The first [VM attempt](../evidence/vm-test-authority-store-identity-2026-09-05.json)
failed before guest creation because the fixture store received the network
run identity instead of the stack UUID. The runtime now passes the stack UUID
and records its cleanup obligation before creating the store. A regression
exercises the actual stack-to-network context propagation.

The next [VM attempt](../evidence/vm-test-authority-guest-start-2026-09-05.json)
booted `gru-member-1` but never reached service readiness. Peak host RSS was
332,275,712 bytes with 512 MiB configured. `ts-node` exited with status 1 and
restarted; orchestrator and TerraBase stayed inactive. Explicit `vm-clean`
passed afterward. No baseline, fourth-Region, fault scenario, or idle resource
budget passed.

Investigation found that the authority client rejected `nats.ClientCert`,
which supplies the verified client certificate through `TLSCertCB`. The
validator now accepts that supported callback while retaining TLS 1.3,
verified server chains, NKey authentication, and disabled mutation buffering.
Real authenticated connection tests reproduce the production credential
loader. Startup diagnostics retain fixed failure categories and preserve an
earlier substantive error when the final attempt times out.

The [callback-fix VM run](../evidence/vm-test-authority-callback-2026-09-05.json)
confirmed `ts-node` active and running, with fresh status showing the signed
artifacts installed. Initial activation then refused a mutation because the
qualification sender has no actual regional authority, and the independent
bootstrap grant path remains unwired. Orchestrator and TerraBase remained
inactive. Peak host RSS was 412,532,736 bytes; no readiness, scenario, or idle
budget passed. Automatic cleanup and explicit `vm-clean` succeeded.

An [abrupt coordinator crash](../evidence/vm-stack-crash-store-2026-09-05.json)
left the journaled first guest and NATS fixture store alive. The first cleanup
refused the active socket because the stack had not yet copied the durable
runtime process identity. Recovery now validates that runtime record against
the run and guest ownership markers, stable process start ticks, and the
claimed executable's device and inode. The inode check handles Firecracker's
jailed `/firecracker` path without accepting a basename match. The corrected
cleaner recovered the same interrupted run successfully; the guest PID, guest
state, fixture store, stack cleanup journal, and planned root links were absent
afterward. The separate network plan file remains as a local artifact. This
qualifies that interrupted-startup cleanup boundary, not the full fault suite.

The [signed-grant VM run](../evidence/vm-test-bootstrap-grant-2026-09-05.json)
exercised authenticated initial drain, deployment, and release through the
real guest `ts-node`. Both orchestrator and TerraBase were activated, then
exited with status 1 and auto-restarted. `ts-node` remained active. Readiness
correctly failed, with peak host RSS 415,526,912 bytes and no scenario pass.
The seed still launches both binaries without complete production
configuration. The captured fixed diagnostics do not identify either exit's
exact cause. Automatic and explicit cleanup passed. This run used the owner
transport grant path; it does not qualify the separate offline bootstrap path.

The [configured GRU attempt](../evidence/vm-test-configured-gru-2026-09-05.json)
launched the orchestrator with its signed settings and captured the fixed
`oci-estate-configuration-missing` category. Activation then stopped because
the command journal rejected the launch field `arguments`. ts-node stayed
active and TerraBase stayed inactive. Peak host RSS was 449,638,400 bytes;
automatic and explicit cleanup passed. No service readiness or scenario
passed. This run predates the credential ownership and retirement integration
and does not qualify that separate path.

The [journal-fix VM run](../evidence/vm-test-configured-journal-fix-2026-09-05.json)
completed initial activation without the rejected-field error. The strict
journal decoder now accepts admitted launch arguments and configuration;
configured replay tests still reject ambiguous and unknown fields.
Both component services then exited with status 1. The orchestrator retained
the exact missing-OCI-configuration category, while TerraBase's fixed
diagnostics did not identify its exit cause. ts-node stayed active. Peak host
RSS was 421,564,416 bytes, and automatic plus explicit cleanup passed.
No full-stack scenario passed. The [final portable evidence](../evidence/bootstrap-delivery-portable-gates-2026-09-05.txt)
records passing `make check` and the complete sandboxvm-tagged race suite for
the integrated source.

The [service-diagnostic VM run](../evidence/vm-test-service-config-diagnostics-2026-09-05.json)
captured both actual guest categories: `oci-estate-configuration-missing` for
the orchestrator and `terrabase-configuration-missing` for TerraBase. Both
services exited with status 1 after activation; ts-node stayed active. Peak
host RSS was 414,420,992 bytes. Automatic and explicit cleanup passed, and no
full-stack scenario passed. These binaries predate the provider package split.

The OCI implementation now separates transport, ownership and resource
adapters in `provider` from reconciliation and bootstrap in `ocireconcile`.
Both packages are below 10,000 Go lines including tests. Consumers use the
extracted APIs directly; no forwarding compatibility layer remains.
The [split verification](../evidence/oci-package-split-gates-2026-09-05.txt)
records passing portable and tagged race suites plus a Linux arm64 cross-build.

NATS subject grammar, taxonomy, account grants, capability policy and the
embedded manifest now live in `natspolicy`. `protocol` retains signed
envelopes, codecs and delivery semantics. Consumers call the extracted APIs
directly. The manifest bytes and protocol test corpus are unchanged, and all
148 existing test and fuzz entry points remain. `protocol` has 7,373 Go lines
including tests; `natspolicy` has 4,526. Every package under `src/orchestrator`
is below 10,000 Go lines, though `hostagent` and `vmqualruntime` have fewer
than 20 lines of room and need extraction before further additions.
The [NATS policy verification](../evidence/natspolicy-split-gates-2026-09-05.txt)
records passing portable and tagged race suites and a Linux arm64 cross-build.
These checks do not establish guest readiness or production composition.

The authority engine now accepts successful lease writes whose stream
revision advances by more than one. Rotation and restore barriers share the
lease stream, so exact-successor revision checks incorrectly fenced valid
renewals. Exact lease identity, epoch, key CAS and overflow checks remain.
The [authority regression evidence](../evidence/authority-stream-revision-gates-2026-09-05.txt)
covers real NATS renewal after sibling-key writes, rejection of stale writes,
successor conflict and journal replay.
