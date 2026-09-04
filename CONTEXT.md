# TerraScale orchestration terminology

The workspace [`GOAL.md`](../GOAL.md) is authoritative. These terms describe
the current target and must not revive the repository's retired container,
generic-scheduler, or regional-blue-green designs.

## Control plane

**TerraScale Orchestrator**  
The Go control plane that declares and reconciles OCI and Cloudflare, places
TerraBase members, operates hosts through `ts-node`, and activates signed
releases. It never carries customer data or serves a customer request.
_Avoid_: container orchestrator, Kubernetes-compatible platform, data plane.

**Declared estate**  
Typed Go configuration containing the complete desired OCI and Cloudflare
estate, including Regions, hosts, storage, networking, identity, edge rules,
telemetry, and health gates.
_Avoid_: manual runbook, console state, best-effort inventory.

**Observed estate**  
Provider and host state re-read by the reconciler before and after a planned
action. Unknown or conflicting authority fails closed.
_Avoid_: assumed state, cached permission to delete.

**Control replica**  
One process participating in the launch JetStream R3 control group. At launch,
one replica is co-hosted in each of GRU, SFO, and FRA; there is one group across
the three Regions.
_Avoid_: independent global master, dedicated control host.

**Regional orchestrator**

The coordinated Go orchestrator processes present in every Region from initial
admission, with one local process on every TerraBase member machine. They
manage local TerraBase instances and reconcile regional OCI resources under
fenced authority issued by the GRU master. It need not host an independent regional JetStream R3.
_Avoid_: remote-only Region, autonomous global master.

**GRU master**

The single active global authority, bootstrapped first. It admits, configures,
upgrades, replaces, and retires regional orchestrators. Global JetStream
replication protects its control state; storage leadership grants no separate
application authority.
_Avoid_: sole durable copy, TerraBase database primary.

**GRU authority**  
The global mutation authority. Losing it may freeze new global control changes
but cannot stop an already admitted data plane.
_Avoid_: TerraBase leader, database primary.

**Control state**  
Fenced, idempotent, restart-safe orchestration intent and receipts stored in
embedded NATS JetStream. It excludes documents, WAL, replication, reactive
frames, query results, and usage truth.
_Avoid_: product database, customer event bus.

## Hosts and delivery

**Member host**  
An admitted Ubuntu LTS machine that runs `ts-node`, TerraBase,
`ts-orchestrator`, and the Grafana agent under systemd. Selected local
orchestrators also host authoritative control-store replicas.
_Avoid_: Kubernetes node, container host.

**`ts-node`**  
The static Go host agent installed by cloud-init and the only component allowed
to mutate a production host. It verifies signatures and digests, installs
versioned binaries, writes hardened units, drains, activates, and rolls back.
_Avoid_: container runtime, package manager, local supervisor.

**Release candidate**  
The signed artifact contract built and submitted by `ts-deploy`. The
orchestrator verifies and mirrors it before any activation.
_Avoid_: mutable tag, latest image, rebuilt rollback.

**GRU canary and rolling rollout**  
Delivery begins on one GRU member, passes drain, process, external health,
replication, and backup gates, then advances one host at a time while preserving
RF=2. Any failed gate returns every touched host to its exact prior digest.
_Avoid_: regional blue-green stack, all-at-once activation.

## Placement

**Launch Region**  
One of GRU, SFO, or FRA. Each begins with two admitted member hosts in separate
failure domains.
_Avoid_: planned Region, edge PoP.

**Placement intent**  
The Region set and peers requested by the orchestrator through private TBEP.
TerraBase owns membership acceptance and replication correctness.
_Avoid_: database leadership, replication implementation.

**Placement lock**  
An immutable residency constraint such as `eu-only`, `br-only`, or an explicit
Region list. Placement, replication, backup, restore, export, branch, repair,
and Region lifecycle must all obey it.
_Avoid_: routing preference, widenable hint.

## Local qualification

**Firecracker qualification stack**  
The mandatory Linux/KVM test environment: six real Ubuntu LTS systemd guests,
the production binaries, provider-contract endpoints, and controlled network,
disk, clock, process, and control-plane faults.
_Avoid_: emulator, container composition, production runtime.

**`SandboxVMProvider`**  
The test-only Go boundary that owns Firecracker lifecycle, guest readiness,
TAPs and Region networks, faultable drives, snapshots, metrics, diagnostics,
and crash-safe cleanup. No production package imports it.
_Avoid_: fake OCI provider, production infrastructure abstraction.

**Provider-contract endpoint**  
A bounded local OCI, Cloudflare, object-storage, or edge endpoint that
reproduces request, response, retry, work-request, timeout, and indeterminate
outcome semantics. It has no backdoor into orchestration decisions.
_Avoid_: unit-test shortcut, claim of real-provider qualification.

**Ready guest**  
A Firecracker guest whose systemd, network, data disk, time configuration,
`ts-node`, and expected service health gate are ready. A running VMM process is
not readiness.
_Avoid_: process started, socket exists.
