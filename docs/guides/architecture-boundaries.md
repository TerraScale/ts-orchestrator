# Architecture boundaries

The workspace [`GOAL.md`](../../../GOAL.md) is the sole authority. The
repository [`GOAL.md`](../../GOAL.md) collects the requirements that apply to
the orchestrator and defines its Firecracker qualification suite.

## Product role

`ts-orchestrator` is TerraScale's product-specific Go control plane. It is the
single automation authority for the declared OCI and Cloudflare estate. It
manages Region and host lifecycle, identity, placement intent, signed release
activation, repair coordination, infrastructure telemetry, and estate-state
publication.

It is not Kubernetes-compatible, a general workload scheduler, a customer
compute product, a query proxy, or part of the data path. It never owns
database mutations, SQLite behavior, CRDT merge, replication correctness,
reactive sync, or authoritative usage.

| Component | Boundary |
| --- | --- |
| TerraBase | Private Rust engine and public API; owns documents, SQLite, replication, repair correctness, reactive sync, and usage truth. |
| Orchestrator | Declares and reconciles infrastructure, operates hosts, supplies placement intent, coordinates repair, and activates releases. |
| `ts-node` | Only agent allowed to mutate a production host; verifies and installs signed binaries and manages hardened systemd units. |
| Dashboard | Vinext Cloudflare Worker; owns identity, organizations, projects, billing, MCP, and the customer/admin UI. |
| `ts-deploy` | Builds, checks, signs, publishes, and submits candidates; never owns rollout state. |

## Control topology

GRU is the global authority. At launch there are no dedicated control hosts.
One control replica is co-hosted on a member host in each of GRU, SFO, and FRA,
and the three replicas form one embedded JetStream R3 group across those
Regions. A Region can move to an autonomous three-replica regional group only
after it has at least three hosts; that is post-launch capacity work.

Control mutations are fenced, authenticated, idempotent, restart-safe, and
durably journaled. Loss of GRU or NATS can freeze new global mutations but
cannot stop reads, eligible writes, replication, or reconnect recovery in an
already admitted Region.

NATS contains orchestrator control state only. Customer documents, WAL,
replication frames, reactive frames, query results, and usage truth never enter
it.

## Estate and providers

The complete desired estate is typed Go configuration. The reconciler observes
OCI and Cloudflare, produces a deterministic dependency-ordered plan, applies
it, re-observes, and records drift and audit events. Missing or ambiguous
ownership fails closed; deletion requires proven TerraScale ownership and
authority.

Routine OCI and Cloudflare changes are automated. The owner performs only
account, plan, payment, and initial credential setup. `bootstrap` creates the
first GRU estate from an empty tenancy and hands authority to the running
control plane. `add-region <code>` creates and qualifies a complete Region.

## Hosts and delivery

Production hosts are Ubuntu LTS minimal with no container runtime, production
OCI image, or registry. They run only `ts-node`, TerraBase, a control replica
where placed, and the Grafana agent. `ts-node` installs versioned static
binaries under `/opt/terrascale`, verifies ed25519 signatures and SHA-256
digests, writes hardened systemd units, coordinates drain, atomically activates
the new version, and restores the prior digest on rollback.

`ts-deploy` submits a candidate but cannot activate it. The orchestrator first
mirrors accepted artifacts to every Region. TerraBase rollout begins with one
GRU canary and then advances one host at a time across Regions while preserving
RF=2 and enforcing drain, health, replication, backup, and catch-up gates.
There is no regional blue-green product stack.

## Placement and residency

Every launch Region has two admitted member hosts. The orchestrator supplies
TerraBase placement intent and peer lists; TerraBase accepts membership and
owns replication and repair correctness. The orchestrator never appoints a
database leader.

A database placement lock is immutable after creation. Placement,
replication, backup, restore, export, branch, repair, and Region lifecycle all
apply the same lock and cannot widen it.

## Local qualification

Firecracker on Linux/KVM is the mandatory local backend. Six real Ubuntu LTS
systemd guests model the launch estate. A test-only Go `SandboxVMProvider`
owns Firecracker lifecycle, TAP and Region networking, deterministic
`nftables`/`tc netem` faults, persistent and faultable drives, snapshots,
readiness, diagnostics, and crash-safe cleanup.

Bounded local OCI, Cloudflare, object-store, and edge endpoints exercise real
provider contracts and failure semantics. They have no privileged path into
orchestration decisions. Production code cannot import Firecracker or register
the local endpoints.

Unit fakes remain useful but do not qualify host lifecycle, delivery, repair,
networking, storage, or degraded mode. Those areas require the complete
Firecracker-backed `make vm-test`. Real OCI and Cloudflare gates still qualify
provider behavior and production performance.

## Trust and visibility

Host and workload identity use short-lived certificates, mutual TLS, SPIFFE
identity, rotated trust bundles, and auditable bootstrap grants. Configuration
contains secret references rather than secret bytes. Secrets and customer
content never enter Git, logs, traces, metrics, fixtures, or receipts.

The orchestrator publishes bounded `estate.*` documents into the control-plane
database on change and at least every ten seconds. The dashboard reads them
through the public SDK. Infrastructure actions remain in the orchestrator CLI;
the dashboard does not gain a private control transport.

Historical ADRs and contract documents may describe implemented legacy
adapters. They remain evidence, not authority for new work.
