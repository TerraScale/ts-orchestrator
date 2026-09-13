# Architecture boundaries

The workspace [`GOAL.md`](../../../GOAL.md) defines product scope, repository responsibilities,
and release gates.

## Product role

`ts-orchestrator` is TerraScale's product-specific C# control plane targeting
.NET 10. It is the single automation authority for the declared OCI and
Cloudflare estate. It manages Region and host lifecycle, identity, placement
intent, signed release activation, repair coordination, infrastructure
telemetry, and estate-state publication.

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

The executable is `src/TerraScale.Orchestrator`. Its current command surface
is `run` (the default), `check`, `catalog`, `provision-journal`, and
`journal-writer`; `runtime plan` and the read-only `operator status` and
`operator members` queries are handled by the same executable. Use the
[repository README](../../README.md) and [design map](../../DESIGN.md) for
the current .NET restore, build, test, and inspection commands.

## Control topology

GRU starts first and hosts the single active global master. Every Region runs
its own regional orchestrator from initial admission. The master manages
those processes; they reconcile local OCI resources and coordinate TerraBase
members under fenced, Region-scoped authority.

Every TerraBase member machine runs its own local `ts-orchestrator` as a
separate systemd service. Local processes coordinate under fenced regional
authority and use local `ts-node` for host mutations. There are no dedicated
control hosts, including after launch. One selected orchestrator in each of GRU, SFO, and
FRA hosts a global control-store replica. Those embedded NATS replicas form the permanent global JetStream R3 after the temporary pre-customer GRU
R1 bootstrap. Regions 4 through 20 also run regional orchestrators but do not
join the global R3. They use it for authoritative control state. A separate
regional R3 requires at least three eligible hosts and remains post-launch
capacity work. Regional process placement and NATS replica placement are
separate decisions.

Control mutations are fenced, authenticated, idempotent, restart-safe, and
durably journaled. Loss of GRU or NATS can freeze new global mutations but
cannot stop reads, eligible writes, replication, or reconnect recovery in an
already admitted Region.

NATS contains orchestrator control state only, including validated BYOK
provider references and wrapped database-key ciphertext. Customer documents,
WAL, replication frames, reactive frames, query results, usage truth, provider
credentials, and plaintext key material never enter it.
The deployed runtime currently serves one AWS KMS authority tuple per process;
NATS-recovered references are checked against that tuple and mismatches fail
closed. Multi-authority hosting requires a new, qualified credential-source
mapping.

## Estate and providers

The complete desired estate is typed C# configuration. The reconciler observes
OCI and Cloudflare, produces a deterministic dependency-ordered plan, applies
it, re-observes, and records drift and audit events. Missing or ambiguous
ownership fails closed; deletion requires proven TerraScale ownership and
authority.

Routine OCI and Cloudflare changes are automated. The owner performs only
account, plan, payment, and initial credential setup. `bootstrap` creates the
first GRU estate from an empty tenancy and hands authority to the running
control plane. `add-region <code>` creates and qualifies a complete Region.

## Hosts and delivery

Production hosts are Ubuntu LTS minimal. They run `ts-node`, TerraBase,
a local `ts-orchestrator`, and the Grafana
agent. Global control-store replicas run only on selected member hosts. `ts-node` installs versioned static
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

Firecracker on Linux/KVM remains the planned local qualification backend. The
earlier six-guest design and its test-only `SandboxVMProvider` are retained in
the [historical qualification guide](running-locally.md) and dated evidence;
they are not a command surface of the current C# solution.

Bounded local OCI, Cloudflare, object-store, and edge endpoints exercise real
provider contracts and failure semantics. They have no privileged path into
orchestration decisions. Production code cannot import Firecracker or register
the local endpoints.

Unit fakes remain useful but do not qualify host lifecycle, delivery, repair,
networking, storage, or degraded mode. A current C# Firecracker qualification
harness and its command contract still need to be restored before those areas
can be qualified locally. Real OCI and Cloudflare gates still qualify provider
behavior and production performance.

## Trust and visibility

Host and workload identity use short-lived certificates, mutual TLS, SPIFFE
identity, rotated trust bundles, and auditable bootstrap grants. Configuration
contains secret references rather than secret bytes. Secrets and customer
content never enter Git, logs, traces, metrics, fixtures, or receipts.

The orchestrator publishes bounded `estate.*` documents into the control-plane
database on change and at least every ten seconds. The dashboard reads them
through the public SDK. Infrastructure actions remain in the orchestrator CLI;
the dashboard does not gain a private control transport.
