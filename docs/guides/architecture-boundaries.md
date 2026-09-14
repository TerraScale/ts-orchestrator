# Architecture boundaries

The workspace [`GOAL.md`](../../../GOAL.md) is authoritative. This page is the
short map for Orchestrator contributors.

## Product roles

| Role | Boundary |
| --- | --- |
| Dashboard | Vinext TypeScript application. Owns Better Auth, organizations, projects, Stripe billing, MCP, and customer workflows. |
| Database API | Go gateway. Owns the public REST and reactive WebSocket API and is the only network TBEP client. |
| TerraBase | Rust database engine. Owns storage, replication, repair, reactive views, backups, and authoritative usage facts. |
| Orchestrator | Go control plane. Owns OCI infrastructure, scheduling, capacity, identity, routing, rollout, and TerraBase placement intent. |
| Deploy | Go CLI used by Forgejo Actions. Builds, tests, publishes images, and submits candidate handoffs. |

Orchestrator never becomes a customer data proxy. Dashboard and customer
applications use the public Database API through `@terrascale/sdk`.

GRU owns the three-replica global authority. GRU, SFO, and FRA each own an
autonomous three-replica regional group and a local JetStream R3 domain. NATS
gateway links move approved control messages between domains. No JetStream
Raft group spans regions.

GRU owns the three-replica global authority. GRU, SFO, and FRA each own an
autonomous three-replica regional group and a local JetStream R3 domain. NATS
gateway links move approved control messages between domains. No JetStream
Raft group spans regions.

When GRU or a gateway is unavailable, a regional quorum continues work already
allowed by its accepted policy. Global policy, catalog changes, new release
admission, and destructive work that needs a complete regional journal wait.
Customer reads, eligible writes, replication, and reactive delivery do not
depend on Orchestrator or NATS availability.

## Database placement and transport

Each database selects from the launch regions GRU, SFO, and FRA. A selected
region stores every logical partition and places two active Members across
independent failure domains.

Orchestrator owns database placement intent, regional capacity, Member and
volume allocation identities, and concrete host placement. TerraBase owns
membership acceptance, replication epochs, repair, catch-up, durability, and
safe retirement. Host pressure may request capacity in a selected region. It
cannot change database geography.

The Database API connects through `terrabase-go` using protobuf/gRPC over
HTTP/2 with TLS 1.3 mutual authentication. TerraBase Member replication uses a
separate direct QUIC transport with mutual authentication. NATS carries neither
protocol.

## Workload runtime

Workloads run as digest-pinned rootless Podman containers inside transient
systemd user units. Container and unit labels bind the allocation ID and
canonical plan fingerprint. Reconciliation refuses foreign, mismatched, or
unfenced processes.

The runtime enforces non-root users, cgroup v2 limits, dropped capabilities,
`no-new-privileges`, read-only root filesystems, seccomp, explicit volumes, and
separate credentials. Stateful placement applies replica anti-affinity and
drain safety before a node can retire.

Tenant compute is the first post-launch feature. The runtime keeps a distinct
unprivileged tenant-container profile without exposing host paths, privileged
execution, provider credentials, or control-plane identities.

## OCI and routing

OCI is the only launch cloud. Ampere ARM64 is the default compute platform.
x86_64 remains supported for TerraBase Members. Provider mutations use
persisted intent, deterministic identities, positive ownership, fenced
authority, and same-operation resume after uncertain outcomes.

Cloudflare owns DNS, global load balancing, TLS termination, and caching for
public cacheable API reads. It does not own control state. Orchestrator manages
the global and regional API hostnames plus the app, docs, and status hostnames
defined by D-24.

## Delivery

Forgejo Actions calls `ts-deploy` to build, test, publish, and submit the exact
candidate digest. The handoff includes source and tree identity, Deploy CLI
identity, image digests, and test results. It does not authorize rollout.

Orchestrator admits the candidate under current fenced authority and owns
regional blue-green rollout, the durable routing generation, and rollback by
the retained digest. CI success on `develop`, immutable image digests, and
tests are the release record. No parallel approval ledger exists.

## Scope limits

Only three regions are built and qualified for launch. The architecture keeps
a ceiling of twenty, but regions four through twenty are post-launch work.
Orchestrator exposes no compatibility API for another cluster manager.
