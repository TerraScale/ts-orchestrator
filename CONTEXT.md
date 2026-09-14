# TerraScale orchestration terms

Use these names in code, issues, tests, and documentation.

## Control plane

**TerraScale Orchestrator**

The Go control plane that provisions OCI, schedules TerraScale workloads on
rootless Podman, manages regional capacity and routing, and coordinates
TerraBase placement through a purpose-built control API.

**Global controller**

One replica of the three-replica GRU global control group. The active replica
owns global policy, release admission, the region catalog, Cloudflare intent,
and regional journal aggregation. It is never a database leader.

**Regional controller**

One replica of a region's three-replica control group. The active replica
executes accepted policy through the regional scheduler, provider, identity,
runtime, and routing adapters.

**Regional policy**

A signed, immutable generation of global policy accepted by one regional
group. It is not a raw NATS message, provider observation, or source-repository
manifest.

**Authority claim**

The current term, session, build, protocol generation, lease, and KV revision
that permit a controller to advance control state while local quorum is
healthy. It does not replace provider, storage, identity, or TerraBase
authorization.

## Runtime

**First-party workload**

A TerraScale service admitted from the closed role catalog and run as a
digest-pinned rootless Podman container under a transient systemd user unit.

**Tenant workload**

A post-launch stateless function run as an unprivileged, digest-pinned OCI
container on a dedicated tenant-worker node. It has no durable local state,
host access, provider credentials, or control-plane identity.

**Allocation**

One admitted workload instance bound to a canonical plan fingerprint, node,
resources, identity, configuration, and artifact digest.

**Node**

A plain OCI Linux host managed by one `ts-node` agent. It runs workloads under
an unprivileged account and reports capacity and drain state to its regional
controller.

**Managed TerraBase**

The stateful database workload. TerraBase owns membership, replication,
repair, and durability. Orchestrator owns capacity and fenced placement intent.

## Delivery

**Candidate handoff**

The external signed document that DEP-3 will define and wire from `ts-deploy`,
identifying the source commit and tree, Deploy CLI, immutable image digests,
test results, target, and rollback digest. Until DEP-3 lands, Orchestrator has
no machine-readable candidate handoff and external candidate documents fail
closed; the handoff grants no rollout authority.

**Regional blue-green rollout**

A rollout that starts a complete green generation beside blue, runs the
required checks, and switches traffic through one durable routing generation.
A pre-cutover failure removes only green.

**Rollback digest**

The retained immutable image digest restored without rebuilding.

One admitted workload instance bound to a canonical plan fingerprint, node,
resources, identity, configuration, and artifact digest.

**Launch region**

One of the three customer-selectable regions: GRU in Sao Paulo, SFO in San
Francisco, or FRA in Frankfurt.

**Planned region**

A location beyond GRU, SFO, and FRA. It is not built, tested, or selectable at
launch.

**Region catalog**

The GRU-owned list of regions admitted for customer selection. Provider
discovery alone cannot add a region to the catalog.
