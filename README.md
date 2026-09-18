# TerraScale Orchestrator

TerraScale Orchestrator is TerraScale's C# control plane, deployed as a
single binary. It provisions the OCI estate, schedules workloads on plain
Linux hosts, manages regional capacity, coordinates TerraBase Member
placement, and owns rollout and routing through a purpose-built control API.

The workspace [`GOAL.md`](../GOAL.md) is the cross-repository authority. The
repository [`GOAL.md`](GOAL.md) points to that authority and records any
repository-local context.

## Ownership boundary

The control plane contains the following responsibilities:

- the GRU global control group and each regional control group;
- OCI compute, block storage, attachments, registry access, control backups,
  and the verified estate configuration;
- rootless workload hosting, placement, autoscaling, cordon, drain, and node
  retirement;
- workload identities, certificates, trust bundles, and secret references;
- TerraBase Member and volume allocation intent;
- regional blue-green rollout and rollback by immutable digest; and
- Cloudflare routing for `api.terrascale.tech`, the GRU, SFO, and FRA regional
  API endpoints, `app.terrascale.tech`, `docs.terrascale.tech`, and
  `status.terrascale.tech`.

It does not own database mutations, CRDT merge semantics, replication,
reactive subscriptions, authoritative usage accounting, customer identity,
billing, SDK behavior, or customer API proxying.

## Control topology

GRU holds the three-replica global authority. GRU, SFO, and FRA each run an
autonomous three-replica regional control group. Each group uses a local
file-backed JetStream R3 domain. NATS gateways distribute approved control
subjects between domains, but no Raft group spans a WAN link.

NATS stores Orchestrator control state only. It never carries customer
documents, WAL records, replication frames, query results, reactive frames, or
usage truth. Existing customer data paths keep serving when the control plane
is unavailable.

## Workload hosting

Production workloads run as rootless Podman containers supervised by transient
systemd user units. Every container and supervisor unit carries the canonical
allocation identity and plan fingerprint. A missing or mismatched fence stops
reconciliation instead of adopting the process.

The runtime requires cgroup v2, the systemd cgroup manager, seccomp, a read-only
root filesystem, dropped capabilities, `no-new-privileges`, bounded resources,
and explicit persistent volumes. TerraBase replicas use anti-affinity and drain
safety so node churn cannot remove the required regional replica floor.

## Database boundary

The public Database API service is the only network TBEP client. It connects
to TerraBase over HTTP/2 with TLS 1.3 mutual authentication. TerraBase
Member-to-Member replication uses its own direct QUIC transport with mutual
authentication. Orchestrator is not on either data path.

Each database chooses from the three launch regions. Every selected region
places two active TerraBase Members per partition across independent failure
domains. Orchestrator supplies capacity and fenced placement intent. TerraBase
alone accepts membership, repair, replica retirement, and durability facts.

## Delivery

`ts-deploy` runs in Forgejo Actions and owns build, test, image publication,
and candidate handoff. The handoff identifies the source commit and tree, the
Deploy CLI version, immutable image digests, and test results. It grants no
rollout authority.

Orchestrator verifies the handoff, admits the exact digest, creates a full
green regional generation beside blue, switches traffic through a durable
routing generation, and rolls back by digest. It never rebuilds during
promotion or rollback.

## Local verification

```bash
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --configuration Release --no-restore
dotnet run --project tests/TerraScale.Orchestrator.Tests -c Release --no-build
```

OCI setup is documented in
[`docs/guides/oci-manual-bootstrap.md`](docs/guides/oci-manual-bootstrap.md).

## Documentation

- [Documentation index](docs/README.md)
- [Architecture boundaries](docs/guides/architecture-boundaries.md)
- [GRU and regional authority](docs/adr/0033-gru-global-authority-and-regional-autonomy.md)
- [Rootless Podman hosting](docs/architecture/podman-rootless-hosting-and-autoscaling.md)
- [Durable work inventory](docs/contracts/durable-work-inventory.md)
- [Controller membership](docs/contracts/controller-membership.md)
- [NATS monitoring snapshot](docs/contracts/nats-monitoring-snapshot.md)
- [NATS gateway operations](docs/runbooks/nats-gateway-operations.md)
- [NATS monitoring](docs/runbooks/nats-monitoring.md)
- [OCI manual bootstrap](docs/guides/oci-manual-bootstrap.md)
