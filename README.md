# TerraScale Orchestrator

TerraScale Orchestrator is TerraScale's C# control plane, deployed as a
single binary. It provisions the OCI estate, schedules workloads on plain
Linux hosts, manages regional capacity, coordinates TerraBase Member
placement, and owns rollout and routing through a purpose-built control API.

The workspace [`GOAL.md`](../GOAL.md) is the cross-repository authority. In priority
order, this repository optimizes for: green suites on every merge; one-command deploys
that hosts converge leaderlessly through NATS; NATS carrying state, artifacts, and
observations end to end; cells that auto-form and auto-join; and real-microVM multi-region
proof. [ADR 0034](docs/adr/0034-autoforming-cells-and-leaderless-host-convergence.md)
records the decisions behind the deploy path.

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
  `status.terrascale.tech`; and
- versioned database/branch placement publication to the edge routing KV for
  SDK discovery, through the ordered, idempotent, retryable EdgeRouting
  publisher (`src/TerraScale.Orchestrator/ControlPlane/EdgeRouting/`, ADR 0050
  §6).

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
domains. Orchestrator supplies capacity and fenced placement intent; the
resulting database/branch placements are published to the edge routing KV so
SDK discovery serves the same intent. TerraBase
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

The remaining suites are `TerraScale.Orchestrator.ControlPlane.Tests`,
`TerraScale.Orchestrator.Protocol.Tests`, `TerraScale.Orchestrator.Scheduler.Tests`, and
`TerraScale.Orchestrator.ModelTests`. The live Firecracker lanes additionally need KVM,
sudo, and prepared inputs:

```bash
TS_ORCH_LIVE_VM=1 TS_ORCH_VM_INPUTS=<inputs> \
  dotnet run --project tests/TerraScale.Orchestrator.Tests -c Release --no-build
```

## Deploying a new TerraBase version

[ADR 0034](docs/adr/0034-autoforming-cells-and-leaderless-host-convergence.md) records the
decisions; the operator path is:

```bash
# 1. publish the artifact into the regional NATS object store (prints its sha256)
terrascale-orchestrator operator artifact-push --file ./terrabase-server \
  --cell gru --nats-url tls://... --nkey-file ... --tls-ca-file ... --tls-cert-file ... --tls-key-file ...

# 2. admit the new digest through the signed direct-delivery endpoint
terrascale-orchestrator operator deploy \
  --service terrabase-server --digest sha256:... --manifest-digest sha256:... \
  --regions gru --source-repository TerraScale/TerraBase \
  --source-commit <40-hex> --source-tree-digest sha256:... \
  --reason "ship v1.2.3" --key-file operator.pem \
  --cell gru --nats-url tls://... --nkey-file ... --tls-ca-file ... --tls-cert-file ... --tls-key-file ...
```

Production provenance additionally requires one durable signed evidence record per artifact
(the CI normally writes it); on a day-one cell, record it once with the CI-artifact key:

```bash
terrascale-orchestrator operator evidence-record   --digest sha256:... --manifest-digest sha256:...   --source-repository TerraScale/TerraBase --source-commit <40-hex>   --source-tree-digest sha256:... --key-file ci-artifact.pem   --cell gru --nats-url tls://... --nkey-file ... --tls-ca-file ... --tls-cert-file ... --tls-key-file ...
```

Every host configured with `TS_ORCH_HOST_ROLES=terrabase-member` then converges itself:
fetch by digest from `ORCH_ARTIFACTS`, verify SHA-256, install under the immutable digest
path, stop the old unit, converge the systemd unit bound to the new binary, observe, and
report. The member's `TERRABASE_*` configuration ships as
`TS_ORCH_HOST_ENV_DIR/terrabase-server.env`, copied to the unit's environment file on every
converge. Stateful roles serialize through the cell replace lease; a failed replacement
restores the exact previous digest. Rollback is a deploy of the previous digest with the
same command.

## Auto-forming cells

`run` converges the regional controller topology idempotently at startup (streams, KV,
object stores, consumers): the first instance creates the cell, later instances join, and
`TS_ORCH_AUTO_PROVISION=0` restores infrastructure-only provisioning. The infrastructure
`ORCH_OPERATIONS` journal always stays with the `provision-journal` command.

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
