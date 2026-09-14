# TerraScale Orchestrator

TerraScale Orchestrator is TerraScale's Go control plane. It provisions the
OCI estate, schedules workloads on plain Linux hosts, manages regional
capacity, coordinates TerraBase Member placement, and owns rollout and
routing through a purpose-built control API.

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

The public Database API is a Go service and the only network TBEP client. It
connects to TerraBase through the shared `terrabase-go` client using
protobuf/gRPC over HTTP/2 with TLS 1.3 mutual authentication. TerraBase
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
gofmt -l .
go vet ./...
go build ./...
go test ./...
go test -race ./...
```

The local rootless runtime guide is
[`docs/guides/running-locally.md`](docs/guides/running-locally.md). OCI setup
is documented in
[`docs/guides/oci-manual-bootstrap.md`](docs/guides/oci-manual-bootstrap.md).
Local process provisioning is a single-host test facility and does not survive
an autoscaler restart.

## Documentation

Run the tooling executable without arguments for the full command inventory.

## Running the current adapter

These commands exercise the current NATS adapter. They do not define the final
product boundary.

```bash
TS_ORCH_CELL=gru \
TS_ORCH_NATS_URL=nats://127.0.0.1:4222 \
TS_ORCH_REPLICAS=1 \
TS_ORCH_PROVIDER=local go run ./cmd/orchestrator check

TS_ORCH_CELL=gru \
TS_ORCH_NATS_URL=tls://control-nats-gru.internal:4222 \
TS_ORCH_REPLICAS=3 \
TS_ORCH_NATS_NKEY_FILE=/run/credentials/terrascale/controller.nk \
TS_ORCH_NATS_TLS_CA_FILE=/run/credentials/terrascale/ca.pem \
TS_ORCH_NATS_TLS_CERT_FILE=/run/credentials/terrascale/controller.pem \
TS_ORCH_NATS_TLS_KEY_FILE=/run/credentials/terrascale/controller-key.pem \
TS_ORCH_PROVIDER=oci \
TS_ORCH_OCI_ESTATE_FILE=/etc/terrascale/oci-estate.json \
  go run ./cmd/orchestrator run
```

OCI mode must run on an OCI compute instance. The orchestrator retrieves the
instance certificate from the fixed instance metadata endpoint and exchanges
it for an in-memory, short-lived session token. No OCI private key file is
configured or written to disk.

Remote NATS connections require TLS, scoped NKey or credentials files, and
complete mutual TLS identity. Credential files must be owner-private. Never
pass raw secret material on the command line or record it in logs, traces,
metrics, NATS, fixtures, or receipts.

The current adapter supports Infisical Universal Auth for secret references.
Explicit typed configuration wins over fetched configuration. The runtime
materializes file-valued secrets into owner-private temporary files and removes
them on shutdown. Production secret retrieval uses authenticated TLS. A
development-only transport or secret default is not part of the target runtime.

## Production repository boundary

The target production solution and artifact contain no embedded development
host, `dev` runtime mode, local product composition, development NATS bootstrap,
development PKI or credentials, fixed lab route, local Podman supervisor,
development-host-specific fixture, or fake-provider runtime registration. Generic fakes
and process fixtures may exist only in test or tooling projects with no
production reference. The current legacy implementation is migration debt, not
a supported Orchestrator feature.

Production releases use regional blue-green. Each Region starts a complete
green generation beside unchanged blue, runs minimum-health, dependency,
authorization, isolation, routing, synthetic customer-journey, and rollback
tests, then switches traffic through one durable routing generation. Failure
before cutover removes only green. Blue remains available through the rollback
window. TerraBase applies the same replacement-before-removal invariant through
surge Members and accepted membership, not a second writable cluster.

## Validation limits

Pure tests and test-owned fixtures do not prove:

- production systemd, containerd, cloud, or provider storage;
- remote mutual TLS and certificate rotation;
- RF=2 local durability and host-loss recovery;
- native TerraBase replication or reactive sync under production load;
- twenty-Region full-mesh behavior;
- noisy-neighbor isolation at measured density;
- direct Auth, Payments, and MCP cutover; or
- public launch readiness.

Production claims require exact candidate-bound evidence from the owning
runtime and the benchmark authority.

## Documentation map

- [Production goal](GOAL.md)
- [Accepted authority ADR](docs/adr/0033-gru-global-authority-and-regional-autonomy.md)
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
