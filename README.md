# TerraScale Orchestrator

`ts-orchestrator` is TerraScale's Go control plane and our Kubernetes
alternative. It declares and reconciles the complete OCI and Cloudflare estate,
runs signed TerraScale binaries under systemd, places TerraBase members, and
repairs drift and host failures. It is never on the customer data path.

The workspace [`GOAL.md`](../GOAL.md) defines product scope, repository responsibilities,
and release gates.

## Boundary

The orchestrator owns:

- OCI compartments, networking, compute, block and object storage, Vault,
  certificates, identity, and lifecycle policy;
- Cloudflare DNS, Cache Rules, Snippets, Worker promotion, KV, WAF, rate rules,
  capability keys, and certificates;
- Region and host bootstrap, capacity, drain, replacement, and safe removal;
- `ts-node`, signed artifact installation, hardened systemd units, activation,
  health gates, and rollback;
- TerraBase placement intent, residency locks, peer lists, repair coordination,
  and backup/restore orchestration through private TBEP gRPC;
- the delivery API consumed by `ts-deploy`, canary and rolling rollout state,
  and automatic rollback;
- embedded NATS JetStream control state; and
- infrastructure telemetry and `estate.*` publication for the admin console.

For customer-managed encryption (BYOK), NATS persists only validated provider
references and wrapped database-DEK ciphertext needed for restart and recovery.
Provider credentials, imported/raw keys, unwrapped DEKs, and customer data stay
in workload-identity or secret-provider boundaries and never enter NATS.
The current runtime binds one AWS KMS workload-identity tuple per process and
fails closed when an admitted reference differs. A multi-authority process
requires a separately qualified credential-source mapping; NATS persistence
does not grant the orchestrator customer-provider credentials by itself.

It does not own database mutations, SQLite or CRDT behavior, replication
correctness, reactive delivery, usage truth, billing, authentication, SDK
behavior, arbitrary customer workloads, or a public query proxy.

## Launch shape

GRU starts first and hosts the single active global master. Every Region runs
its own co-hosted regional orchestrator to manage its OCI resources and
TerraBase members under GRU authority. The GRU, SFO, and FRA processes also
host the permanent global JetStream R3. Later Regions run regional
orchestrators without joining that global storage group. Each Region starts
with two admitted TerraBase member hosts.

Bootstrap uses a temporary pre-customer GRU R1, then admits synchronized SFO
and FRA replicas and promotes to R3 before customer admission. Existing
Regions keep serving when the orchestrator, GRU, or NATS is unavailable.

Production hosts are Ubuntu LTS minimal and contain no Docker, Podman,
containerd, container image, or registry. Cloud-init installs only `ts-node`.
It verifies signed binaries, writes hardened systemd units, and performs
orchestrator-coordinated drain, activation, and rollback. Ampere A1 arm64 is
the default host shape and E5 amd64 is the automatic capacity fallback.

`ts-deploy` builds, signs, publishes, and submits a binary candidate (D-68).
The orchestrator mirrors it into every Region, deploys one GRU canary, then
rolls one host at a time while preserving RF=2 (D-67). It owns Worker and
Snippet promotion as well.

## Firecracker qualification

Every orchestrator behavior must pass locally without OCI or Cloudflare
credentials on real Ubuntu LTS systemd guests under Firecracker on Linux/KVM.
Another VMM, containers, host processes, and fakes alone do not qualify the
host lifecycle.

The test-only Go `SandboxVMProvider` uses the pinned official Firecracker Go
SDK and the pinned Unix-socket OpenAPI for operations absent from the SDK. It
owns TAPs, Region bridges or namespaces, `nftables` partitions, `tc netem`
profiles, persistent and faultable drives, snapshots, guest readiness, bounded
diagnostics, and crash-safe cleanup. Local OCI and Cloudflare endpoints model
their real contracts and failures without entering production composition.

The required workflow is:

```bash
make vm-doctor
make vm-image
make vm-smoke
make vm-stack
make vm-test
make vm-clean
```

`make vm-test` runs the six-host GRU/SFO/FRA topology and covers bootstrap,
`add-region`, R3 control, reconciliation, systemd delivery and rollback,
placement locks, host and Region failure, partitions and latency, storage
faults, certificate and key rotation, restore drills, degraded mode, and
cleanup after interruption. See [running locally](docs/guides/running-locally.md).

The Firecracker targets are part of the accepted design but are not all
implemented in the current worktree yet. Until they land, passing the existing
Go tests does not qualify production-facing orchestration behavior.

## Current implementation

The checked-in code is organized around the Go control plane and its native
systemd host agent. New work deletes retired roles and topology in the same
series and preserves durable control history and fail-closed behavior during
cutover.

Focused Go validation is:

```bash
gofmt -l .
go vet ./...
go build ./...
go test -race ./...
```

`make check` is the portable repository verification set. The separate
Firecracker `make vm-test` gate runs on Linux/KVM before candidate submission
on every `develop` push, including documentation changes.

## Documentation

- [Workspace goal](../GOAL.md#ts-orchestrator)
- [Documentation index](docs/README.md)
- [Architecture boundaries](docs/guides/architecture-boundaries.md)
- [Firecracker local qualification](docs/guides/running-locally.md)
- [Production readiness and refactoring inputs](docs/guides/production-readiness.md)
- [Current package map](DESIGN.md)
- [Current terminology](CONTEXT.md)
