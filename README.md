# TerraScale Orchestrator

`ts-orchestrator` is TerraScale's Go control plane and our Kubernetes
alternative. It declares and reconciles the complete OCI and Cloudflare estate,
runs signed TerraScale binaries under systemd, places TerraBase members, and
repairs drift and host failures. It is never on the customer data path.

The workspace [`GOAL.md`](../GOAL.md) is the sole product authority. The
repository [`GOAL.md`](GOAL.md) collects the decisions that apply here and adds
the Firecracker qualification contract. Historical ADRs and implementation
records explain old code; they do not override either goal.

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

It does not own database mutations, SQLite or CRDT behavior, replication
correctness, reactive delivery, usage truth, billing, authentication, SDK
behavior, arbitrary customer workloads, or a public query proxy.

## Launch shape

GRU is the global authority. At launch, one control replica is co-hosted on a
member host in each of GRU, SFO, and FRA; those three replicas form one
JetStream R3 control group across the Regions. Each Region has two admitted
TerraBase member hosts. Existing Regions keep serving when the orchestrator,
GRU, or NATS is unavailable.

Production hosts are Ubuntu LTS minimal and contain no Docker, Podman,
containerd, container image, or registry. Cloud-init installs only `ts-node`.
It verifies signed binaries, writes hardened systemd units, and performs
orchestrator-coordinated drain, activation, and rollback. Ampere A1 arm64 is
the default host shape and E5 amd64 is the automatic capacity fallback.

`ts-deploy` builds, signs, publishes, and submits a candidate. The orchestrator
mirrors it into every Region, deploys one GRU canary, then rolls one host at a
time while preserving RF=2. It owns Worker and Snippet promotion as well.

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

The checked-in code still contains earlier control contracts and migration
debt. Current commands describe that code only. New work must move toward the
goals, delete retired roles and topology in the same series, and preserve
durable control history and fail-closed behavior during cutover.

Focused Go validation is:

```bash
gofmt -l .
go vet ./...
go build ./...
go test -race ./...
```

The complete repository verification set is `make check`; under the target
contract it also runs the Firecracker smoke and full VM qualification on a
Linux/KVM runner.

## Documentation

- [Repository goal](GOAL.md)
- [Documentation index](docs/README.md)
- [Architecture boundaries](docs/guides/architecture-boundaries.md)
- [Firecracker local qualification](docs/guides/running-locally.md)
- [Current package map](DESIGN.md)
- [Current terminology](CONTEXT.md)
- [Superseded architecture record](docs/architecture/orchestrator.md)

Historical ADRs, phase records, and evidence remain records of what was once
implemented or decided. Their bodies must not be cited as current authority
when they conflict with the workspace or repository goal.
