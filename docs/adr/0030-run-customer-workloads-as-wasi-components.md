# Run customer workloads as WASI Components

Status: superseded by [ADR 0031](0031-run-tenant-workloads-as-unprivileged-oci-containers.md) on 2026-08-24; accepted on 2026-08-23

Tracking: [TerraScale.Orchestrator#27](https://git.terrascale.tech/TerraScale/TerraScale.Orchestrator/issues/27)

TerraScale Orchestrator runs signed first-party TerraScale services as trusted
OCI containers and admits customer stateless or serverless workloads only as
WASI Preview 2 Components. HTTP and TerraScale Project Queue are the launch
triggers. The platform owns public listeners and NATS consumers, so customer
components receive neither raw NATS credentials nor unrestricted host
networking.

Each customer allocation receives a separate process and cgroup boundary on a
tenant-worker node, plus a capability-limited WASI host. It is not a hardware
VM boundary. Tenant workers do not share nodes with TerraBase or control-plane
roles. TerraBase remains the only platform-managed stateful workload and runs
as a trusted OCI container under its specialized storage, topology, backup,
restore, upgrade, and recovery controller.

The public artifact and WIT contracts do not name runwasi, Wasmtime, Spin,
wasmCloud, Oracle Cloud Infrastructure, or a host CPU architecture. The first
runtime implementation may use containerd, runwasi, and Wasmtime. Existing
Linux OCI images, native executables, privileged processes, host devices,
arbitrary POSIX applications, GPUs, and unrestricted networking are outside
the launch contract. A later isolated full-Linux tier may use Kata Containers,
but it requires a separate product and architecture decision.

This ADR supersedes [ADR 0027](0027-open-workload-admission.md) and
[ADR 0028](0028-isolate-tenant-workloads-with-microvms.md). ADR 0029 remains in
force.

## Consequences

- Customer language support depends on producing a compatible WASI Component,
  not on accepting source code or Dockerfiles.
- The scheduler maintains separate trusted-container and tenant-component node
  classes, admission policies, capacity measurements, and qualification gates.
- Source components remain portable across supported host architectures, while
  precompiled caches are keyed by runtime compatibility and target
  architecture.
- TerraBase access uses a versioned capability or credential-hiding gateway
  scoped to the invoking tenant and project.
- Bare metal and KVM are no longer launch requirements for customer compute.
  They remain relevant only to a future full-Linux isolation tier.
