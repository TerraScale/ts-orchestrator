# Firecracker local qualification (historical design)

This guide preserves the Firecracker qualification design and command output
from the pre-C# implementation. It is historical evidence for the host,
delivery, repair, degraded-mode, and fault-handling requirements; it is not a
current command interface. The current C# runtime commands are documented in
the repository [README](../../README.md) and [design map](../../DESIGN.md).

The [workspace goal](../../../GOAL.md#ts-orchestrator) still requires the complete orchestrator to run locally on
real Ubuntu LTS systemd guests under Firecracker. Running `ts-node` directly
on the developer host is not equivalent.

The targets described here were the required interface for that earlier
implementation. They are not implemented by the current C# solution. Until a
C# qualification harness and its command contract are restored, local VM
qualification remains incomplete.

## Boundary

Firecracker is test infrastructure, never a production provider. The
historical test-only Go `SandboxVMProvider` controlled Firecracker through the
pinned official Go SDK and a typed Unix-socket OpenAPI client for operations
the SDK did not expose. Production packages cannot import either client.

Local provider-contract endpoints stand in for OCI, Cloudflare, object
storage, and the edge. They reproduce authentication, pagination, etags, rate
limits, asynchronous work requests, retries, conflicts, timeouts, uncertain
mutations, and eventual consistency. They do not bypass the public command,
reconciler, delivery API, or `ts-node`, and passing them is not proof that a
real cloud account is healthy.

## Required host

The qualifying host is Linux with:

- writable KVM access;
- the repository-pinned Firecracker and `jailer` binaries;
- the required kernel virtualization features;
- `ip`, `nft`, and `tc` for provider-owned networks and faults;
- the safe block-device facilities selected by the disk-fault implementation;
- enough disk for the base guest and six copy-on-write or sparse instance
  disks; and
- at least 4 GiB available for the bounded VM stack, outside the build and
  test-controller processes.

The historical `make vm-doctor` command checked every prerequisite without
changing host state. It
prints the failed capability and repair action, verifies every pinned digest,
and refuses to qualify macOS, Windows, software emulation, or a Linux host
without KVM. An amd64 host runs amd64 guests and an arm64 host runs arm64
guests; Firecracker does not perform cross-architecture emulation.

Creating TAPs, namespaces, traffic rules, and some block faults requires
narrow host privileges. The provider must use a small audited setup boundary
limited to TerraScale-labelled resources. It cannot grant the whole test
controller unrestricted persistent root access.

## Guest artifact

The historical `make vm-image` command reproducibly built or verified a
versioned Ubuntu LTS minimal
raw disk, guest kernel, and cloud-init seed template. Every input and output is
checksum-verified. The build uses no Docker, Podman, containerd, OCI image, or
remote install script.

The guest must provide:

- systemd as PID 1 and cgroup v2;
- a unique machine ID, hostname, host key, and cloud-init instance identity;
- one root disk and a separate persistent TerraScale data disk;
- deterministic network and DNS configuration;
- the same system users and systemd facilities required on OCI Ubuntu hosts;
- console and journal collection with bounded output; and
- a test-only SSH or vsock control channel for copying binaries, executing
  diagnostics, and checking readiness.

That control channel may prepare a test, but cannot replace the production
`ts-node` path being tested. A guest becomes ready only after systemd is
running, its network and data disk are ready, time configuration is applied,
`ts-node` is healthy, and the expected service passes its real health gate.
Firecracker process startup alone is never a readiness signal.

## Six-host topology

The full stack mirrors the launch estate:

```text
GRU: gru-member-1 + gru-member-2, control on gru-member-1
SFO: sfo-member-1 + sfo-member-2, control on sfo-member-1
FRA: fra-member-1 + fra-member-2, control on fra-member-1
```

Each guest has one vCPU and 256–512 MiB configured memory. The six guests must
stay at or below 4 GiB aggregate idle host RSS and one aggregate idle host CPU
core. Tests record configured memory, boot and ready time, peak and idle RSS,
idle CPU, disk usage, and cleanup time and fail the declared limits.

The provider creates a stable private endpoint for every guest, an isolated
local network per Region, and explicit links between Regions. Traffic never
uses production services. `nftables` partitions a Region or Region pair while
preserving the selected local network. `tc netem` adds deterministic latency,
jitter, loss, reordering, duplication, and bandwidth ceilings. Removing a
profile restores the baseline and the test verifies recovery.

Firecracker file-backed drives and safe host block controls provide persistent
restart, fill, expansion, read-only and I/O-error transitions, detach and
reattach, selected corruption, snapshots, and restore. A fault targets a data
disk unless the test explicitly exercises root-disk or host loss.

## Historical pre-C# commands

The following invocation is retained to identify the commands used by the
dated qualification records. It is not runnable in the current checkout:

```bash
make vm-doctor
make vm-image
make vm-smoke
make vm-stack
make vm-test
make vm-clean
```

The targets have these contracts:

- `vm-doctor` is read-only and validates the host and all pinned artifacts.
- `vm-image` produces or verifies the reproducible Ubuntu systemd artifacts.
- `vm-smoke` creates one guest and proves boot, explicit readiness, execution,
  cgroup v2, systemd hardening, network, disk persistence, diagnostics, and
  cleanup.
- `vm-stack` starts the six guests and local provider endpoints and prints only
  bounded connection information, never credentials.
- `vm-test` owns its stack, runs the full acceptance suite, collects bounded
  failure diagnostics, and always attempts cleanup.
- `vm-clean` reads the provider's cleanup journal and removes only exact,
  labelled TerraScale test resources. It never scans and deletes unrelated
  Firecracker processes, TAPs, namespaces, rules, disks, or directories.

The provider writes its cleanup journal before creating each host resource.
The next invocation can therefore recover after cancellation, a failed
assertion, a controller crash, or a Firecracker/jailer crash without guessing
ownership.

## What `vm-test` proves

The suite covers:

1. greenfield GRU bootstrap followed by `add-region sfo` and `add-region fra`;
2. the three co-hosted replicas forming one cross-Region JetStream R3 group;
3. declared OCI and Cloudflare reconciliation, including drift, retries,
   eventual state, uncertain mutations, and refusal to delete unowned state;
4. signed `ts-node` installation, hardened units, drain, health, activation,
   catch-up, rollback, and persistent data;
5. the GRU canary and one-host-at-a-time rollout while RF=2 remains available;
6. Worker and Snippet promotion and rollback through the local edge contracts;
7. KV ordering and refresh, estate publication, metrics, logs, and bounded
   labels;
8. host loss, Region loss, partitions, latency and loss, clock skew, disk
   faults, expired certificates, A1-capacity failure, and E5 selection;
9. placement-lock enforcement across placement, replication, backup, restore,
   export, branching, repair, and Region changes;
10. restore drills, JetStream snapshots, and per-Region artifact mirrors;
11. the admitted data plane continuing while GRU, NATS, or the control plane is
    unavailable; and
12. idempotent cleanup after normal completion and every supported interruption.

Real GRU bootstrap, Cloudflare convergence, production performance, WAN
behavior, and provider availability remain separate production gates. The
Firecracker suite must pass before those gates are attempted; it does not
replace them.
