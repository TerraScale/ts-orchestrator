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

| Flag | Default | Meaning |
| --- | --- | --- |
| `--node-id` | required | lowercase DNS-style node token |
| `--nats-url` | required | regional NATS URL the agent dials |
| `--node-class` | `greenfield` | informational node class token (the provisioner passes it) |
| `--podman-binary` | `/usr/bin/podman` | absolute rootless podman path |
| `--xdg-runtime-dir` | `/run/user/<uid>` | absolute XDG runtime dir of this account |
| `--seccomp-profile` | `/etc/terrascale/seccomp/terrascale-default-v1.json` | absolute path of the seccomp JSON every created container loads (podman fails the create when the file is absent) |
| `--run-as-uid` | current uid | must equal the current uid and be nonzero |
| `--heartbeat-interval` | `10s` | heartbeat cadence |
| `--connect-timeout` | `5s` | NATS dial timeout |
| `--cpu-quota-percent` | `10000` | the node CPU envelope reported in heartbeats |
| `--tasks-max` | `512` | the node task ceiling reported in heartbeats |
| `--logical-cpu-count` | host CPU count | scales the load average into a CPU percent |

The heartbeat's running-task gauge comes from the agent's own tracked
allocations (its executor), not from `/proc/loadavg`, so the autoscaler's
retire gate observes the node's own allocations; the load average only feeds
the CPU-used dimension.

Before the first converge, place a seccomp profile document at the
`--seccomp-profile` path (or point the flag at one) — for local bring-up a
permissive profile is enough to prove the plumbing:

```sh
sudo install -D -m 0644 /dev/null /etc/terrascale/seccomp/terrascale-default-v1.json
echo '{"defaultAction":"SCMP_ACT_ALLOW"}' | sudo tee /etc/terrascale/seccomp/terrascale-default-v1.json >/dev/null
```

NixOS note: podman lives at `/run/current-system/sw/bin/podman`, so pass
`--podman-binary /run/current-system/sw/bin/podman`. Native systemd plans also
need `/usr/bin/systemctl`; on hosts without it, run OCI plans only (the
systemd adapter's binary paths are fixed in the runtime package).

## Terminal 3 — the autoscaler

The orchestrator's `autoscaler` role reads its explicit configuration from
documented environment variables (run `./bin/orchestrator catalog` for the
full list), ticks the deterministic engine, and executes the actions it
emits: provision/retire through a local process provisioner that spawns
`ts-node` as the configured unprivileged uid, and cordon through the node's
NATS subject.

```sh
TS_ORCH_NATS_URL=nats://127.0.0.1:4222 \
TS_ORCH_AUTOSCALER_TICK_INTERVAL=10s \
TS_ORCH_AUTOSCALER_MIN_NODES=1 \
TS_ORCH_AUTOSCALER_MAX_NODES=3 \
TS_ORCH_AUTOSCALER_SCALE_UP_HEADROOM_PERCENT=30 \
TS_ORCH_AUTOSCALER_SCALE_DOWN_HEADROOM_PERCENT=40 \
TS_ORCH_AUTOSCALER_SCALE_UP_CONFIRM_TICKS=2 \
TS_ORCH_AUTOSCALER_SCALE_DOWN_CONFIRM_TICKS=3 \
TS_ORCH_AUTOSCALER_MAX_CONCURRENT_PROVISIONS=2 \
TS_ORCH_AUTOSCALER_FLAP_SUPPRESSION_TICKS=3 \
TS_ORCH_AUTOSCALER_AGENT_BINARY=/abs/path/to/bin/ts-node \
TS_ORCH_AUTOSCALER_RUN_AS_UID=1000 \
TS_ORCH_AUTOSCALER_DRAIN_MAX_LAG_BYTES=1048576 \
TS_ORCH_PROVIDER=local \
  ./bin/orchestrator autoscaler
```

What it does on every tick: nodes are tracked from their heartbeats (a node
silent for three tick intervals leaves the snapshot), the drain gate consults
the stateful `ReplicaDrainSafetyEvaluator`, and the emitted actions are
applied fail-closed — the role stops on the first failed provision, cordon,
or retire rather than retrying blind. A scheduler publishes the typed,
complete observation feed on `terrascale.scheduler.v1.autoscaler`; fresh
`demandComplete` data can drive scale-up, while fresh `placementComplete`
data is required before any drain. Missing or stale feed data never becomes
synthetic demand or replica health.

## Sending a converge request

A workload command is a `WorkloadCommandRequest` — the serialized canonical
plan plus a bounded command id — sent as a NATS request on the node's
converge subject. The `planJson` field is a byte array on the wire, so the
plan text must be base64-encoded; with the `nats` CLI and `jq`:

```sh
nats req terrascale.node.v1.as-node-1.converge \
  "$(jq -Rs '{planJson: (@base64), commandId: "local-converge-1"}' < plan.json)"
```

where `plan.json` is a canonical plan. This is a complete, valid example for
an OCI dashboard allocation (the digest must be the real sha256 of the
artifact; the image reference must resolve where the node can pull it):

```json
{
  "schemaVersion": 2,
  "role": "customerDashboard",
  "driver": "ociContainer",
  "allocationId": {
    "value": "dashboard-a"
  },
  "artifactDigest": {
    "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  },
  "architecture": "x64",
  "resources": {
    "memoryMaxBytes": 1073741824,
    "tasksMax": 512,
    "cpuQuotaPercent": 200,
    "cpuWeight": 500,
    "ioWeight": 300,
    "nice": 0,
    "memoryHighBytes": 966367641,
    "memorySwapMaxBytes": 0
  },
  "systemd": null,
  "oci": {
    "containerId": "terrascale-dashboard-a",
    "imageReference": "registry.terrascale.internal/terrascale/terrascale-dashboard@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "platform": "linux/amd64",
    "security": {
      "runAsUser": 65532,
      "runAsGroup": 65532,
      "noNewPrivileges": true,
      "readOnlyRootFileSystem": true,
      "droppedCapabilities": ["ALL"],
      "seccompProfile": "terrascale-default-v1",
      "cgroupParent": "terrascale/dashboard-a"
    },
    "resources": {
      "memoryMaxBytes": 1073741824,
      "tasksMax": 512,
      "cpuQuotaPercent": 200,
      "cpuWeight": 500,
      "ioWeight": 300,
      "nice": 0,
      "memoryHighBytes": 966367641,
      "memorySwapMaxBytes": 0
    }
  }
}
```

The agent decodes the payload through the strict plan decoder (unknown
fields, wrong schema versions, and non-canonical execution plans are
rejected), re-computes the canonical fingerprint, and fences the podman
container with the `terrascale.allocation` and `terrascale.fingerprint`
labels. The reply is the `ConvergeReceipt`:

```json
{"CommandId":"local-converge-1","Accepted":true,"Detail":"Allocation dashboard-a converged through the OciContainer driver.","PlanFingerprint":"<64-hex-fingerprint>"}
```

The other subjects follow the same shape: `observe`, `stop`, and `delete`
take the same command payload and answer with their receipts; `cordon` takes
`{"commandId":"...","cordoned":true}` and answers with an acknowledgment;
`drain-status` takes `{"commandId":"..."}` and answers with the node's
allocation observations.

## The tests

The deterministic proof (embedded NATS, real agent and engine, fake podman —
no network, no containers):

```sh
go test ./tests/ -run TestPodmanAutoscaleLaneEndToEnd -v
```

The live podman smoke is gated twice — by the `live_podman` build tag and by
`TS_ORCH_LIVE=1` — so the ordinary sweep never touches a real runtime. It
runs the real `ProcessPodmanClient` as your unprivileged user against the
local image `localhost/benchmark-csharp-noble:latest` (present on this host;
it never pulls from the network) and asserts preflight, create (not
started), start, Running, stop, delete, and Absent:

```sh
TS_ORCH_LIVE=1 go test -tags live_podman ./tests/live/ -run Podman -v
```

Set `TS_ORCH_LIVE_PODMAN_BINARY=/abs/path/to/podman` to point it at a
non-default podman installation.
