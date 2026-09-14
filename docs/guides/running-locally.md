# Firecracker local qualification (historical design)

This guide composes the lane end to end on one development host: NATS, one or
more `ts-node` host agents, and the local process provider driven by the real
autoscaler engine. Everything runs under your own unprivileged account.
`ts-node` starts each rootless Podman container inside a fenced transient
systemd user unit. The agent rejects uid 0 and setuid execution before it
parses the rest of its configuration.

The [workspace goal](../../../GOAL.md#ts-orchestrator) still requires the complete orchestrator to run locally on
real Ubuntu LTS systemd guests under Firecracker. Running `ts-node` directly
on the developer host is not equivalent.

The targets described here were the required interface for that earlier
implementation. They are not implemented by the current C# solution. Until a
C# qualification harness and its command contract are restored, local VM
qualification remains incomplete.

- rootless Podman 5.x with cgroup v2 delegation (`podman info` must succeed as
  your user), plus `systemctl` and `systemd-run` for a systemd **user** manager
  with linger enabled (`loginctl enable-linger "$USER"`);
- Go 1.27;
- the regional NATS URL you will use everywhere below, written `nats://127.0.0.1:4222`
  in the examples.

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

For a single node, either run the orchestrator's embedded NATS role from an
explicit configuration file:

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

…or start any NATS server that listens on the URL the other roles use. The
node transport only needs core NATS (no JetStream). A local `nats://` URL is
accepted for this single-host lane. The production autoscaler command requires
`tls://`, a scoped NKey, and mTLS files, as shown below.

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

`ts-node` is the per-node host agent binary. Every input is an explicit flag;
the only ambient reads are the current uid (for the `--run-as-uid` default)
and the CPU count (for `--logical-cpu-count`). It validates the rootless
context at startup and exits non-zero before touching anything if either its
real or effective uid is 0, or if those uids differ. `--run-as-uid` must equal
that nonzero effective uid.

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
| `--systemctl-binary` | `/usr/bin/systemctl` | absolute systemctl path used with `--user` |
| `--systemd-run-binary` | `/usr/bin/systemd-run` | absolute systemd-run path used to create transient user units |
| `--xdg-runtime-dir` | `/run/user/<uid>` | absolute XDG runtime dir of this account |
| `--seccomp-profile` | `/etc/terrascale/seccomp/terrascale-default-v1.json` | absolute path of the seccomp JSON every created container loads (podman fails the create when the file is absent) |
| `--nats-nkey-file` | none | production NKey seed path; required with `tls://` |
| `--nats-tls-ca-file` | none | production NATS CA path; required with `tls://` |
| `--nats-tls-cert-file` | none | production NATS client certificate path; required with `tls://` |
| `--nats-tls-key-file` | none | production NATS client key path; required with `tls://` |
| `--run-as-uid` | current uid | must equal the current uid and be nonzero |
| `--heartbeat-interval` | `10s` | heartbeat cadence |
| `--connect-timeout` | `5s` | NATS dial timeout |
| `--cpu-quota-percent` | `10000` | the node CPU envelope reported in heartbeats |
| `--tasks-max` | `512` | the node task ceiling reported in heartbeats |
| `--logical-cpu-count` | host CPU count | scales the load average into a CPU percent |

For an OCI allocation named `dashboard-a`, the supervisor unit is
`terrascale-dashboard-a.service`. Its description contains the exact
`terrascale.allocation`, `terrascale.fingerprint`, and immutable 64-hex Podman
container ID. `ExecStart` and `ExecStop` address that immutable ID, not the
reusable container name. An existing running container with an absent unit, a
mismatched description, or a replacement container under the same name fails
closed instead of being adopted. Inspect it with:

```sh
systemctl --user status terrascale-dashboard-a.service
systemctl --user show terrascale-dashboard-a.service \
  --property=Description --property=ActiveState
podman inspect terrascale-dashboard-a \
  --format '{{ index .Config.Labels "terrascale.allocation" }} {{ index .Config.Labels "terrascale.fingerprint" }}'
```

The heartbeat's running-task gauge comes from the agent's own tracked
allocations (its executor), not from `/proc/loadavg`, so the autoscaler's
retire gate observes the node's own allocations; the load average only feeds
the CPU-used dimension.

Before the first converge, install the shipped profile or point
`--seccomp-profile` at its repository copy:

```sh
sudo install -D -o root -g root -m 0644 \
  .terrascale/seccomp/terrascale-default-v1.json \
  /etc/terrascale/seccomp/terrascale-default-v1.json
sha256sum /etc/terrascale/seccomp/terrascale-default-v1.json
```

The expected SHA-256 is
`52f89c2c6abbd08f091c1ec332b29f4d0ab28cf580e9d229bc516741f07025a1`.
The runtime checks that digest before preflight and every create. It also
rejects symbolic links in the path, non-regular or oversized files, files not
owned by root or the node account, and files writable by group or other.

NixOS note: pass all three store-profile paths:

```sh
--podman-binary /run/current-system/sw/bin/podman \
--systemctl-binary /run/current-system/sw/bin/systemctl \
--systemd-run-binary /run/current-system/sw/bin/systemd-run
```

The native-binary adapter still uses `/usr/bin/systemctl`; these two systemd
path flags configure the OCI Podman supervisor added by this lane.

## Terminal 3 — the autoscaler

The orchestrator's `autoscaler` role reads explicit configuration from the
environment (run `./bin/orchestrator catalog` for the full list), ticks the
deterministic engine, and executes the actions it emits. This stage accepts
only `TS_ORCH_AUTOSCALER_PROVIDER=local-dev`. That provider provisions and
retires real `ts-node` child processes; cordon and drain checks use the node's
NATS subjects. It records ownership only in the autoscaler process. A restart
loses that ownership, so this provider is for local lifecycle validation only.
It is not a persistent or production provider.

The command keeps the authenticated NATS boundary. Supply one scoped NKey and
mTLS identity for the autoscaler, then one separately issued identity for each
child node. Put node credentials in a private directory using the names
`<node>.seed`, `<node>.ca.pem`, `<node>.pem`, and `<node>.key`; the autoscaler
loads the set matching the node it is provisioning. The NATS account must ACL
each identity to that node's heartbeat, converge, cordon, and drain-status
subjects.

```sh
TS_ORCH_NATS_URL=tls://127.0.0.1:4222 \
TS_ORCH_NATS_NKEY_FILE=/run/credentials/autoscaler/nkey.seed \
TS_ORCH_NATS_TLS_CA_FILE=/run/credentials/autoscaler/ca.pem \
TS_ORCH_NATS_TLS_CERT_FILE=/run/credentials/autoscaler/client.pem \
TS_ORCH_NATS_TLS_KEY_FILE=/run/credentials/autoscaler/client.key \
TS_ORCH_AUTOSCALER_PROVIDER=local-dev \
TS_ORCH_AUTOSCALER_NODE_NATS_CREDENTIAL_DIRECTORY=/run/credentials/ts-node/nodes \
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

The ordinary deterministic proof uses embedded NATS, the real agent and
engine, and fake Podman. It is simulated runtime/provider evidence, not a live
host claim:

```sh
go test ./tests/ -run TestPodmanAutoscaleLaneEndToEnd -v
```

The live Podman smoke is gated twice by the `live_podman` build tag and
`TS_ORCH_LIVE=1`. It uses a digest-pinned dashboard image already present in
the rootless store and never pulls. The image reference must match the
canonical runtime plan. The smoke proves the effective Podman process reports
rootless mode, cgroup v2, the systemd cgroup manager, and seccomp. A static
probe first proves `getppid` works with seccomp disabled and returns `ENOSYS`
under the shipped profile. The smoke then proves seccomp-backed create, exact
canonical fencing, immutable-ID unit binding, joined Running observation,
unit-mediated stop, recreation after systemd collects the transient unit,
delete, and Absent:

```sh
TS_ORCH_LIVE=1 \
TS_ORCH_LIVE_PODMAN_IMAGE=registry.terrascale.internal/terrascale/terrascale-dashboard@sha256:<digest> \
go test -tags live_podman ./tests/live/ -run Podman -count=1 -v
```

Set `TS_ORCH_LIVE_PODMAN_BINARY=/abs/path/to/podman` to point it at a
non-default Podman installation. Set `TS_ORCH_LIVE_SECCOMP_PROFILE` to test an
installed copy of the shipped profile. On NixOS also set
`TS_ORCH_LIVE_SYSTEMCTL_BINARY` and `TS_ORCH_LIVE_SYSTEMD_RUN_BINARY`.

The live autoscaler smoke is separately gated. It builds `ts-node`, then runs
the real autoscaler engine against `LocalProcessNodeProvisioner` and
`CommandProcessSpawner`. It observes the child heartbeat over real NATS,
cordons it, checks its empty drain report, and retires the exact child. This is
single-host provider-lifecycle evidence. The test calls the engine and
`LocalProcessNodeProvisioner` directly against embedded unauthenticated NATS.
It does not run the `orchestrator autoscaler` role, production TLS and NKey
wiring, scheduler observation subscription, workload convergence, restart
recovery, or OCI:

```sh
go build -o /tmp/ts-node-orch4 ./cmd/ts-node
TS_ORCH_LIVE_AUTOSCALER=1 \
TS_ORCH_LIVE_TS_NODE_BINARY=/tmp/ts-node-orch4 \
go test -tags live_autoscaler ./tests/live/ -run Autoscaler -count=1 -v
```

The role-level live lane starts the actual `orchestrator autoscaler` command,
connects with authenticated TLS/NKey NATS, publishes a complete scheduler
observation feed, and observes a real `ts-node` child launched with its
node-scoped credentials. It also requires the read-only OCI estate variables
used by the role. Prepare credentials for `baseline-node` and `as-node-1` in
the configured directory. This lane is gated by `TS_ORCH_LIVE_AUTOSCALER_ROLE=1`:

```sh
go build -o /tmp/orchestrator-orch4 ./cmd/orchestrator
TS_ORCH_LIVE_AUTOSCALER_ROLE=1 \
TS_ORCH_LIVE_ORCHESTRATOR_BINARY=/tmp/orchestrator-orch4 \
go test -tags live_autoscaler_role ./tests/live/ -run AutoscalerRole -count=1 -v
```
