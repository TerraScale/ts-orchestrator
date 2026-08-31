# Running the rootless-hosting and autoscaling stack locally

This guide composes the lane end to end on one development host: NATS, one or
more `ts-node` host agents, and the local process provider driven by the real
autoscaler engine. Everything runs under your own unprivileged account.
`ts-node` starts each rootless Podman container inside a fenced transient
systemd user unit. The agent rejects uid 0 and setuid execution before it
parses the rest of its configuration.

The lane design is
[`../architecture/podman-rootless-hosting-and-autoscaling.md`](../architecture/podman-rootless-hosting-and-autoscaling.md);
the deterministic end-to-end proof lives in
`tests/podman_autoscale_e2e_test.go` and the on-host podman proof in
`tests/live/podman_live_smoke_test.go`.

## Prerequisites

- rootless Podman 5.x with cgroup v2 delegation (`podman info` must succeed as
  your user), plus `systemctl` and `systemd-run` for a systemd **user** manager
  with linger enabled (`loginctl enable-linger "$USER"`);
- Go 1.27;
- the regional NATS URL you will use everywhere below, written `nats://127.0.0.1:4222`
  in the examples.

On NixOS the absolute podman and systemctl paths differ from the conventional
ones; see the notes on `--podman-binary` below.

## Build

From the repository root:

```sh
go build -o bin/orchestrator ./cmd/orchestrator
go build -o bin/ts-node ./cmd/ts-node
```

## Terminal 1 — the NATS server

For a single node, either run the orchestrator's embedded NATS role from an
explicit configuration file:

```sh
TS_ORCH_NATS_SERVER_CONFIG_FILE=/path/to/nats.conf \
  ./bin/orchestrator nats-server
```

…or start any NATS server that listens on the URL the other roles use. The
node transport only needs core NATS (no JetStream). A local `nats://` URL is
accepted for this single-host lane. The production autoscaler command requires
`tls://`, a scoped NKey, and mTLS files, as shown below.

## Terminal 2 — a node host agent

`ts-node` is the per-node host agent binary. Every input is an explicit flag;
the only ambient reads are the current uid (for the `--run-as-uid` default)
and the CPU count (for `--logical-cpu-count`). It validates the rootless
context at startup and exits non-zero before touching anything if either its
real or effective uid is 0, or if those uids differ. `--run-as-uid` must equal
that nonzero effective uid.

```sh
./bin/ts-node \
  --node-id as-node-1 \
  --nats-url nats://127.0.0.1:4222 \
  --podman-binary /usr/bin/podman \
  --heartbeat-interval 5s
```

The agent subscribes to the six node subjects
(`terrascale.node.v1.as-node-1.{converge,observe,stop,delete,cordon,drain-status}`),
answers with the typed receipts, and publishes
`terrascale.node.v1.as-node-1.heartbeat` every interval.

Flags (all optional except the first two):

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
