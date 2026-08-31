# Running the rootless-hosting and autoscaling stack locally

This guide composes the lane end to end on one development host: NATS, one or
more `ts-node` host agents, and the local process provider driven by the real
autoscaler engine. Everything runs under your own unprivileged account.
`ts-node` starts each rootless Podman container inside a fenced transient
systemd user unit. Nothing in this lane runs as uid 0.

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
context at startup and exits non-zero before touching anything if it is run
as uid 0.

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
`terrascale.allocation` and `terrascale.fingerprint` values. Its `ExecStart`
runs `podman start --attach`; its fixed `ExecStop` runs rootless `podman stop`.
An existing running container with an absent unit or a mismatched description
fails closed instead of being adopted. Inspect it with:

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

Before the first converge, place a seccomp profile document at the
`--seccomp-profile` path (or point the flag at one) — for local bring-up a
permissive profile is enough to prove the plumbing:

```sh
sudo install -D -m 0644 /dev/null /etc/terrascale/seccomp/terrascale-default-v1.json
echo '{"defaultAction":"SCMP_ACT_ALLOW"}' | sudo tee /etc/terrascale/seccomp/terrascale-default-v1.json >/dev/null
```

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
deterministic engine, and executes the actions it emits. The single-host
provider provisions and retires real `ts-node` processes; cordon and drain
checks use the node's NATS subjects. This command uses the production NATS
boundary, so supply a scoped NKey and mTLS identity. The provisioner passes
the same files to every child node agent.

```sh
TS_ORCH_NATS_URL=tls://127.0.0.1:4222 \
TS_ORCH_NATS_NKEY_FILE=/run/credentials/autoscaler/nkey.seed \
TS_ORCH_NATS_TLS_CA_FILE=/run/credentials/autoscaler/ca.pem \
TS_ORCH_NATS_TLS_CERT_FILE=/run/credentials/autoscaler/client.pem \
TS_ORCH_NATS_TLS_KEY_FILE=/run/credentials/autoscaler/client.key \
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
`TS_ORCH_LIVE=1`. It uses an image already present in the rootless store and
never pulls. It proves Podman preflight, systemd user-manager preflight,
seccomp-backed create, fenced transient-unit start, joined Running
observation, unit-mediated stop, delete, and Absent:

```sh
TS_ORCH_LIVE=1 \
TS_ORCH_LIVE_PODMAN_IMAGE=localhost/your-existing-image:tag \
go test -tags live_podman ./tests/live/ -run Podman -count=1 -v
```

Set `TS_ORCH_LIVE_PODMAN_BINARY=/abs/path/to/podman` to point it at a
non-default Podman installation. On NixOS also set
`TS_ORCH_LIVE_SYSTEMCTL_BINARY` and `TS_ORCH_LIVE_SYSTEMD_RUN_BINARY`.

The live autoscaler smoke is separately gated. It builds `ts-node`, then runs
the real autoscaler engine against `LocalProcessNodeProvisioner` and
`CommandProcessSpawner`. It observes the child heartbeat over real NATS,
cordons it, checks its empty drain report, and retires the exact child. This is
live single-host provider evidence. It is not OCI evidence:

```sh
go build -o /tmp/ts-node-orch4 ./cmd/ts-node
TS_ORCH_LIVE_AUTOSCALER=1 \
TS_ORCH_LIVE_TS_NODE_BINARY=/tmp/ts-node-orch4 \
go test -tags live_autoscaler ./tests/live/ -run Autoscaler -count=1 -v
```
