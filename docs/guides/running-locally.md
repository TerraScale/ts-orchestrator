# Running the host-agent stack locally

This guide composes the lane end to end on one development host: NATS and one
or more `ts-node` host agents. Everything runs under your own unprivileged
account. `ts-node` starts each workload as a fenced transient systemd user
unit (D-69: there is no container runtime). The agent rejects uid 0 and setuid
execution before it parses the rest of its configuration.

## Prerequisites

- `systemctl` and `systemd-run` for a systemd **user** manager with linger
  enabled (`loginctl enable-linger "$USER"`);
- Go 1.27;
- the regional NATS URL you will use everywhere below, written `nats://127.0.0.1:4222`
  in the examples.

On NixOS the absolute systemctl paths differ from the conventional ones; pass
`--systemctl-binary` and `--systemd-run-binary` with the store paths.

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
accepted for this single-host lane.

## Terminal 2 — a node host agent

`ts-node` is the per-node host agent binary. Every input is an explicit flag;
the only ambient reads are the current uid (for the `--run-as-uid` default)
and the CPU count (for `--logical-cpu-count`). It validates its identity at
startup and exits non-zero before touching anything if either its real or
effective uid is 0, or if those uids differ. `--run-as-uid` must equal that
nonzero effective uid.

```sh
./bin/ts-node \
  --node-id as-node-1 \
  --nats-url nats://127.0.0.1:4222 \
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
| `--node-class` | `greenfield` | informational node class token |
| `--systemctl-binary` | `/usr/bin/systemctl` | absolute systemctl path used with `--user` |
| `--systemd-run-binary` | `/usr/bin/systemd-run` | absolute systemd-run path used to create transient user units |
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

For an allocation named `nats-a`, the supervisor unit is
`terrascale-nats-a.service`, created with `--collect` so it disappears when it
stops. Inspect it with:

```sh
systemctl --user status terrascale-nats-a.service
systemctl --user show terrascale-nats-a.service \
  --property=Description --property=ActiveState
```

The heartbeat's running-task gauge comes from the agent's own tracked
allocations (its executor), not from `/proc/loadavg`; the load average only
feeds the CPU-used dimension.

## Sending a converge request

A workload command is a `WorkloadCommandRequest` — the serialized canonical
plan plus a bounded command id — sent as a NATS request on the node's
converge subject. The `planJson` field is a byte array on the wire, so the
plan text must be base64-encoded; with the `nats` CLI and `jq`:

```sh
nats req terrascale.node.v1.as-node-1.converge \
  "$(jq -Rs '{planJson: (@base64), commandId: "local-converge-1"}' < plan.json)"
```

where `plan.json` is a canonical native-systemd plan (the digest must be the
real sha256 of the artifact):

```json
{
  "schemaVersion": 2,
  "role": "nats",
  "driver": "nativeSystemd",
  "allocationId": { "value": "nats-a" },
  "artifactDigest": {
    "value": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  },
  "architecture": "arm64",
  "resources": {
    "memoryMaxBytes": 2147483648,
    "tasksMax": 512,
    "cpuQuotaPercent": 200,
    "cpuWeight": 800,
    "ioWeight": 800,
    "nice": 0,
    "memoryHighBytes": 1932735283,
    "memorySwapMaxBytes": 0
  },
  "systemd": {
    "unitName": "terrascale-nats-a.service",
    "executable": "/opt/terrascale/artifacts/nats-server/sha256-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/nats-server",
    "arguments": ["--config", "/var/lib/terrascale-nats-a/config.json"],
    "properties": ["Type=exec", "Restart=always"]
  },
  "oci": null
}
```

The agent decodes the payload through the strict plan decoder (unknown
fields, wrong schema versions, and non-canonical execution plans are
rejected), re-computes the canonical fingerprint, and fences the transient
unit against the canonical plan. The reply is the `ConvergeReceipt`:

```json
{"CommandId":"local-converge-1","Accepted":true,"Detail":"Allocation nats-a converged through the NativeSystemd driver.","PlanFingerprint":"<64-hex-fingerprint>"}
```

The other subjects follow the same shape: `observe`, `stop`, and `delete`
take the same command payload and answer with their receipts; `cordon` takes
`{"commandId":"...","cordoned":true}` and answers with an acknowledgment;
`drain-status` takes `{"commandId":"..."}` and answers with the node's
allocation observations.

## The tests

The deterministic proof of the executor, transport, and systemd adapter lives
with their packages:

```sh
go test ./src/orchestrator/hostagent/ ./src/orchestrator/runtime/ -v
```
