# Running the ts-node host agent locally

This guide runs the D-69 host agent (`ts-node`) on one development host: a
local NATS, one agent, and — optionally — one component under a hardened
systemd SYSTEM unit. There is no container runtime anywhere (D-69): the
agent installs signed static binaries into `/opt/terrascale/<component>/`
and launches them under systemd.

`ts-node` is the one privileged thing on a host: it runs as **root**
because writing SYSTEM units, creating system accounts, and driving
`systemctl` is its job. Every component it launches runs unprivileged
under its dedicated account. On a real OCI host the cloud-init
(`provider.TSNodeCloudInit`) installs the binary behind the
`/opt/terrascale/ts-node/current` symlink and one unit with no arguments;
locally you run the same binary with `sudo` and an explicit `--config`.

## Prerequisites

- root (via `sudo`) — the agent exits before touching anything otherwise;
- `systemctl`, `useradd`, and `chronyc` at their conventional absolute
  paths (all overridable in the configuration file);
- Go 1.27;
- a NATS server on `nats://127.0.0.1:4222` (the embedded role or any
  server; core NATS is enough).

## Build

From the repository root:

```sh
go build -o bin/ts-node ./cmd/ts-node
```

## Terminal 1 — the NATS server

```sh
TS_ORCH_NATS_SERVER_CONFIG_FILE=/path/to/nats.conf \
  ./bin/orchestrator nats-server
```

…or start any NATS server listening on `nats://127.0.0.1:4222`.

## Terminal 2 — the agent

Everything the agent reads is one strict JSON file (unknown fields are
rejected; nothing is read from the environment). Write a development
configuration:

```json
{
  "nodeId": "dev-node-1",
  "natsUrl": "nats://127.0.0.1:4222",
  "releasePublicKey": "<64-hex ed25519 public key of your dev signing key>",
  "manifestPath": "/etc/terrascale/manifest.json",
  "installRoot": "/opt/terrascale",
  "dataVolumeRoot": "/var/lib/terrascale",
  "heartbeatIntervalMilliseconds": 5000,
  "reconcileIntervalMilliseconds": 5000
}
```

`releasePublicKey` pins the key that release artifacts must be signed with;
it is never fetched from the network. `natsNkeyFile`, `natsTlsCaFile`,
`natsTlsCertFile`, and `natsTlsKeyFile` carry the credentials when
`natsUrl` is `tls://`. Then:

```sh
sudo mkdir -p /etc/terrascale
sudo cp dev-config.json /etc/terrascale/ts-node.json
sudo ./bin/ts-node
```

With an empty (or missing) manifest the agent simply serves the RPC
subjects and publishes heartbeats; no units are touched.

## The manifest

`/etc/terrascale/manifest.json` declares the desired components; the agent
watches it and reconciles — install the signed release, create the
dedicated system account, render the D-69 hardened unit, enable and start
it. A component that leaves the manifest is retired; its data volume is
kept (deleting a database is a human decision).

```json
{
  "components": [
    {
      "name": "terrabase",
      "version": "1.2.3",
      "artifactUrl": "https://releases.example/terrabase/1.2.3/terrabase",
      "signatureUrl": "https://releases.example/terrabase/1.2.3/terrabase.sig",
      "sha256": "<64-hex digest of the artifact>",
      "user": "terrascale-terrabase",
      "dataVolume": "/var/lib/terrascale/terrabase",
      "cpuWeight": 200,
      "memoryMaxBytes": 8589934592,
      "ioWeight": 300,
      "needsNetlink": false
    }
  ]
}
```

Reconciliation installs a new version **beside** the current one and never
flips the `current` symlink — the flip is the orchestrator-coordinated
deploy below.

## The RPC surface

The agent answers request-reply JSON (camelCase, unknown fields rejected)
on `terrascale.node.v1.<nodeId>.<leaf>` over the control NATS. The leaves:

| Leaf | Payload | Reply |
| --- | --- | --- |
| `drain` | `{"commandId":"…","drain":true}` | `DrainReceipt` (draining, quiesced) |
| `drain-status` | `{"commandId":"…"}` | `NodeStatusReport` (state, quiesce gate, host facts) |
| `deploy` | `{"commandId":"…","component":"terrabase","version":"1.2.3"}` | `DeployReceipt` |
| `rollback` | `{"commandId":"…","component":"terrabase"}` | `DeployReceipt` |
| `heartbeat` | publish-only, every interval | `HostHeartbeat` (clock offset, disk, versions) |

With the `nats` CLI, the rollout choreography:

```sh
# begin the drain: component units stop gracefully
nats req terrascale.node.v1.dev-node-1.drain '{"commandId":"d1","drain":true}'

# poll the quiesce gate
nats req terrascale.node.v1.dev-node-1.drain-status '{"commandId":"s1"}'

# flip the current symlink to the installed release and start it
nats req terrascale.node.v1.dev-node-1.deploy \
  '{"commandId":"p1","component":"terrabase","version":"1.2.3"}'

# back to serving
nats req terrascale.node.v1.dev-node-1.drain '{"commandId":"d2","drain":false}'

# emergency: symlink back to previous plus restart, from any state
nats req terrascale.node.v1.dev-node-1.rollback \
  '{"commandId":"r1","component":"terrabase"}'
```

`deploy` fails closed unless the node is quiesced; `rollback` works from
any state. The heartbeat carries the D-69 clock rule: the measured chrony
offset and an unhealthy flag beyond 500 ms (an unreadable clock is also
unhealthy — the member engine refuses new writes on that fact).

## The tests

The deterministic proofs live with the package: unit rendering pinned to
D-69's directive list, signed-install failure modes, symlink flip and
rollback, the drain lifecycle, manifest reconciliation, and the RPC
surface — all under `t.TempDir()` with fakes for systemctl/useradd, no
root and no live systemd:

```sh
go test ./src/orchestrator/hostagent/ ./cmd/ts-node/ -v
```
