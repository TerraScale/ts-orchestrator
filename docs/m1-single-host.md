# M1 single-host node (W2)

`ts-orch single-host --state /var/lib/ts-orch` runs one SwarmKit manager that
is also its only Active worker, with the containerd executor
(`/run/containerd/containerd.sock`). No OCI, Vault, NetBird, NATS or admission.
Runs as root. Entry point: `app.RunSingleHost(ctx, args, output)` (W6 registers
`case "single-host"` in `internal/cli/cli.go`).

## State layout

| Path | Content |
|---|---|
| `<state>/swarm/` | SwarmKit certificates, Raft log, `admission.json`, `node.lock` |
| `<state>/control.sock` | Control socket (below); symlink to the upstream `<state>/swarm/control.sock` |
| `<state>/runtime-logs/` | Container logs written by the executor |

Restart reopens the same node ID and Raft state. A missing certificate or Raft
directory with existing state is refused, never re-founded. Other features
(edge certs, ...) use their own `<state>/<name>/` directory.

## Control socket contract (for W3 `service` CLI and W6)

- Transport: gRPC over the unix socket `<state>/control.sock` (default `/var/lib/ts-orch/control.sock`).
- Security: TLS pinned to the node's root CA (`<state>/swarm/certificates/swarm-root-ca.crt`),
  server name `swarm-manager`. Access is root-only (state dir mode 0700).
- API: upstream SwarmKit `api.ControlClient`
  (`github.com/moby/swarmkit/v2/api`): `CreateService`, `UpdateService`,
  `ListServices`, `GetService`, `RemoveService`, `ListTasks`, `ListNodes`, ...
- Client: `swarmruntime.DialSingleHost(stateDir) (api.ControlClient, *grpc.ClientConn, error)`;
  the caller closes the connection. Path helpers: `swarmruntime.SingleHostSocket(stateDir)`,
  `swarmruntime.SingleHostSwarmDir(stateDir)`.
- Fixed values: node hostname `single-host`, remote API `127.0.0.1:4242`
  (loopback only; nothing joins).

Example (`service ls`):

```go
client, conn, err := swarmruntime.DialSingleHost("/var/lib/ts-orch")
if err != nil { return err }
defer conn.Close()
services, err := client.ListServices(ctx, &api.ListServicesRequest{})
```

## Release push over NATS (W14)

`single-host` also runs a minimal embedded NATS server (`internal/releasepush`):
one TLS client listener on `0.0.0.0:4222`, 64 KiB max payload, no JetStream,
cluster, gateway or leaf. The self-signed ECDSA listener certificate is created
once under `<state>/nats/`. ts-orch adds an iptables `INPUT` ACCEPT for tcp/4222
above Ubuntu's REJECT on every start; the edge NSG allows tcp/4222.

CI holds no secret. Its GitHub Actions OIDC token (audience `ts-orch`) is the
NATS token and is embedded in every release message. ts-orch verifies RS256
against GitHub's JWKS, `iss`, `aud=ts-orch`, `exp`/`nbf` (1 min skew),
`repository_owner=TerraScale` and `ref=refs/heads/main`. A CI connection may
publish only `ts.release.>` and subscribe only `_INBOX.>`; ts-orch's own
in-process connection uses an in-memory token. Everything else is refused.

| Subject | Request | Reply |
|---|---|---|
| `ts.release.version` | none | `{"version": "<vcs.revision>"}` |
| `ts.release.ts-orch` | `{"sha", "binaries": {"<goarch>": {"url", "sha256"}}, "token"}` | `{"state": "current" \| "installed" \| "stale" \| "rejected"}` |
| `ts.release.app` | `{"service", "image": "ghcr.io/terrascale/<name>@sha256:...", "token"}` | not wired yet (slice B) |

A ts-orch release needs a token from `TerraScale/ts-orchestrator` whose `sha`
claim equals `sha`, and a URL under
`https://github.com/TerraScale/ts-orchestrator/releases/download/<tag>/terrascale-orchestrator-linux-<goarch>`.
ts-orch downloads it (60 s, one immediate retry), checks `sha256`, keeps the old
binary as `terrascale-orchestrator.prev`, renames the new one over the real path
of its executable, replies `installed` and exits non-zero; systemd restarts it
after `RestartSec=1s`. Containers keep running: the executor's `Close` only
disconnects from containerd, whose shims own the tasks, `Node.Stop` cancels
before leaving so workloads survive, and `KillMode=mixed` only kills what is left in ts-orch's own cgroup (the shims live under `containerd.service`). A
release from an older GitHub run (`run_id`) than the installed one is `stale`.

CI pushes with

```sh
ts-orch release push --sha "$GITHUB_SHA" --tag "<release tag>" --dir dist
```

`--dir` holds `terrascale-orchestrator-linux-{amd64,arm64}` (the uploaded
assets). The job needs `permissions: id-token: write`. Push reads
`deploy/m1/regions.json` (a new region is one line there), pushes to every
region concurrently, polls `ts.release.version` every 250 ms until it equals
`--sha` (3 min limit) and prints one JSON line per region:

```json
{"region":"gru","state":"installed","connect_ms":180,"accepted_ms":4200,"serving_ms":9800}
```

It exits non-zero if any region failed; one region's failure never stops the others.
