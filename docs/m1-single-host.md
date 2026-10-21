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

## Operator commands

Run on the host as root. Every command reads `/var/lib/ts-orch` over the
control socket; none changes state. Known failures end in `. Fix: <next step>`.

| Command | Shows |
|---|---|
| `ts-orch service ps <svc>` | Tasks newest first: ID, node, state, desired state, time in state, last error; then `Fix:` for the newest task's error |
| `ts-orch service logs [-f] <svc>` | Newest task's container stdout then stderr (`<state>/runtime-logs/ts-<task>/`); `-f` follows appended output |
| `ts-orch service inspect <svc>` | JSON: service ID, version, created/updated, image digest, and the declared spec. Secrets are names only; values never enter the spec |
| `ts-orch events [-f]` | Latest 100 task and service state records, oldest first; `-f` streams changes from the manager's watch API |

Single-host runs no NATS, so `events` reads SwarmKit's watch API.

Deploy check: `service apply -f x.json`, then `events -f` until the task shows
`running`, then `service logs <svc>`.

Common errors and fixes:

| Error contains | Fix |
|---|---|
| `swarm-root-ca.crt: permission denied` | Run with `sudo` |
| `control.sock: connect: connection refused` | `sudo systemctl status ts-orch`; `sudo journalctl -u ts-orch -n 50` |
| `signed container material is pending` | Check every name in `service inspect` `.spec.secrets` exists in OCI Vault and the host's ts-orch release delivers Vault secrets; re-apply |
| `disk capacity or retained storage is unavailable` | Each task reserves 10 GiB: `df -h /var/lib/containerd /var/lib/ts-orch` |
| `no suitable node` | The host is out of CPU, memory, disk or the port: `service ls`, remove or shrink a service |
| `load admitted container image` | Registry unreachable or digest missing: `sudo ctr -n terrascale images pull <image>` |
| `exited with status` / `non-zero exit` | `ts-orch service logs <svc>` |

The full table is `operatorFixes` in `internal/app/service_ops_cli.go`.
