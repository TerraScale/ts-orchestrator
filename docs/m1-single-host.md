# M1 single-host node (W2)

`ts-orch single-host --state /var/lib/ts-orch` runs one SwarmKit manager that
is also its only Active worker, with the containerd executor
(`/run/containerd/containerd.sock`). No OCI, Vault, NetBird, NATS or admission.
Runs as root. Entry point: `app.RunSingleHost(ctx, args, output)` (W6 registers
`case "single-host"` in `internal/cli/cli.go`).

Image pulls from `ghcr.io` authenticate as `MarioGK` with the OCI Vault secret
`<cell>-ghcr-pull-token` (`gru-1-ghcr-pull-token` on ts-gru-1), read at pull
time with the instance principal from the instance's `<cell>-vault`; other
registries pull anonymously.

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
one TLS client listener on `0.0.0.0:4222`, 64 KiB max payload, at most 256
connections and 64 subscriptions each, 5 s auth timeout, no JetStream, cluster,
gateway or leaf. ts-orch adds an iptables `INPUT` ACCEPT for tcp/4222 above
Ubuntu's REJECT on every start; the edge NSG allows tcp/4222.

The listener certificate is self-signed ECDSA, created once under
`<state>/nats/` and never replaced while either file exists (a half-written
pair is refused, not regenerated), so its pin survives restarts and upgrades.

CI holds no secret. Its GitHub Actions OIDC token (audience `ts-orch`) is the
NATS token and is embedded in every release message. ts-orch verifies RS256
against GitHub's JWKS, `iss`, `aud=ts-orch`, `exp`/`nbf` (1 min skew),
`repository_owner=TerraScale`, `ref=refs/heads/main`, `event_name=push` and
`job_workflow_ref` in the code list `releaseWorkflows` (today only
`TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main`; the
token's `repository` must own that workflow). A CI connection may publish only
`ts.release.>` and subscribe only its run's inbox `_INBOX.<run_id>.>`; ts-orch's
own in-process connection uses an in-memory token. Everything else is refused.

| Subject | Request | Reply |
|---|---|---|
| `ts.release.version` | none | `{"version": "<vcs.revision>"}` |
| `ts.release.ts-orch` | `{"sha", "binaries": {"<goarch>": {"url", "sha256"}}, "token"}` | `{"state": "current" \| "installed" \| "stale" \| "rejected"}` |
| `ts.release.app` | `{"service", "image": "ghcr.io/terrascale/<name>@sha256:...", "token"}` | not wired yet (slice B) |

A ts-orch release needs a token from `TerraScale/ts-orchestrator` whose `sha`
claim equals `sha`, and the URL must be exactly that run's release asset:
`https://github.com/TerraScale/ts-orchestrator/releases/download/ci-<sha>-run-<run_id>/terrascale-orchestrator-linux-<goarch>`
(`run_id` from the verified token). ts-orch downloads it (60 s, one immediate
retry), checks `sha256`, keeps the old binary as `terrascale-orchestrator.prev`,
renames the new one over the real path of its executable, replies `installed`
and exits non-zero; systemd restarts it after `RestartSec=1s`. Containers keep
running: the executor's `Close` only disconnects from containerd, whose shims
own the tasks, `Node.Stop` cancels before leaving so workloads survive, and
`KillMode=mixed` only kills what is left in ts-orch's own cgroup (the shims live
under `containerd.service`). A release from an older GitHub run (`run_id`) than
the installed one is `stale`.

### Regions and pins

`deploy/m1/regions.json` lists every region; a new region is one line:

```json
[
  {"region": "gru", "nats": "tls://163.176.124.12:4222", "spki_sha256": "<pin>"}
]
```

`spki_sha256` is the hex (or base64) sha256 of the listener's
SubjectPublicKeyInfo. CI accepts exactly that key; a region with no or an
invalid pin is reported as failed and the others continue. Fill it once from
the host (it creates the certificate if absent):

```sh
sudo ts-orch release pin --state /var/lib/ts-orch
```

Pins were read on each host with the command above and cross-checked against
the live listener's TLS key from outside (2026-10-22): gru `3100cce0…5ad9`,
sjc `c4007100…94fd`, fra `b54fe502…6181`. `TestCommittedRegionsArePinned`
fails CI when a region line has no valid pin.

### CI

The `release-push` job in `.github/workflows/ci.yml` runs after `build` on a
publishing push to main. It is the only job with `id-token: write`
(`contents: read`). It downloads the amd64 and arm64 assets of
`ci-${GITHUB_SHA}-run-${GITHUB_RUN_ID}`, checks out `deploy/m1/regions.json`
and runs

```sh
dist/terrascale-orchestrator-linux-amd64 release push --sha "${GITHUB_SHA}" --dir dist
```

Push mints the token, derives the release tag from its `run_id`, pushes to
every region concurrently, polls `ts.release.version` every 250 ms until it
equals `--sha` (3 min limit) and prints one JSON line per region, which the
job writes to its summary:

```json
{"region":"gru","state":"installed","connect_ms":180,"accepted_ms":4200,"serving_ms":9800}
```

It exits non-zero if any region failed; one region's failure never stops the others.

## Operator commands

Run on the host as root. Every command reads `/var/lib/ts-orch` over the
control socket; none changes state. Known failures end in `. Fix: <next step>`.

| Command | Shows |
|---|---|
| `ts-orch service ps <svc>` | Tasks newest first: ID, node, state, desired state, time in state, last error; then `Fix:` for the newest task's error |
| `ts-orch service logs [-f] <svc>` | Newest task's container stdout then stderr (`<state>/runtime-logs/ts-<task>/`); `-f` follows appended output |
| `ts-orch service inspect <svc>` | JSON: service ID, version, created/updated, image digest, and the declared spec. Secrets are names only; values never enter the spec |
| `ts-orch events [-f]` | Latest 100 task and service state records, oldest first; `-f` streams changes from the manager's watch API |

Single-host's NATS carries only releases, so `events` reads SwarmKit's watch API.

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
