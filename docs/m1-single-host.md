# M1 single-host node (W2)

`ts-orch single-host --state /var/lib/ts-orch` runs one SwarmKit manager that
is also its only Active worker, with the containerd executor
(`/run/containerd/containerd.sock`). No OCI, Vault, NetBird, NATS or admission.
Runs as root. Entry point: `app.RunSingleHost(ctx, args, output)` (W6 registers
`case "single-host"` in `internal/cli/cli.go`).

Image pulls from `ghcr.io` authenticate as `MarioGK` with the OCI Vault secret
`<cell>-1-ghcr-pull-token` (`gru-1-ghcr-pull-token` on ts-gru-1), read at pull
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
`job_workflow_ref` either `TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main`
(ts-orch releases) or a key of the code map `appServices` (app image
workflows; the token's `repository` must own that workflow). A CI connection may publish only
`ts.release.>` and subscribe only its run's inbox `_INBOX.<run_id>.>`; ts-orch's
own in-process connection uses an in-memory token. Everything else is refused.

| Subject | Request | Reply |
|---|---|---|
| `ts.release.version` | none | `{"version": "<vcs.revision>"}` |
| `ts.release.ts-orch` | `{"sha", "binaries": {"<goarch>": {"url", "sha256"}}, "token"}` | `{"state": "current" \| "installed" \| "stale" \| "rejected"}` |
| `ts.release.app` | `{"service", "image": "ghcr.io/terrascale/<service>@sha256:...", "token"}` | `{"state": "done" \| "failed" \| "rejected", "result": [<mesh rows>]}` |

An app release needs a token from a workflow `appServices` allows to release
`service` (`app-canary.yml` here: `app-canary`; terrascale `images-ghcr.yml`:
`terrabase`, `ts-auth`; ts-dashboard `images-ghcr.yml`: `ts-dashboard`), and
the image name must equal the service. The receiving host reads the service's
newest desired spec on the mesh, changes only its digest (same repository) and
applies it to every region it targets: pre-pull, fast replacement, ready path.
If a targeted region fails or is not ready within 70 s, it re-applies the
previous spec everywhere (40 s) unless a newer release replaced it. A service
must have been applied once with `ts-orch service apply -f`. From an image
workflow:

```sh
ts-orch release app --service terrabase --image ghcr.io/terrascale/terrabase@sha256:<arm64 digest>
```

It tries the regions in `deploy/m1/regions.json` order until one accepts the
connection and prints `{"via","state","serving_ms","error","regions"}`.

`ts.release.mesh.state` returns `{"<service>": "<desired image>"}`; besides the
multi-region workflow, only `app-digests.yml` may call it, and only it. That
workflow (every 10 min and after each canary release) runs `ts-orch release
digests --out deploy/m1/app-digests.json` and commits the file to branch
`app-digests`, so the git record of every released digest never lags the
hosts by more than 10 min.

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

`service ps|logs|inspect` and `events`: see [m1-runbook.md](m1-runbook.md#operator-commands).
