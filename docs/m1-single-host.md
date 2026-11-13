# M1 single-host node (W2)

`ts-orch single-host --state /var/lib/ts-orch` runs one SwarmKit manager that
is also its only Active worker, with the containerd executor
(`/run/containerd/containerd.sock`). No OCI, Vault, NetBird, NATS or admission.
Runs as root. Entry point: `app.RunSingleHost(ctx, args, output)` (W6 registers
`case "single-host"` in `internal/cli/cli.go`).

Image pulls from `ghcr.io` authenticate as `MarioGK` with the OCI Vault secret
`gru-1-ghcr-pull-token`, read at pull time from gru-vault with the instance
principal (every region, cross-region); blob downloads follow GHCR's redirect to
`pkg-containers.githubusercontent.com` without credentials. Other registries
pull anonymously.

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
| `ts.release.version` | none | `{"version": "<vcs.revision>", "rolled_back": "<sha>", "error": "<why>"}` |
| `ts.release.ts-orch` | `{"sha", "binaries": {"<goarch>": {"url", "sha256"}}, "token"}` | `{"state": "current" \| "installed" \| "stale" \| "rolled_back" \| "rejected"}` |
| `ts.release.app` | `{"service", "image": "ghcr.io/terrascale/<service>@sha256:...", "token"}` | `{"state": "done" \| "failed" \| "rejected", "result": [<mesh rows>]}` |

An app release needs a token from a workflow `appServices` allows to release
`service` (`app-canary.yml` here: `app-canary`; terrascale `ci.yml`:
`terrabase`, `ts-auth`; ts-dashboard `images-ghcr.yml`: `ts-dashboard`), and
the image name must equal the service. The receiving host reads the service's
newest desired spec on the mesh, changes only its digest (same repository) and
applies it to every region it targets, one region at a time: pre-pull, fast
replacement, ready path, bake. Each region gets its readiness timeout
(`readyTimeoutSeconds`, 60 s by default) plus 30 s to pull and submit plus the
bake budget; regions the spec does not place answer at once. If a targeted
region fails or misses its window, the release re-applies the previous spec
everywhere unless a newer release replaced it. The release ends by a deadline
fixed when it starts: the rollout windows of all regions plus one rollback
window. A service
must have been applied once with `ts-orch service apply -f`, except `app-canary`:
its authenticated workflow initializes the embedded, bounded canary spec on its
first release or after removal. Failed creation rolls back to absence while
retaining the signed-run floor. The canary runs after successful main CI has delivered the new
receiver, using its narrowly scoped `workflow_run` identity. From an image workflow:

```sh
ts-orch release app --service terrabase --image ghcr.io/terrascale/terrabase@sha256:<arm64 digest>
```

It tries the regions in `deploy/m1/regions.json` order until one accepts the
connection. While the release runs it prints one line per event: the rollout
order and deadline, each region's outcome as it reports (`sjc applied in 40.5s
(pulled ..., submitted ..., ready ..., bake ...)` or `gru failed after 2m0s: not
ready within 1m0s: task application readiness returned HTTP 503`), and the
rollback. It then prints `{"via","state","serving_ms","error","regions"}` and
fails with each failed region's cause. It waits until the deadline the release
reported plus 20 s, so a caller needs no time limit of its own.

`ts.release.mesh.state` returns `{"<service>": "<desired image>"}`; besides the
multi-region workflow, only `app-digests.yml` may call it, and only it. That
workflow (nightly, after each App release canary run, and on dispatch) runs
`ts-orch release digests --out deploy/m1/app-digests.json` and commits the
file to branch `app-digests`. Releases that reach the hosts through another
path (for example a `ts-dashboard` release from the monorepo's image
workflow, which does not trigger it) are not recorded until the next run, so
the branch can lag the hosts by hours; it is a record, not a live view.
That branch, not the `deploy/m1/services/*.json`
specs in this repository, is the running fleet's pin of record: the specs
carry a service's first image only and are never updated by releases.

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
the installed one is `stale`. An immutable binary (`chattr +i`) is `rejected`
with the `chattr -i` command to run; the swap leaves no `.next` behind.

A pushed binary is on probation until it serves the release subjects: install
writes `nats/release-trial` in the state directory, each start counts itself
there first, and serving removes it. A third start, or no serving 2 min after
install, renames `.prev` back over the binary, records `nats/release-rolled-back`
and exits, so systemd starts the previous binary. That binary reports
`rolled_back` on `ts.release.version` and push fails with state `rolled_back`
instead of timing out; a retry of the same run is refused, a newer run installs.

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

Image GC runs every ten minutes and after successful bakes, retaining desired,
rollback, floor and container images; shared pull/prepare locks and containerd
leases protect in-flight work. Stateless services reserve 2 GiB of disk (their
retained image and bounded logs); only services with mounts keep 10 GiB.

## Host data volumes

New hosts created by region add receive a 100 GB balanced (10 VPU/GB) block
volume in the instance's availability domain. Its display name is the host
name plus -data. Discovery uses these free-form tags:

| Tag | Value |
|---|---|
| terrascale-managed-by | ts-orchestrator |
| terrascale-resource | data-volume |
| terrascale-host | host name |

Cloud-init waits for the paravirtualized attachment at
/dev/oracleoci/oraclevdb, mounts its ext4 filesystem by UUID at
/var/lib/ts-data, and bind-mounts /var/lib/ts-data/ts-orch at
/var/lib/ts-orch before installing and starting the agent. Service data
stays at /var/lib/ts-data/terrabase. The agent's systemd drop-in requires
both mounts, checks both before starting, and stops the agent when either
mount is stopped. Binary upgrades preserve this drop-in.

Formatting is allowed only for a volume created in the current invocation,
with no filesystem or partition signature, no child block devices, no mount
and every byte verified zero. An existing ext4 filesystem is mounted without
formatting, even on a newly created volume. A retained volume without a
filesystem is refused. A partial create that left an unformatted volume
therefore requires operator inspection before proceeding; another add
never grants permission to format it.

Each host compartment has a managed daily incremental backup policy,
scheduled at 02:00 UTC with seven days of retention. The policy and its
assignment converge on subsequent adds. A second successful add reports
the volume, policy, assignment and attachment as unchanged.

    ts-orch region add CODE --host NAME --dry-run

The read-only plan includes the volume, backup policy, assignment and
attachment. Removing a host discards its boot disk and keeps the data
volume and its backup policy assignment. A later add for the same name
finds the tagged volume, launches in its availability domain and reattaches
it. Conflicting or ambiguous volumes and attachments are refused. Once a
new volume has been created, launch stays in that availability domain and
tries the free fault domains there.

    ts-orch region rm CODE --host NAME --delete-volume

This also removes the data volume after typing the exact host name at an
interactive prompt. Confirmation happens before termination. The command
waits for detachment before deleting; existing backups expire under their
retention policy. Dry-run only prints the deletion plan.

An existing instance without a tagged data volume is adopted unchanged.
This command does not migrate its boot-disk data or mount an empty volume
over it. Moving existing hosts needs a separate operation that stops the
services and copies their data first.

The disposable M1 E2E flow exercises real loop-device formatting, rejects
raw nonzero data and blank retained disks without changing their contents,
keeps the filesystem UUID and sentinel service/identity files across
reattachment, and runs the normal service journey from the mounted volume.
It also stops the data mount and checks that the agent stops, then starts
the agent and verifies that its mount dependencies restore the saved data.
It does not create or delete OCI resources.
