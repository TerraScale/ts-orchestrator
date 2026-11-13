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
| `ts.release.version` | none | `{"version": "<vcs.revision>", "sha256": "<running binary digest>", "sha256_unavailable": "<why>", "rolled_back": "<sha>", "error": "<why>"}` |
| `ts.release.ts-orch` | `{"sha", "binaries": {"<goarch>": {"url", "sha256"}}, "token"}`, optional header `Ts-Orch-Preflight` | `{"state": "current" \| "installed" \| "stale" \| "rolled_back" \| "rejected", "refusal": {...}}` |
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
retry), checks `sha256`, runs the candidate's preflight when the release
declares one (see [releases.md](releases.md#ts-orch-candidate-preflight)),
keeps the old binary as `terrascale-orchestrator.prev`,
renames the new one over the real path of its executable, replies `installed`
and exits non-zero; systemd restarts it after `RestartSec=1s`. Containers keep
running: the executor's `Close` only disconnects from containerd, whose shims
own the tasks, `Node.Stop` cancels before leaving so workloads survive, and
`KillMode=mixed` only kills what is left in ts-orch's own cgroup (the shims live
under `containerd.service`). A release from an older GitHub run (`run_id`) than
the installed one is `stale`. A request for the running revision is `current`
and installs nothing, also when it is another build of that commit. An
immutable binary (`chattr +i`) is `rejected`
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

Push mints the token and the preflight declaration, derives the release tag
from its `run_id`, pushes to every region concurrently, polls
`ts.release.version` every 250 ms until it names `--sha` and, when the host
reports a digest and did not answer `current`, one of the release's digests
(3 min limit; a rollback of `--sha` is checked first) and prints one JSON line
per region, which the
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

Each new host receives a 100 GB balanced block volume (10 VPU/GB), named
HOST-data, in its availability domain. Discovery requires all three tags:

| Tag | Value |
|---|---|
| terrascale-managed-by | ts-orchestrator |
| terrascale-resource | data-volume |
| terrascale-host | host name |

The volume is created before launch, fixing placement to its availability
domain. Retained volumes also fix placement there. The launch call atomically
sets the instance launch metadata keys `terrascale-data-volume` to that exact volume ID and
`terrascale-data-may-format` to `true` only when this invocation created it;
otherwise it sets `false`. The volume records `terrascale-data-instance` before
attachment. Every attachment reads both resources back and requires both IDs
to agree. Changing the instance to another volume is refused, with both IDs
in the error. A volume bound to another instance can only be rebound after
that instance is terminated. An unfinished instance with format permission is
stopped, detached and terminated; it cannot be reused to adopt another disk.
Its retained volume must be inspected and initialised before a new add.

Only the invocation that created the exact volume may launch a host allowed
to format it, only for that instance, and only once. On the boot disk,
`/var/lib/ts-orch-bootstrap/format-consumed` is created exclusively and synced,
including its parent directory, before formatting; it records the volume ID,
disk serial, device size and UTC time. An existing record always prevents formatting,
even with stale launch arguments. A rerun after successful formatting refuses
without changing the disk. A reboot mounts through fstab and the unit checks.
An adopted volume always needs an inspected UUID and never receives format
permission.

Before formatting, first boot waits for the consistent device path, requires
a block device resolving to one whole disk without parent, children or mounts,
and reads its size successfully. Its model must be exactly `BlockVolume`, its
serial must contain 32 hexadecimal digits, and its WWN must equal `0x` followed
by that serial. A consumed permission record refuses another format. A bounded
request to `/opc/v2/instance/` must return valid JSON with a non-empty string
`id` and an object `metadata`. The two binding keys above must be non-empty
strings: a volume OCID and exactly `true` or `false`, matching the script
arguments. Missing, null, empty, incorrectly typed or mismatched fields,
unreachable metadata and timeouts refuse. The attachment metadata endpoint
is not available for this attachment type and is never requested.

On the operator side, the tool creates the volume in this run, binds it to this
instance, attaches it exclusively with `/dev/oracleoci/oraclevdb`, and observes
ATTACHED before treating add as successful. On the host side, the provider's
udev helper maps the attachment's unique device name through its SCSI LUN to
that consistent path; the host cannot read the volume's OCID from the disk.

The remaining gates require at least 2 GiB, complete zero reads of the first
and last GiB, and a zero 1 MiB sample at each intermediate GiB. Under pipefail,
a short read or read error refuses. Only after those reads may `blkid -p`
return status 2 with no output, `wipefs --no-act` return status 0 with no
signatures, and `lsblk` report no filesystem type. A validated UTC time and
exclusive creation of the consumed record, followed by syncing the record and
its parent directory, precede mkfs. Every device wait and probe has an explicit
timeout; disagreement, error, unexpected output or timeout refuses without
formatting. The samples are not proof of emptiness; creation and binding in
this invocation establish the format permission. At 100 GiB the reads cover
2 GiB plus 98 MiB; their elapsed time remains to be measured on a disposable
cloud host.

A crash after permission is consumed and before format completes deliberately
leaves the host stuck. Retire the instance, retain the volume and inspect it
offline. If it contains a verified filesystem, record its inspected UUID and
set the initialised tags by hand as described below, then adopt it. If it is
blank or half-formatted, quarantine it from discovery by removing its
`terrascale-host` discovery tag and create a fresh volume in a new invocation.
Never delete the consumed record to retry formatting.

The ext4 filesystem mounts by UUID at `/var/lib/ts-data`, with service data
under `/var/lib/ts-data/terrabase` and a bind mount from its `ts-orch` directory
to `/var/lib/ts-orch`. Identical systemd drop-ins for ts-orch and NetBird require
both mounts, stop with either mount, and check the mounted filesystem UUID
against `/etc/ts-orch/data-volume-uuid` and the device against
`/dev/oracleoci/oraclevdb` before starting. They also compare the disk serial
against `/etc/ts-orch/data-volume-serial`. Each captured command has its status
checked and an explicit non-empty check before comparison; command failures
cannot compare as two empty values. The state bind mount must have the same
device number as the data mount and filesystem root `/ts-orch`, while the data
mount must have filesystem root `/`. Upgrades preserve these drop-ins.
A host missing its data volume at boot requires console recovery. Agent unit
dependencies do not themselves quiesce existing database containers.

Add confirms the mount through the release listener's authenticated health
reply, using the existing GitHub OIDC token channel and the listener pin.
The operator needs an OIDC-capable environment; a listener handshake alone
cannot confirm the mount. The report contains the exact mount point, the
consistent data-slot device path after resolving and comparing its source,
filesystem UUID, filesystem type, disk serial and device size in bytes. Add requires
`/var/lib/ts-data`, `/dev/oracleoci/oraclevdb`, ext4, API size in GiB converted
to bytes, and the UUID already recorded on an adopted volume. A missing or
mismatched report fails without updating the volume. For a volume created
in this invocation, a full match writes and reads back
`terrascale-data-formatted=yes`, `terrascale-data-uuid=UUID` and
`terrascale-data-serial=SERIAL`. An adopted volume carrying a serial must match
it before any initialisation tag is changed; an older initialised volume
without one uses its UUID and receives the serial only after all other
comparisons pass. A serial is a second identity, never proof of the volume's
OCID by itself. It is believed stable across attachment changes, pending the
drill below. Those tags
make it an adopted volume on every subsequent invocation.

Each host compartment has a daily incremental backup policy at 02:00 UTC
with seven-day retention. Schedule and assignment are read back; another
assigned policy is refused. Backups are crash consistent and do not quiesce
the database. Database recovery after restore remains part of the cloud drill.

Removal always asks the provider for SOFTSTOP, waits for STOPPED, detaches and
waits for DETACHED, then terminates and waits for TERMINATED. The vendored
SDK documents that SOFTSTOP forces power-off after the provider's 15-minute
grace period; this can require crash recovery if shutdown did not finish.
No detach is allowed before STOPPED, whether or not the host answers. The
termination request explicitly preserves data volumes. Volumes, backups and
backup assignments are never deleted by remove.

| Observed instance / attachment | Removal action |
|---|---|
| RUNNING / attached | SOFTSTOP, then wait for STOPPED |
| STOPPING / attached | Wait for STOPPED |
| STOPPED / attached | Detach, then wait for DETACHED |
| STOPPED / DETACHING | Wait for DETACHED |
| STOPPED / DETACHED | Terminate, preserving data volumes |
| TERMINATING / detached | Wait for TERMINATED |
| No live instance | Report the retained volume |

Each interrupted removal resumes from API state. Add refuses STOPPING or
STOPPED hosts and asks the operator to finish or abandon the removal; it
never restarts them. After termination, add can launch a replacement for the
retained, initialised volume. An instance missing the launch binding is
refused; adopting boot-disk state requires a separate migration.

### Adopting a restored or cloned volume

Inspect the filesystem and its data outside add, confirm the intended host
and availability domain, and record its actual ext4 filesystem UUID. Set the
three discovery tags above, `terrascale-data-formatted=yes`, and
`terrascale-data-uuid` to that inspected UUID by hand. If a binding tag was
copied, verify the old bound instance is terminated before reusing it; do not
assign the clone to a running instance. Then run add for the intended name.
Missing tags or UUIDs refuse attachment. This path never grants format
permission, even if signatures are absent. Never mark a blank volume as
initialised in an attempt to make add format it.

### Local lane and disposable cloud drill

The local cloud model checks launch metadata, binding readbacks, authenticated
mount reports including serial mismatches and serial backfill, initialisation
tags and interrupted removal lifecycle states. It rejects detachment from an
instance that is still running. The metadata server returns the instance
document's real top-level keys with launch bindings under `metadata`, and 404
for the attachment endpoint. A real stalled HTTP connection exercises curl's
deadline, alongside unreachable HTTP, malformed JSON and missing, null,
empty, incorrectly typed or mismatched identity and binding values.

The loop-device exercise checks zero device writes for every refusal and
compares all bytes at batch boundaries. Existing stale permission, second
first-boot, read error, short read, probe failure, timeout and disagreement
cases remain. It checks real mount reporting, every service checker command's
failure and empty output, serial mismatch and the wrong second bind source.
A loop device cannot model a block volume's model, serial or WWN: lane command
adapters supply `BlockVolume`, a fixed 32-hex serial and its matching WWN, and
inject invalid values. The real device reads, writes, filesystem, UUID and
mounts use the loop device. Local loop exercises require a private mount
namespace and clean up their loop devices and mounts. The full service journey
runs on a disposable systemd runner. No cloud resources are used by the lane.

Graceful-stop timing and forced-stop behaviour, serial stability, and API
metadata/tag propagation remain unproven by the lane. Drill them on a
disposable host:

1. Verify the instance document's typed launch metadata and provider's
   consistent data-slot path before first format; missing fields must refuse.
   Measure the bounded reads on a 100 GB balanced volume.
2. Interrupt after creation, launch, binding, attachment, permission consumption,
   format and tag writes; verify no subsequent invocation formats a retained
   disk and follow offline recovery for an interrupted format.
3. Hand an adopted volume to a waiting stale script; verify launch binding or
   the consumed boot-disk record prevents formatting and preserves all bytes.
4. Repeat first boot and reboot with the disk present, missing and exchanged;
   verify UUID and serial preconditions prevent services using another
   filesystem, including an incorrect state bind source.
5. Confirm authenticated reports reject an answering but unmounted host, wrong
   UUID, serial, size, filesystem and device without initialisation tag changes.
6. Detach a volume and attach it to a new instance; verify its serial remains
   unchanged. If the serial changes, remove this comparison before moving any
   production host; do not bypass it during a move.
7. Interrupt removal at RUNNING, STOPPING, STOPPED, DETACHING, DETACHED and
   TERMINATING; verify graceful shutdown, forced-stop fallback, detachment
   order, retained backups and refusal to restart a stopped host.
8. Read back launch metadata and binding tags immediately and after
   interruptions to measure propagation and verify refusal on stale reads;
   check daily backups, seven-day expiry, duplicate volume refusal, conflicting
   attachments and unexpected backup assignments.
9. Restore a scheduled backup and clone a volume, inspect and tag the UUID,
   adopt without format, and verify filesystem and database recovery with
   sentinel data and host identity intact.
