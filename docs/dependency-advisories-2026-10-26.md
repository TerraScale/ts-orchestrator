# Dependency qualification, 2026-10-26

Dated record of 2026-10-26; the current procedure is [GitHub producer verification](releases.md#github-producer-verification).

The executable graph is selected by the root module and its local SwarmKit,
NATS and OCI replacements. The independent e2e module and all three replacement
modules also receive package/test scans. Historical manifests under `docs/`
remain immutable evidence and do not select current executable dependencies.

Run `bash scripts/ci/audit-dependencies.sh source` using Go 1.27.3. It runs
govulncheck 1.9.0 on all five package/test graphs, including locally patched
sources. An imported vulnerable package, scanner error or invalid graph fails
the existing test job. No advisory is ignored. The existing Go build/module
caches retain the scanner compilation and downloads; only one race shard scans.
The scanner binary is checksum-verified before execution and self-audited against
the current feed, including its compiler and full module graph.
Main repeats the source check before qualification and scans both actual release
binaries before publishing their bytes. Symbol tables are retained (`-w`, rather
than `-s -w`) because stripped binaries cannot reliably establish package
absence. The amd64 baseline comparison adds about 11 MB to the executable.

## Manifest and selected-version findings

The standalone SwarmKit manifest had stale indirect WebSocket and OpenTelemetry
bounds even though the application selected patched versions. Refreshing its
dependency metadata removes obsolete entries and explicitly selects patched
WebSocket 1.5.3, OTLP exporters 1.46.0 and Goldmark 1.8.6. Root selections remain
at least as new. Root also pins patched ebpf 0.22.0 and xz 0.5.17. NATS and OCI
standalone graphs now select patched x/mod 0.41.0 and x/net 0.61.0, with compatible
x/crypto 0.58.0 and x/sys 0.49.0. These changes do not replace local runtime code.

Full `go list -m -json all` graphs include upstream requirements whose packages
are absent from the build. They are retained in the audit evidence rather than
treated as a zero-match module scan. The affected unused constraints are AWS
v1.37.0, Docker distribution v2.8.3+incompatible, Prometheus
v2.5.0+incompatible and monolithic etcd/v3 v3.5.5. OpenPGP is the
maintenance record in x/crypto v0.58.0 (standalone SwarmKit: v0.57.0).
The exact selected-module reports, five test-inclusive package inventories and
complete advisory records are retained in the PR/ticket evidence index.


| Record | Disposition and verification |
| --- | --- |
| GO-2026-5932, x/crypto OpenPGP | Unmaintained package family, no fixed version. All five package/test graphs and both release binary symbol scans must show no affected package. Other x/crypto packages remain maintained dependencies. |
| GO-2022-0635 / GO-2022-0646, aws-sdk-go v1 | Affected S3 encryption packages are absent from all five package/test graphs. No AWS SDK is embedded in the release executable. |
| GO-2026-5264 / GHSA-8rm2-7qqf-34qm, old Prometheus module | Remote-read server packages are absent. The application uses separate maintained metrics/client modules. Replacing the old incompatible-major constraint with the newer v0 module forces unrelated MVS downgrades, so its unused constraint is documented. |
| etcd/v3 3.5.5: GO-2024-2528, -2529, -2530; GO-2026-4806, -4808; GHSA-6vch-q96h-7gc3, -q8m4-xhhv-38mg, -rfx7-8w68-q57q, -x35m-3gp4-4fh5, -xg4h-6gfc-h4m8 | The monolithic module's packages are absent; actual etcd packages come from the separate patched api/client/pkg/server 3.6.14 modules. |
| GHSA-685w-q87j-wqw3, docker/distribution v2 | Affected registry code is absent; the application uses separate maintained distribution/reference and containerd modules. |

These are package-absence dispositions, not advisory suppressions or claims
that every transitive module constraint has zero advisory matches. The stricter
package gate rejects a future import of an affected package. Repeated controls
in tracked Git fixtures imported vulnerable x/net/html 0.48.0 (five package
findings, exit 3) and an invalid import (loading error, exit 1). These supersede
the old final-control logs, which stopped at a Git error before scanning.
Scanner diagnostics never count as clean. The replacement-baseline control used
the actual published x/net 0.48.0 sources and upstream commit: binding passed,
then the official OSV response contained findings and the baseline audit failed.
Additional controls rejected version/path/identity/commit/source drift, missing
source, malformed responses and transport errors; both valid empty response
forms passed. Complete responses, exact commands and exit codes are retained in
the PR/ticket evidence index.

## Replacement provenance

Runtime source provenance remains in the existing records:

- SwarmKit `github.com/moby/swarmkit/v2` v2.1.2: upstream `12ce3490ef26cbca6ef9b243cb013fffbfe6a6cb`.
- NATS 2.15.0: `third_party/nats-server/README.terrascale.md`, upstream
  `eb763679aa3c24a40dcd3012aa046ad1996d851c` and recorded local runtime patches.
- OCI 65.126.0: `docs/patches/oci-sdk-v65.126.0-context/provenance.json`, upstream
  `d48ee53a6d31d110dbe1316cf8762a191b916747` and recorded context patches.

This change updates their dependency metadata, not those archived provenance
snapshots. Required CI and exact merged binary evidence remain necessary before
advancement. This qualification does not establish a production exploit or
change the deployment ownership boundary.

Govulncheck cannot match advisories against local replacement versions. Before
either source or binary scans, `scripts/ci/audit-replacements.py` checks the exact
root requirements, selected versions, replacement paths, declared module names,
and recorded upstream versions/commits above. Reviewed SHA-256 digests bind every
tracked replacement file, including dependency manifests; source drift or missing
sources fails and requires renewed review. The helper then queries the official
OSV API for all three published baselines, prints complete raw responses, and
fails on any finding at any severity or any request/response error. No record is
filtered. This baseline check does not establish that local patches are safe or
equivalent to an upstream commit: actual patched sources and tests still receive
their separate native package scans. Exact-head integration CI remains required.

## 2026-10-27: x/net 0.62.0

GO-2026-6866 and GO-2026-6860 (x/net/html, fixed in 0.62.0) failed the root graph
at x/net 0.61.0 and standalone SwarmKit at 0.60.0. The root module and all three
replacement manifests now select x/net 0.62.0. SwarmKit also moves to x/text 0.43.0
and x/tools 0.51.0, which the root already selected. Only `go.mod` and `go.sum`
changed in the replacements, and their reviewed digests in
`scripts/ci/audit-replacements.py` were recomputed. `bash scripts/ci/audit-dependencies.sh source`
reports no vulnerabilities in all six scans.

## 2026-11-16: replica scaling authority and placement

C11 adds `manager/replicas.go` to check the local Raft term and service version
inside replica transactions, without forwarding writes or replacing release
rollback history. `manager/scheduler/replicas.go` uses the existing readiness,
resource-request, placement-constraint, platform, host-port and replica-limit
filters to count additional placements. The two-node lifecycle journey exercises
these additions with real containerd tasks. The SwarmKit source digest is renewed
in `scripts/ci/audit-replacements.py`; its published upstream baseline is unchanged.

## 2026-11-17: node removal placement

C12 adds `Relocatable` to `manager/scheduler/replicas.go`. It places every live
task of a leaving node on the other nodes through the same readiness,
resource-request, placement-constraint, platform, host-port and replica-limit
filters, so the region leader drains a node only when its tasks fit elsewhere.
The SwarmKit source digest is renewed in `scripts/ci/audit-replacements.py`; its
published upstream baseline is unchanged.

## 2026-11-17: app image identity

C42 adds `api/app_image.go` and updates `manager/orchestrator/task.go` to
compare legacy TerraScale GHCR references and package-only references by the
same package and manifest digest. Reason: SwarmKit's updater and up-to-date
task filter compare the new template with immutable stored task snapshots,
so normalizing only the submitted spec still replaces a serving task.
The desired template keeps its new reference for future tasks; different
packages or digests still require replacement. The native installation
journey verified no successor and retained RUNNING tasks for the same digest;
the native rollout journey verified a new task ID for a different digest.
The reviewed SwarmKit source SHA-256 in `scripts/ci/audit-replacements.py` is
`b7e83a749008520a074ba5cff4629088538c7a636603858ac8449e507eaa5f9f`.
The published `github.com/moby/swarmkit/v2` v2.1.2 baseline and upstream commit
`12ce3490ef26cbca6ef9b243cb013fffbfe6a6cb` remain unchanged.

## 2026-11-18: SwarmKit CA forwarding advisory

Upstream moby/swarmkit merged a private security fix as
`a34f01e8c294ace05ffbfc2aef669f8fb8b7e8d5` ("Merge commit from fork", 2026-11-03,
"ca: forward a request to the leader only once"). Our v2.1.2 copy had the same
`ca/forward.go`: `WithMetadataForwardTLSInfo` built the outgoing metadata from
the incoming context and never refused an already forwarded request, so a
request forwarded twice to the leader carried the forwarding manager's identity
as the client. The fix is ported unchanged: an already forwarded request is
refused with `ResourceExhausted`, the metadata starts from the outgoing context
and a missing peer clears `remote_addr`. Upstream `0562f4d2f` only swaps the
archived go-grpc-prometheus dependency and is not ported.
The reviewed SwarmKit source SHA-256 in `scripts/ci/audit-replacements.py` is
`4309b7cfbae7ab97c517aa89172fbda7b74773fc3d1716bb752e9cb76a34877e`; the
v2.1.2 baseline and upstream commit `12ce3490ef26cbca6ef9b243cb013fffbfe6a6cb`
remain unchanged.

## 2026-11-18: updater adopts a candidate only once it runs

C1b changes `manager/orchestrator/update/updater.go`. `useExistingTask` used to
adopt an existing clean task, stop the slot's other tasks and return at once,
even while the adopted task was still pending. A restarted updater could
therefore stop the old task of every slot before any replacement ran. It now
waits for the adopted task to run before the worker takes the next slot. Under
start-first order it starts the adopted task and stops the slot's other tasks
only once it runs, as `updateTask` does. It also counts the adopted task's
failures toward the failure action. The e2e-m1 rollback lane exercises this
with real containerd tasks.
The reviewed SwarmKit source SHA-256 in `scripts/ci/audit-replacements.py` is
`57ce89504a724988faacc67fc8e5841b892c8dfee8c5e7bf491d53831473c57b`; the
v2.1.2 baseline and upstream commit `12ce3490ef26cbca6ef9b243cb013fffbfe6a6cb`
remain unchanged.

## 2026-11-18: scheduler re-queues wanted tasks and counts a waiting replacement once

C1c changes three files in `manager/scheduler`. Neither behaviour is fixed upstream
at v2.1.3 or at master `a34f01e8c` (2026-11-03).

- `scheduler.go` `noSuitableNode` used to drop every task whose spec version
  was older than its service's from the scheduling queue, writing nothing to
  it, so no later event brought it back. Every service write bumps the spec
  version, including a labels-only write and the stop-first update-order
  rewrite. A still-wanted pending task then stayed pending even after room
  appeared (gru ts-dashboard, 2026-11-18). Now only an old-version task that is
  pending and desired shutdown is shut down; every other task gets its error
  and is re-queued.
- `nodeinfo.go`, `filter.go`: tasks of the same service and slot on one node
  that publish the same lowest port hold their largest CPU and memory
  reservation once, not the sum. The TerraScale runtime never starts a task
  while a live container holds one of its ports, so at most one of them runs
  at a time. A stop-first replacement waiting beside its predecessor, such as
  TerraBase while its regional handoff is refused, therefore fits in the
  predecessor's room. The predecessor holds its full reservation until it
  leaves the node, so no other task takes that room while it still runs.
  Tasks without a published port, such as start-first apps on task ports,
  keep one reservation each. Generic resources, including disk, are claimed
  per task as before. When and how a task stops is unchanged.

The e2e-m1 rollback lane exercises both with real containerd tasks.

## 2026-11-18: a fixed-port replacement starts only once its predecessor stops

C24 changes `manager/orchestrator/restart/restart.go` and
`manager/orchestrator/taskinit/init.go`. A stop-first replacement waited for
its old task to stop for at most `defaultOldTaskTimeout` (one minute) and was
then started anyway; after a manager leader change, `taskinit` started every
task left at desired state READY at once, without looking at the old task. A
TerraBase predecessor whose regional handoff is refused keeps running and
keeps its host ports, so its replacement started into
`host port 6432,8080 is reserved`. `DelayStart` with `waitStop` now also waits,
without a timer, while a task of the same service that was told to stop is
still starting or running in the replacement's slot or on its node (node not
down). It applies only to tasks that publish host ports and stay at desired
state READY; start-first updates never wait, because their old task is still
desired RUNNING. `taskinit` goes through `DelayStart` for the same check.
The e2e-m1 rollback lane holds a predecessor 70 s past SIGTERM.
The reviewed SwarmKit source SHA-256 in `scripts/ci/audit-replacements.py` is
`24fbdff9ea98eee78ffe5ccb5b913d3a86004b9578649937650749f97ce34310`; the
v2.1.2 baseline and upstream commit `12ce3490ef26cbca6ef9b243cb013fffbfe6a6cb`
remain unchanged.
