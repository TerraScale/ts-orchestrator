# CORE local containerd qualification — 2026-10-16

This evidence covers a disposable local `linux/amd64` runtime. It does not qualify
ARM, OCI capacity, regional HA, production rollout, networking or database safety.

## Candidate and fixture

| Input | Observed value |
| --- | --- |
| Host | `mariogk-dev`, NixOS, Linux `7.2.10`, x86_64, cgroup v2, btrfs |
| Source baseline | `7a7abb4136c0de6fe3560d43e2b3af414b6dfd4b` |
| containerd | `v2.4.2`, revision `b7a25261e029d68978bbf290df0a62fc819b3c51` |
| containerd upstream amd64 tar SHA-256 | `35880c1dd4627e8ce56526bfabb39c144e83458ffdb197ce6f05d17d94d7d91e` |
| runc | `v1.5.2`, commit `v1.5.2-0-g29dd3dc`, libseccomp `2.6.1` |
| runc upstream amd64 SHA-256 | `599f6f94ff8c5057241eff0d54c3c74f95c34935b6457b33fe545defc61e9488` |
| SwarmKit library candidate | `v2.1.2`; not exercised by the raw runtime probe |
| Fixture | `/tmp/ts-core-runtime.45lrvd`, namespace `terrascale` |
| Image index | `docker.io/library/alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8` |
| Selected amd64 child | `sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764` |
| ARM64 child, discovered only | `sha256:2e1a7aa4cbc4e9e5222bb4c24a839aa1a6170ea5492d644777ce7b178824e44f` |

Both upstream release artifacts passed their publishers' SHA-256 files before
execution. The runc pin also matches containerd `v2.4.2`'s
`script/setup/runc-version`. No host package or system service was installed or
reconfigured. All local daemon and runtime commands ran at CPU priority 19.

The private fixture owns its root, state, temporary files, opt path, gRPC/ttrpc
sockets and shim sockets. The gRPC socket is root-owned mode 0660 within a mode
0700 temporary directory. No host runtime socket was mounted into a container.
The runtime probe used upstream `ctr` directly and no Docker Engine.

## Raw runtime results

At approximately `2026-10-16T18:46Z`, the isolated daemon reported the exact
containerd version/revision above. Overlayfs, native and btrfs snapshotter plugins
were available. `ctr run --rm` executed:

```sh
/bin/sh -c 'echo runtime-ready; uname -m; test ! -e /run/containerd/containerd.sock'
```

Observed output and result:

```text
runtime-ready
x86_64
exit status: 0
TASK    PID    STATUS
CONTAINER    IMAGE    RUNTIME
```

The task and container inventories were empty afterward.

At approximately `2026-10-16T18:49Z`, a detached container ran
`echo durable-runtime-ready; exec sleep 300`. The fixture's exact daemon PID
received SIGTERM and was restarted with the same private configuration. Before
and after inventory output compared byte-for-byte equal:

```text
TASK                      PID        STATUS
ts-core-identity-smoke    2956392    RUNNING
```

The same container process survived the daemon restart. SIGTERM did not stop
this PID-1 sleep process; SIGKILL stopped it with exit 137. The task and container
were removed and the namespace returned to an empty task inventory. This proves
containerd/shim process persistence only; executor-agent recovery is recorded
separately below.

## Executor and embedded SwarmKit results

The corrected source handoff is `a81c3c7481ab6261e23572bd5f0474d07c477109`;
subsequent readiness code at `fe486035f22105553146ac625d29bfed6230d95e` is
not qualified by these runtime logs. The passing combined binary is retained
locally at `/tmp/ts-core-combined.test`, built with Go `1.27.1`, SHA-256
`436617d275327d80f05d4a833860feb9e3145735d6ffe70028074d078c4b8032`.
The recovery binary was compiled before that commit, from
`d6cf7154` plus the executor/test changes subsequently captured by `a81c3c74`,
with the shared development `go.mod`/`go.sum` union patch, rather than a clean
exact-commit tree. It imports the pinned
SwarmKit/containerd versions above. The earlier failing combined run used the
uncorrected fixture source; its binary was overwritten, so its binary hash and
exact committed source identity cannot now be recovered. This record preserves
one successful sample per scenario; it is not a benchmark distribution, cost
comparison or evidence of improved performance.

| Real boundary scenario | Result | Observed duration |
| --- | --- | --- |
| `TestContainerdLifecycleAgentRecovery` | PASS: two agent processes recovered one running PID; conflicting identity rejected; non-root/read-only constraints, bounded surviving logs, failed logger rejection, metrics, graceful shutdown and idempotent removal asserted | 2.65 seconds |
| `TestContainerdHostPortReservationRecovery` | PASS: duplicate host-port reservation refused across executor reconstruction and released after removal | 2.25 seconds |
| Initial `TestRuntimeServiceSurvivesNodeRestart` | FAIL: fixture command exited 127; no HTTP readiness; convergence deadline and node cleanup failed | 180.01 seconds |
| Corrected `TestRuntimeServiceSurvivesNodeRestart` | PASS: actual manager/agent scheduled the container, application stayed ready while node stopped, original node/task/PID returned after restart, service removal deleted container | 4.87 seconds |

The first combined fixture assumed BusyBox provided `httpd`. It did not. The
corrected fixture uses its actual persistent `nc -lk -e` HTTP responder; the failed
run remains retained. The failure log also contains repeated host-port rejection
while the failed original container retained its reservation. The passing run
contains `network support is unavailable` errors from SwarmKit's unsupported
allocator path. This private host-network scenario does not establish overlay
networking or general network allocation.

The corrected run at `2026-10-16T19:52:57Z` reported:

```text
real service 9j16x60efgzu0qm8jfyxb292s retained task mskselo4vpm7y2jw20t49xmzn pid 3381976 across node restart; state=002
--- PASS: TestRuntimeServiceSurvivesNodeRestart (4.87s)
PASS
```

The parent runtime owner observed an empty namespace after cleanup; this evidence
worker did not independently requery it after NET borrowed the daemon.

### Recorded commands

The runtime owner recorded the corrected compile command below, run in
`/tmp/ts-orchestrator-core`. The file lock serialized it with other shared local
checks; local CPU priority and build parallelism were bounded.

```sh
flock /tmp/ts-orch-refactor-gate-check.lock env GOMAXPROCS=2 GOFLAGS='-p=2 -mod=mod' nice -n 19 timeout 120s go test -c -o /tmp/ts-core-combined.test ./internal/swarmruntime
sudo -n nice -n 19 /tmp/ts-core-combined.test -test.v -test.run '^TestRuntimeServiceSurvivesNodeRestart$' -test.timeout=5m -containerd-socket /tmp/ts-core-runtime.45lrvd/containerd.sock > /tmp/ts-core-runtime.45lrvd/evidence/combined-runtime-recovery.log 2>&1
```

The earlier combined invocation used the same test binary path, disposable
socket and five-minute test timeout, with a selector covering the executor,
host-port and service-restart scenarios listed above. Its exact selector was
not retained; only actual run names/results from the complete log are claimed.
No test was rerun by this evidence-only handoff after NET reserved the daemon.

The private daemon configuration was:

```toml
version = 4
root = '/tmp/ts-core-runtime.45lrvd/root'
state = '/tmp/ts-core-runtime.45lrvd/state'
temp = '/tmp/ts-core-runtime.45lrvd/tmp'
disabled_plugins = ['io.containerd.cri.v1.images', 'io.containerd.cri.v1.runtime', 'io.containerd.grpc.v1.cri', 'io.containerd.nri.v1.nri']
[plugins.'io.containerd.server.v1.grpc']
  address = '/tmp/ts-core-runtime.45lrvd/containerd.sock'
  uid = 0
  gid = 0
[plugins.'io.containerd.server.v1.ttrpc']
  address = '/tmp/ts-core-runtime.45lrvd/containerd.sock.ttrpc'
  uid = 0
  gid = 0
[plugins.'io.containerd.shim.v1.manager']
  socket_dir = '/tmp/ts-core-runtime.45lrvd/shim'
[plugins.'io.containerd.internal.v1.opt']
  path = '/tmp/ts-core-runtime.45lrvd/opt'
```

The raw runtime probe commands used the same private address and namespace:

```sh
sudo -n nice -n 19 env PATH=/tmp/ts-core-runtime.45lrvd/bin:/run/current-system/sw/bin /tmp/ts-core-runtime.45lrvd/bin/containerd --config /tmp/ts-core-runtime.45lrvd/config.toml
sudo -n nice -n 19 /tmp/ts-core-runtime.45lrvd/bin/ctr --address /tmp/ts-core-runtime.45lrvd/containerd.sock --namespace terrascale run --rm docker.io/library/alpine:3.22 ts-core-ctr-smoke /bin/sh -c 'echo runtime-ready; uname -m; test ! -e /run/containerd/containerd.sock'
```

The tag in the early raw probe resolved to the retained index digest above.
The executor scenarios use the pinned architecture-specific child manifest.

### Retained raw evidence

The complete original logs remain locally under the fixture's `evidence/`
directory. Compressed byte-preserving copies are committed beside this document;
`gzip -dc <file> | sha256sum` verifies their original bytes.

| Original log / committed gzip | Original SHA-256 |
| --- | --- |
| `combined-runtime-final.log` / `core-containerd-local-2026-10-16-final.log.gz` | `3e6b3b600a19fbc37394d7925b139d1f77a893117ab88df43c053a328df18001` |
| `combined-runtime-recovery.log` / `core-containerd-local-2026-10-16-recovery.log.gz` | `7bf2f6264733f098d9a1a689f2ec0999d4ffd936c561e357262180bcda1baa64` |

Runtime configuration SHA-256:
`d8fcfee667381177b5368ad0b564c51656772f13212a7cce50a6137fbe54182b`.
The raw `ctr` identity-before/after files each contain the identical PID/status
shown above. Full daemon logs and downloaded artifacts remain in the disposable
local fixture; they are not required to inflate this small retained result.

## Logical three-manager leader loss

`TestRuntimeThreeManagerLeaderLoss` passed in **27.13 seconds** on the same
local runtime at approximately `2026-10-16T20:12:46Z`. Three independently
persisted managers joined through real upstream manager tokens, certificate
exchange and Raft. The fixture paused task admission on the current leader so
the serving task ran on a surviving agent. It stopped the actual leader node,
probed the real HTTP container during election, and observed a new two-manager
quorum leader after **17.053651416 seconds**:

```text
logical three-manager failover jp6fe4ifop5u2q3pnc7y96ac5 -> ewy7e16tfahp3gd3bxmt4b5c9 in 17.053651416s retained task c7na6vto3kw03eix68oghoi3l pid 3508635; new-leader create/update/remove passed
--- PASS: TestRuntimeThreeManagerLeaderLoss (27.13s)
PASS
```

The surviving application retained its original task and PID, with exactly one
container for that service. The new leader created a second real workload,
committed a service metadata CAS, and removed both services and their containers.
Independent `ctr tasks ls` and `ctr containers ls` observations in namespace
`terrascale` were empty before the fixture was released to NET. The daemon itself
was not stopped or reconfigured during this scenario.

This is one same-host logical manager-loss sample. It does not prove host-loss
HA, regional HA, an ungraceful crash, continuous availability between probe
samples, partitions, concurrent bootstrap, rollback or architecture portability.

### Candidate and commands

Own test commits: `9482beede024d1859a386987e33a11888cb857fe`,
`61b29735e3fbb4f876349e2cf9be06ed6dc1e482`, and
`70652e25` on CORE baseline `43ab842a`. The local development candidate also
included borrowed autoscale fix `550e3653` (local cherry-pick `fcdd5337`), the
shared dependency union patch, and an uncommitted baseline-only correction from
`NewAutoscaler(..., tracing, ...)` to its declared variable `racing`. Two initial
compiles failed on that inherited typo before it was corrected. These patches
are not part of the new failover test commits. This is not a clean exact-commit
or integrated-candidate qualification.

| Input | SHA-256 |
| --- | --- |
| `/tmp/ts-core-failover.test` | `24f73dc891089cb9cd734be992995bd0e7badeb9e86c874dceb5e5efd47cf21b` |
| Development `go.mod` | `19b439ed68fb22e3308a1c328638f2e8c82f573b77d721ac54a8a8d7f2c36c9f` |
| Development `go.sum` | `fe49c8f0fe3996e14c628180f5aaf32adef2b064487450c44bd4495dcbbd43a6` |
| `/tmp/core-combined-dependencies.patch` | `8169be8ffa27ade2d5b4af18d69299b4a0ec3e647023f7582f811ac60f832b0c` |
| Raw `three-manager-failover.log` | `e20185e5a23da83d8dd99efea102da0bd82ba3b8646ab6add7fcc6ac7d9addf1` |

The raw log is retained beside this document as
`core-containerd-local-2026-10-16-failover.log.gz`, preserving its original bytes.
The successful cached build used QA's explicitly reserved capacity lane:

```sh
# Working directory: /tmp/ts-orchestrator-failover
flock /tmp/ts-orch-refactor-capacity-check.lock env GOMAXPROCS=2 GOFLAGS='-p=2 -mod=mod' nice -n 19 timeout 120s go test -c -o /tmp/ts-core-failover.test ./internal/swarmruntime
sudo -n nice -n 19 /tmp/ts-core-failover.test -test.v -test.run '^TestRuntimeThreeManagerLeaderLoss$' -test.timeout=5m -containerd-socket /tmp/ts-core-runtime.45lrvd/containerd.sock > /tmp/ts-core-runtime.45lrvd/evidence/three-manager-failover.log 2>&1
```

## Operational finding

containerd 2.4's configuration version 4 moved gRPC/ttrpc addresses into
`plugins.'io.containerd.server.v1.grpc'` and
`plugins.'io.containerd.server.v1.ttrpc'`. The initial fixture used the old
`[grpc]` section, which containerd silently ignored, briefly binding default
`/run/containerd/containerd.sock` and `.ttrpc`. The owner detected the absent
expected private socket before launching any container and stopped that exact
fixture daemon PID `2885104`. Its sockets disappeared on exit; no existing daemon
was running and no system service was changed. The corrected fixture explicitly
sets both plugin addresses and `io.containerd.shim.v1.manager.socket_dir` beneath
the private temporary directory.

Future fixture launchers must verify the effective v4 addresses before starting,
then verify the live socket and version before any task is created.

## Remaining qualification

Production entrypoints and ownership transfer remain unqualified by these package
scenarios; the old execution owner has not been cut over.
No cloud resources, credentials, paid capacity, production workloads or running
host services were changed. ARM64, multi-node regional integration, production
ingress, external socket bind conflicts, rollout/rollback, three-manager HA and
stateful fencing remain outside these results. The durable adapter reservation
check and local HTTP readiness are limited to the scenarios recorded above.
