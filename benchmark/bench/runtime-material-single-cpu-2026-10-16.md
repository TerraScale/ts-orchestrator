# Containerd material and single-CPU integration evidence

Both scenarios passed on 2026-10-16 on Linux/amd64. This evidence covers frozen
source `7d1508c34c6d6d1527eafecd80e01f9a3be14752` **with the development overlays
listed below**. It does not qualify a clean checkout, the final integrated
candidate, ARM execution, or production function credentials.

| Scenario | Observed test duration | Result |
| --- | ---: | --- |
| `TestContainerdSingleCPUAllocatable` | 2.64 s | PASS; child observed one CPU and 750m allocatable |
| Nested `TestContainerdLifecycleAgentRecovery` | 2.60 s | PASS; real container lifecycle and two agent-process recoveries retained one task PID |
| `TestContainerdFunctionMaterialBoundary` | 2.29 s | PASS; real nonroot process read the immutable, read-only material mount and survived client reconnect without duplication |

These are observed integration-test durations, not latency or capacity benchmarks.
The single-CPU test constrains the agent subprocess with `taskset` before Go
starts. The disposable containerd daemon retains its normal host affinity. This
proves nonzero advertised capacity and real bounded task execution; it does not
measure headroom on a one-CPU VM under load.

## Candidate and commands

The source worktree was `/tmp/ts-orchestrator-runtime-function-material`.
The successful binary was `/tmp/ts-runtime-function-material.test`, SHA-256
`a25d400c494146c3da33a5d3bfc187329c32f9cd11e530c77d2e4e2195101b85`.
The binary is not checked into this repository.

The fixture used the architecture-specific child manifest
`docker.io/library/alpine@sha256:3e9b4b680bfc9fb5269227cffbd6d42be39fbf7c0b908123913864aa4447e764`.
The test workloads run as `65532:65532`, with a read-only root filesystem,
250m CPU and 64 MiB memory limits. Function material is mounted only at the
fixed `/run/ts-orch/function` path.

The cached compile ran after QA explicitly reserved the capacity lane:

```sh
flock /tmp/ts-orch-refactor-capacity-check.lock timeout 180s \
  env GOMAXPROCS=2 GOFLAGS=-p=2 nice -n 19 \
  go test -c -o /tmp/ts-runtime-function-material.test ./internal/swarmruntime \
  > /tmp/ts-runtime-function-material-build.log 2>&1
```

It exited 0 in approximately 12 seconds, with an empty success log. The compiler
lane was released before the runtime scenarios. An earlier compile attempt
failed on missing development dependencies (`validDigest` and
`ociclient.RequestContext`); the listed peer overlays corrected those missing
inputs before the successful compile.

CORE exclusively reserved the disposable daemon for this run after NET's
explicit release:

```sh
sudo -n env GOMAXPROCS=2 nice -n 19 /tmp/ts-runtime-function-material.test \
  -test.v \
  -test.run '^Test(ContainerdFunctionMaterialBoundary|ContainerdSingleCPUAllocatable)$' \
  -test.timeout=5m \
  -containerd-socket /tmp/ts-core-runtime.45lrvd/containerd.sock \
  > /tmp/ts-runtime-function-material-runtime.log 2>&1
```

The runner exited 0. The compressed, unedited runtime output is retained in
[runtime-material-single-cpu-2026-10-16.log.gz](runtime-material-single-cpu-2026-10-16.log.gz).
The uncompressed log SHA-256 is
`d86ce0abb00914ae5ea21a3132ad7cd795ddecaaa62e6ab03145d0c09679a6a8`.

## Development dependency provenance

These overlays were present during compilation and were excluded from the
executor source commits. `go.mod` and `go.sum` came from the parent integration
worktree `/tmp/ts-orchestrator-core`; that development module union was not a
separately committed dependency candidate. The exact input hashes distinguish
this run from later parent integration changes.

| Input | SHA-256 |
| --- | --- |
| `go.mod` | `19b439ed68fb22e3308a1c328638f2e8c82f573b77d721ac54a8a8d7f2c36c9f` |
| `go.sum` | `fe49c8f0fe3996e14c628180f5aaf32adef2b064487450c44bd4495dcbbd43a6` |
| `internal/ociclient/retry.go` | `3acb4127a447e3130f29578b5bde93fa590dcd9cd2c222f330ee42d3420df5fb` |
| `internal/ociregion/registry/pullauth.go` | `b43c94d857099292b035010ed2c09e70215599a0155ff3b4e54cd56a68bbfb98` |
| `internal/ociregion/registry/registry.go` | `2b518fb0826f5c753602894a5b9b75a36daaa77edecc1eb47950d30a6bebace1` |
| `internal/ociregion/registry/retention.go` | `92b69aa438e69f75fc96521a2d1af4e372b3b8dbba28a38327049d8314ee046a` |
| `internal/swarmruntime/registry.go` | `604c8ff6373346470c5b380a771e2ef3c5997e6913fd35daca590ea57b0bce55` |

The four OCI sources were copied from
`/tmp/ts-orch-oci-registry-auth`. Their matching source commits are
`e3a12435fc8aa7f0b184dcf14744772062b29911` (`retry.go`),
`cf553305e04ea78c540a77fe8aa6bedf2cff4e87` (`pullauth.go`), and
`2badf08973a6583ddaffdafed49a73afdcd6bb27` (registry ownership and retention).
The runtime registry source was copied from
`/tmp/ts-orchestrator-core-registry`; its exact bytes match
`12e3de169e10e71659bfb4b6f74f8db7213a15e4`.
These scenarios used the public image resolver and do not qualify private OCIR
credentials or later revisions of the registry adapter.

## Observable boundaries and cleanup

The material scenario crossed the real containerd, runc, kernel mount and
process boundaries. It rejected absent authority, mismatched recipient and
node bindings, expired grants, an extra caller-selected file path, immutable
credential replacement, and proof/force-update mutation. A nonroot process
proved the ten fixed files readable and the material directory unwritable.
Client reconnect retained the same worker PID; a new expired-grant check still
rejected reattachment. Task removal deleted its recipient files.

The lifecycle child also exercised log-collector readiness failure, agent
process recovery, identity conflict rejection, bounded logs, metrics, wait
cancellation, graceful shutdown and idempotent removal.

After both tests finished, these independent read-only commands returned only
the table headers shown below:

```sh
sudo -n /tmp/ts-core-runtime.45lrvd/bin/ctr \
  --address /tmp/ts-core-runtime.45lrvd/containerd.sock \
  --namespace terrascale tasks list
# TASK    PID    STATUS

sudo -n /tmp/ts-core-runtime.45lrvd/bin/ctr \
  --address /tmp/ts-core-runtime.45lrvd/containerd.sock \
  --namespace terrascale containers list
# CONTAINER    IMAGE    RUNTIME
```

The `terrascale` namespace had no remaining tasks or containers at handoff.
Image cache was retained. No daemon configuration changed. The daemon was then
explicitly released to CORE qualification; no compiler or runtime check remained
queued by this task.

## Qualification limits and later fixture change

The material provider supplied test-only synthetic bytes. This evidence does
not exercise real signed function intent, OCI Vault delivery, narrow broker
credentials, mTLS ingress, tenant Wasm execution, or the complete app producer
and consumer pipeline. No live OCI, NetBird or production resource was changed.

After this frozen run, test-only commit
`4e732fcb` changed `integrationImage` to select a pinned child by the native
`runtime.GOARCH`, while preserving the same amd64 child. Its ARM child is
`sha256:2e1a7aa4cbc4e9e5222bb4c24a839aa1a6170ea5492d644777ce7b178824e44f`;
unsupported architectures fail explicitly. That later selector was not part of
the tested binary. The ARM child was discovered, not execution-qualified by this
run. The final integrated source and native ARM image still need their owning
qualification scenarios.
