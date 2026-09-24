# Local development

The repository pins Go 1.27.1 in `.mise.toml`. On a first checkout, trust that
repository config and install its toolchain, then run the same verification
targets used in CI:

```bash
mise trust .mise.toml
mise install
mise exec -- make verify
mise exec -- make build
```

`make verify` checks formatting, runs all Go tests, runs `go vet`, and runs the
tests with the race detector. `make build` writes the current-platform binary
to `dist/terrascale-orchestrator`.

## Regional NATS lab

Use a disposable directory for JetStream storage. A single-node lab config
sets `nats.lab` to `true` and provides an embedded NATS listener and
`store_dir`; R3 labs need one process per peer, unique `instance` and
`store_dir` values, and route seed addresses in `nats.embedded.routes`. The
strict configuration fields and secure-mode requirements are documented in
[`internal/natscell/runtime.go`](../internal/natscell/runtime.go) and
[`internal/app/config.go`](../internal/app/config.go).

The binary accepts `run`, `host`, `check`, and `operator` commands with
`--config FILE`; `identity-new --key FILE` creates an owner-private Ed25519
key and prints the matching public key. Hosts cannot start the embedded NATS
server. Keep private keys outside the repository.

By default, the artifact object store is limited to 2 GiB and each embedded
NATS server's file store to 8 GiB. Controller startup reserves at least 1.5
GiB of that configured file-store limit beyond the artifact quota for
control-state streams and buckets. Reducing or exhausting the artifact quota
does not evict admitted objects. An interrupted or concurrent upload may
leave chunks behind, and the current implementation has no automatic garbage
collection or repository-managed cleanup path. Once the quota is full, new
uploads fail with `ErrArtifactStoreFull`.

Managed OCI mode requires `controller.oci_region_intent_file`,
`controller.oci_region_config`, and `controller.placement_config` together.
The placement file accepts `environment`, `member_role`, `resources`, and an
optional `tick_millis` (zero means the five-second default; otherwise 100 to
300000). Managed placement can create region-bound hosts and retained volumes
but stops at `awaiting-runtime-contract` after confirmed attachment; host
image/bootstrap/enrollment remain operator-provided, and no TerraBase serving
claim is made. See [`internal/app/managed_config.go`](../internal/app/managed_config.go)
and [`internal/placement/controller.go`](../internal/placement/controller.go)
for the strict parser and lifecycle boundary.

## Firecracker qualification

Use the four-VM harness described in
[`tests/firecracker/README.md`](../tests/firecracker/README.md). First run its
read-only prerequisite check, then start the live qualification from the
repository root:

```bash
python3 tests/firecracker/qualify.py check
python3 tests/firecracker/qualify.py run
```

The harness requires Firecracker, `/dev/kvm`, `/dev/net/tun`, the pinned kernel
at `/tmp/vm-inputs/vmlinux`, and the pinned base filesystem at
`/tmp/vm-inputs/rootfs.ext4`. `check` creates no VMs or network devices. `run`
needs passwordless `sudo` for the documented network, mount, and service
setup commands. It builds the current Linux amd64 binary, verifies the Go
source stayed unchanged during the build, and creates fresh working copies of
the guest images in a private per-run directory. The scenario covers the
controller/operator/host path, workload execution, host reboot recovery, and
control-quorum loss and recovery. A successful local test run does not replace
this guest qualification.

### Latest local qualification

On 2026-09-24, the four-VM run passed at source revision
`df09ee5692b4a5dc60230f019d1265efccb2f972` using Go 1.27.1 via `mise`. It observed an
admitted native workload running in the guest, host restart recovery, a
replacement deployment after one controller/NATS node loss, a rollback
command refused before submission while quorum was absent, and a successful
rollback after quorum recovery. During controller loss, host session
renewal/reporting failed with `context deadline exceeded`; systemd restarted
the host agent and the workload later returned to running. This demonstrates
recovery, not uninterrupted availability. No durable rollback rejection
receipt was produced without quorum.

The harness-built binary SHA-256 is
`58734d4f88704cd23cc93c94b99de1442030d9688f87159f35175e02d57458b9`; its Go
source manifest SHA-256 is
`41b62b99f5a563339a61a3c7bccc1037f1228e9432351252b6652a75041b4284`. The
pinned Linux 6.1.155 kernel hash is
`e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2`; the
Ubuntu root filesystem hash is
`dd49aee1d9c28f8e781a627bec744db3a961ce4402950130ff9268504c551314`. The
summary at `/tmp/ts-orch-fc-evidence-20260924-live15/summary.json` has SHA-256
`4d1d6d7dc78ec1aeca09279521bdba9ae11744f8bc6cc425b6a8ae6ea89a6c2e`; its
`logs/events.json` SHA-256 is
`91729e7022415835abce25392cdc34b1811a314448939223d014a657c737c25a`.

The runner correction passed `mise exec -- go test ./internal/host -count=1`
and `mise exec -- go test -race ./internal/host -count=1`. Seven native
cgroup-runner tests passed without skips on the pinned guest image; see
`/tmp/ts-orch-fc14-runner-repro/fixed-guest-1/logs/runner-tests.txt` (SHA-256
`5b5b0ca3a87e35155d3109eb793fc6ad273987b37cbca771accfb540b9c4e8b5`). The
complete Go suite and `go vet ./...` passed for the source committed as
`69823ca4124d910b105d7af3d7a543a1baca7461` before this runner-only correction.
Static Linux artifacts for `df09ee5` and their hashes are in
[release boundaries](releases.md#local-static-build-receipt).

The focused app-level caller is
`mise exec -- go test ./internal/app -run TestAuthenticatedOperatorToHostDelivery -count=1`.
It exercises signed host registration and placement admission, artifact
admission, deployment and status, and host-agent delivery over NATS using an
in-memory workload runner. It does not start a guest process or test VM reboot
and quorum recovery.
