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

The focused app-level caller is
`mise exec -- go test ./internal/app -run TestAuthenticatedOperatorToHostDelivery -count=1`.
It exercises signed host registration and placement admission, artifact
admission, deployment and status, and host-agent delivery over NATS using an
in-memory workload runner. It does not start a guest process or test VM reboot
and quorum recovery.
