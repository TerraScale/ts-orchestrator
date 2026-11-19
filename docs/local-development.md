# Local development

This repository contains the current Go `ts-orchestrator` executable.

The `go` line of `go.mod` pins the Go version, and `.mise.toml` installs the same
one. On a first checkout, trust that repository config and install its toolchain,
then lint and build:

```bash
mise trust .mise.toml
mise install
mise exec -- make lint
mise exec -- make build
mise exec -- make release-linux
```

`make lint` checks formatting, templ output, `go vet`, shell scripts and the
repository policies. `make build`
writes the current-platform binary to `dist/ts-orch`. Use `ts-orch` for operator
tasks and implement new operational tooling as Go subcommands rather than
Python scripts; see [contributing](../AGENTS.md).

`make release-linux` builds Linux amd64 and arm64 binaries with cgo disabled.
It is a cross-build target; it does not demonstrate execution on ARM64 or
qualify a deployed preview. See [release boundaries](releases.md) for CI and
artifact qualification limits.

## Regional NATS lab

Use a disposable directory for JetStream storage. A single-node lab config
sets `nats.lab` to `true` and provides an embedded NATS listener and
`store_dir`; R3 labs need one process per peer, unique `instance` and
`store_dir` values, and route seed addresses in `nats.embedded.routes`. The
strict configuration fields and secure-mode requirements are documented in
[`internal/natscell/runtime.go`](../internal/natscell/runtime.go) and
[`internal/app/config.go`](../internal/app/config.go).

The binary accepts `bootstrap-controller`, `run`, `host`, `check`, and
`operator` commands with `--config FILE`; `identity-new --key FILE` creates an owner-private Ed25519
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
The placement file accepts `environment`, `member_role` and `resources`.
Placement runs every five seconds. Managed placement can create region-bound hosts and retained volumes
and, after confirmed attachment, publish signed TerraBase desired state; it
then holds at `awaiting-healthy`. Host image, first-boot configuration, and
enrollment remain operator-provided, the orchestrator does not mount the guest
volume, and no TerraBase serving claim is made.
