# Local development

This repository contains the current Go `ts-orchestrator` executable. The
workspace GOAL prioritizes end-to-end API behavior and an
early, low-cost ARM64 preview of ts-orchestrator with TerraBase. It authorizes
that preview under a combined recurring-cost cap of **US$200/month for
qualification testing and preview**; these local commands do not deploy or
qualify it. The management resource-protection and pressure/restart acceptance
requirement is defined as D15 in the workspace GOAL; the commands below do not
establish that runtime qualification.

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
volume, and no TerraBase serving claim is made. See [`internal/app/managed_config.go`](../internal/app/managed_config.go)
and [`internal/placement/controller.go`](../internal/placement/controller.go)
for the strict parser and lifecycle boundary.

## Prior local qualification (2026-09-24)

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

Static Linux artifacts for `df09ee5` and their hashes are in
[release boundaries](releases.md#local-static-build-receipt).
