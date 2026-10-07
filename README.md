# TerraScale Orchestrator

TerraScale Orchestrator is a Go control plane distributed as one binary. A
regional controller embeds its NATS server and JetStream store; hosts connect
to the regional cell to receive signed, digest-pinned desired state. Forgejo
Actions owns source verification and binary builds. The orchestrator owns
artifact admission and rollout authority. `ts-deploy` is not the build or
rollout engine for this repository.

Use **`ts-orch` as the operational CLI**. Implement new deployment,
provisioning, bootstrap, release, and inspection tooling as Go subcommands in
this executable instead of creating Python scripts or separate tools. CI and
automation should call those commands. Operational tools and qualification
drivers live in Go feature packages; shell wrappers select the environment
and invoke the CLI. See [contributing](CONTRIBUTING.md) and [CLI boundaries](docs/cli.md).

Regional foundation and first-controller setup are operator-run; after the
identity and authority handoff, the orchestrator forms that cell's remaining
controller peers. See the [manual regional bootstrap runbook](docs/region-bootstrap.md)
for the current supported procedure and its limits.

`ts-infra` manages shared Email Delivery only. The operator prepares regional
networking, IAM, and bootstrap inputs and starts controller A; `ts-orchestrator`
then forms the same-cell B/C peers and manages ARM workload hosts and TerraBase
deployment. The current `ts-infra` source and guarded workflow do not seed or
manage regional resources.

Every TerraScale secret lives in OCI Vault; OpenBao is retired. See
[secrets](docs/secrets.md) for names, who may read what, and
`ts-orch vault put` and `render`.

This is a greenfield Go implementation. It does not promise compatibility with
the retired C# commands, configuration, NATS subjects, or state. The current
implementation and its gaps are described in [the architecture notes](docs/architecture.md).

## Build and verify

This repository pins Go 1.27.1 in `.mise.toml`:

```bash
mise trust .mise.toml  # first checkout only
mise install
umask 022
mise exec -- make verify
mise exec -- make build
mise exec -- make release-linux
```

All first-party tests use Go's standard `testing` package. `make test` runs
`go test ./...`; `make verify` checks formatting, runs `go vet`, and runs all
Go suites with the race detector, including deployment and qualification
driver contracts. Their operational implementations also use Go; Python is
not a prerequisite for first-party tooling or tests.
See [Go testing](docs/testing.md) for focused suites and external prerequisites.
`make build` creates `dist/ts-orch` for the current host. The same executable runs
the controller, host agent, and operator tooling:

```bash
dist/ts-orch --help
dist/ts-orch bootstrap --help
dist/ts-orch release --help
dist/ts-orch image --help
dist/ts-orch oci-region --help
dist/ts-orch qualification --help
dist/ts-orch run --config controller.json
dist/ts-orch operator hosts --config operator.json
```

See [the unified CLI](docs/cli.md) for command migration and feature boundaries.
Change a cell's servers and load balancer backends only with `ts-orch node`
([node operations](docs/node-operations.md)), never with the `oci` CLI.
`make release-linux` creates static Linux amd64 and arm64 executables and
requires no Go runtime on the target machine. Forgejo CI repeats the checks
against the event's exact commit, verifies both ELF architectures and the
embedded Git revision, and prints SHA-256 digests.

See [local development](docs/local-development.md) for Firecracker
qualification and [release boundaries](docs/releases.md) for what CI proves
and what still needs a separate release process.

## Current limits

The signed native-workload path has an app-level test with an in-memory runner.
A four-VM Firecracker qualification passed for the pinned test image at source
revision `df09ee5692b4a5dc60230f019d1265efccb2f972`, covering guest execution,
host restart recovery, and workload recovery through controller loss and
quorum restoration. During controller loss, host session renewal/reporting
failed with `context deadline exceeded`; systemd restarted the host agent and
the workload later returned to running. This demonstrates recovery, not
uninterrupted availability or compatibility with arbitrary or production
kernels. Exact image and binary hashes are in [the prior local qualification
record](docs/local-development.md#prior-local-qualification-2026-09-24).
Managed OCI placement can provision a host
and retained volume. After the attachment is positively observed and the
runtime artifact and managed mount path are ready, it publishes signed
TerraBase desired state; the host verifies an existing exclusive mount of the
retained filesystem, launches the member, and reports local process and mount
status. Placement then holds at `awaiting-healthy`: it never claims a database
member is serving, and the orchestrator does not discover, format, or mount the
guest block device itself. Host image preparation, first-boot configuration,
and signed enrollment remain operator steps.

OCI provider behavior has only fake-provider and offline simulator coverage;
no live OCI account has been mutated. A create accepted by
OCI whose result is lost before its recovery result is durably journaled stays
unowned. Matching tags alone do not authorize adoption; manual inspection and
reconciliation are required. Artifact uploads are bounded by a 2 GiB default
quota, but interrupted or concurrent uploads can leave chunks in the store.
There is no repository-managed cleanup path, automatic garbage collection, or
admitted-object eviction. Once the quota is full, new uploads fail with
`ErrArtifactStoreFull`.
Live OCI mutation, scale-in, region decommission, production authority
failover, signed release publication, and guest-level rollback remain outside
the evidence currently available here. Do not use this repository as a
production-ready cloud control plane.
