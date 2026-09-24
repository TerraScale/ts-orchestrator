# TerraScale Orchestrator

TerraScale Orchestrator is a Go control plane distributed as one binary. A
regional controller embeds its NATS server and JetStream store; hosts connect
to the regional cell to receive signed, digest-pinned desired state. Forgejo
Actions owns source verification and binary builds. The orchestrator owns
artifact admission and rollout authority. `ts-deploy` is not the build or
rollout engine for this repository.

This is a greenfield Go implementation. It does not promise compatibility with
the retired C# commands, configuration, NATS subjects, or state. The current
implementation and its gaps are described in [the architecture notes](docs/architecture.md).
The [pre-migration archive](docs/archive/pre-migration/README.md) retains the
former operational documentation, and [evidence records](docs/evidence/)
remain unchanged as historical receipts rather than Go acceptance evidence.

## Build and verify

This repository pins Go 1.27.1 in `.mise.toml`:

```bash
mise trust .mise.toml  # first checkout only
mise install
mise exec -- make verify
mise exec -- make build
mise exec -- make release-linux
```

`make verify` checks Go formatting, runs tests, runs `go vet`, and repeats the
tests with the race detector. `make build` creates `dist/terrascale-orchestrator`
for the current host. `make release-linux` creates static Linux amd64 and
arm64 executables and requires no Go runtime on the target machine. Forgejo CI
repeats the checks against the event's exact commit, verifies both ELF
architectures and the embedded Git revision, and prints SHA-256 digests.

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
kernels. Exact image and binary hashes are in [the qualification record](docs/local-development.md#latest-local-qualification).
Managed OCI placement can provision a host
and retained volume, then stops at
`awaiting-runtime-contract` after the attachment is positively observed. It
does not start TerraBase, prove a mounted volume, or claim a database member is
serving. Host image preparation, bootstrap, and signed enrollment remain
operator steps.

OCI provider behavior has only fake-provider coverage. A create accepted by
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
