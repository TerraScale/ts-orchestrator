# Contributing

## Use the unified Go CLI

`ts-orch` is the preferred interface for operational tooling. Implement new
provisioning, deployment, bootstrap, release, image coordination, inventory,
and inspection features as Go subcommands in the existing executable. Do not
create Python operational scripts or a separate project for these features.

Before adding automation, check whether a `ts-orch` command already provides
the operation. Extend that command or its feature package when appropriate.
Forgejo workflows and shell entry points should call the CLI; validation,
signing, provider operations, retry policy, and durable progress belong in Go.
Thin wrappers may select tools or pass arguments, but must not duplicate the
command's operational logic.

Existing Python and shell operational tools are migration targets, not the
template for new features. Migrate them feature by feature, preserving their
admission, ownership, resume, and verification contracts. Existing Python test
and Firecracker harnesses may continue to exercise the product. External image
tools such as QEMU/libguestfs remain build prerequisites.

## Keep features together

Keep each feature's command parsing, services, and tests together. The
bootstrap CLI lives in `internal/bootstrap/cli`, and the release CLI lives in
`internal/release/cli`. Add the dispatch entry in `internal/cli`; keep the
executable entry point thin. Avoid accumulating unrelated operational features
in `internal/app`.

Commands should support automation: write results to stdout and errors to
stderr, exit unsuccessfully on errors, and pass cancellation to network and
subprocess operations. Local signing and verification commands must work
without starting NATS or loading a controller configuration.

Use the authenticated regional operator path for an established cell so that
the controller owns mutation authority and reconciliation. Initial bootstrap
supports explicit direct OCI operations before the cluster exists. Preserve
reviewed inputs, signed object validation, file permissions, and overwrite
checks when moving operations into the CLI.

## Verify changes

The repository pins its Go toolchain through `.mise.toml`:

```sh
mise trust .mise.toml
mise install
umask 022
mise exec -- make verify
mise exec -- make build
dist/ts-orch --help
```

The qualification tests expect ordinary `022` file creation permissions and
check explicitly restricted files separately. Published binaries require a
clean committed source tree; after committing, run
`mise exec -- make release-check` to verify static Linux amd64 and arm64
artifacts and their embedded source revision.

See [the unified CLI](docs/cli.md) for command migration and
[local development](docs/local-development.md) for qualification details.
