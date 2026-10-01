# Unified orchestrator CLI

TerraScale Orchestrator ships one Go executable for controller, host, and
operator operations. `make build` writes `dist/ts-orch` and a compatibility
symlink at `dist/terrascale-orchestrator`. Published Linux artifacts and guest
installation paths retain their existing `terrascale-orchestrator` names;
these executables expose the same commands. Release receipt artifact identities
and systemd service commands therefore keep their existing names.

## Command migration

| Previous invocation | Unified invocation |
| --- | --- |
| `ts-bootstrap <command> [flags]` | `ts-orch bootstrap <command> [flags]` |
| `ts-release <command> [flags]` | `ts-orch release <command> [flags]` |
| `terrascale-orchestrator run --config FILE` | `ts-orch run --config FILE` |
| `terrascale-orchestrator host --config FILE` | `ts-orch host --config FILE` |
| `terrascale-orchestrator operator ...` | `ts-orch operator ...` |

The standalone `cmd/ts-bootstrap` and `cmd/ts-release` entry points have been
removed. Build operator tooling with `go build ./cmd/terrascale-orchestrator`
or `make build`. Existing subcommand flags, signed object formats, validation,
file permissions, and overwrite checks are preserved. Group help is available
through `ts-orch bootstrap --help` and `ts-orch release --help`.

The deployment scripts' `--bootstrap-tool` and `--release-tool` arguments now
accept the unified executable; both may point to the same file. Image promotion
still builds the source-specific standalone release tool when promoting a
pinned image from a revision predating this migration. Historical qualification
records retain the names and hashes of the binaries actually tested.

## Feature boundaries

Prefer `ts-orch` for new operational features. Implement them as Go commands
in their feature packages instead of adding Python scripts or separate
executables. CI and operator automation should invoke those commands. Keep
business logic, validation, and provider effects in Go; use thin wrappers only
for environment setup and invocation. See [contributing](../CONTRIBUTING.md).

`internal/cli` dispatches commands. Runtime composition stays in `internal/app`;
bootstrap commands and their tests live in `internal/bootstrap/cli`, and release
commands and their tests live in `internal/release/cli`. Domain verification and
provider code remain in their existing feature packages. CLI command packages
receive cancellation and output from the executable without changing global
process output or starting NATS.

Local signing and verification need no runtime role configuration. Publishing
and provisioning commands retain their explicit OCI credentials and reviewed
input requirements. Offline root keys are supplied only to the commands that
need them; controller and host startup do not load them.

## Remaining script migrations

This first migration consolidates the existing Go bootstrap and release tools
and updates their image and regional deployment callers. Regional inventory,
cost admission, bootstrap-attempt scheduling, image import, and image-build
coordination still run through the existing Python and shell tools. Port these
features separately, preserving their admission and resume contracts. Image
building continues to need external QEMU/libguestfs tools.

Operations against an established cell should use the authenticated operator
path and controller-owned reconciliation. Initial bootstrap must support direct
OCI operations before the regional cluster exists.
