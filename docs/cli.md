# Unified orchestrator CLI

TerraScale Orchestrator ships one Go executable for controller, host, and
operator operations. `make build` writes `dist/ts-orch`. Published Linux artifacts and guest
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
| `python3 deploy/image/image-inputs.py ...` | `ts-orch image inputs ...` |
| `python3 deploy/image/offline-guestfs.py ...` | `ts-orch image guestfs ...` |
| `python3 deploy/image/promote-image.py ...` | `ts-orch image promote ...` |
| `python3 deploy/netbird/client.py ...` | `ts-orch netbird client ...` |
| `python3 deploy/netbird/install-client.py ...` | `ts-orch netbird install ...` |
| `python3 deploy/oci-region/preview.py ...` | `ts-orch oci-region preview ...` |
| `python3 deploy/oci-region/attempt.py ...` | `ts-orch oci-region attempt ...` |
| `python3 deploy/oci-region/import-image.py ...` | `ts-orch oci-region import-image ...` |
| `python3 deploy/oci-region/public-api.py ...` | `ts-orch oci-region public-api ...` |
| `python3 tests/runtime_priority/qualify.py ...` | `ts-orch runtime-priority qualify ...` |
| `python3 tests/runtime_priority/pressure.py ...` | `ts-orch runtime-priority pressure ...` |
| `python3 tests/runtime_priority/alpha_runner.py ...` | `ts-orch runtime-priority pressure ...` |
| `python3 tests/runtime_priority/alpha_adapter.py ...` | `ts-orch runtime-priority adapter ...` |
| `python3 tests/runtime_priority/probe_admission.py ...` | `ts-orch runtime-priority probe-admission ...` |
| `python3 tests/firecracker/qualify.py ...` | `ts-orch qualification firecracker generic ...` |
| `python3 tests/firecracker/memberstatus/qualify.py ...` | `ts-orch qualification firecracker memberstatus ...` |
| `python3 tests/firecracker/managedmember/qualify.py ...` | `ts-orch qualification firecracker managedmember ...` |
| `python3 tests/firecracker/production/qualify.py ...` | `ts-orch qualification firecracker production ...` |
| `python3 tests/firecracker/production/prepare_base.py ...` | `ts-orch qualification firecracker prepare-base ...` |
| `python3 scripts/ci/m0_oci_real_caller.py ...` | `ts-orch qualification real-caller ...` |
| `python3 scripts/ci/terrabase-source-digest-v1.py ...` | `ts-orch source-digest ...` |

The standalone `cmd/ts-bootstrap` and `cmd/ts-release` entry points have been
removed. Build operator tooling with `go build ./cmd/terrascale-orchestrator`
or `make build`. Existing subcommand flags, signed object formats, validation,
file permissions, and overwrite checks are preserved. Group help is available
through `ts-orch bootstrap --help` and `ts-orch release --help`.

The deployment scripts' `--bootstrap-tool` and `--release-tool` arguments
default to the unified interface; both may point to the same executable.
For historical standalone tools, `ts-orch oci-region preview` requires explicit
`--legacy-bootstrap-tool` and `--legacy-release-tool` flags for their respective
arguments. Regional bootstrap attempts inspect their retained, pinned source
layout when building tools and on resume: sources containing
`cmd/ts-bootstrap/main.go` keep standalone `ts-bootstrap` and `ts-release`
tools and pass those explicit preview flags. Current sources build one
`ts-orch` and use the `bootstrap` and `release` namespaces. Image promotion
also builds the source-specific standalone release tool when promoting a
pinned image from a revision predating this migration. Historical qualification
records retain the names and hashes of the binaries actually tested.

The M0 OCI real-caller qualification script accepts the unified executable as
`--bootstrap`, with a retained local-build receipt identifying `ts-orch`,
`terrascale-orchestrator`, or `terrascale-orchestrator-linux-amd64`. It invokes
`bootstrap open-customer-material`. Historical receipts identifying
`ts-bootstrap` retain the standalone invocation. The verified receipt identity
selects the interface, so renaming the executable does not change it. Both
interfaces require the receipt and binary to match the qualified operator's
exact source revision and tree, module hashes, clean build metadata, and
retained build/test command and log hashes. A historical bootstrap tool cannot
be paired with an operator qualified from a newer source revision.

## NetBird configuration

`ts-orch netbird` also reconciles the NetBird manager with the desired state
embedded in the binary; see [NetBird](../deploy/netbird/README.md#desired-state-and-reconciliation).
Without `--apply` these commands only read.

| Command | Effect |
| --- | --- |
| `ts-orch netbird sync [--apply] [--pat-file FILE]` | Plan, or with `--apply` reconcile, groups, policies, network, DNS and settings |
| `ts-orch netbird prune-peers [--apply] [--offline-for DURATION]` | List, or with `--apply` delete, offline GRU server peers of replaced revisions |
| `ts-orch netbird remove-peers (--slot NAME... \| --all) [--apply]` | List, or with `--apply` delete, the disconnected GRU server peers of decommissioned slots |
| `ts-orch netbird setup-key --out FILE [--apply]` | Plan, or with `--apply` create, the GRU server setup key; its value goes only to the new owner-only FILE |
| `ts-orch netbird inventory` | Print the manager's groups, policies, networks, DNS and peers |

## Secrets

`ts-orch vault` keeps secrets in OCI Vault; see [secrets](secrets.md) for the
naming scheme and who may read what.

| Command | Purpose |
| --- | --- |
| `ts-orch vault put --vault-id OCID --key-id OCID --compartment-id OCID --name NAME --file FILE` | Store FILE once as secret NAME with the operator's `~/.oci/config`, then prove the stored copy equals FILE |
| `ts-orch vault render --vault-id OCID --scope SCOPE --template FILE --out FILE` | On a host, as root: fill each `{{KEY}}` with secret `<scope>-<key>` read with the instance principal; write FILE atomically, mode `0600` |

## Services

`ts-orch service` adds, updates and removes a running cell's services with
signed service sets; see [services](services.md) for the model, trust chain
and runbook.

| Command | Purpose |
| --- | --- |
| `ts-orch service list --config OPERATOR_JSON` | Print the cell's current service set |
| `ts-orch service add\|update --config F --role R --profile F [--spec F] [--out F]` | Plan the next generation; `--out` writes the unsigned candidate |
| `ts-orch service remove --config F --role R [--out F]` | Plan removing a drained role |
| `ts-orch release sign-service-delegation ... --out F` | Offline: the root lets the release leaf sign the cell's service sets |
| `ts-orch release sign-service-set --candidate F --delegation F --root-key F --signing-key F --out F` | Offline: the leaf signs a candidate |
| `ts-orch service apply --config F --file SIGNED` | Apply a signed set on the authority leader |

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

Keep all first-party tests in Go using the standard `testing` package. Driver
contracts call native Go feature APIs or the unified CLI; Go owns their
fixtures, provider substitutions, assertions, and lifecycle.
See [Go testing](testing.md) for verification and feature-local fixtures.

Bootstrap and release commands retain normal SIGINT/SIGTERM termination in the
executable, including during synchronous OCI credential setup. Their Go `Run`
APIs accept caller cancellation and return cancellation and output-write errors.

Local signing and verification need no runtime role configuration. Publishing
and provisioning commands retain their explicit OCI credentials and reviewed
input requirements. Offline root keys are supplied only to the commands that
need them; controller and host startup do not load them.

## Operational dependencies

`ts-orch verify --live` runs opt-in, read-only production observations; see
[live verification](live-verification.md) for evidence requirements and gaps.

Regional inventory, cost admission, bootstrap attempts, image import, image
coordination, runtime-pressure tools, and Firecracker qualification drivers
are native Go features in the same executable. CI and image shell entry points
invoke those commands. Image operations run from the source checkout when
they need its manifests, unit files, or pinned build inputs. Image building
still uses external QEMU/libguestfs tools; live qualification still needs its
reviewed guest artifacts and host privileges.

The runtime-priority probe is the source-matched ARM64 `ts-orch` executable,
published as `terrascale-d15-qualify`; invoke its `runtime-priority qualify`
namespace. Probe admission binds that executable's exact bytes to its
publication evidence. Historical qualification records retain the paths,
hashes, and interpreter commands actually used at their recorded revision.

Operations against an established cell should use the authenticated operator
path and controller-owned reconciliation. Initial bootstrap must support direct
OCI operations before the regional cluster exists.
