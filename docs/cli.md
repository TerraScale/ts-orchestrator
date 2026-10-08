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
| `ts-orch netbird setup-key --out FILE [--servers-group GROUP] [--apply]` | Plan, or with `--apply` create, the GRU (or GROUP, e.g. `sfo-servers`) server setup key; its value goes only to the new owner-only FILE |
| `ts-orch netbird inventory` | Print the manager's groups, policies, networks, DNS and peers |
| `ts-orch netbird dns [enable] [--apply] --netbird COMMAND` | Plan, or install, native operator DNS with a brief overlay reconnect; use another SSH transport or a detached invocation |
| `ts-orch netbird dns --config-dir /etc/netbird-wt0/config.d --netbird netbird-wt0 --apply` | Enable NixOS operator DNS and persist an owned `90-ts-orchestrator-dns.json` override |
| `ts-orch netbird dns --split-resolver --upstream IP --netbird COMMAND --apply` | Route `nb.ts.internal` through a local host-network container's resolver; preserve existing search/options and route other queries to the explicitly supplied current upstream |
| `ts-orch netbird image-input --plan PLAN --setup-key-secret-id OCID --out FILE` | Write another region's image `netbird.json` from its reviewed plan, offline |

## Secrets

`ts-orch vault` keeps secrets in OCI Vault; see [secrets](secrets.md) for the
naming scheme and who may read what.

| Command | Purpose |
| --- | --- |
| `ts-orch vault put --vault-id OCID --key-id OCID --compartment-id OCID --name NAME --file FILE` | Store FILE once as secret NAME with the operator's `~/.oci/config`, then prove the stored copy equals FILE |
| `ts-orch vault render --vault-id OCID --scope SCOPE --template FILE --out FILE` | On a host, as root: fill each `{{KEY}}` with secret `<scope>-<key>` read with the instance principal; write FILE atomically, mode `0600` |
| `ts-orch region plan LABEL OCI_REGION --out FILE [--from PLAN]` | Derive a non-home region's plan from another region's reviewed plan; reads OCI, creates nothing ([new region](new-region.md)) |
| `ts-orch region create LABEL OCI_REGION --state DIR --attempt-base FILE --home-plan FILE` | Bring the region up: foundation, private peering with gru-1, NetBird, founding attempt, edge, DNS, Atlas, verify; resumable, prints each step's wall time |
| `ts-orch region verify LABEL --plan BOUND_PLAN [--wait D]` | Fail unless api and auth answer, every load balancer backend is healthy and Atlas lists the region |
| `ts-orch atlas key --plan FILE` | Store the Atlas publish key once as `<cell>-atlas-publish-key`; print the Worker's `PUBLISH_KEYS` (see [Atlas](atlas.md)) |
| `ts-orch atlas add-region --config OPERATOR_JSON --cell CELL [--out FILE]` | Plan listing a catalog region in the global home's `atlas` section; `--out` writes the unsigned candidate for `release sign-spec --root` (see [Atlas](atlas.md#add-a-region)) |
| `ts-orch atlas publish --plan FILE --section FILE` | Publish a cell spec `atlas` section to Atlas once, as the leader does every 10 s |

## Cell spec

`ts-orch get`, `diff` and `apply` read and amend a running cell's signed
desired state; `ts-orch service` plans service changes to it. See
[cell spec](cell-spec.md) for the model, trust chain and runbook.

| Command | Purpose |
| --- | --- |
| `ts-orch get --config OPERATOR_JSON` | Print the cell's current spec |
| `ts-orch diff --config F -f FILE` | Plan a candidate or signed spec on the leader: changes, `root_required`, `requires_binary` |
| `ts-orch service add\|update --config F --role R --profile F [--spec F] [--out F]` | Plan the next generation; `--out` writes the unsigned candidate |
| `ts-orch service remove --config F --role R [--out F]` | Plan removing a drained role |
| `ts-orch release sign-spec-delegation ... --out F` | Offline: the root lets the release leaf sign ordinary amendments |
| `ts-orch release sign-spec --candidate F (--delegation F \| --root) --root-key F --signing-key F --out F` | Offline: the leaf, or for a widening change the root, signs a candidate |
| `ts-orch apply --config F -f SIGNED` | Apply a signed spec on the authority leader |

## Fleet deployment

CI runs `ts-orch release deploy` for every `main` merge; see
[automatic fleet deployment](continuous-delivery.md#automatic-fleet-deployment-ts-557-part-1).

| Command | Purpose |
| --- | --- |
| `ts-orch release deploy --dir D --source-revision SHA --update-delegation F --root-key F --signing-key-secret NAME --vault-id OCID --environment E --source-checkout DIR --namespace NS --cell C... --arch A...` | Sign the release for every cell, then publish it to each region in order, the first being the canary, and wait for each to complete |
| `ts-orch release service-deploy --role R --binary F --repository URL --commit SHA --source-checkout DIR --environment ENV --actor A --signing-key-secret S --vault-id V --namespace NS --cell C...` | CI: release a native service (TerraBase, ts-auth) to every region, canary first, through its service release channel ([automatic service releases](continuous-delivery.md#automatic-service-releases-ts-610)) |
| `ts-orch release fleet-status --namespace NS [--cell C...] [--role R...]` | Print every region's release channel and rollout status as JSON lines; with `--role`, each named service role's release status instead |

## Orchestrator rollouts

`ts-orch rollout` sets the cell's desired orchestrator release, which the
authority leader rolls out to the controllers; see
[continuous delivery](continuous-delivery.md#leader-run-controller-self-update).
Every command prints the leader's JSON reply.

| Command | Purpose |
| --- | --- |
| `ts-orch rollout status --config OPERATOR_JSON` | Desired release, the last ten generations, the leader's rollout status and its newest release channel report |
| `ts-orch rollout publish --config F --receipt F [--delegation F]` | Make a signed release the next generation (upload the binary with `operator artifact-push` first) |
| `ts-orch rollout pause --config F` | Start no further rollout; one in flight finishes |
| `ts-orch rollout resume --config F` | Undo pause and retry the rollback of a frozen rollout |
| `ts-orch rollout rollback --config F --to GEN` | Publish generation GEN again as a new generation and stop the rollout in flight |

## Root key rotation

`ts-orch operator trust-roots` and `trust-rotate` rotate the cell's root keys
without a rebuild; see [root rotation](root-rotation.md).

| Command | Purpose |
| --- | --- |
| `ts-orch operator trust-roots --config F [--out CHAIN]` | Print the current roots; `--out` writes the chain to extend |
| `ts-orch release sign-root-rotation --genesis-root F --chain F ... --new-root F --signing-key F [--signed F] --out F` | Offline: an old or new root adds its signature |
| `ts-orch operator trust-rotate --config F --file SIGNED` | Apply a complete rotation on the authority leader |

## Feature boundaries

`ts-orch disaster-recovery replicate --config FILE [--apply]` prepares
dedicated cross-region Object Storage mirrors, historical backfills and Vault
key replicas. It does not execute a full-cell recovery drill. See
[disaster recovery](disaster-recovery.md) for the exact copy layout and the
remaining cold-restore requirements.

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
