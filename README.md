# TerraScale Orchestrator

Read the [required zero-configuration operating contract](docs/zero-configuration.md).
Current configuration paths described below are implementation limitations, not
production activation instructions.

TerraScale Orchestrator is a Go control plane distributed as one binary. A
regional controller embeds its NATS server and JetStream store; hosts connect
to the regional cell to receive signed, digest-pinned desired state. GitHub
Actions supplies the current source-verification and binary-build adapter. The orchestrator owns
artifact admission and rollout authority. `ts-deploy` is not the build or
rollout engine for this repository.

Apply an already signed release bundle with:

```sh
ts-orch release apply --dir BUNDLE --root-key TRUSTED_ROOT --namespace NS
```

Application verifies per-region signed channels and digest-named binaries;
it requires no particular Git repository or signing secret. GitHub remains a
producer adapter. Notification hooks are nonauthoritative hints; existing
polling recovers missed notifications. No new webhook endpoint or storage
adapter is implemented. See [the signed-bundle contract](docs/releases.md#apply-a-signed-release-bundle)
for layout, ordering limits and the current OCI application path.

Use **`ts-orch` as the operational CLI**. Implement new deployment,
provisioning, bootstrap, release, and inspection tooling as Go subcommands in
this executable instead of creating Python scripts or separate tools. CI and
automation should call those commands. Operational tools and qualification
drivers live in Go feature packages; shell wrappers select the environment
and invoke the CLI. See [contributing](AGENTS.md) and [CLI boundaries](docs/cli.md).

The [cluster visibility contract](docs/cluster-visibility.md) specifies the
complete human/AI CLI and dashboard target: shared cluster APIs, metric discovery
and history, Go templ + Datastar + ECharts, and one dashboard stylesheet.

The required production path admits private NetBird members automatically,
discovers every region and infers local identity from execution location.
**Current gap (TS-796):** first-controller/regional foundation still depends on
explicit bootstrap inputs. The [legacy bootstrap inventory](docs/region-bootstrap.md)
records those limits; it is not proof of automatic admission.

`ts-infra` manages shared Email Delivery only. The operator prepares regional
networking, IAM, and bootstrap inputs and starts controller A; `ts-orchestrator`
then forms the same-cell B/C peers and manages ARM workload hosts and TerraBase
deployment. The current `ts-infra` source and guarded workflow do not seed or
manage regional resources.

OCI Vault must automatically create, deliver and configure every first-party
production secret. Vendor keys are stored once and discovered automatically.
See [secrets](docs/secrets.md) for least-privilege and current delivery limits;
existing storage/delivery evidence does not prove end-to-end automation.

Open the [operator dashboard over NetBird](docs/dashboard/README.md#netbird-access)
for the access contract, current gaps, and the
`scripts/check-dashboard-access.sh` live check from each operator device.

This is a greenfield Go implementation. It does not promise compatibility with
the retired C# commands, configuration, NATS subjects, or state. The current
implementation and its gaps are described in [the architecture notes](docs/architecture.md).

## Build and verify

CI is the merge gate; local checks are optional before push. Follow the
[GitHub contribution workflow](AGENTS.md#shipping-code) for PRs and reviews.

The `go` line of `go.mod` pins the Go version, and `.mise.toml` installs the same one:

```bash
mise trust .mise.toml  # first checkout only
mise install
umask 022
nice -n 19 mise exec -- make lint
nice -n 19 mise exec -- make build
nice -n 19 mise exec -- make release-linux
```

`make lint` checks formatting, templ output, `go vet`, shell scripts and the repository policies; the only test here is the single-host E2E (`test/e2e/m1/run.sh`), and product behaviour is proven by the journey E2E in the terrascale repo.
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
See [the network address plan](docs/network/address-plan.md) for dedicated
mesh/region/bridge reservations, the live audit and
`scripts/check-network-coexistence.sh` (exit 0 requires both meshes and DNS
on PCs/user clients, and NetBird connectivity on regional servers).
Change a cell's servers and load balancer backends only with `ts-orch node`
([node operations](docs/node-operations.md)), never with the `oci` CLI.

The cell spec pins NetBird clients; ts-orch installs missing agents and rolls
pin changes one node at a time. See [managed NetBird](docs/netbird-managed.md)
for first adoption, verified artifacts and the pin-bump workflow.

`make release-linux` creates static Linux amd64 and arm64 executables and
requires no Go runtime on the target machine. GitHub CI repeats the checks
against the event's exact commit, verifies both ELF architectures and the
embedded Git revision, and prints SHA-256 digests.

See [release boundaries](docs/releases.md) for what CI proves
and what still needs a separate release process.

## Current limits

Managed OCI placement can provision a host
and retained volume. After the attachment is positively observed and the
runtime artifact and managed mount path are ready, it publishes signed
TerraBase desired state; the host verifies an existing exclusive mount of the
retained filesystem, launches the member, and reports local process and mount
status. Placement then holds at `awaiting-healthy`: it never claims a database
member is serving, and the orchestrator does not discover, format, or mount the
guest block device itself. Host image preparation, first-boot configuration,
and signed enrollment remain operator steps.

No live OCI account has been mutated. A create accepted by
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
