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

Keep operational tools and qualification drivers in the Go feature packages.
Preserve their admission, ownership, resume, and verification contracts when
changing them. External image tools such as QEMU/libguestfs remain build
prerequisites.

Write all first-party tests in Go with the standard `testing` package. Keep
cases, fixtures, assertions, and test lifecycle in Go; use `t.TempDir`,
`t.Context`, and `httptest` where appropriate. Test native feature APIs or
the `ts-orch` command interface, using injected provider and process boundaries
for offline contracts. Do not add Python test suites or separate test runners.
Store inert fixture data under feature-local
`testdata` directories.

## Change servers and load balancers only through ts-orch

ts-orchestrator owns a cell's servers and load balancer backends (TS-632).
Humans and agents change them with `ts-orch node`
(`drain|undrain|reboot|resize|add|retire`) and the cell spec, never with
the `oci` CLI, the console or scripts: the leader drains nodes for
releases and rollouts itself, and its edge reconciler undoes hand edits.
See [node operations](docs/node-operations.md).

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

`make test` runs `go test ./...`; `make verify` checks formatting, runs `go vet`,
and runs every Go suite with the race detector. Use `go test ./path -run Name`
for focused checks. First-party tooling and tests require no Python. Actual Firecracker
VM qualification remains an explicit environment-dependent command.

The qualification tests expect ordinary `022` file creation permissions and
check explicitly restricted files separately. Published binaries require a
clean committed source tree; after committing, run
`mise exec -- make release-check` to verify static Linux amd64 and arm64
artifacts and their embedded source revision.

## Test tiers

Tests belong to one of three tiers. `internal/testutil/tier` selects them, so
a tier is chosen with `-short` and `TS_TEST_TIER`, never with build tags, and
`go vet ./...` still sees every test.

| Tier | Runs | Command | Contains |
|---|---|---|---|
| T0, fast | every pull request | `TS_TEST_TIER=pr make ci-verify` (race tests with `-short`); `make test-fast` locally | Unit tests and the single-process safety invariants: fencing, lease reserves, authority epochs, CAS, signed configuration, idempotent journaled OCI operations, and one case of every image-builder rejection family. |
| T1, integration | every push to `develop` and `main` | `make ci-verify` (`TS_TEST_TIER=full`, the default) | T0, plus tests that call `tier.Integration(t)`, plus `make fixturetest-check` (`go vet` and the fixturegen tests with `-tags fixturetest`). |
| T2, qualification | `image.yml`, before the image is built, where the runner supplies fixtures | `scripts/ci/qualify-image.sh` with `TS_TEST_TIER=qualification` | Tests that call `tier.Qualification(t, envs...)`: real TerraBase members, cross-language packets and rendered enrollment bundles. Firecracker VMs qualify through `ts-orch qualification firecracker ...`. |

`image.yml` builds only revisions whose full `ci.yml` run on `main` passed,
so T1 gates every image even though pull requests run only T0.

Choose the tier when you add a test:

- Keep a test in T0 when it protects a safety invariant. If such a check only
  exists inside a slow multi-process lab, add a fast single-process test for
  it before tiering the lab.
- Call `tier.Integration(t)` first in a test that starts several processes,
  waits on real lease or session timers, or repeats a complete offline image
  build. Keep one representative case of each rejection family in T0.
- Call `tier.Qualification(t, "TS_FIXTURE_ENV", ...)` instead of skipping
  when real infrastructure is missing. It returns the variables' values and
  skips while they are unset, but in a `TS_TEST_TIER=qualification` run a
  missing variable fails the test. `tier.Unavailable(t, ...)` does the same
  for opt-ins with custom conditions. Add the test's suite to
  `scripts/ci/qualify-image.sh`, which also fails a suite that skips or runs
  no test.
- Leave measurements, such as
  `TS_ORCH_RUN_DEPLOYMENT_CONVERGENCE_MEASUREMENT`, as plain opt-ins; they
  are not pass/fail gates.

To enable T2 on a runner, provide the fixture variables listed in
`scripts/ci/qualify-image.sh` to the image job and set the repository
variable `TS_QUALIFICATION_SUITES` to the suites it supplies. While the
variable is unset, `image.yml` skips the step.

`scripts/ci/racetest/race-test.sh` runs the race tests. It packs the tests of
the slowest packages into shards by the estimates in
`scripts/ci/racetest/race-durations.txt` and starts the longest shards first.
Timer-bound labs (`idle` there) run in a separate pool of
`TS_RACE_IDLE_JOBS` slots beside the `TS_RACE_JOBS` CPU slots. Tests marked
`norace` run in CPU shards without the race detector (at most
`TS_RACE_NORACE_SHARDS`, default 2); mark only tests whose code paths start
no goroutine, such as the bootstrapstart founder runtime and replacement
tests, where `-race` cost about fifteen times the CPU and could find
nothing. When you add a
test that runs for more than a few seconds under `-race`, add its estimate,
with a `/<seconds>` suffix if `-short` changes it.

Run local builds and tests at low CPU priority, for example
`nice -n 19 make test-fast`, so they do not starve other work on a shared
machine. CI runs at normal priority, so do not add `nice` to the Makefile,
workflows or scripts.

See [the unified CLI](docs/cli.md) for command migration and
[local development](docs/local-development.md) for qualification details.
