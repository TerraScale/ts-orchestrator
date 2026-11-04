# Go testing

All first-party tests use Go's standard `testing` package. Keep cases,
fixtures, assertions, and lifecycle management alongside the feature in
`*_test.go`; store inert inputs and golden observations in `testdata`.

```sh
umask 022
mise exec -- make test
mise exec -- make verify
mise exec -- go test ./tests/deploy -run TestImageInputs
mise exec -- go test -race ./tests/runtime_priority
```

`make test` runs `go test ./...`. `make verify` checks Go formatting, runs
`go vet ./...`, and runs the complete suite with the race detector. The race
scheduler shards long product packages and runs every test, example, and
fuzz seed once. GitHub uses the same tests through `make ci-verify`, together
with static release-binary checks.

Deployment, OCI admission, CI, runtime-priority, and Firecracker driver
contracts are ordinary Go packages. They call native feature APIs or `ts-orch`
and inject cloud, filesystem, transport, and process boundaries where needed.
Expected results and assertions belong in Go. First-party tools and tests
require no Python interpreter. New tests must not use Python test frameworks
or wrap a separate test runner.

The shared script helper records repository source inputs for Go's test
cache, bounds subprocess lifetimes, and terminates their process group on
cancellation. Use it for tests that invoke repository scripts. Go's test
cache cannot see what a subprocess reads, so name the repository paths the
command reads with `script.Track` and run it with `script.Exec`:
`tests/deploy` tracks `deploy/` and `tests/ci` tracks `scripts/ci/`. A
command that reads only inputs the test itself opened, copied into a
temporary directory or embedded with `go:embed` (as `scripts/ci/racetest`
does) needs no `Track`. `script.Run` still tracks the whole tree, so any
edit re-runs its test; prefer `Track`. Go keys tracked files on size and
modification time, and CI stamps every tracked file of its fresh checkout
with a time derived from its git object id (`scripts/ci/stablemtime`), so a
test whose inputs did not change is served from the persistent cache. Use
separate bounded cleanup contexts when cleanup runs after `t.Context()` is
canceled.

Tests are tiered (see [CONTRIBUTING.md](../CONTRIBUTING.md#test-tiers)):
pull requests run `go test -short`, which skips tests that call
`tier.Integration`; pushes run everything. Tests that need real
infrastructure call `tier.Qualification` with the variables that supply it:
they skip while those are unset and fail in a `TS_TEST_TIER=qualification`
run. Other environment-dependent tests, such as root or cgroup capability
checks, use `t.Skip` with the missing prerequisite.
GitHub run admission uses the standard `gh` CLI and validates run identity,
repository, workflow, attempt and paginated jobs before accepting evidence.
Run its focused mock API checks locally:

```sh
nice -n 19 go test ./internal/githubapi
```

## TerraBase upgrade traffic regression (TS-719, first slice)

The under-load fence regression `TestTerraBaseReleaseFenceUnderLoad` and its
file `internal/app/release_fence_load_test.go` were removed by the app test
cut (fcc2abcdf). The surviving fence coverage is
`TestReleaseFenceRestartsOneFencedNodeAtATime` and
`TestReleaseFenceStopsOnALostLease` in `internal/app/release_fence_test.go`:
one fenced node restarts at a time, and a deposed leader performs no further
load-balancer or restart steps (`authority.ErrFenced`). They run in the fast
CI tier without request traffic.

```sh
nice -n 19 env GOMAXPROCS=2 GOFLAGS=-p=1 mise exec -- go test \
  ./internal/app -run '^TestReleaseFence' -count=1 -v
```

This is simulated fencing evidence. It does not qualify real
TerraBase replication or storage, OCI load-balancer draining, keep-alive
behavior, or a staging deployment. TS-719 remains open for a dedicated
staging CI job with pinned baseline/candidate releases, SDK data traffic
without retries, a deliberately failing gate, and retained per-node and
request evidence. The repository currently records no dedicated staging
cell identity or runner credentials; production cells must not be substituted.

Offline driver contracts do not start Firecracker guests. Actual VM
qualification still uses the explicit commands and prerequisites in the
[Firecracker guide](../tests/firecracker/README.md) and
[production guide](../tests/firecracker/production/README.md).
