# Fast execution

`make test-fast` still runs the entire `go test -short ./...` package graph.
Its `test-fast-build` prerequisite exposes the ordinary Go warm-up to
`ts-ship`, so compilation stays outside the Fast execution clock. The runner
lists cases with the warmed build cache, then runs at most 12 Go processes
with two parallel tests and two runtime CPUs per process (`-p=1 -parallel=2
-cpu=2`). Known slow packages have up to six shards;
all other packages have one. Each shard uses the original Go test binary and
inherits its environment, preserving `TestMain` helper dispatch and `-short`
skips. Sharding requires the same process isolation as running focused Go tests.

The committed short estimates in `../racetest/race-durations.txt` and observed
plain Fast package costs guide deterministic longest-first packing. Estimates
only affect scheduling: new cases and packages always run. This runner does
not change the race scheduler, select a change subset, or retry failures.
Benchmarks stay excluded, while executable examples and fuzz seed tests are
included alongside ordinary tests.

Each shard runs uncached with `-json`. The runner requires exactly one `run`
and one terminal event for every discovered top-level case, rejects unexpected
or duplicate executions, and fails on any test, package or subprocess failure.
Other shards continue after failure. The printed temporary directory retains
raw JSON logs and `receipts.json`, with planned cases, actual terminal events
(including subtests and fuzz seeds), elapsed times and coverage errors. No
tests are silently omitted when listing or execution is invalid.

`go test ./scripts/ci/fasttest` checks the execution contract using subprocess
Go fakes, including bounded concurrency, full coverage, examples, fuzz seeds,
helper dispatch, invalid discovery, missing/duplicate actual executions and
failure propagation without retries. Full-suite timing is proven separately
through `ts-ship` on a dev host.
