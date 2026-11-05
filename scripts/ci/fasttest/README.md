# Fast execution

`make test-fast` still runs the entire `go test -short ./...` package graph.
Its `test-fast-build` prerequisite compiles the runner, discovers the complete
short-tier inventory, and retains the exact test binaries and output converter.
Compilation and preparation use the build budget; execution uses the strict
30-second Fast budget. A source fingerprint refuses execution after any source
change until preparation runs again.

The runner executes at most 24 isolated top-level cases at once, with two
parallel subtests and two runtime CPUs per process (`-parallel=2 -cpu=2`).
Repeated exported names remain together because Go's test selector executes
every matching declaration. Each process uses the original test binary,
working directory and search path, preserving `TestMain` helper dispatch and
`-short` skips. Every passing test must take less than 10 seconds.

Committed observations in `durations.txt` guide deterministic longest-first
ordering. Estimates only affect scheduling: new cases and packages always run.
The runner does not change the race scheduler, select a change subset, or retry
failures. Benchmarks stay excluded, while executable examples and fuzz seed tests are
included alongside ordinary tests.

Each shard runs uncached and its output passes through Go’s `test2json`. The runner requires exactly one `run`
and one terminal event for every discovered top-level case, rejects unexpected
or duplicate executions, and fails on any test, package or subprocess failure.
Other shards continue after failure. The job-local `artifacts/fasttest/prepared/` directory retains
raw JSON logs and `receipts.json`, with planned cases, actual terminal events
(including subtests and fuzz seeds), elapsed times and coverage errors. No
tests are silently omitted when listing or execution is invalid.

`go test ./scripts/ci/fasttest` checks the execution contract using subprocess
Go fakes, including bounded concurrency, full coverage, examples, fuzz seeds,
helper dispatch, invalid discovery, missing/duplicate actual executions and
failure propagation without retries. Full-suite timing is proven separately
through `ts-ship` on a dev host.
