# Candidate synchronization recovery verification

Implementation commit `a6e5d260` fixes two failures in candidate preparation.

The production OCI SDK integration test failed with `publication bytes differ`
because Object Storage metadata carries bare SHA-256 hex while signed artifact
contracts carry `sha256:` digests. Candidate publication and archive metadata
comparisons now use the provider format. The in-memory object reader now
returns that same format, so it cannot hide this integration failure.

Reference-store preparation now publishes `scope.json` atomically. Before
that change, an interrupted direct write could leave a partial committed pin
that prevented all subsequent retries. Recovery tests cover an empty directory,
an interrupted temporary write, unknown files, malformed temporary names,
unsafe permissions, and a partial committed pin. Only the first two cases are
removed. Existing candidate tests exercise successful preparation and replay
through real private NATS brokers.

Verification used Go 1.27.1 on linux/amd64 with the Modern Go Guidelines CLI.
These commands passed against the implementation committed above:

```sh
make check
go test -tags sandboxvm -race ./src/orchestrator/candidatesync ./src/orchestrator/vmcandidateseed ./src/orchestrator/vmimage
```

The [portable output](candidate-recovery-portable-2026-09-05.txt) records
formatting, vet, build, and the complete uncached race suite. The
[tagged output](candidate-recovery-tagged-2026-09-05.txt) records the targeted
guest preparation checks. These development checks do not establish a passing
Firecracker suite, permanent R3 transition, real-provider qualification, or
production readiness.
