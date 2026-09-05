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

## Firecracker attempt

The privileged doctor passed with the existing root-owned VM cache. The full
`make vm-test` attempt then booted `gru-member-1` with 512 MiB. ts-node and the
local orchestrator were active and running. TerraBase exited with status 1 and
the fixed diagnostic category `terrabase-configuration-missing`. No guest
readiness or qualification scenario passed. Peak measured guest cgroup memory
was 521,396,224 bytes; no idle resource budget was established.

The [machine report](vm-test-candidate-recovery-2026-09-05.json) and
[command output](vm-test-candidate-recovery-2026-09-05.txt) retain the failed
attempt, executable digests, startup categories, and cleanup observations.
Automatic cleanup completed and a subsequent explicit
[`make vm-clean`](vm-clean-candidate-recovery-2026-09-05.txt) exited zero.
The command output contains the exact root, repository, and TerraBase binary
arguments. The commands used passwordless sudo with this PATH:

```text
/home/mariogk/.local/share/mise/installs/go/1.27.1/bin:/run/current-system/sw/bin:/usr/bin:/bin
```

This was a development attempt with ephemeral qualification signatures, not
immutable published release evidence. It started with the implementation of
`a6e5d260` in the worktree before that commit and the evidence commit were
created. The report does not establish a clean source-revision binding.

The guest manifest producer currently gives TerraBase no `--config` argument.
The adjacent TerraBase checkout at `678d6da846c083d8bb24392a9049a99e2a08ed58`
requires `--config PATH` or `TERRABASE_CONFIG_FILE`. Its production runtime
also explicitly returns a Membership startup error after constructing the
member because no durable orchestrator membership source is configured.
The inspected checkout had unrelated uncommitted API/contract changes; this
source inspection does not prove the behavior of the supplied executable
beyond the missing-configuration failure observed in the VM.

The next integration requires a versioned production configuration and durable
membership producer/consumer path through the real engine. A local-development
configuration would not qualify the production topology required by GOAL.md.
