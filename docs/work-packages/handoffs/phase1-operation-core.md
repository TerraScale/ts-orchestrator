# Phase 1 fenced operation core handoff

- Branch: `phase1/operation-core`
- Work package: `docs/work-packages/phase1-operation-core.md`
- Scope changed: lane-owned ControlPlane source/tests and this handoff only
- External I/O or mutation: none

## Result

Implemented a pure, append-only operation reducer for `INV-004`, `INV-005`, and
the stale-writer protection in `INV-006`. Immutable commands carry explicit time,
generation/resource version, observation identity, writer epoch, target,
idempotency key, payload digest, and deadline. No wall clock, environment,
filesystem, network, NATS, provider SDK, or arbitrary callback enters the public
decision API.

The journal models prepare, irreversible authorization, dispatch, recovery,
observation, terminal, and resumable safety-hold records. Every event is
sequence-bound to the prior SHA-256 digest. Replay canonicalizes reordered exact
duplicates, rejects conflicting same-sequence bodies and broken links, validates
the irreversible authorization gates again, and produces a deterministic state
digest. Canonical values are type-tagged, invariant-culture, count/length
delimited, and timestamps normalize to UTC ticks.

Only a committed authorization can produce a provider dispatch intent. Its
action, target, desired generation/terminal state, payload digest, idempotency
key, authorization digest, and deadline come exclusively from the frozen
record. A strictly higher epoch after dispatch appends a recovery transfer and
emits only a read-only reconciliation intent; it does not issue another provider
mutation and fences the old epoch. Unknown/in-progress outcomes likewise emit a
reconciliation intent rather than interpreting timeout as failure.

The TUnit suite has 14 adversarial tests covering crash/restore after every
required checkpoint, deterministic decision/state digest equality, stale
epochs/generations, every authorization gate, complete prepared-intent equality,
deadline equality, hold re-evaluation, higher-epoch recovery, reordered and
duplicated delivery, corrupt hashes, duplicate sequence IDs with different
bodies, undefined enum values, null journal entries, malformed compensation and
work-request identities, observation before dispatch, inconsistent target truth,
unknown-outcome reconciliation, and contradictory terminal observations.

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore -- --no-progress --output Detailed
dotnet run --project tests/TerraScale.Orchestrator.ContractTests/TerraScale.Orchestrator.ContractTests.csproj --no-build --no-restore -- --no-progress --output Detailed
git diff --check
```

The locked solution restore/build passes with zero warnings. The focused
ControlPlane suite passes 14/14. The repository-wide `dotnet test` command also
runs the passing ControlPlane and Contract suites, but currently exits 8 because
the pre-existing Protocol and Scheduler test executables contain zero tests;
this lane does not own those projects.

## Deliberate limitations

- The core emits persistence/adapter intents but performs no persistence or I/O.
- Provider-specific retry-token, work-request, ambiguity, and compensation
  policy remains unresolved by ADR 0020 and is not fabricated here.
- A pre-dispatch authorization held because its deadline expired preserves the
  committed operation, but cannot resume mutation without a future explicit,
  action-specific recovery policy; read-only post-dispatch reconciliation is
  already supported after deadline.
- The cryptographic digest proves deterministic content equality inside this
  core; journal authenticity/signature and durable CAS belong to later adapters.
