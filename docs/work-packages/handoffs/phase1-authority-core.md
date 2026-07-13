# Phase 1 regional authority core handoff

- Branch: `phase1/authority-core`
- Work package: `docs/work-packages/phase1-authority-core.md`
- Scope changed: lane-owned authority source/tests and this handoff only
- External I/O or mutation: none

## Result

Implemented a pure authority reducer for `INV-004`, with `INV-005` referenced
only for append/replay/idempotency behavior proven here. It emits typed
compare-and-set, compare-and-delete, and read intents; it never reads a clock,
NATS, environment, filesystem, network, or policy default.

Each reducer journal is explicitly scoped to one `(AuthorityId, CandidateId)`
attempt history. The regional KV CAS record is the shared authority truth across
candidates. Tests model three candidate journals reading the same baseline,
select one CAS winner, return that winner's exact truth to the losers, and prove
only the winner receives a mutation permit. A later candidate advances the
shared epoch after the prior lease expires, and the stale candidate fences when
it evaluates that higher-epoch truth.

Mutation permission is not cached in `AuthorityState`. A point-in-time typed
`MutationAuthorityPermit` is returned only from an exact successful CAS/read or
explicit evaluation. It binds authority, candidate, lease, epoch, KV revision,
observation identity, supplied server time, and supplied monotonic elapsed
duration. Follower, acquisition-pending, renewal-pending, release-pending,
read-only/held, and fenced states receive no permit. Renewal cannot extend an
epoch until exact CAS success; release removes permission before delete is sent.

The model supports explicit absent genesis `(revision=0, epoch=0, lease=null)`
and advances it to revision/epoch one. All later revisions and epochs are
positive. Epoch, revision, and server-expiry overflow are preflighted before an
impossible mutation intent and produce typed holds. Expiry equality, partition
uncertainty, clock anomaly, CAS uncertainty/failure, mismatched identity,
higher epoch, and stale/out-of-order request results all remove or deny mutation
authority. Held candidates may recover through an exact read; fenced candidates
have no self-unfence command.

Events use a deterministic, type-tagged, length/count-delimited SHA-256 chain.
Replay accepts reordered exact duplicates, rejects conflicting bodies/broken
links, and revalidates request identity, authority scope, CAS evidence, lease
ownership, epoch/revision succession, supplied time, outcome/error mapping, and
terminal fence/hold vocabulary before applying any event.

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore -- --no-progress --output Detailed
dotnet run --project tests/TerraScale.Orchestrator.ContractTests/TerraScale.Orchestrator.ContractTests.csproj --no-build --no-restore -- --no-progress --output Detailed
git diff --check
```

The authority suite contains 17 focused tests; combined with the existing 14
operation tests, the ControlPlane executable runs 31 tests. Coverage includes
crash/replay at every intent/result boundary, deterministic decision/state
digests, three-candidate CAS interleavings, acquisition/renewal/release/read,
pending-state permission denial, exact and mismatched results, duplicate and
out-of-order observations, stale old leaders, genesis, all overflow classes,
expiry equality, partition and clock anomalies, cross-authority evidence, and
rehashed corrupt journal events.

## Deliberate limitations

- The core models KV observations and emits intents but performs no persistence,
  NATS operation, lease scheduling, or retry.
- Lease duration, renewal timing, server time, monotonic elapsed duration, and
  partition/clock certainty are mandatory caller inputs; no default is encoded.
- The point-in-time permit must be consumed by a coordinator that binds it to
  the corresponding operation decision. It is not a transferable credential.
- NATS KV linearization/conformance and durable journal/CAS adapter behavior
  remain later L0C/runtime evidence.
