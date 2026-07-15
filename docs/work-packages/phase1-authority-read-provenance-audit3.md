# Phase 1 Authority read-intent provenance audit

## Scope and base

- Base: central `chore/phase0-bootstrap` at `e009eec` after final rebase.
- Allowed production paths: Authority contracts, digest encoding, and pure engine; focused/property tests and this work package.
- No NATS, clock, filesystem, process, network, provider, VM, deployment, or sibling-repository operation.

## Executable defect

An accepted leader read that can later restore a mutation permit and an ordinary genesis follower read emitted equal adapter-facing values:

```text
ReadAuthorityIntent { AuthorityId = regional-authority, RequestId = shared-read }
```

The same output also collided across candidates. Although the complete decisions and journal events differed, the persisted execution intent erased the candidate, resume posture, accepted epoch/revision high-water, and confirmed observation. The intent alone therefore could not prove which candidate or known authority truth authorized the read.

## Correction

`ReadAuthorityIntent` is now assembled internally from the already validated `RequestAuthorityRead`, replayed `AuthorityState`, and computed resume status. It retains:

- exact candidate identity;
- exact follower/leader/read-only-held resume posture;
- accepted highest epoch and KV revision;
- the exact nullable confirmed observation.

The authority decision digest includes all five coordinates. Exact immutable replay remains equal; changing any one coordinate changes both intent equality and the decision digest. Follower, leader, ordinary held, and held-leader recovery read sites are covered. Read requests still emit no mutation permit, and existing response handling still replays state and performs its exact safety checks before a leader read can restore a permit.

No public constructor, setter, positional deconstructor, or independent public factory was added. Because `ReadAuthorityIntent` remains a nominal C# record in the existing `AuthorityIntent` hierarchy, the compiler-generated `<Clone>$` can copy an already accepted immutable intent without changing its get-only properties. This audit tests and records that precise copy surface rather than claiming it is clone-free; removing it would require broader hierarchy churn unrelated to the provenance defect.

## Evidence boundary

These fields are accepted-read execution and provenance coordinates. They are not adapter-enforced conditional-read parameters, proof of response authenticity, a transferable mutation authorization, or evidence of NATS KV linearization. The adapter and journal coordinator must still correlate and authenticate the result, and real NATS behavior remains L0C/integration evidence.

All existing enums, numeric values, errors, transitions, and validation precedence are unchanged.

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore -warnaserror
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj -c Release --no-build --no-restore -- --no-progress
git diff --check
```

Recorded after the final rebase: Release solution build passed with zero warnings and errors; focused Authority passed 28/28; all five executables passed 782/782 (ControlPlane 573, Contract 24, Model 38, Protocol 70, Scheduler 77).
