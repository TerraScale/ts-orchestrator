# Phase 1 authority mutation-permit provenance audit 4

## Scope and base

- Exact starting base: central commit `6fb86b534de7c06990f9017fb7645225a552f358`.
- Production scope: Authority contracts, pure engine, and canonical digest encoding.
- Evidence scope: focused regressions, authority/operations property corpus, accepted-output construction closure, and this work package.
- No NATS, KV, clock service, provider, SDK, network, filesystem, process, VM, deployment, or sibling-repository effects.

## Executable defects

`MutationAuthorityPermit` previously projected lease and evaluation coordinates but erased the accepted command that minted it. Two accepted `EvaluateMutationAuthority` commands with different request identities and otherwise identical evidence produced record-equal permits and equal decision digests.

Binding only `RequestId` was insufficient. A successful `ObserveAuthorityCas`, a successful leader-resume `ObserveAuthorityRead`, and an `EvaluateMutationAuthority` could use the same request identity, observation, and health while representing different accepted authorization acts. The flattened permits again compared equal. Both collisions were captured as executable failing tests before production changed.

## Correction

The construction-closed permit now retains the exact immutable `AuthorityCommand` object accepted by the engine. Its internal constructor admits only the three permit-producing shapes:

- successful `ObserveAuthorityCas` with non-null observation and lease;
- successful `ObserveAuthorityRead` with non-null observation and lease;
- `EvaluateMutationAuthority` with non-null lease evidence.

All existing permit projections and the derived `RequestId` come from that one command. The private engine helper accepts only the command, so no caller can pair one command identity with another observation or health value. Rejected, held, uncertain, failed, null-observation, null-lease, and unrelated command paths do not mint a permit.

The `mutation-permit-v1` digest binds a distinct command-type tag and every command field using the existing length- and type-framed canonical encoder. This includes all identities, request identity, CAS outcome, nullable observation shape, revision, epoch, observation identity, nested lease fields, server and monotonic time, and both certainty flags. Exact replay is culture-independent; independently changing any admitted command field or command type changes the digest.

## Construction and replay closure

Public accepted-output factories remain exactly `AuthorityEngine.Decide`/`Replay` and `OperationEngine.Decide`/`Replay`. Authority and operation decisions, mutation permits, and concrete intents retain non-public construction and public get-only state. Public positional commands and journal events remain input/replay DTOs and cannot independently mint an accepted output; engine replay still validates journal digest, sequence, identity, and transition semantics.

The permit has no public constructor, public setter, positional deconstructor, or independent static factory. The compiler-generated record `<Clone>$` is the only public copy route. It copies an already accepted immutable permit, retains the exact authorizing-command reference, and cannot alter a get-only coordinate.

The evidence suite covers exact-reference retention for all three mint routes, null-permit iff proofs for rejected/held shapes, independent field/type/null-shape sensitivity, 1,000 deterministic cross-culture cases, and a strict content-addressed authority replay-corpus entry for request-provenance separation.

## Evidence boundary

The retained command proves which pure-engine input authorized this in-memory accepted output. It does not authenticate the command, prove NATS KV linearization, establish adapter correlation, or make the permit a transferable provider authorization. Those properties require later adapter/integration evidence.

No enum values, numeric assignments, state transitions, or error-precedence rules changed.

## Verification after final central rebase

```text
dotnet build TerraScale.Orchestrator.slnx --no-restore
dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build -- --no-progress
git diff --check
```

Recorded after rebasing onto central `1f73564`: the Release solution build passed with zero warnings and errors. All five test executables passed 870/870: ControlPlane 643, Contract 29, Model 44, Protocol 70, and Scheduler 84. This includes the two saved counterexamples, construction closure, deterministic properties, and strict corpus replay.
