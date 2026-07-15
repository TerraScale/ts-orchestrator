# Phase 1 delivery core handoff

- Branch: `phase1/delivery-core`
- Work package: `docs/work-packages/phase1-delivery-core.md`
- Scope changed: lane-owned delivery source/tests and this handoff only
- External I/O or mutation: none

## Result

Implemented pure GitOps source, CI runner, artifact promotion, and release
rollout decision engines for `INV-005`. The engines consume caller-supplied
typed evidence and emit closed fetch, verify, plan, dispatch, promote, stage,
advance, rollback, or hold intents. They contain no Git, Forgejo, process,
filesystem, network, clock, signing, approval, or provider implementation.
Every emitted intent, decision, error, and trace has assembly-internal
construction and public read-only inspection, so external callers cannot forge
an authorized-looking mutation result without executing the decision engine.

Source reconciliation binds evidence to the exact source, ref, generation,
commit, tree, manifest, desired digest, signature, schema attestation,
dependency attestation, and complete dependency proof set. Branch movement and
webhook delivery are never authority. Lower generations hold, while same-
generation replay is idempotent only when every source field and dependency is
equal. Dependency order is canonicalized without weakening exact-set checks.

CI decisions validate an explicit closed job-kind/trust-zone/capability matrix,
fresh bounded runner sequence evidence, runner availability, attempts, retry
authorization, and idempotency identity. Selection is ordinal and permutation
and culture invariant. Product-validation work can use only untrusted product
runners and compile/test capabilities; promotion and control recovery have
separate narrowly closed authority surfaces.

Promotion binds qualification evidence to the exact release and generation,
source tree, dependency
lock, generated schema digest, artifact, artifact digest, test/evidence
attestations, signing identity, signature, approval, and compatibility proofs.
Compatibility is explicit for N-to-N and both N/N-1 directions; failure in any
direction denies promotion. A change to any subject dimension invalidates the
entire qualification rather than partially reusing evidence.

Rollout consumes one exact signed artifact and desired generation, an ordered
cell list, exact per-cell forward and rollback availability bound to the release,
operation, generation, artifacts, digests, and both forward and rollback
signatures, disruption and
availability authorization, and staged health proof. Completed-cell evidence
binds operation, release, cell, generation, artifact, digest, signature, and
healthy proof and must form the exact prefix. A lost stage response advances
from exact evidence without restaging. Pending health and process-exit-like
absence of health never advance; failed health deterministically rolls back the
known local digest only when the caller-selected policy permits it.

Reviewer counterexamples were converted into direct regressions: dependency
proof substitution and cross-revision evidence replay; same-generation changes
to ref, manifest, signature, or dependencies; stage evidence from another
operation/signature; bare or mismatched completed-cell claims; promotion proof
replay across release/generation; and availability replay across a rollout or
artifact. Public errors carry only closed requirement and error codes.

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore -- --no-progress --output Detailed
dotnet run --project tests/TerraScale.Orchestrator.ContractTests/TerraScale.Orchestrator.ContractTests.csproj --no-build --no-restore -- --no-progress --output Detailed
dotnet run --project tests/TerraScale.Orchestrator.ModelTests/TerraScale.Orchestrator.ModelTests.csproj --no-build --no-restore -- --no-progress --output Detailed
dotnet run --project tests/TerraScale.Orchestrator.Protocol.Tests/TerraScale.Orchestrator.Protocol.Tests.csproj --no-build --no-restore -- --no-progress --output Detailed
dotnet run --project tests/TerraScale.Orchestrator.Scheduler.Tests/TerraScale.Orchestrator.Scheduler.Tests.csproj --no-build --no-restore -- --no-progress --output Detailed
git diff --check
```

The delivery suite contains 16 focused tests covering branch races, duplicate
webhooks, dependency order and substitution, source replay, lower/conflicting
generations, deterministic runner selection, trust-zone escape, explicit retry,
full promotion invalidation, N/N-1 compatibility, staged regional progress,
lost responses, availability, local rollback, exact operation/signature/cell
completion proofs, culture/permutation stability, and reflection-based denial
of executable, secret, callback, process, network, and I/O surfaces. Reflection
also proves that intents, decisions, errors, and traces expose no public
instance constructor. Stage, advance, and rollback payload tests prove exact
operation and forward/rollback signature preservation.
The final direct executable run passed all 247 repository tests: Contract 8,
ControlPlane 139, Model 17, Protocol 42, and Scheduler 41.

## Deliberate limitations

- The core models observations and emits intents; adapters own durable queues,
  Git/OCI resolution, runner lifecycle, artifact transfer, signing, promotion
  leases, journaling, deployment, and health collection.
- Repository placement, manifest schema/defaults, source credentials, runner
  freshness windows, attempt limits, approvals, signing policy, compatibility
  attestations, rollout order/strategy, availability, and rollback policy are
  mandatory caller-owned inputs or upstream evidence. No policy default is
  encoded here.
- Source dependency cycle detection and full cross-repository graph planning
  remain an upstream graph compiler concern; this core proves and freezes its
  exact dependency inputs.
- Durable NATS acknowledgement, one-writer fencing, interruption recovery, and
  real runner/registry/cell conformance remain later integration evidence.
