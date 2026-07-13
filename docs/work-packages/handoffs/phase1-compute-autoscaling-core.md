# Phase 1 compute autoscaling and regional survival core handoff

- Branch: `phase1/compute-autoscaling-core`
- Work package: `docs/work-packages/phase1-compute-autoscaling-core.md`
- Base: refreshed integrated control-plane commit `2e8d757`
- Scope changed: lane-owned compute source/tests and this handoff only
- External I/O or mutation: none

## Result

Implemented pure scale-out, scale-in, and regional-survival decision engines for
`REQ-O011` and the `INV-005` proof/replay boundary. Inputs are immutable typed
evidence; outputs are closed observe, persist-plan, authorize, request-create,
enroll, ready, cordon, drain, deregister, detach/retain, revoke, terminate,
audit, or hold intents. Every intent, decision, error, and trace has no public
instance constructor and exposes public read-only inspection, so callers cannot
forge an authorized mutation result outside the engine.

Every compute proof binds the exact cell, node class, template, shape,
placement domain, accepted artifact/digest, demand, provider fingerprint,
generation, controller epoch, and operation. Scale-out keeps demand, a
proposed plan, separately persisted-plan evidence, capacity authorization,
provider create observation, and node
progress as distinct evidence. The desired node count and resource envelope
must match across demand, plan, and authorization. Budget, quota, provider
capacity, cost, and placement each fail independently. An unknown provider
outcome emits only observation of the recorded idempotency key; it cannot emit
a second create. Later checkpoints retain and revalidate the full plan,
authorization, exact provider resource, identity attestation, enrollment,
bootstrap/disk checks, placement, and service-health prefix. Each checkpoint
requires every completed proof and rejects any future proof before its state;
the persist-plan intent freezes desired count, resources, and plan identity,
while authorization consumes the exact persistence proof without requiring its
future authorization result.

Stale or missing ordinary demand holds. Explicit, bounded failed-host or safety
replacement may continue without a sustained metric window, but still requires
an explicit typed demand and all normal plan/capacity proofs. This exception is
structurally limited to the two closed safety triggers.

Scale-in binds one exact node, provider resource, LB registration, volume,
operation, generation, epoch, and provider fingerprint. It requires fresh
sustained low-use, caller-supplied cooldown and lifetime proof, positive cost
benefit, replacement capacity, availability headroom, healthy regional control
and NATS evidence, no conflicting operation, and explicit stateful approval.
The checkpoint prefix is exact from candidate through cordon, drain,
deregistration, volume handling, revocation, termination, boot-volume absence,
and orphan audit; skipped or future proofs hold. Critical seed/control/NATS/
TerraBase roles retain an R3 floor. Elastic-stateful, control-NATS,
product-NATS, and TerraBase store roles require retained disposition and an
exact controller owner; truly stateless roles require ephemeral disposition
with no owner. No volume-delete, blind pool reduction, adoption, or
orphan-accept intent exists.

Regional survival readiness binds the exact signed/encrypted bundle generation,
provider fingerprint, accepted and rollback artifacts/digests/signatures,
encrypted secret-version identities, full node-class/template/shape/domain
tuples, trust, NATS, DNS, backup, authority epoch, journal/snapshot positions,
and caller-supplied freshness/expiry positions. Disconnected replacement also
binds its exact cell, template tuple, accepted artifact, operation, provider,
idempotent create key, bundle generation, and controller epoch. Ordinary
readiness requires that this irrelevant replacement target be absent;
disconnected authorization requires it to be present and exact. Plaintext secret
material and offline root keys have no representable field.

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

The compute suite contains 20 focused tests. Coverage includes every scale-out
and scale-in crash checkpoint, lost provider response, stale and bounded safety
demand, cross-authority proof replay, count/resource authorization joins,
budget/quota/capacity/cost/placement vetoes, null and skipped prefixes,
conflicting operations, critical floors, stateful veto/retention, exact LB,
volume, revocation, instance termination, boot absence and orphan audit,
complete/expired/mismatched survival bundles, disconnected target replay,
defensive copies, culture/permutation stability, forbidden surfaces, and public
constructor forgery reflection.
The final direct executable run passed all 317 repository tests: Contract 8,
ControlPlane 209, Model 17, Protocol 42, and Scheduler 41.

## Deliberate limitations

- The engines emit typed intents only. Provider calls, durable operation
  journals, NATS, scheduler placement, agent enrollment, runtime health, LB,
  volume, identity, backup, and orphan adapters remain outside this pure lane.
- Demand windows, safety bounds, cooldown, lifetime, count floors/caps,
  resource/cost envelopes, placement choice, compatibility, bundle freshness,
  expiry, and approval policy are mandatory caller inputs; no default is
  selected here.
- Provider idempotency/work-request semantics, real regional capacity and quota
  conformance, billing evidence, disconnected SmolVM recovery, and OCI A1
  replacement remain later integration/deployment evidence.
