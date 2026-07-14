# Phase 1 compute accepted-output audit handoff

- Base: `c70173a`
- Scope: pure compute contracts, engine, tests, and this handoff
- External I/O or mutation: none

## Defect and correction

The scale-out and scale-in engines validated complete evidence but discarded
part of it when constructing their authorizing outputs.

Two accepted scale-out requests could share a binding and provider create key
while differing in their persisted plan, resource envelope, capacity proofs,
and exact provider-absence observation. Both produced the same publicly
observable `RequestCreateIntent`. The intent now retains the exact validated
`PersistedScaleOutPlan`, `CapacityAuthorization`, and
`ProviderCreateEvidence`; its compatibility `CreateKey` is asserted equal to
the retained evidence key.

Likewise, two accepted stateful scale-in requests could share a target binding
and revocation proof while differing in low-use/availability authorization,
retained-volume proof, and stateful owner. Both produced the same publicly
observable `TerminateNodeIntent`. The intent now retains the exact validated
`ScaleInAuthorization` and revoked-prefix `ScaleInProgress`; its compatibility
`RevocationProof` is asserted equal to the retained progress proof.

The change adds no policy, transition, error, action, trace, or acceptance
path. Existing validation order and denial precedence are unchanged. No
provider adapter or executable operation was introduced.

## Independent regression evidence

- Adversarial accepted pairs differ only in the evidence formerly discarded
  by each output and prove the exact originating references are retained.
- The completeness oracle verifies every new field and the compatibility-field
  equality constraints across generated cases.
- Reflection pins the exact public property shape of all 16 concrete compute
  intents, rejects public setters and constructors, and prevents unrelated
  intent expansion.
- The public observable enum inventory is unchanged: 10 compute triggers,
  7 node roles, 9 scale-out states, 10 scale-in states, 4 provider-create
  statuses, 4 stateful dispositions, 3 volume dispositions, 16 actions,
  20 errors, 16 traces, and 3 requirement codes, each including its sentinel.

## Validation

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo -c Release /warnaserror
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj -c Release --no-build --no-restore -- --no-progress --output Detailed
```

The focused Release run passed 528/528 with zero build warnings and errors.
Final all-suite and diff checks are recorded by the integration handoff.

## Non-claims

This is pure decision-core evidence only. It does not claim provider adapter,
OCI, Pulumi, disconnected replacement, destructive termination, VM, L0C,
SmolVM, ARM64, or deployment acceptance.
