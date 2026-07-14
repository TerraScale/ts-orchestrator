# Phase 1 CI dispatch provenance audit

## Scope and base

- Base: central `chore/phase0-bootstrap` at `6ea6200` after the required final rebase.
- Allowed paths: CI delivery contracts/engine, CI decision tests/corpus, and this work package.
- Pure deterministic decision work only; no runner, Forgejo, Git, registry, NATS, filesystem, network, process, signing service, provider, VM, or deployment action.

## Executable defect

A valid ProductValidation request in `UntrustedProduct` using runner sequence 20/capability `Compile` and a distinct valid TrustedBuild request in `TrustedBuild` using the same runner identity at sequence 80 with `Compile/Test/Sign` produced the same complete adapter-facing dispatch fields:

```text
pipeline|job|shared-runner|tree|7|1|key
```

The accepted output retained the execution IDs but erased the exact job trust policy, sequence window/retry context, selected runner zone/sequence/availability/capability inventory, and identity-length policy that passed validation. A reused or re-enrolled runner ID could therefore be relabeled without detection from the persisted dispatch intent.

## Correction

`DispatchJobIntent` is now assembled internally only from the already validated `JobRequest`, selected `RunnerEvidence`, and explicit maximum identity length. It retains those exact immutable instances and policy value. Existing compatibility getters derive from them rather than duplicating independently mixable constructor parameters.

`JobRequest` and `RunnerEvidence` already defensively snapshot their caller-supplied zone and capability sequences. Mutation of the source arrays after construction cannot change the retained dispatch. The canonical test fingerprint is length/count-delimited and covers every request field/list in order, every selected-runner field/list in order, and the maximum identity length. The pinned replay corpus was regenerated against this complete fingerprint.

The request/evidence DTOs are nominal classes with reference equality. Therefore the supported replay assertion is canonical full-fingerprint equality for semantically identical immutable values, not structural object equality. The intent itself remains construction-closed with no public constructor, setter, deconstructor, or factory.

## Compatibility and precedence

No input DTO, enumeration, numeric value, error, trace, policy, or selection behavior changed. Existing compatibility getters remain available. Precedence remains runner-input acquisition bound, job validation, retry denial, exhausted attempts, job trust policy, runner validation, duplicate evidence, freshness/availability, zone, runner-zone confinement, capability match, ordinal selection, then dispatch.

## Evidence boundary

This accepted output binds the execution subject and caller-supplied selected runner evidence used by the pure decision. The evidence is validated input, not an attestation or proof of runner authenticity, enrollment, capability possession, network/process isolation, or real trust-zone enforcement. Rejected and alternate candidates are intentionally not retained, so this is not complete ordinal-selection provenance. Real runner/Forgejo/NATS behavior remains later conformance and integration evidence.

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore -warnaserror
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj -c Release --no-build --no-restore -- --no-progress
git diff --check
```

Recorded after the final rebase: Release solution build passed with zero warnings and errors; focused CI passed 14/14; all five executables passed 793/793 (ControlPlane 584, Contract 24, Model 38, Protocol 70, Scheduler 77).
