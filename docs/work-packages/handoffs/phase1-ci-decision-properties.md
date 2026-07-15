# Phase 1 CI trust-zone decision property handoff

## Result

Added four deterministic 1,000-case independent-oracle families for the existing pure CI decision surface:

- exhaustive closed job-kind/trust-zone/capability policy decisions;
- ordinal fresh compatible runner selection under generated permutations and Turkish/Japanese culture changes;
- retry authorization versus maximum-attempt precedence with exact generation and idempotency preservation;
- duplicate, stale/unavailable, wrong-zone, and capability-missing runner evidence precedence.

Accepted dispatches assert the exact pipeline, job, runner, tree, generation, attempt, and idempotency subject. Public decision, dispatch/hold intent, error, and trace types remain construction-closed.

The eight-entry replay corpus is capped at 32 KiB and 64 entries, uses a closed scenario catalog, bounded ASCII IDs, unique seeds/IDs, exact fields, and a complete resource SHA-256 of `780cc2d0e5ac5298eeec0dfa1b2d937dda844e2a47c5a4e75fa2be092ad7a967`. Every expected value is an exact SHA-256 fingerprint of the emitted dispatch identity. Mutating a corpus seed changes the replay fingerprint, proving the seed participates in executed inputs and outputs.

## Compatibility and production impact

The completeness audit proved a production trust-boundary defect: a trust-valid job could dispatch to a runner whose capability inventory also carried authority forbidden in that runner's zone. For example, an untrusted product runner with `Compile`, `Test`, and `ProductionDeploy` was accepted because selection checked only the requested subset.

`DeliveryEngine.DecideJob` now confines every fresh requested-zone candidate to the closed runner inventory before required-capability matching: untrusted product permits `Compile`/`Test`; trusted build permits `Compile`/`Test`/`Sign`; production release permits `Promote`/`ProductionDeploy`; control recovery permits only `ControlRecover`. An unsafe candidate does not poison a request when a safe candidate remains.

The independent matrix covers all 16 forbidden zone/capability pairs and all 8 allowed job/capability pairs. Review corrections fixed the initial erroneous forbidden-pair count and split job enum validation from runner enum validation across 10 independent unspecified/undefined modes. Every generated family compares an `en-US` baseline with `tr-TR`, `ar-SA`, and `ja-JP` replays.

## Verification

The pre-fix exact-tree regression failed both safety families because the unsafe runner emitted `DispatchJobIntent` with no error. Post-fix verification is recorded below.

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
Passed

dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore --nologo -m:1 -warnaserror
Build succeeded: 0 warnings, 0 errors

Focused CI completeness properties: 4 passed, 0 failed, 0 skipped
Full ControlPlane suite: 468 passed, 0 failed, 0 skipped

git diff --check
Passed
```

## Non-claims

No runner, process, Git/Forgejo, registry, network, filesystem runtime, NATS, cloud/provider, signing implementation, secret delivery, artifact execution, or deployment was exercised. This does not satisfy L0, L3S, L4, production readiness, or deployment acceptance.
