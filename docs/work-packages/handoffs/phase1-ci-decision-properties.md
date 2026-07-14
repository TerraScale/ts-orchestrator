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

None. This shard changes tests, an embedded test corpus, and work-package documentation only. The prior Delivery bounded-snapshot hardening already covers hostile enumerable inputs; no new unbounded production input or fail-closed defect was found.

## Verification

```text
dotnet build tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-restore --nologo -m:1
Build succeeded: 0 warnings, 0 errors

dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore -- --no-progress --output Normal
Passed: 346, failed: 0, skipped: 0

git diff --check
Passed

Serial full-solution build passed with zero warnings/errors. Other executable suites passed:
Contract 24, Model 38, Protocol 50, Scheduler 69. Whole-repository total: 527 passed, 0 failed, 0 skipped.
```

## Non-claims

No runner, process, Git/Forgejo, registry, network, filesystem runtime, NATS, cloud/provider, signing implementation, secret delivery, artifact execution, or deployment was exercised. This does not satisfy L0, L3S, L4, production readiness, or deployment acceptance.
