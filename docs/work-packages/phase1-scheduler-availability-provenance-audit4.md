# Phase 1 scheduler availability authorization provenance audit

## Scope and base

- Base: central `chore/phase0-bootstrap` at `2c7015589841311a3e1027e81a1a78273cfc7967` after the required final rebase.
- Allowed paths: scheduler availability contracts/evaluator, scheduler tests, and this work package.
- Pure deterministic L0 policy only; no scheduler adapter, NATS, filesystem, process, network, systemd, container, VM, cloud/provider, credential, drain, maintenance, placement, or deployment side effect.

## Executable defect

Two valid placement requests with different replica, node, and failure-domain targets produced the same complete public admitted decision when their counts, resources, policy, and observations otherwise matched:

```text
A: replica-d -> node-d / fd-d
B: replica-e -> node-e / fd-e
```

Both exposed only `Admitted = true` plus the same thirty numeric trace rows. The accepted output therefore erased which exact change, service policy, observation generation/snapshot, and resource request had passed the pure availability gates. A persisted admission could be relabeled only by rejoining caller-controlled input.

## Correction

`AvailabilityDecision.AcceptedRequest` now retains the exact already validated immutable `AvailabilityEvaluationRequest` only when every trace row admits. `Admitted` is derived exclusively from `AcceptedRequest != null`; there is no independent admitted constructor parameter or state. Held and rejected decisions always contain a null request.

The evaluator does not flatten or clone the authorization subject. The retained request therefore preserves the exact policy and change object identities plus the request's defensive immutable observation snapshot and generation values. Existing trace construction, values, order, and semantics are unchanged.

Tests use a complete length/count-delimited canonical projection covering every service-policy field, all eight reserve dimensions, every placement/maintenance/drain change field and resource dimension, completeness, candidate/current observation generations, and every observation field. Observation entries are canonically ordered for semantic replay; equivalent permutations remain fingerprint-equal across cultures without claiming structural equality of separately constructed request objects. Every accepted change path retains its exact request. Every exercised held/rejected family and all 1,000 lower/equal/higher generation cases prove `Admitted` if and only if an accepted request exists.

The public type has no constructor, setter, or deconstructor. Assembly-wide inspection permits only `AvailabilityPolicyEvaluator.Evaluate` to originate decisions. The record's compiler-generated instance clone can copy an existing immutable decision but cannot create an admitted decision from nothing or attach a request to a denial.

## Compatibility, precedence, and corpus

No request, change, observation, policy, reason, outcome, resource, or generation enum/numeric value changed. The established thirty-row reason order and all held/rejected precedence remain unchanged. No scheduler selection, availability gate, topology rule, capacity/reserve arithmetic, or generation policy changed.

The existing scheduler replay corpus is byte-identical and retains its pinned schema/content address. Its historical outcome fingerprint covers the pre-existing result/trace surface and intentionally does not claim accepted-request identity. Audit4's dedicated complete projection supplies the new provenance evidence; silently versioning an unrelated historical corpus would overstate what its fixtures were designed to prove.

## Evidence boundary

The subject proves which caller-supplied immutable request the pure evaluator admitted. It is not proof that observations are authentic, current, durably accepted, or persisted; that caller-owned stateful safety is correct; or that an adapter performed placement, drain, or maintenance. It does not authorize product/database geography and does not prove provider, runtime, NATS, failure-domain, host, VM, or cloud behavior.

This audit makes no full-domain property, mutation, fuzz, model-schedule, L0C, L3S/L4, deployment-evidence, production-readiness, or production-qualification claim.

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore -warnaserror
dotnet run --project tests/TerraScale.Orchestrator.Scheduler.Tests/TerraScale.Orchestrator.Scheduler.Tests.csproj -c Release --no-build --no-restore -- --no-progress
git diff --check
```

Recorded after the final rebase: Release solution build passed with zero warnings and errors; focused audit tests passed 7/7; Scheduler tests passed 84/84; all five executables passed 828/828 (ControlPlane 601, Contract 29, Model 44, Protocol 70, Scheduler 84).
