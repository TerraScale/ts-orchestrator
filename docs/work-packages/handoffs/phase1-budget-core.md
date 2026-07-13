# Phase 1 budget core handoff

- Branch: `phase1/budget-core`
- Work package: `docs/work-packages/phase1-budget-core.md`
- Scope: pure budget authorization and inventory/billing anomaly decisions
- Provider prices/actions, billing APIs, clocks, I/O, mutations, and cost/SLO defaults: unchanged

## Implemented model

- Cell, node-class, cost-center, resource, price-evidence, and approval identities are immutable and require explicit positive character bounds.
- `BudgetQuantity` is a checked non-negative `long` fixed-point base-unit value. Changes use an explicit increase/decrease direction plus non-negative magnitude; floating point and negative quantities are absent.
- `BudgetVector` covers CPU, memory, storage, IOPS, throughput, public IPs, load-balancer backends, hourly spend, and daily spend in a fixed invariant order.
- Caller policy supplies per-node-class minimum/warm/maximum counts; cell/global automatic and approval bands; cell/global budget ceilings; cell/global provider/account hard limits; emergency posture; maximum evidence age; maximum evidence count; safety purpose; and typed approval scope.
- Evidence is explicitly scoped and typed for cell/global usage, node-class counts, and price identity. Status and numeric age are caller observations; no wall clock is read.

## Decision behavior

- Missing, null, unknown, stale, over-age, duplicate, conflicting, negative-count, over-limit, or wrong-scope evidence produces `Held`. Enumeration stops at the explicit combined evidence bound.
- Projection uses checked arithmetic. Overflow/underflow holds without wrapping. Node minimum/maximum, warm protection, every automatic/approval/forbidden band, budget ceilings, and provider/account hard limits are evaluated deterministically.
- `Automatic` is the only immediately authorized kind. `ApprovalRequired` is not authorized and contains only a typed immutable approval scope plus the numeric trace; there is no callback, command, arbitrary message, lookup, or provider action.
- The stable invariant trace includes current/projected cell/global usage, delta, every automatic/approval/budget/provider vector, current/projected/minimum/warm/maximum node counts, all evidence ages and maximum age, and binding dimensions.
- In emergency posture, ordinary growth is forbidden and every decrease is held, so this core cannot authorize termination. Availability repair still passes through hard policy. An explicitly classified storage-only/no-node data-loss-prevention increase is automatic even beyond budget bands, but never beyond provider/account hard limits.

## Anomaly behavior

The pure anomaly detector accepts an explicit complete-inventory assertion and bounded, scoped, fresh observations. It reports typed findings for:

- owned but undesired/orphaned resources;
- owned unattached resources;
- desired but missing owned resources;
- billing without an owned resource; and
- owned resources missing from billing.

Findings are defensively copied, canonically ordered, secret-safe, and never decide deletion or any other mutation.

## Verification

The 25 focused TUnit tests cover identity/quantity boundaries, culture stability, default closure, policy construction, defensive copies, all nine independent dimensions, exact bands, cell/global budget and hard limits, node min/warm/max, arithmetic limits, approval secrecy, evidence permutations/failures/ages/bounds, emergency safety behavior, and anomaly discrepancy/evidence matrices.

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode
dotnet build TerraScale.Orchestrator.slnx --no-restore
dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore -- --treenode-filter '/*/*/Budget*/*'
dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore
git diff --check
```

Result: solution build passed with zero warnings/errors; focused budget tests passed 25/25; full ControlPlane tests passed 69/69.

## Deliberate semantic choices and limitations

- Fixed-point unit scale is owned by the future versioned policy schema; this core compares only values already expressed in the same caller-selected base units.
- Warm is an approval floor: a decrease below warm but not below minimum requires approval. Minimum/maximum violations are forbidden.
- Emergency termination protection is conservative: every decrease is held because this pure budget input cannot prove that a decrease is non-terminating.
- Early held decisions caused by absent/incomplete evidence have no fabricated numeric trace; all decisions after complete evidence contain the full trace.
- No price estimation, currency conversion, provider quota lookup, billing reconciliation fetch, anomaly deletion policy, or mutation is implemented.
