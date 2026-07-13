# Phase 1 observability and Grafana projection core

## Predecessor

- Contract steward commit: `069fccf`
- Metrics/log/trace implementation selections, persistence topology, retention, cardinality budgets, alert thresholds, and Grafana delivery mechanism remain explicit inputs.

## Goal

Implement pure telemetry admission/cardinality, regional aggregation health, alert routing, and exact immutable Grafana projection decisions from `ORCHESTRATOR.md:1041-1095`. It emits typed projection intents only.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Observability/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Observability*.cs`
- `docs/work-packages/handoffs/phase1-observability-projection-core.md`

## Required behavior

- Immutable bounded cell/tenant/service/signal/metric/label/dashboard/datasource/folder/alert/contact/role/user/release/operation identities; checked cardinality/retention/generation quantities; closed signal, persistence, access, projection, and action catalogs.
- Telemetry admission receives explicit label-key/value catalogs and per-scope cardinality budgets. Unknown/unbounded labels, secret-bearing fields, raw credentials/keys, tenant crossover, stale generation, or budget overflow rejects before ingest intent.
- Regional metrics/log/trace health is evaluated independently with caller-selected HA/persistence/retention policies; GRU loss cannot erase regional evidence. Missing/stale observations hold promotion and produce typed degraded findings, not fabricated health.
- Grafana projection is an exact deterministic function of accepted roles/cells/datasources/dashboards/folders/alerts/contact points/access policy. Drift emits create/update/delete intent only under exact generation/ownership; unmanaged resources are reported and never silently adopted/deleted.
- Dashboard/query/provisioning executable text is not accepted as arbitrary caller input; projections select reviewed catalog entries plus typed parameters. Operator roles are least privilege and tenant/cell scopes cannot broaden by merge.
- Emit closed admit/drop/aggregate/project/create/update/delete/report-drift/route-alert/hold intents and stable code/numeric trace; no query/config JSON blob, credential, secret, callback, Grafana/OTel client, network/filesystem/clock, or I/O.
- Defensive copies; culture/permutation/replay; cardinality explosion; secret label; tenant isolation; signal outage; stale persistence; exact projection drift; unmanaged resource; access escalation; alert dedupe/routing; and secret-safe/reflection tests.
- No telemetry/Grafana SDK, database/network/filesystem/clock, implementation/retention/cardinality/threshold/default catalog, or mutation.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`

