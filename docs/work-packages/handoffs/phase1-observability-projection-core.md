# Phase 1 observability and Grafana projection core handoff

- Work package: `docs/work-packages/phase1-observability-projection-core.md`
- Predecessor: `069fccf`
- Integration base: `3e2f747`
- Scope changed: `src/TerraScale.Orchestrator.ControlPlane/Observability/**`, `tests/TerraScale.Orchestrator.ControlPlane.Tests/ObservabilityDecisionTests.cs`, and this handoff
- External/destructive actions: none

## Result

The control plane now has four pure observability decisions: bounded telemetry admission, regional metric/log/trace health aggregation, immutable Grafana desired-state projection, and alert routing. Every authorization binds exact operation, tenant, cell, signal, schema/rule digest, generation, and independently scoped completeness evidence applicable to that decision. Authorized decisions contain only passed trace reasons.

Telemetry admission accepts only cataloged label keys and values classified as bounded public data. Unknown, forbidden, unbounded, cross-tenant/cell, stale, out-of-order, incomplete, schema-replayed, and over-budget inputs fail before an admit intent. Cardinality arithmetic does not increment or overflow an attacker-controlled counter; admission requires the current complete scope to remain below its explicit caller-selected limit.

Regional health requires the closed Metric/Log/Trace policy set and exactly one current observation for each signal. Persistence, retention, ingest replicas, query replicas, and encrypted local-spool policy are evaluated independently. Central loss preserves regional evidence and produces a typed degraded ingest finding. Missing, duplicate, stale, future, policy-mismatched, under-replicated, or exhausted-spool evidence produces typed findings but cannot authorize promotion. Spool exhaustion records explicit data loss without representing product readiness as dependent on telemetry.

Grafana projection reconciles only reviewed datasource, folder, dashboard, alert, contact-point, and least-privilege access catalog selections. Tenant, cell, and global access use a closed subject union; the projection boundary and exact tenant/cell/global authority subject must match, and one user cannot receive merged duplicate assignments. A complete inventory proof is independently bound to operation, owner, tenant, cell, generation, and current observation sequence. Create, update, delete, and drift changes carry that exact inventory/CAS proof plus desired and, where applicable, observed material. Unmanaged or conflicting resources are reported and are never adopted or deleted. Scope crossover, access escalation, stale/future inventory, or ownership mismatch holds all mutation.

Alert routing requires fresh complete dedupe evidence bound to the exact operation, tenant, cell, signal, rule digest, generation, sequence, contact identity/catalog, severity, and state. Delivery keys use alert identity plus state, so a firing event routes once, its resolved transition remains routable, and the exact same transition cannot be delivered twice.

No query/config text, JSON provisioning blob, endpoint, URL, credential, password, secret value, private key, callback, process, filesystem, network, database, clock, client SDK, or I/O surface is accepted or used. Retention, cardinality, persistence, HA replica requirements, spool capacity/overflow policy, alert route, catalog selections, and collection limits have no implementation defaults. Label, catalog/value, observation, desired/observed resource, and delivered-event collections stop and reject at caller-supplied positive bounds before materializing boundary-plus-one data.

## Adversarial coverage

The focused tests cover label/secret/cardinality attacks, tenant/cell/operation/schema replay, stale/future/out-of-order evidence, missing and duplicate signal observations, independent ingest/query loss, GRU reachability loss, persistence/retention mismatch, spool exhaustion and data loss, closed signal policies, Grafana create/update/delete/report drift, unmanaged collision, incomplete/replayed/future inventory, scope/access escalation, alert route/dedupe replay across every subject dimension, state transitions, defensive copies, culture/permutation stability, authorized-trace consistency, malformed enums/identities/quantities, forbidden public shapes, intent forgery, and secret-safe traces.

## Validation

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo
dotnet test TerraScale.Orchestrator.slnx --no-build --no-restore -- --disable-logo --no-progress
git diff --check
```

The focused control-plane project passes 247 tests. The locked whole solution passes 355 tests with zero failures or skips and builds with zero warnings or errors.

## Integration boundary

This package emits typed decisions and projection intents only. OTel collection/export, local spool storage, metrics/log/trace backends, Grafana provisioning delivery, immutable replica operation, query execution, alert delivery, operator authentication, and persistence/event application remain downstream adapters. Those adapters must not weaken evidence scope, synthesize missing health, broaden access, adopt unmanaged resources, delete without exact observed proof, or introduce hidden defaults.
