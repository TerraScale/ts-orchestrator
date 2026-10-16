# OBS source and integration evidence, 2026-10-16

The OBS refactor stream is incomplete. These results qualify local boundaries,
not deployed GRU/San Jose/FRA coverage, browser behavior or production authority.
QA owns integrated publication; no OBS main push or cloud mutation was performed.

## Source slices

| Source commits | Behavior | Current validation |
| --- | --- | --- |
| `f490b0cb`, `c7997d16`, `e3c4b9d4` | Shared bounded registry/history catalog, actual metadata exposure and requested series limit | Focused integrated API check passed on `da1637f7` |
| `1ade5006`, `211fca1b`, `f0bd4876` | Authenticated CLI, history gaps/loss/rate support, collection/logging/tracing boundary scenarios | Existing focused CLI passed; new history/telemetry cases passed in affected checks below |
| `9abb875e`, QA `ccea5ea4` | Dashboard test migration, registry dashboard and global-view resource HTTP APIs | Dashboard/globalview suites passed on `4bd2f088` |
| `46789697`, `06b36a30` | Host archive validation through durable publication/replay, transport bounds and corrected fixtures | All selected host/catalog/server cases passed on `c5958f9a` |
| `f54638bf`, `d937c2a6`, `17c92896`, `53be4639` | CLI resource consumers, dashboard uncertainty, globalview NATS/HTTP migration, source cadence | Checks pending coherent shared dependencies and QA lane |

The parent-tree dependency copy `51457908` is QA's existing `ccea5ea4`;
it is not an additional feature for integration.

## Exact checks

Every command used `GOMAXPROCS=2 GOFLAGS=-p=2 nice -n 19`, bounded timeout and
the QA-approved capacity lock. No unbounded background check remains.

1. Clean `da1637f7`, focused `TestMetricCatalog|TestObserve|TestMetricDashboard`
   across observability, CLI, dashboard subpackages and globalview: passed.
   Log [da1637f7.log](obs-checks-20261016/da1637f7.log).
2. Clean `4bd2f088`, full observability, CLI, dashboard subpackages and globalview:
   dashboard/accesscheck/devfake/globalview passed. Observability found three
   fixture failures, subsequently fixed by `06b36a30`. CLI compilation found an
   unused shared app import; QA fixed it. Log [4bd2f088.log](obs-checks-20261016/4bd2f088.log).
3. Clean `c5958f9a`, focused
   `TestObserve|TestMetricCatalog|TestServerValidates|TestHostMetric|TestBoundHostMetric|TestDrill|TestUnreadVolumes`:
   observability passed in 57.952 seconds. CLI/dashboard compilation stopped at
   shared `internal/release/container.go` references to missing `ProductionProof`.
   These consumers remain unverified. Log [c5958f9a.log](obs-checks-20261016/c5958f9a.log).

## Migration inventory

- Dashboard: 170 old cases became 151 boundary cases; 29 old names were replaced
  by 10 consolidated HTTP workflows. Plain and race checks passed before the
  additional metric/drilldown changes. Exact previous-name inventory retained at
  `/tmp/ts-obs-dashboard-migration-report.md`.
- Observability: history queries use actual authenticated HTTP, collection uses
  snapshot HTTP, logs use on-disk output, tracing crosses HTTP/NATS/logfile, and
  parser failures use actual proc/filesystem inputs and snapshot output. Seven
  remaining host encoder/validation cases now publish and replay over JetStream;
  oversized persisted bytes are rejected at the actual NATS stream limit.
- Globalview: all 33 case names retained. Former builder cases now use production
  `publishOnce`, real NATS `Follow` and TCP HTTP reads; former acceptance/decoder
  cases exercise malformed subjects/bodies and inspect the resulting API view.
  Collector coverage uses an actual NATS snapshot responder/aggregator and a
  closed connection instead of the old cluster mock. Persistent/restart and
  leader/cadence scenarios already cross JetStream. New migration is unverified.
- CLI: actual registry/history/auth/bounds, real missing-member NATS aggregation
  and resource HTTP workflows cover current/missing/stale/truncated/unavailable
  responses and versioned output. New resource cases are unverified.

This inventory covers the claimed slices only. QA's repository-wide inventory
still controls the integration-only completion claim.

## Remaining producer and acceptance gaps

1. OCI must supply admitted management endpoints and read-scoped operator Vault
   access. Structural foundation records and NetBird names are not authorization.
   Normal CLI still has the existing manual benchmark/diagnostic bridge.
2. Detailed CORE service, OCI regional operation and MESH admitted-roster sources
   need shared app wiring. RUNNING never establishes application readiness;
   a foundation operation never establishes regional serving readiness.
3. WASM has a source-backed worker snapshot and exact-tenant mTLS HTTP route;
   the manager-side authenticated inventory/client collection path remains open.
   No broader worker credential or observation wildcard was introduced.
4. No live fleet/browser/OCI/NetBird, privileged runtime, failure qualification or
   resource-overhead measurement was performed. Fixed history retention metadata
   describes supported retention, not proof that every tier survived restoration.
