# Service availability SLOs (TS-714)

This first slice defines the closed-beta policy, executable Prometheus rules
and importable Grafana dashboard. It does **not** install a monitoring backend
or enable production SLO coverage. No Prometheus/Grafana deployment is managed
by this repository today. Alert routing belongs to its separate ticket.

## Policy

| Service label | Objective | Window | Eligible operations |
| --- | --- | --- | --- |
| `terrabase` | 99.9% | Rolling 30 days | Public database API requests |
| `ts-auth` | 99.9% | Rolling 30 days | Public authentication/identity API requests |
| `ts-dashboard` | 99.9% | Rolling 30 days | Dashboard pages, platform API and MCP requests |
| `ts-atlas` | 99.9% | Rolling 30 days | Discovery and global proxy requests |
| `ts-router` | 99.9% | Rolling 30 days | Admitted inference requests, including streams |

These are initial engineering targets for the closed beta, not customer SLAs.
The five `slo:objective` rules in [slo-rules.yml](slo-rules.yml) are the
machine-readable definitions. The policy counts availability only; latency
targets require service-specific measurement and are outside this slice.

Availability is `good / (good + bad)`. All replicas and regions of one service
are aggregated by request volume, after calculating each counter's rate to
preserve independent process resets. One service has one fleet SLO; this can
hide a low-traffic region's failure. Per-region health needs separate alerts.
Proxies and their backends each count their own request: a dependency outage
can legitimately burn both services' budgets.

## Required telemetry contract

The rules consume a **new contract**, not an existing exported metric:

```text
terrascale_slo_requests_total{service="terrabase",outcome="good"} 1000
terrascale_slo_requests_total{service="terrabase",outcome="bad"} 1
```

Every serving instance must initialize both counters to zero and increment
exactly one for each completed eligible operation. Scrape labels must preserve
instance identity until `rate`/`increase` is applied. Only the five service
labels above and outcomes `good` and `bad` are allowed; never label tenants,
users, credentials, request IDs or raw paths. Transport and streaming failures
must be observed at the boundary that sees the terminal result, rather than
counting an early HTTP 200 as success.

- `good`: completed service operation, including an intentional client-error
  response (invalid input, denied credentials, missing resource, tenant quota).
- `bad`: server/dependency failure, unexpected cancellation, service-side
  timeout, capacity rejection or stream failure after headers were sent.
- Excluded: health/readiness/metrics probes, internal replication and background
  work; client disconnects explicitly attributable to the caller. Unattributed
  failures count as bad. Do not fabricate a completed operation for a dropped
  connection: monitor unreachable instances and ingress failures separately.

The owning service instruments its boundary. Cross-product calls continue
through SDKs; no service business data is copied into the orchestrator.
Application data remains in TerraBase. These repository files are policy
configuration and fixtures, not a new application data store. Backend and
Grafana provisioning/storage must follow the existing TerraScale ownership
and persistence rules in the runtime activation slice.

Known integration gaps at this slice: ts-auth emits OpenTelemetry through OTLP
and has no `/metrics` route. There is no verified normalized counter for any
of the five services yet. Use current service mainline contracts when wiring
the collector. Never relabel health checks or process readiness into request
success.

## Burn-rate alerts

Burn is `bad request fraction / 0.001`. Both windows must cross the threshold
in the same evaluation; no additional `for` delays the burn alerts.

| Alert | Long / short window | Burn | Severity | Budget consumed in long window |
| --- | --- | --- | --- | --- |
| `ServiceSLOBurnFast` | 1h / 5m | >14.4× | critical | 2% |
| `ServiceSLOBurnSlow` | 6h / 30m | >6× | critical | 5% |
| `ServiceSLOBurnDaily` | 1d / 2h | >3× | warning | 10% |
| `ServiceSLOBurnSteady` | 3d / 6h | >1× | warning | 10% |

The budget percentages assume stationary request volume. The rules use actual
request-weighted fractions. Alerts may overlap; routing/deduplication is not
configured here. Labels include `service`, `slo`, `severity`, `long_window`
and `short_window`. Investigate the affected service's terminal failures and
recent releases; an alert grants no automatic rollout or scaling authority.

Zero traffic gives an undefined error fraction, not 100% availability and not
a burn alert. `ServiceSLOTelemetryMissing` fires when either outcome has no
samples in 5 minutes for a further 10 minutes, including a service that was
never instrumented. This detects fleet-wide absence, not one missing replica.
Scrape/ingress health and expected-instance inventory are separate prerequisites.

The 30-day budget is `1 - bad_fraction / 0.001`, may be negative, and is not
clamped to hide exhaustion. Prometheus evaluates available samples during
startup; results are **provisional until the full window is observed**. Its
history must retain at least 30 days (35 days recommended). Gaps and missing
replicas can bias fractions; no-data is never evidence of health.

## Validate and enable in a follow-up slice

1. Run the evaluations with the pinned Prometheus 3.15.0 `promtool` (archive
   SHA-256 is pinned in [the workflow](../../.github/workflows/slo.yml)):

   ```sh
   TS_SLO_PROMTOOL=/absolute/path/to/promtool GOMAXPROCS=2 GOFLAGS=-p=2 \
     nice -n 19 mise exec -- go test ./tests/slo -count=1
   ```

2. Verify service-owned instrumentation and all serving targets before loading
   rules. Confirm both zero-initialized outcomes, exclusions, replica identity,
   resets, streaming errors and loss of a target. Record the actual backend,
   storage decision and scrape inventory. Do not touch Forgejo/ts-ops/homelab
   hosts or re-found serving cells for this work.
3. Load `slo-rules.yml` using the existing Prometheus backend's `rule_files`,
   retaining at least 30 days. Verify its rules API reports no evaluation errors
   and each service has both outcome counters. No backend target is specified
   or mutated by this slice.
4. Import [slo-dashboard.json](slo-dashboard.json) in Grafana and select the
   Prometheus datasource. It shows objective, measured availability, remaining
   budget, requests, windowed burn rates and firing alerts. Confirm missing
   metrics display no data and never a green/100% default.
5. Observe real traffic and a controlled fixture failure; verify paired-window
   firing and recovery. Record evidence before declaring coverage active.
   Remove the rule-file entry and imported dashboard to revert the policy
   assets; service telemetry remains useful independently.

`tests/slo` evaluates the shipped rules with Prometheus itself: all five
services, sustained burn, recovery, isolated short-window spikes, independent
counter resets, request weighting, zero traffic and missing outcomes. The SLO
workflow runs these checks on every change to the assets or tests; regular Go
verification also checks the dashboard JSON without a Prometheus installation.
