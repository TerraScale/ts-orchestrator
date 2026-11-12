# Service availability SLOs (TS-714)

These files define the closed-beta policy, executable Prometheus rules and
importable Grafana dashboard. The existing gru monitoring backend and alert
routing are described in [the production runbook](production/README.md).
Coverage requires native counters and verified collection for each service.

## Policy

| Service label | Objective | Window | Eligible operations |
| --- | --- | --- | --- |
| `terrabase` | 99.9% | Rolling 30 days | Public database API requests |
| `ts-auth` | 99.9% | Rolling 30 days | Public authentication/identity API requests |
| `ts-dashboard` | 99.9% | Rolling 30 days | Dashboard pages, platform API and MCP requests |

These are initial engineering targets for the closed beta, not customer SLAs.
The three `slo:objective` rules in [slo-rules.yml](slo-rules.yml) are the
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
exactly one for each completed eligible operation. Caller-abandoned requests
increment neither counter and are excluded from both numerator and denominator.
Scrape labels must preserve
instance identity until `rate`/`increase` is applied. Only the three service
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

TerraBase uses its native Prometheus listener on port 9091. Auth already exports
ASP.NET HTTP duration counts on a dedicated ephemeral metrics listener. The
orchestrator discovers that listener from the running task's owned sockets;
no fixed port or service change is required. Recording rules normalize these
existing counts into the contract, preserving `service`, `instance` and `region`.
The HTTP recording adapter counts 5xx, 408, 499 and explicit transport errors as
bad when caller attribution is unavailable; other completed 1xx–4xx responses
count good. HTTP 499 is not inherently a service failure: a confirmed caller
disconnect is excluded, including when reported as 499 or a cancellation
exception. Status alone must not override positive caller attribution.
Probes, known internal routes and unclassified
routes are excluded, including auth metrics requests without a route. Both
outcomes initialize to zero only when the real HTTP counter is present.

This HTTP baseline cannot distinguish capacity from tenant-quota 429s, OAuth
errors encoded in HTTP 200, or every late protocol failure. It measures the
available HTTP signal; it does not claim complete protocol-level coverage.
Dashboard has no existing exporter and supplies native terminal counters on a
guarded loopback `/metrics` app listener. Its emitter must distinguish visitor
disconnects from service-initiated aborts: a caller disconnect without an
independent service failure is excluded, even if response completion throws.
Service-initiated aborts, dependency failures and service-side deadlines remain
bad; an aborted request must never become a good completion. A cancellation
token alone does not establish a service failure. Unattributed transport errors
remain bad. Atlas and router are not deployed and have no objectives or
dashboard selection. Never relabel readiness as request
success. Verify collection and outcomes against the installed releases.

## Burn-rate alerts

Burn is `bad request fraction / 0.001`. Both windows must cross the threshold
in the same evaluation, and the long window must meet its minimum eligible
request count; no additional `for` delays the burn alerts.

| Alert | Long / short window | Burn | Severity | Budget consumed in long window | Minimum long-window requests |
| --- | --- | --- | --- | --- | --- |
| `ServiceSLOBurnFast` | 1h / 5m | >14.4× | critical | 2% | 695 |
| `ServiceSLOBurnSlow` | 6h / 30m | >6× | critical | 5% | 1,667 |
| `ServiceSLOBurnDaily` | 1d / 2h | >3× | warning | 10% | 3,334 |
| `ServiceSLOBurnSteady` | 3d / 6h | >1× | warning | 10% | 10,000 |

For burn threshold `B`, choose `N = ceil(10 / (B * 0.001))`.
At `requests >= N`, crossing the unchanged threshold requires
`bad > N * B * 0.001`: respectively 10.008, 10.002, 10.002 and 10.
Thus one or two bad requests cannot trigger a burn alert. Counts use per-instance
`increase` over the long window before summing by service, matching the burn
ratio's reset handling and good/bad population. Prometheus extrapolates these
counts; this is a minimum estimated volume, not an exact integer event count.
Low-volume failures remain visible in the SLO dashboard and budget.

The budget percentages assume stationary request volume. The rules use actual
request-weighted fractions. Alerts may overlap; routing/deduplication is not
configured here. Labels include `service`, `slo`, `severity`, `long_window`
and `short_window`. Investigate the affected service's terminal failures and
recent releases; an alert grants no automatic rollout or scaling authority.

Zero traffic gives an undefined error fraction, not 100% availability and not
a burn alert. `ServiceSLOTelemetryMissing` fires when no request counter of any outcome has
samples in 5 minutes for a further 10 minutes, including a service that was
never instrumented. This detects fleet-wide absence, not one missing replica.
The production `ServiceReadinessFailed` alert independently probes public
endpoints, including dashboard readiness and its dependencies, and pages after
five minutes of sustained failure without any request-volume guard. It covers
a dashboard outage even when request counters remain scrapeable and traffic is
zero. Missing counters still trigger `ServiceSLOTelemetryMissing`.
Scrape/ingress health and expected-instance inventory are separate prerequisites.

The 30-day budget is `1 - bad_fraction / 0.001`, may be negative, and is not
clamped to hide exhaustion. Prometheus evaluates available samples during
startup; results are **provisional until the full window is observed**. Its
history must retain at least 30 days (35 days recommended). Gaps and missing
replicas can bias fractions; no-data is never evidence of health.

## Validate and enable in a follow-up slice

1. Verify service-owned instrumentation and all serving targets before loading
   rules. Confirm both zero-initialized outcomes, exclusions, replica identity,
   resets, streaming errors and loss of a target. Record the actual backend,
   storage decision and scrape inventory. Do not touch ts-ops/homelab
   hosts or re-found serving cells for this work.
2. Load `slo-rules.yml` using the existing Prometheus backend's `rule_files`,
   retaining at least 30 days. Verify its rules API reports no evaluation errors
   and each service has both outcome counters. No backend target is specified
   or mutated by this slice.
3. Import [slo-dashboard.json](slo-dashboard.json) in Grafana and select the
   Prometheus datasource. It shows objective, measured availability, remaining
   budget, requests, windowed burn rates and firing alerts. Confirm missing
   metrics display no data and never a green/100% default.
4. Observe real traffic and a controlled fixture failure; verify paired-window
   firing and recovery. Record evidence before declaring coverage active.
   Remove the rule-file entry and imported dashboard to revert the policy
   assets; service telemetry remains useful independently.
