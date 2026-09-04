# NATS monitoring observability snapshot

Status: adapter evidence for the Orchestrator messaging observability contract.
Subject tokens name the mandatory `ts.orch.v2` control root selected by the
repository `GOAL.md`; the checked-in adapter serves this root.
Everything below is generated from the typed catalog
(`NatsMonitoringInstrumentCatalog`, `NatsAlertCatalog`) — the single source of
truth the tests assert against. Production dashboards/alerting remain a separate,
approved operation (issue external effects clause).

**Dormancy note (composition root):** the monitoring runtime
(`NatsMonitoringRuntime`) is an adapter library surface. The composition root
does **not** start it yet — wiring it needs an operator-supplied monitoring
endpoint and credential provisioning decision that this ticket deliberately does
not invent. The service-endpoint statistics endpoint and the process telemetry
instruments are live today; the `$SYS` observer becomes live when the composition
root gains that configuration surface.

## Scope and identity model

- One read-only monitoring identity (`system-monitor`) in the `system` account of
  each cluster. Its permission plan is `NatsMonitoringPermissions.Create()`:
  publish exactly the six `$SYS.REQ.SERVER.PING.*` request subjects; subscribe
  exactly `$SYS.ACCOUNT.*.ADVISORY.>`, `$SYS.JETSTREAM.ADVISORY.>`, `_INBOX.>`.
- The plan validates itself at construction: any grant outside the read-only
  request subjects or the advisory/inbox subscriptions is rejected, so a hostile
  grant cannot be passed through the plan verbatim.
- The plan cannot publish control work, mutate JetStream, read KV/object secret
  or journal material, or reach any product-plane subject — proven in
  `NatsMonitoringPermissionsTests` (pure, hostile-grant construction included)
  and `NatsGatewayR1MonitoringTests.Monitoring_identity_is_denied_...` (real
  server, no-reply denial evidence bracketed by positive-delivery and
  positive-request controls).
- Supervision is one-directional: any observation failure — transport, timeout,
  or an unexpected fault from a hostile reply — degrades availability truthfully
  and is retried; no supervision state can delay, gate, or fail regional control
  (`NatsMonitoringSupervisionTests`, `NatsMonitoringRuntimeRoundTests`). A cold
  observer (no successful round yet) reports degraded, never available.

## Instruments

Units, bounded label keys, source subjects, and failure behavior per instrument:

| Instrument | Unit | Labels | Source | Failure behavior |
| --- | --- | --- | --- | --- |
| `terrascale.orchestrator.nats.service.requests` | `{request}` | service, endpoint, result | local service endpoints | absent until first request |
| `terrascale.orchestrator.nats.service.errors` | `{error}` | service, endpoint, result | local service endpoints | absent until first error |
| `terrascale.orchestrator.nats.service.request.duration` | `ms` | service, endpoint, result | local service endpoints | absent until first request; p50/p95/p99 also on the stats endpoint |
| `terrascale.orchestrator.nats.client.reconnects` | `{reconnect}` | cell, plane | CONNZ | holds last value while degraded; disappears when unavailable |
| `terrascale.orchestrator.nats.connections` | `{connection}` | cell, plane | CONNZ | holds last value while degraded |
| `terrascale.orchestrator.nats.routes` | `{route}` | cell, plane | ROUTEZ | holds last value while degraded |
| `terrascale.orchestrator.nats.gateways` | `{gateway}` | cell, plane, state | GATEWAYZ | connected/disconnected keep updating |
| `terrascale.orchestrator.nats.accounts` | `{account}` | cell, plane | ACCOUNTZ | holds last value while degraded |
| `terrascale.orchestrator.nats.jetstream.domains` | `{domain}` | cell, plane | JSZ | holds last value while degraded |
| `terrascale.orchestrator.nats.streams` | `{stream}` | cell, plane, stream_class | JSZ detail | per-class disappears when its class stops reporting |
| `terrascale.orchestrator.nats.consumers` | `{consumer}` | cell, plane, stream_class, consumer_class | JSZ detail | per-class disappears when its class stops reporting |
| `terrascale.orchestrator.nats.consumer.lag` | `{message}` | cell, plane, stream_class, consumer_class | JSZ detail | never fabricates zero lag |
| `terrascale.orchestrator.nats.consumer.redelivered` | `{message}` | cell, plane, stream_class, consumer_class | JSZ detail | never reset by a monitoring restart |
| `terrascale.orchestrator.nats.consumer.ack_pending` | `{message}` | cell, plane, stream_class, consumer_class | JSZ detail | holds last value while degraded |
| `terrascale.orchestrator.nats.flowcontrol.waiting` | `{consumer}` | cell, plane, stream_class, consumer_class | JSZ detail | stale gauge is unknown, not zero |
| `terrascale.orchestrator.nats.messages` | `{message}` | cell, plane, stream_class, consumer_class, result | JSZ detail deltas | observation gap pauses the counter without backfill |
| `terrascale.orchestrator.nats.stream.bytes` | `By` | cell, plane, stream_class | JSZ detail | per-class disappears when its class stops reporting |
| `terrascale.orchestrator.nats.stream.duplicates` | `{message}` | cell, plane, stream_class | application dedup | absent when no deduplication ran |
| `terrascale.orchestrator.nats.kv.watches` | `{watch}` | cell, plane, store_class | JSZ detail | holds last value while degraded |
| `terrascale.orchestrator.nats.objectstore.objects` | `{object}` | cell, plane, store_class | JSZ detail | holds last value while degraded |
| `terrascale.orchestrator.nats.objectstore.bytes` | `By` | cell, plane, store_class | JSZ detail | holds last value while degraded |
| `terrascale.orchestrator.nats.server.memory` | `By` | cell, plane | VARZ | holds last value while degraded |
| `terrascale.orchestrator.nats.storage.bytes` | `By` | cell, plane | VARZ, JSZ | holds last value while degraded |
| `terrascale.orchestrator.nats.partition.duration` | `ms` | cell, plane | GATEWAYZ | grows while fully disconnected; resets on recovery |
| `terrascale.orchestrator.nats.recovery.duration` | `ms` | cell, plane | GATEWAYZ | holds last completed recovery duration |
| `terrascale.orchestrator.nats.certificate.expiry.days` | `d` | cell, plane, certificate_class | local credentials | missing certificates absent, not zero |
| `terrascale.orchestrator.nats.monitoring.availability` | `{boolean}` | cell, plane, condition | supervision | the one signal guaranteed to exist (1/0/-1) |
| `terrascale.orchestrator.nats.mesh.cells` | `{cell}` | cell, plane, state | directory + membership + GATEWAYZ | never fabricates health |
| `terrascale.orchestrator.nats.advisories` | `{advisory}` | cell, plane, result | advisory subscriptions | advisory loss pauses the counter and degrades availability |

Label value domains are closed enumerations (plane, cluster role, stream class,
consumer class, store class, certificate class, result, state, condition,
endpoint) plus bounded cell tokens; every value is ≤ 63 characters — the cap
matches the canonical DNS-style cell rule, the longest legal value any label can
carry. Instance, session, NKey, message, and operation identifiers are not
representable as label keys (`NatsMonitoringLabels.ForbiddenKeyFragments`).
Rendered Prometheus label values escape the three exposition-format-critical
characters (backslash, double quote, newline), so no label value can forge
another metric line.

## Mesh census semantics (deliberate)

The per-cell gateway census (`terrascale.orchestrator.nats.gateways`) aggregates
every responding cluster's outbound link map per round. Two deliberate
semantics:

- **Per-round census.** The responding-cluster map is cleared at the start of
  every observation round, so a cluster that stops answering loses its previous
  map immediately instead of keeping a severed cell "connected" forever.
- **Zero-evidence disconnect.** For a cell with neither a live link report nor
  any response — no evidence at all — the disconnected count is reported as
  `expected cells − 1` rather than zero. Reporting zero connected and zero
  disconnected would read as "empty topology"; the fabricated floor makes
  "no evidence" render as the partition signal it is. Cells with any evidence
  report exactly the observed counts.

## Input bounding and failure containment

- Every `$SYS` reply is refused before parsing beyond 4 MiB
  (`NatsMonitoringParsers.MaximumReplyBytes`): an oversized reply is a hostile
  shape, not a census.
- Parsers are fail-closed end to end: a hostile value (negative counters,
  overflowed per-class merges) becomes a null observation — a shape mismatch the
  supervisor counts — never an exception into the observation loop. The per-class
  consumer merge is revalidated after summation for exactly this reason.
- Round failure diagnostics (`LastRoundError`) carry the exception type and a
  redacted, length-bounded message through the same `NatsMonitoringRedaction`
  boundary production output uses; raw exception text never survives it.

## Grafana/Prometheus-facing output

`NatsMonitoringSnapshot.From(aggregate)` projects the bounded aggregate into
typed snapshot entries; `RenderPrometheus()` renders the same entries as
Prometheus text exposition with unit/source/failure comments per metric family.
Unavailable monitoring emits exactly one entry — its availability — and never
zero-fills series.

## Alert rules

`NatsAlertCatalog` — each rule names its instruments, a canonical failure state,
an explicit recovery condition, and a runbook:

- `nats.gateway.partition` (critical): partition duration > 30s with disconnected
  mesh state; recovers when links reconnect and mesh returns healthy/stale.
- `nats.gateway.recovery.slow` (warning): recovery exceeds 30s after links
  report connected.
- `nats.consumer.lag` (warning): lag > 1000 for 2 minutes per class.
- `nats.consumer.redelivery.storm` (warning): redelivery deltas dominate deliveries.
- `nats.flowcontrol.pressure` (warning): waiting > 0 for 5 minutes.
- `nats.storage.pressure` (warning): storage > 80% of the declared limit.
- `nats.server.memory.pressure` (warning): memory > 80% of the container limit.
- `nats.certificate.expiry.risk` (critical): remaining days < 30.
- `nats.advisory.slow.consumer` (warning): slow-consumer advisories increasing.
- `nats.advisory.leader.change` (critical): leader change plus degraded mesh.
- `nats.mesh.conflicting` (critical): conflicting controller sessions.
- `nats.monitoring.unavailable` (warning): observability blind for 2 minutes.

## Service endpoint statistics

The regional control service exposes a read-only `stats` endpoint
(`ts.orch.v2.<cell>.query.stats`) serving `NatsServiceStatsDocument`: service
name, build version, status-contract schema generation, health, and per-endpoint
request/error counts with p50/p95/p99/max latency over a bounded 256-sample
reservoir per endpoint. Endpoint names are the closed enumeration
(health, instance_health, status, members, stats, direct_delivery); no subject,
requester, or payload dimension exists.

## Evidence

- Pure: `NatsMonitoringObservationTests` (parser shapes, hostile-value fail-closed
  behavior, oversized-reply refusal, mesh states), `NatsMonitoringPermissionsTests`
  (allowlist minimality, hostile-grant rejection, redaction),
  `NatsMonitoringSupervisionTests` (availability truthfulness, cold-monitor
  semantics), `NatsMonitoringRuntimeRoundTests` (round failure degrades-and-retries,
  sanitized diagnostics), `NatsMonitoringInstrumentTests` (bounded cardinality,
  escaping), `NatsServiceEndpointStatsTests`, `GlobalCellDirectoryContractTests`.
- Real NATS (RF1 fixture lane): `NatsGatewayR1MonitoringTests` — representative
  observations, gateway partition/recovery, no-reply denial evidence bracketed by
  positive-delivery and positive-request controls, and fast-fail monitoring
  unavailability with the control plane serving.
- RF1 evidence is regional-development evidence only, never production
  R3/quorum evidence.
