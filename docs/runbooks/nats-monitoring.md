# NATS monitoring runbook

> Applies only to the current optional Orchestrator NATS control adapter. NATS
> health is not database health. TerraBase causal lag, replication, repair,
> reactive sync, and usage require engine-owned signals.

Operator procedures for the NATS monitoring observability contract: the
bounded instruments in `NatsMonitoringInstrumentCatalog`, the alert rules in
`NatsAlertCatalog`, and the read-only monitoring identity's permission plan in
`NatsMonitoringPermissions`. Every alert condition, state, and remediation below is
the exact descriptor the catalog produces; when this document and a live signal
disagree, the signal wins.

Two boundaries frame everything below:

1. **Monitoring is read-only by construction.** The identity publishes exactly the
   six `$SYS.REQ.SERVER.PING.*` request subjects and subscribes only to the two
   advisory families plus its inbox. It cannot publish control work, mutate
   JetStream, read KV/object journal or secret material, or reach the product
   plane. There is no operator action that can widen this without a code change.
2. **Monitoring loss never harms control.** Advisory loss or observer death
   degrades observability truthfully — `available`, `degraded`, then
   `unavailable` — while regional control keeps running. No remediation below
   should ever gate or restart a control plane component to fix a metric.

## Reading the truthfulness signal first

`terrascale.orchestrator.nats.monitoring.availability` (labels
`terrascale.cell`, `plane`, `condition`) is the one signal guaranteed to exist:

- `available` — the observer completed a round within the last 30 s with no
  failures between rounds.
- `degraded` — observations are aging (30 s–2 min old) or one round failed; the
  other gauges hold their last observed values. Degrade is expected during
  fixture/server restarts and brief network blips.
- `unavailable` — no successful observation for 2 minutes or more. Series other
  than availability itself are withdrawn rather than zero-filled: a gap in a
  gauge means "unknown", never "zero".

A cold observer (started, no successful round yet) reports `degraded`, never
`available` — treat a freshly restarted monitor's first minute as
not-yet-trusted. The failure description is exposed sanitized
(`NatsMonitoringRuntime.LastRoundError` in diagnostics; exception type plus
redacted, length-bounded message) and never carries credentials.

## Alert conditions and operator actions

Each rule below names its instruments, the canonical failure state that fires it,
the recovery condition that clears it, and the action.

### `nats.gateway.partition` (critical)

Fires when: `partition.duration` > 0 for more than 30 s and `mesh.cells{state="disconnected"}`
shows the cell. Recovery: links reconnect and mesh state returns healthy or stale.

1. Confirm the partition is real from a second observer if available (the mesh
   census aggregates every responding cluster; a cell that stops answering
   GATEWAYZ reports disconnected from its peers' side).
2. Check the isolated region's local control is still serving — it should be;
   regional autonomy is the designed behavior during a gateway fault. Do not
   restart control components to fix the metric.
3. Inspect the gateway network path for the isolated cell (host/network level);
   follow `runbooks/nats-gateway-operations.md` for link-level remediation.
4. After links return, `recovery.duration` reports how long the partition
   lasted; if it exceeds 30 s after connectivity returned, that is
   `nats.gateway.recovery.slow` — investigate reconnect backoff before assuming
   automatic healing.

### `nats.mesh.conflicting` (critical)

Fires when: `mesh.cells{state="conflicting"}` is non-zero — a cell's live
membership reports conflicting controller sessions.

1. This is a control-plane signal surfaced through monitoring, not a monitoring
   fault. A conflict clears when the surviving session's next renewal replaces
   the classified predecessor (the T-21 semantics).
2. If it persists past two renewal intervals (~10 s) plus the semantic lease
   (20 s), investigate the cell's controller set directly; do not act through
   the monitoring identity (it has no write surface).

### `nats.consumer.lag` (warning)

Fires when: `consumer.lag` > 1000 messages for 2 minutes on any stream/consumer
class. Recovery: lag < 100 for 5 minutes.

1. Identify the class pair from the labels (`stream_class`, `consumer_class`);
   the classifier is total, so `unknown` means an unexpected durable name — treat
   an `unknown` class appearing as its own signal (new consumer shape deployed
   without a classification update).
2. Check whether the consumer's controller process is running and acknowledging;
   lag with rising `ack_pending` points at a stalled consumer, lag alone at a
   burst.

### `nats.consumer.redelivery.storm` (warning)

Fires when: `redelivered` deltas outpace `messages{result="delivered"}` for 5
minutes. Recovery: redelivery delta zero for 5 minutes.

1. Redelivery storms usually mean acks are being lost or arriving after
   `AckWait`. Check the consumer's ack path and the controller's processing
   latency.

### `nats.flowcontrol.pressure` (warning)

Fires when: `flowcontrol.waiting` > 0 for 5 minutes on any class. Recovery:
waiting == 0 for 5 minutes.

1. Consumers holding the stream back via flow control are slow by definition —
   same triage as lag, but the pressure is on the stream side. A stale gauge
   (monitoring degraded) is unknown, not zero: never treat a monitoring gap as
   "pressure resolved".

### `nats.storage.pressure` (warning) / `nats.server.memory.pressure` (warning)

Fires when: `storage.bytes` (or `server.memory`) exceeds 80% of the
topology-declared limit for 10 minutes. Recovery: below 70%.

1. Compare against the declared stream `MaxBytes`/server limits from the
   topology, not against host capacity.
2. Storage growth in `stream.bytes{stream_class=...}` identifies which class is
   consuming; retention policy is a per-stream owner decision, not a monitoring
   action.

### `nats.certificate.expiry.risk` (critical)

Fires when: `certificate.expiry.days` < 30 for any `certificate_class`.
Recovery: rotation raises remaining days above 30.

1. Rotate the expiring certificate through the normal rotation procedure for its
   class (`server_listener`, `gateway_link`, or `monitoring_client`). A missing
   certificate is absent from the metric, not zero — absence after a rotation
   means the observer lost its credential, which is its own availability issue.

### `nats.advisory.slow.consumer` (warning) / `nats.advisory.leader.change` (critical)

Fires when: `advisories{result="slowconsumer"}` (or `leaderchange`) increases.
Recovery: no new advisories for 15 minutes (slow consumer) or mesh returns
healthy with a stable leader (leader change).

1. Slow-consumer advisories point at a subscription not draining — usually the
   same consumers as the lag alert.
2. Leader change alone is normal during maintenance; leader change with degraded
   mesh is the quorum-loss signal — treat as the gateway-partition procedure
   above plus JetStream meta-layer inspection.

### `nats.monitoring.unavailable` (warning)

Fires when: availability `condition="unavailable"` for 2 minutes. Recovery:
condition returns to `available`.

1. Check the observer's process and its connection to the pinned server. The
   observer fails fast on a dead endpoint and never retries in a storm; a
   persistent unavailable means the endpoint or identity is broken, not a
   transient.
2. While blind, assume nothing about the gauges: the withdrawn series mean
   unknown. Confirm control-plane health through the controller status/members
   service endpoints, which do not depend on the monitoring identity.

## What the metrics can never tell you

By design, no monitoring output carries connection identities, stream or
consumer names, session or NKey identifiers, message IDs, customer payloads, or
credentials. If an investigation needs one of those, use the owning control-plane
surface (status/members service endpoints, journal records) — never attempt to
widen the monitoring permission plan to obtain it.
