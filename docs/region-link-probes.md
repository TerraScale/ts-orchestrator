# Continuous regional link probes

Each controller requests every other known region's existing authenticated
`ts.orch.v1.<region>.obs.region` service at startup and every minute, independent
of dashboard traffic. Requests bypass the dashboard cache and retain the
existing JWT permissions, mTLS leaf transport, reply validation and deadlines.
The region page shows its outgoing results, latency, WAN condition and the last
repair attempt. A result more than two minutes old becomes stale.

The host agent scrapes the loopback native TerraBase `/metrics` endpoint only
while the same verified process is running. Its authenticated host report and
regional shared history retain the original scrape timestamp and exact native
region identities. No extra environment setting or peer mapping is required.
The source's existing signed `TERRABASE_REGION` identity selects the destination's
incoming WAN measurements; region suffixes are never guessed.

WAN health requires fresh, coherent observations from every granted TerraBase
receiver, with the expected source membership. Missing, stale, partial replay,
incomplete topology or zero-membership evidence stays unknown. Lag is measured
in change groups. Conflicts, new ahead failures and caught-up staleness above
one minute fail the probe. Persistent authenticated-request or explicit WAN
failures appear as critical dashboard insights with separate duration timers.
Normal replication backlog and unknown WAN evidence remain visible in the link
table. Catalog regions without an authenticated link retain `not_linked`; they
do not report a failed request or raise an outage insight.

Explicit authenticated-request failures on admitted links and failed WAN
observations reconnect this broker's authenticated link leaves. TS-803 links
bind the regional cell account.
Attempts sharing the same transport are coalesced with a five-minute retry
bound. Native NATS reconnect/failover remains responsible for redialing; regional
routes, clients and JetStream state remain running. With no connected leaves,
native retries continue and the attempted repair remains failed. Disconnecting
leaves can briefly interrupt cross-region traffic on their shared transport.
No NATS gateway is configured in the current transport.

The decision journal records failure, reconnect attempt and recovery separately.
Neither a reconnect count nor missing telemetry establishes recovery: a new
authenticated reply with complete healthy WAN evidence is required. Metrics
expose probe timestamp, request success/duration, WAN observation/health and
group lag under `ts_orch_region_*` with peer and controller member labels.

`GET /v1/link-health` on the public Machines API exposes only regional health:
the expected/missing controller roster and each answering controller's minute
probe states, WAN lag in change groups and original observation times. It uses
the existing authenticated local snapshot scatter-gather, bounded to two seconds,
and shares each result for three seconds. It never probes remote regions or
repairs a link on an HTTP request. The response excludes private addresses,
credentials, metrics, operational details and journal entries. `/healthz` and
readiness retain their existing meaning; cross-region failure does not withdraw
a regional load balancer backend.

A 200 is evidence availability, not healthy connectivity. A consumer must check
every expected controller and every admitted destination discovered through
Atlas, retaining each original probe time. Repeated HTTP polls cannot renew old
evidence. Probe times record when WAN was assessed; original WAN scrape times
are not exposed by this endpoint. Missing controllers, absent probes and
observations older than two minutes are monitoring loss; `not_linked`, unknown
WAN and normal backlog do not prove a measured outage. TLS authenticates the
discovered public origin; no controller report token or manually copied Worker
secret is required.

This endpoint is the producer contract. ts-status consumption, independent expiry
and automatic incidents remain the next slice. Credential renewal needs TS-803's
issuing authority to publish and sign a successor, then the existing privileged
installer to adopt it in place; refetching expired Vault bytes is insufficient.
Live GRU/SJC acceptance waits
for TS-803's completed linking and qualified deployment handoff.
