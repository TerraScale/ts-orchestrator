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
observations reconnect this broker's leaves in its pinned interregion account.
Attempts sharing the same transport are coalesced with a five-minute retry
bound. Native NATS reconnect/failover remains responsible for redialing; regional
routes, clients and JetStream state remain running. With no connected leaves,
native retries continue and the attempted repair remains failed. Disconnecting
leaves can briefly interrupt traffic on their shared interregion account.
No NATS gateway is configured in the current transport.

The decision journal records failure, reconnect attempt and recovery separately.
Neither a reconnect count nor missing telemetry establishes recovery: a new
authenticated reply with complete healthy WAN evidence is required. Metrics
expose probe timestamp, request success/duration, WAN observation/health and
group lag under `ts_orch_region_*` with peer and controller member labels.

This slice does not provide automatic expired-credential issuance or ts-status
incident delivery. Credential renewal needs the issuing authority to publish and
sign a successor, then the existing privileged installer to adopt it in place;
refetching expired Vault bytes is insufficient. ts-status needs an authenticated
heartbeat consumer with independent freshness expiry. Live GRU/SFO acceptance
still waits for TS-774's completed rotation and qualified deployment handoff.
