# Edge latency

The edge shares one socket budget across local HTTP/1.1, h2c, peer TLS and
regional upstream transports: 16,384 active, idle or establishing connections
in total, with at most 8,192 to one task address across those transports.
Together with C18's 32,768 accepted HTTP client connections, this accounts for
49,152 of the production 65,536 descriptors and leaves 16,384 for listeners,
NATS, PostgreSQL and other node work. Budget exhaustion returns 503 with
`upstream_node` or `upstream_task`; closing a connection releases its share.

Each transport keeps at most 128 idle connections per task, matching C18's
per-source connection allowance, and at most 4,096 idle connections overall.
The shared budget still applies to every retained socket across transports.
Connections grow on demand, use HTTP keep-alive and expire after 90 idle
seconds. The HTTP/2 cleartext transport for gRPC shares the same accounting.
HTTP/1.1 retains its 30-second response-header deadline. Per-source limits,
upload deadlines, replay budgets and streaming limits are unchanged.

A ready local service whose port is not held for handoff wins before peer
selection in `peerCandidates`. Peer balancing is reached only when the local
replica cannot serve the request. TerraBase's fenced regional-writer routing
remains authoritative for database writes.

## Duration metrics

The existing host metrics endpoint on the node's NetBird address, port 9108,
exports `ts_orch_edge_request_duration_seconds` as a Prometheus histogram with
`name`, `region` and `stage` labels. Only names in the edge's served HTTP route
inventory allocate series; unknown client Host values never become labels.
Removed names disappear on the next scrape. A name retired across a scrape
starts fresh counters if it is re-added. The same endpoint exports
`ts_orch_edge_client_connections` for accepted active and idle client sockets,
`ts_orch_edge_upstream_connections` (including establishing connections) and
`ts_orch_edge_upstream_connection_limit` for the shared budget. Before mesh admission, region is
`local`; admitted nodes use their discovered mesh region.

Every completed HTTP handler records both `stage="total"` and
`stage="upstream"`. Total covers handler entry through response copying.
Upstream sums transport calls (including connection acquisition and headers)
and response-body reads; nested local forwarding is counted once. Replay to
another region after response headers is measured as upstream as well.
Requests handled entirely by the edge record zero upstream time. Both stages
use identical buckets from 100 microseconds through 30 seconds and +Inf.

Average edge time, including response-copy work and client backpressure, is:

```promql
(
  sum by (name, region) (rate(ts_orch_edge_request_duration_seconds_sum{stage="total"}[5m]))
- sum by (name, region) (rate(ts_orch_edge_request_duration_seconds_sum{stage="upstream"}[5m]))
)
/
sum by (name, region) (rate(ts_orch_edge_request_duration_seconds_count{stage="total"}[5m]))
```

Subtract sums or averages over matching requests, never histogram quantiles.
TLS handshake and client-to-edge round trips happen before handler entry and
are excluded. Long streams are observed when their handler finishes.
For hijacked WebSockets, total follows the proxy lifetime and upstream includes
upstream reads; concurrent client writes are not upstream time.

## Production slowdown alert

The production monitoring renderer reads `deploy/observability/production/latency-budgets.json` and generates
`EdgeLatencyBudgetExceeded` for every HTTP name in every discovered region.
It aggregates the total-stage buckets across hosts by `name`, `region` and
`le`, computes p95 over fifteen minutes, and requires an over-budget result
for another fifteen minutes. The critical alert retains `name` and `region`
and uses the existing Alertmanager relay route. No outside production
requests are added. Handler p95 includes long streams; inspect upstream time
and request mix before interpreting it as connection latency. PostgreSQL
is not covered by this HTTP histogram alert.

Before enabling the rules, evaluate both the p95 expression and its budget
comparison against current Prometheus data, retaining the nonempty baseline
and empty comparison as evidence. For the initial common edge limit:

```promql
histogram_quantile(0.95,
  sum by (name, region, le) (
    rate(ts_orch_edge_request_duration_seconds_bucket{stage="total"}[15m])
  )
) > 0.1
```

On 2026-11-16 the existing gru production Prometheus returned an empty
vector even without the comparison: no histogram baseline was available.
That is missing telemetry, not proof of healthy latency. Deploy C20's
histogram and activate C3's scrape coverage, then collect representative
per-name/per-region p95 values and recalibrate the table before approval.
No live alert installation or healthy-fleet proof is claimed by this draft.

## TLS and drain

Public TLS offers h2 and HTTP/1.1. Certificate selection reads the in-memory
certificate cache; background reconciliation does disk and ACME work.
Go's automatic session tickets resume TLS 1.2 and TLS 1.3 reconnects to the
same running listener, with automatic in-process key rotation. Tickets are
not persisted or shared across nodes; a different node or process performs
a fresh handshake. No new shared ticket secret is introduced.

Drain first withdraws readiness and advertised services. When an external
health checker probed in the last minute, listeners keep accepting and serving
requests for the existing 20-second health-propagation grace, measured from
readiness withdrawal. This covers the NLB's 10-second probe interval, 5-second
timeout and one failed probe. After propagation, listeners close admission
and HTTP servers use `Shutdown` to finish active handlers and close idle
keep-alive connections. Hijacked WebSockets retain their existing lifecycle.

## Proof lane

The existing `e2e-m1 / edge-limits` lane builds the edge from `origin/main`
with Go's overlay mechanism and from the PR against the same backend and CA.
The overlay uses main's edge and observability sources without injecting PR
fields, wrappers or instrumentation. Both builds use their own duration
histograms, transport and drain behavior.
For each it reports three sets of 100 fresh and 100 kept-alive first-byte
samples, TLS 1.2/1.3 resumption and h2 negotiation, and the upstream connection
count in the second 16-request burst. The PR must reuse the warm pool without
opening connections and reports histogram total, upstream and edge time.
It also holds an in-flight response across drain, checks readiness returns 503
while fresh HTTPS requests still succeed, waits for shutdown after the real
20-second propagation interval, then checks HTTPS admission has stopped and
the held response finishes successfully.

The same lane runs `edge-upstream.py` against an edge child with the production
65,536 descriptor limit. Clients and backends run outside the edge process. Dedicated Go HTTP/2 load
processes keep 128 requests on each explicitly owned connection, so TLS work
cannot starve the Python backend event loop and the client population stays
fixed during measurement. It warms one task with 512 concurrent requests, confirms 128 idle
connections remain, then drives two busy tasks to the shared 16,384 connection
budget. It fills one task with 8,192 HTTP/1.1 sockets and checks a concurrent h2c
request to that task returns 503, then checks node overload responses and descriptor
headroom with accepted client connections padded to 32,640. Parked clients
complete HTTP requests first and then remain idle on keep-alive connections;
they do not expire under the request-header deadline.
The snapshot contains 16,256 active plus 128 idle upstream sockets; all active
responses must finish successfully after release.
