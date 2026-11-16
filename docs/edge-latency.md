# Edge latency

The loopback HTTP transport shares a pool across routed names. It keeps up to
32,768 idle connections overall and per task, matching C18's per-node public
connection limit (65,536 descriptors split between clients and upstreams).
Connections are created on demand, use HTTP keep-alive, and expire after 90
idle seconds. The HTTP/2 cleartext transport for gRPC inherits these values;
HTTP/1.1 keeps its existing 30-second response-header deadline. Per-source
limits, upload deadlines, replay budgets and streaming limits are unchanged.

A ready local service whose port is not held for handoff wins before peer
selection in `peerCandidates`. Peer balancing is reached only when the local
replica cannot serve the request. TerraBase's fenced regional-writer routing
remains authoritative for database writes.

## Duration metrics

The existing host metrics endpoint on the node's NetBird address, port 9108,
exports `ts_orch_edge_request_duration_seconds` as a Prometheus histogram with
`name`, `region` and `stage` labels. Only names in the edge's served HTTP route
inventory allocate series; unknown client Host values never become labels.
Removed names disappear on the next scrape. Before mesh admission, region is
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

## TLS and drain

Public TLS offers h2 and HTTP/1.1. Certificate selection reads the in-memory
certificate cache; background reconciliation does disk and ACME work.
Go's automatic session tickets resume TLS 1.2 and TLS 1.3 reconnects to the
same running listener, with automatic in-process key rotation. Tickets are
not persisted or shared across nodes; a different node or process performs
a fresh handshake. No new shared ticket secret is introduced.

Drain disables HTTP keep-alive and closes the HTTPS accept socket before
withdrawing readiness and advertised services. The server then waits for
active HTTP handlers with `Shutdown`, including long streams. HTTP port 80
remains available for load-balancer probes during the existing health-check
grace period and returns 503 for health/readiness. It then shuts down
gracefully too. Hijacked WebSockets retain their existing lifecycle.

## Proof lane

The existing `e2e-m1 / edge-limits` lane builds the edge from `origin/main`
with Go's overlay mechanism and from the PR against the same backend and CA.
The baseline receives the same duration instrumentation, retaining main's
transport and drain behavior, so both builds expose comparable overhead.
For each it reports three sets of 100 fresh and 100 kept-alive first-byte
samples, TLS 1.2/1.3 resumption and h2 negotiation, and the upstream connection
count in the second 16-request burst. The PR must reuse the warm pool without
opening connections and reports histogram total, upstream and edge time.
It also holds an in-flight response across drain, checks the HTTPS accept
socket has closed before HTTP health returns 503, then checks the response
finishes successfully.
