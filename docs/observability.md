# Observability

`internal/observability` is the leaf slice for metrics, health, structured
logs, the in-memory event bus and cell-wide member snapshots. Everything it
serves is read-only and none of it is admission evidence.

## Configuration

Both the `run` (controller) and `host` roles read an optional
`observability` section. Its zero value is the default and is omitted from
canonical JSON, so configs signed before this section existed keep their
exact bytes.

```json
"observability": {
  "listen_address": "127.0.0.1:9464",
  "bearer_token_file": "/etc/terrascale-orchestrator/observability-token",
  "tls_cert_file": "",
  "tls_key_file": "",
  "log_format": "json",
  "log_level": "info",
  "cluster_aggregation": false,
  "dashboard": false
}
```

| Field | Default | Rule |
| --- | --- | --- |
| `listen_address` | `127.0.0.1:9464` | Literal `IP:port`. Loopback, RFC 1918/ULA private or NetBird CGNAT (`100.64.0.0/10`) only. `off` disables the listener. Wildcard, public, link-local and multicast addresses are rejected at config load. |
| `bearer_token_file` | none | Required for any non-loopback address. A private (`0600`) file holding one 32-4096 byte token. |
| `tls_cert_file`, `tls_key_file` | none | Optional pair; serves TLS 1.3. |
| `log_format` | `json` | `json` or `logfmt`. |
| `log_level` | `info` | `debug`, `info`, `warn` or `error`. |
| `cluster_aggregation` | `false` | Answer and issue `ts.orch.v1.<cell>.obs.snapshot`. See below. |
| `dashboard` | `false` | Serve the read-only operator dashboard on this listener. See below. |

A signed controller config may bind only loopback or its own signed broker
address, and any token or TLS file must live under
`/etc/terrascale-orchestrator/`.

A listener that cannot bind is logged and skipped; telemetry never stops a
controller from serving its region.

## Routes

| Route | Auth | Content |
| --- | --- | --- |
| `GET /healthz` | none | `ok` while the process answers. |
| `GET /readyz` | none | 200 when every check passes, else 503. Checks: `startup`, and on controllers `nats`, `cluster` (full replica count), `authority` (lease observed; leadership is a gauge, not a readiness gate). Details are fixed phrases. |
| `GET /metrics` | token | Prometheus text: `process_*`, `go_*` and `ts_orch_*`. |
| `GET /v1/snapshot[?metrics=1]` | token | This member's `MemberSnapshot` JSON. |
| `GET /v1/cluster[?metrics=1]` | token | Cell-wide `ClusterSnapshot` (only with `cluster_aggregation`). |
| `GET /v1/events?after=N&limit=M` | token | Recent events, oldest first. |

Requests carrying `Forwarded`, `X-Forwarded-For` or `X-Real-IP` are rejected,
as on the host enrollment listener.

## Metrics

| Family | Source |
| --- | --- |
| `ts_orch_build_info`, `ts_orch_ready`, `ts_orch_ready_check{check}` | collector |
| `ts_orch_authority_{leader,ready,can_mutate,epoch,revision,lease_expiry_timestamp_seconds}` | authority snapshot |
| `ts_orch_nats_*`, `ts_orch_js_meta_*`, `ts_orch_js_store_*`, `ts_orch_js_stream_*{stream}`, `ts_orch_js_consumer_*{stream,consumer}` | `natscell.Runtime.Observe` (in-process `Varz`/`Jsz`/`Routez`; the NATS HTTP monitor stays off) |
| `ts_orch_oci_requests_total{service,operation,code}`, `ts_orch_oci_request_duration_seconds`, `ts_orch_oci_throttled_total` | `oci` SDK dispatcher wrapper; operations are templated (`GET /instances/{id}`), never raw OCIDs |
| `ts_orch_reconcile_total{loop,result}`, `ts_orch_reconcile_duration_seconds`, `ts_orch_reconcile_last_success_timestamp_seconds` | placement controller |
| `ts_orch_terrabase_members{stage}`, `ts_orch_terrabase_replicas{database,partition,state}`, `ts_orch_rollout_progress_ratio` | `placement.Summarize` (first 64 partitions labeled) |
| `ts_orch_delivery_intents_total{result}`, `ts_orch_delivery_transport_retries_total` | delivery consumer |
| `ts_orch_host_*` | `/proc/stat`, `/proc/meminfo`, `/proc/pressure/*`, `statfs` on role mounts |
| `ts_orch_log_records_total{level}` | slog handler |

Scrape-time sections are cached for three seconds so scrapes, dashboard ticks
and snapshot requests do not repeatedly walk JetStream or `/proc`.

## Logs and events

The runtime installs one `slog` default handler tagged with `cell`, `member`
and `role`; stdlib `log` output goes through the same handler. Records at WARN
and above, and records carrying `"event", true`, are also published into a
2048-entry in-memory ring (`observability.EventBus`) that the dashboard lists
and streams. Feature slices tag records with `"component", "<slice>"`.

The event bus does not depend on `log_level`: an INFO record tagged as an
event, or a WARN record under `log_level: error`, still reaches the bus even
though the log output omits it. An event identical to one published in the
last five minutes (same level, component, message and attributes) is kept off
the bus, so a loop that logs the same warning every tick cannot push every
other event out of the ring; every such record is still written to the log.

## Cell-wide aggregation

With `cluster_aggregation`, each controller subscribes to
`ts.orch.v1.<cell>.obs.snapshot` and answers with its `MemberSnapshot`; any
member gathers all of them within one second and lists non-answering members
as missing. Only controllers may publish on that subject: operator
credentials have an exact publish list and host credentials publish only their
own observation subjects.

Production controller credentials do not yet carry the subscribe grant
`ts.orch.v1.<cell>.obs.>`. The credential validator accepts the grant but the
bootstrap issuer does not add it; adding it is a trust decision for the next
credential rotation. Until then leave `cluster_aggregation` off in production.

## Dashboard

`internal/dashboard` is a read-only operator dashboard served on the same
private listener as `/metrics` when `dashboard` is `true`. It is built with
templ (generated `*_templ.go` files are committed), Datastar and Pico CSS;
every asset is embedded in the binary and nothing is loaded from a CDN.

| Route | Content |
| --- | --- |
| `GET /` | Cluster overview: readiness, members answering and missing, authority lease, JetStream meta leader, partitions, collection errors, recent events. |
| `GET /members` | Controllers (role, build, uptime, lease, routes, CPU, load, memory, PSI) and the hosts that carry TerraBase seats. |
| `GET /nats` | Servers, meta group peers, streams and consumers. |
| `GET /oci` | OCI API calls per templated operation: errors, throttling, latency. |
| `GET /storage` | JetStream store usage and filesystem capacity per member. |
| `GET /terrabase` | Placement partitions, desired and serving seats, seat stages per host. |
| `GET /rollouts` | Managed runtime update progress and delivery intent counters. |
| `GET /events[?level=&component=]` | The event ring, newest first, filtered by minimum level and component. |
| `GET /<page>/stream` (`/overview/stream` for `/`) | Datastar SSE stream for the page. |
| `GET /assets/<hash>/<file>` | Embedded CSS and JS, content-addressed and cached as immutable. Unauthenticated: they hold no cell state. |
| `GET /login`, `POST /login`, `POST /logout` | Browser sign-in. |

Each page renders completely on the first request, so it is readable without
JavaScript. The page then opens its stream, which re-renders the page content
every two seconds and patches it only when the HTML changed; the events page
instead follows the event bus and prepends new rows. One listener serves at
most 16 concurrent streams. The cell-wide view is fetched at most once every
two seconds whatever the number of open pages. A missing or failing provider
renders as a short note; raw upstream error text is never shown.

Access control follows the listener:

- With `bearer_token_file`, every page and stream requires either the
  `Authorization: Bearer` header or a session cookie. `POST /login` exchanges
  the token for a session cookie (`HttpOnly`, `SameSite=Strict`, `Secure` with
  TLS) valid for 12 hours. The cookie is MACed with a random per-process key,
  so a restart signs every browser out, and it grants exactly the read-only
  access of the token. Login and logout refuse cross-site form posts
  (`Sec-Fetch-Site`, `Origin`). A browser navigation without credentials is
  redirected to `/login`; other clients get `401`.
- Without a token the listener is loopback only (enforced at config load
  and in `Start`), and the dashboard additionally refuses any `Host` header
  that is not an IP literal or `localhost`, so a web page cannot reach it
  through DNS rebinding.

Session cookies are accepted only when `dashboard` is on; otherwise the
listener accepts the bearer header alone, exactly as before. Responses carry
a `Content-Security-Policy` of `'self'` only (plus `'unsafe-eval'` for
Datastar expressions), `X-Frame-Options: DENY` and `no-store`.

Regenerate templates with `make generate`; `make generate-check` (part of
`verify` and `ci-verify`) fails when a committed `*_templ.go` file is stale.

## Dashboard contract

A dashboard consumes these interfaces only (`internal/observability/providers.go`):
`SnapshotSource` (`*Collector`), `ClusterSource` (`*Aggregator`),
`EventSource` (`*EventBus`) and `ReadinessSource` (`*Health`). Additional
read-only routes mount on the same listener with `Server.Handle`, which applies
the bearer token (or a dashboard session); `Server.HandleStatic` is only for
public embedded files.
