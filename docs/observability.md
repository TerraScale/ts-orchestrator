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
  "listen_address": "127.0.0.1:9463",
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
| `listen_address` | `127.0.0.1:9463` | Literal `IP:port`. Not 9464: a TerraBase member's loopback admin listener uses it on the same host. Loopback or RFC 1918/ULA private only; NetBird addresses (`10.200.0.0/16`) are private. CGNAT (`100.64.0.0/10`) is rejected. `off` disables the listener. Wildcard, public, link-local and multicast addresses are rejected at config load. |
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

Closed-beta service availability policy, multi-window burn-rate rules and an
importable Grafana dashboard live in
[deploy/observability/slo.md](../deploy/observability/slo.md). These are policy
assets; service request telemetry and a verified monitoring backend are
prerequisites before claiming production SLO coverage.

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
| `ts_orch_host_clock_{synchronized,offset_seconds,max_error_seconds}` | read-only `adjtimex`: the kernel state the time daemon sets (see [clock sync](#clock-sync)) |
| `ts_orch_log_records_total{level}` | slog handler |
| `ts_orch_credential_expiry_timestamp_seconds{name,kind}` | controllers: `maintenance.Scan` over every configured certificate and NATS JWT file (see [self-healing](self-healing.md)) |

Scrape-time sections are cached for three seconds so scrapes, dashboard ticks
and snapshot requests do not repeatedly walk JetStream or `/proc`.

### Clock sync

TerraBase refuses remote HLC stamps more than 1 s ahead, and its leases
assume bounded drift (TS-642). Every node syncs to the OCI NTP service at
169.254.169.254: the signed host image installs
`/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf` (polling every
32–64 s), and the bootstrap and controller units require
`systemd-timesyncd` and `systemd-time-wait-sync` (see [releases](releases.md)).
The controller also refuses broker effects while the kernel's error bound
exceeds 250 ms.

The `clock_skew` insight reads each member's error bound, the larger of the
kernel's maximum error and the last measured offset. It warns above 100 ms,
turns critical above 500 ms, and turns critical when the kernel reports the
clock unsynchronized. The bound grows by 500 µs/s while no NTP sample
arrives, so a node that silently lost its server warns after about 3 minutes
and turns critical after about 16. A daemon that polls less often than every
~3 minutes (chrony's default `maxpoll 10`) would raise false warnings; keep
the poll interval near 64 s if the daemon changes. Insights show on the
dashboard; no channel pushes them to a person yet (TS-625, ntfy).

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

### Log scan

`scripts/log-scan.sh` counts the WARN and ERROR records of the last 20
minutes per service and node, then lists the most frequent classes (TS-661).
Run it from any operator device in the NetBird with `~/.oci/config`; it picks
the host's NetBird client and calls `ts-orch log-scan`:

```sh
nice -n 19 scripts/log-scan.sh                # last 20 minutes
nice -n 19 scripts/log-scan.sh --since 24h --top 30
```

It reads each node's `terrascale-orchestrator*` units over `ts-orch netbird
ssh`: the controller, the host agent, embedded NATS (`[WRN]`, `[ERR]`) and
the TerraBase and ts-auth members (`warn:`, `fail:`, `crit:`), attributed by
process name. Fly app `ts-dashboard` comes from `fly logs --no-tail`, which
holds only its last 100 lines. The nodes are every peer the host's NetBird
client lists under a cell node or server name (`ts-gru-1`, `ts-sfo-2`,
`gru-1-ctl-1`); `TS_LOG_SCAN_NODES` names them instead. A node it cannot
read prints `unreadable` and fails the command; warnings and errors do not.

## Cell-wide aggregation

With `cluster_aggregation`, each controller subscribes to
`ts.orch.v1.<cell>.obs.snapshot` and answers with its `MemberSnapshot`; any
member gathers all of them within one second and lists non-answering members
as missing. Only controllers may publish on that subject: operator
credentials have an exact publish list and host credentials publish only their
own observation subjects.

Production controller credentials carry the subscribe grant
`ts.orch.v1.<cell>.obs.>` only when their bootstrap material was issued with
`"grantVersion": 2` in the reviewed controller configuration
(`generate-controller-material`). The default (absent, `0` or `1`) issues the
earlier grant set without it, so existing material is unchanged. The grant is
subscribe-only: it lets each controller answer the read-only telemetry
requests (`obs.snapshot`, region summaries, decision queries); publishing on
`obs.*` is unchanged. The credential validator accepts both grant sets.

Material is immutable, so enabling it is a rotation:

1. Add `"grantVersion": 2` to the reviewed controller configuration, record
   its new SHA-256, and issue new material into a new directory.
2. Roll the controllers onto the new credentials one at a time.
3. Only then set `cluster_aggregation: true` in the signed controller
   configuration. A controller whose credentials lack the grant logs that
   its responders were skipped and keeps running.

Rolling back is the same rotation with the grant version removed. Leave
`cluster_aggregation` off until every controller of the cell runs material of
grant version 2.

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

### On the NetBird address (cell spec)

A signed controller config may bind only loopback or its broker address, and
it changes only with a re-found. The cell spec's `dashboard` section
([cell spec](cell-spec.md)) instead makes every controller of the cell serve
the dashboard on its own NetBird address (`10.200.0.0/16`, the first one its
interfaces carry) at port 9463, beside the signed listener:

```json
"dashboard": {"token": {"vault": "<the region's Vault OCID>", "name": "<cell>-1-orch-dashboard-token"}}
```

- The token is a Vault secret of role `orch-dashboard` in the cell's own
  region, read with the controller's instance principal when the section
  changes and every 5 minutes, so a rotated secret takes effect without a new
  spec; while Vault is unavailable the listener keeps the token read last.
- The listener requires the token (bearer header or browser login, as
  above), accepts DNS names such as `ts-sfo-1.nb.ts.internal:9463`, and serves
  `/healthz`, `/readyz`, `/metrics`, `/v1/events` and the dashboard. The
  NetBird policy `operators-to-<cell>-servers-dashboard` opens TCP 9463 to
  operators only (`deploy/netbird/README.md`).
- A node without a NetBird address yet, a port it cannot bind or a token it
  cannot read is logged and retried every 5 seconds; it never stops the
  controller. Removing the section closes the listener.
- The dashboard reads the same providers as the signed listener's. Without
  `cluster_aggregation` (credentials without the observability grant) it
  shows this controller's own snapshot and its region's other controllers
  as unobserved, and other regions as unreachable.

Adding or changing the section needs a root; it needs binary level 18.

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
