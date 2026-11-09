# TerraBase wire TLS edge

**Retired 2026-11-04.** TerraBase no longer has a custom wire listener
(`TerraBaseOptions.WirePort` is gone), so `terrabase.json` drops
`TERRABASE_WIRE_PORT` and its `wire` block. The edge stops serving 7464 for
TerraBase. The rest of this page is history.

Every region serves `api.terrascale.tech:7464` and its own regional API hostname
with direct TLS and the edge's existing ACME certificates. No ALPN is required.
After TLS terminates, the edge forwards binary frames unchanged to the local
private listener. It does not add the Postgres PROXY header. Unknown SNI and
plaintext connections are rejected before connecting to TerraBase.

The TerraBase service declares `wire.port=7465`, matching its existing
`TerraBaseOptions.WirePort` through `TERRABASE_WIRE_PORT=7465`. The public edge
owns 7464. Private port 7465 stays blocked externally, like Postgres backend 6432.

## Private loopback 127.0.0.1:8081

TerraBase binds its internal listener (8081) only on the host's NetBird
address, and it speaks only HTTP/2 without TLS (h2c). ts-auth and ts-dashboard
use `http://127.0.0.1:8081`, which the edge serves as protocol `terrabase`: an
h2c server (`internal/edge/regional.go`, `serveRegionalInternal`) that relays
each request to `<wt0 IPv4>:8081` on its own, so pooled client connections
pick the backend per request. TerraBase restarts stop-first (21-30 s with
nothing listening), so a refused dial to `<wt0 IPv4>:8081` is retried for up
to 60 s, REST and extended CONNECT alike; the request fails with 502 only
past that. A refused dial sent nothing, so the retry is safe for any method,
and ts-auth and ts-dashboard need it: the .NET SDK retries only
serialization conflicts and a busy tenant, not a 502.

- REST requests go through a reverse proxy that keeps the caller's `Host` and
  streams the response.
- SQL WebSocket sessions use HTTP/2 extended CONNECT (RFC 8441: `:method
  CONNECT`, `:protocol websocket`). The edge advertises
  `SETTINGS_ENABLE_CONNECT_PROTOCOL=1`, opens its own extended CONNECT stream
  to TerraBase on a dedicated connection (`internal/edge/tunnel.go`), returns
  TerraBase's status and headers, and then relays both directions as the bytes
  arrive, within a 256 KiB flow-control window. A client END_STREAM is passed
  on, so TerraBase can still answer after it. The session ends when TerraBase
  ends its side, when either side resets, or when the client goes away.
  TerraBase must answer the CONNECT within 60 s.
- HTTP/1.1 Upgrade is refused, as TerraBase's internal listener is h2-only.

Go 1.27 turns on extended CONNECT in `net/http` only through
`GODEBUG=http2xconnect=1`, which it reads once at start. The binary sets it
itself: `internal/edge/extendedconnect` is initialized before `net/http` and
the edge package removes the variable again, so child processes do not inherit
it. Every HTTP/2 server in ts-orch therefore advertises extended CONNECT,
public :443 included, and browsers then open WebSockets over HTTP/2 there. The
edge turns such a request into the HTTP/1.1 Upgrade that the backend already
serves (`internal/edge/upgrade.go`: a fresh `Sec-WebSocket-Key`, and
`Upgrade`, `Connection` and `Sec-WebSocket-Accept` dropped from the answer)
and relays the stream with the same routing, identity and security headers as
an HTTP/1.1 WebSocket. Only a `101 Switching Protocols` from the backend opens
the stream; any other 2xx (an SPA catch-all answering 200 with HTML) is sent
as 502, because under RFC 8441 a 2xx tells the browser the WebSocket is open.

`GODEBUG=http2xconnect=0` in the service environment turns extended CONNECT
off: the binary leaves any `http2xconnect=` value the operator set. Then no
ts-orch HTTP/2 server advertises `SETTINGS_ENABLE_CONNECT_PROTOCOL`. On :443
browsers fall back to HTTP/1.1 WebSockets and the adapter goes unused. On
127.0.0.1:8081 TerraBase SQL WebSocket sessions fail ("The HTTP/2 server does
not support extended CONNECT requests") while REST keeps working, so use it
only to contain a defect in the extended CONNECT path.

If another process holds 127.0.0.1:8081 (the retired
`fr1-terrabase-loopback.socket` shortcut), the bind error names it,
`EdgeListenerUnavailable` fires for `protocol="terrabase"`, and the edge binds
within 5 s of the port being freed.

## Automatic releases and service rollout (FR1)

No release has a manual prerequisite. Each public protocol starts and retries
independently. A bind failure logs the affected protocol and leaves the others
serving. Prometheus host scrapes include `ts_orch_edge_listener_ready` with five
fixed protocol values; `EdgeListenerUnavailable` alerts after one minute.

Wire activates only after a TCP readiness probe confirms its configured private
backend. Missing routes, unavailable private listeners and an occupied public
7464 leave wire down while HTTP, HTTPS and Postgres continue. Readiness is
rechecked every five seconds, and wire automatically recovers after either
release order. Its exact host firewall ACCEPT rule is withdrawn while blocked
and opened only after the edge owns the public TLS socket, keeping a legacy
native plaintext listener private.

FR1 rolls the merged orchestrator release through the normal automatic path.
Update each region's preserved live TerraBase declaration with
`env.TERRABASE_WIRE_PORT=7465` and `wire: {"port":7465,
"hostname":"api.terrascale.tech"}` through the normal gated service rollout.
Preserve live images, secrets and resources; never apply the example's stale
image or secret references. Either component can roll first safely.

After local TLS works, FR1 reconciles public NSG TCP7464 and verifies certificate
chain and hostname from delta on every regional public IP, with
`api.terrascale.tech` as SNI. Keep private7465 blocked. Recheck Postgres
verify-full on5432. COS routes the public handshake evidence to RT6.

No data format change, wipe, new credentials or paid service is needed.
