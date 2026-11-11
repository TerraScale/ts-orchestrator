# TerraBase wire TLS edge

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
  ends its side, when either side resets, when the client goes away, or when
  a regional drain or bootstrap hold ends it (below).
  TerraBase must answer the CONNECT within 60 s.
- HTTP/1.1, and with it an HTTP/1.1 Upgrade, is refused (the connection is
  reset): like TerraBase's internal listener, this server speaks only h2c.

Go 1.27 turns on extended CONNECT in `net/http` only through
`GODEBUG=http2xconnect=1`, which it reads once at start. The binary sets it
itself: `internal/edge/extendedconnect` is initialized before `net/http` and
the edge package removes the variable again, so child processes do not inherit
it. Every HTTP/2 server in ts-orch therefore advertises extended CONNECT,
public :443 included, and browsers then open WebSockets over HTTP/2 there. The
edge turns such a request into an HTTP/1.1 Upgrade request
(`internal/edge/upgrade.go`: a fresh `Sec-WebSocket-Key`, and `Upgrade`,
`Connection` and `Sec-WebSocket-Accept` dropped from the answer) and relays
the stream with the same routing, identity and security headers as an
HTTP/1.1 WebSocket. The reverse proxy closes the adapted stream before its
handler returns, and from then on the adapter refuses every write, so a copy
from the backend that is still running when the client's side fails cannot
write into the finished HTTP/2 stream. Only a `101 Switching Protocols` from
the backend opens the stream; any other 2xx (an SPA catch-all answering 200
with HTML) is sent as 502, because under RFC 8441 a 2xx tells the browser the
WebSocket is open.

A backend on a loopback port (a customer app, NetBird) gets that HTTP/1.1
Upgrade on its port. TerraBase's public route (port 8080) does not: once the
mesh runs, `regionalRoundTrip` (`internal/edge/regional.go`) sends every
request for it to the region's fenced writer, on that node's internal
listener over h2c, and HTTP/2 has no Upgrade. So a WebSocket handshake for
TerraBase, whether the client sent it over HTTP/1.1 or as RFC 8441, goes there
as an extended CONNECT stream on a dedicated connection (`upgradeTunnel`),
with the request's headers except `Sec-WebSocket-Key` and the hop-by-hop ones.
TerraBase's 2xx reaches an HTTP/1.1 client as `101 Switching Protocols` with
the `Sec-WebSocket-Accept` of its key, and an RFC 8441 client as the 200 of
the adapter above; any other answer passes through as TerraBase's answer. A
handshake is a GET whose `Upgrade` lists `websocket`, with `Connection:
Upgrade`, `Sec-WebSocket-Version: 13` and a `Sec-WebSocket-Key` of 16 bytes
(RFC 6455 4.2.1); every backend gets it with `Upgrade: websocket`. Any other
request with an `Upgrade` reaches TerraBase as the ordinary request it also
is, without `Upgrade`. A complete handshake on a path that has no WebSocket
endpoint gets TerraBase's answer to the CONNECT (404), where TerraBase asked
over HTTP/1.1 ignores the upgrade. A client's half-close reaches TerraBase
as END_STREAM, as on 127.0.0.1:8081.

Every regional request holds an ingress lease from its admission until its
response body ends. A drain or bootstrap hold first withdraws admission, so a
request that arrives during the hold waits without a lease, and then waits
until no lease is left before it hands over or stops the writer. After a hold,
and while a request that waited for it is still being answered, requests are
paced through two recovery slots. A request waits for the hold to end, then
for its slot, and only then takes its lease, so the next hold waits only for
the requests being served, not for the paced backlog. A request that fails
before its response reaches the client, or whose handler panics, gives its
lease back at once.

Once a stream is open (the 101, or the 2xx of an extended CONNECT on
127.0.0.1:8081), it no longer counts as an admitted regional request: it gives
back its ingress lease, its admission slot and its pacing, so a regional drain
or bootstrap hold never waits for it. Instead, as soon as a drain or
bootstrap hold holds the ingress, the edge ends the streams it relayed to the
drained node, and every stream it relays in the region when that node is the
region's writer; a bootstrap hold always holds the writer. The writer case
covers a stream the edge sent to the previous writer within its 250 ms owner
cache after TerraBase moved the writer itself: TerraBase relays that stream
to the new writer (`HomeSocketRelay`) and holds an ingress lease there too.
The edge ends only the streams it relays itself, so a drain or hold ends
every stream of the region only while one edge serves the region, as today:
the founder serves the region's edge and a joiner serves none
(`internal/app/app.go`).
The client sees its connection end, as when TerraBase restarts, and its next
handshake meets the hold like any request. The edge sends no WebSocket close
frame (1012) itself: it relays opaque bytes and cannot tell where TerraBase's
current frame ends. What keeps an old socket from writing after the handoff
is TerraBase: it fences the source (`RegionalOwners.Drain`) once every stream
on it has ended, and its lease gate then refuses every write there.

Public WebSocket streams have their own budget, apart from the 1,024
admission slots: at most 64 per client address (the address the edge sends in
`X-TerraBase-Forwarded-For`; an IPv6 address counts by its /64) and 512 per
edge, half of TerraBase's 1,024 regional ingress slots. Streams on
127.0.0.1:8081 come from this host's own services and count toward neither:
they have their own bound of 256 per edge, a quarter of those slots, so this
edge's sockets and tunnels together leave at least 256 of them for REST. Past
a bound a handshake gets `429 Too Many Requests` (the address) or `503
Service Unavailable` (the edge), with `Retry-After: 1`, a `Content-Length`
and a one-line body naming the bound. A stream leaves its budget as soon as
either side ends: TerraBase ends its side, the stream fails, or the client
goes away.

When a backend ends a WebSocket, the edge ends the client's side too. Go's
reverse proxy would only half-close an HTTP/1.1 client (a TLS close_notify,
the TCP connection still open) and then wait for the client without a
deadline. A WebSocket has no half-close (RFC 6455 7.1.1), so the edge closes
that connection, as it already ends an RFC 8441 client's stream.

Every write the edge relays to an upgraded client waits at most 120 s, the
idle timeout of :80 and :443, for the client to take it: a WebSocket or any
other HTTP/1.1 Upgrade on :443, an RFC 8441 stream on :443, and an extended
CONNECT stream on 127.0.0.1:8081. A client that takes no data for 120 s while
the edge has some to send is cut, whatever its average rate: the edge closes
its HTTP/1.1 connection or resets its HTTP/2 stream. A write carries at most
32 KiB, so a client that reads slower than about 270 bytes per second is cut
too. When the edge ends a stream while a write to the client still waits, it
cuts that write at once.

A client that stops reading its whole HTTP/2 connection to :443 or
127.0.0.1:8081 is bounded too: the edge closes the connection once a write to
it makes no progress for 120 s, which ends every stream on it, REST, SSE and
gRPC included. On TLS a write that times out breaks the connection, so on
:443 the bound applies to each socket write, at most one HTTP/2 frame (16 KiB
unless the client allows larger frames): a client that takes at least that
much every 120 s while the edge is sending is never cut, however long its
response or stream lasts.

`e2e-m1` drives this path through a second edge
(`test/e2e/m1/regional`), built from the same tree and set up with the calls
`internal/app/app.go` makes: `SetRoutes`, `SetRequestProofSecret`,
`SetRegionalNodes`, and `DrainRegionalNode` from a control port. It runs in its
own network namespace beside the installed ts-orch, in front of two writer
stand-ins on 127.0.0.2:8081 and 127.0.0.3:8081 that check the peer credential,
answer the rollout status, prime and drain calls, and echo extended CONNECT
streams. Through the real :443 it sends one REST request, one HTTP/1.1
WebSocket and one RFC 8441 WebSocket, each of which echoes a frame, then
drains the writer with both sockets open: the drain must finish within 5 s
and end both sockets, and the next REST request must reach the new writer. It
does not cover the mesh wiring in `internal/app/app.go` (`mesh.Run`, the drain
request over NATS, the Vault peer credential), TerraBase itself, NetBird,
`HomeSocketRelay`, or a region with two edges; only a real region proves those.

An Upgrade never fails over to another region (`failover` in
`internal/edge/replay.go` skips it): while a stop-first service on a loopback
port is replaced, it waits up to 20 s for the new task, then gets 502.

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

## Retired: TerraBase wire TLS on :7464

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
