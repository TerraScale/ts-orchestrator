# Edge readiness and regional backend selection

External load balancers can probe `GET /edge/ready` on HTTP port 80 using the
host address directly. No Host header or TLS SNI is required. HTTPS port 443
serves the same endpoint when the client supplies a routed hostname and trusts
its certificate. `HEAD` is also accepted; other methods return 405. Public
ports answer with the status code only: 200 or 503 and no body. The JSON detail
(missing conditions, missing certificate names) is served only on the mesh-facing
port 9108 ([edge certificates](edge-certificates.md)).

A 200 response means this edge has its four listeners, a valid edge inventory,
usable trusted certificates for its served names, HTTP readiness responses, and
reachable local Postgres backends. On a manager, HTTP readiness probes each
backend on loopback, exactly as release health always has. On a worker it
follows the same routing as public requests, so a service that runs on another
host passes through that host's ready edge. Missing dependencies return 503. The endpoint bypasses
service routing and cannot be answered by another host on behalf of the edge
being checked. Draining returns 503 immediately and withdraws the edge's
advertised ready services.

Every edge starts with its route inventory unloaded. A manager reports
`routes unavailable` until its service and readiness tables have been stored;
a mesh hostname does not bypass this condition. A successfully loaded empty
inventory is valid, so a region with no application services can serve its
native mesh name once its certificate is ready.

Release health joins the edge's infrastructure conditions (listeners, routes,
bootstrap, ingress, backends) on every host. The one exception is a worker's
`edge inventory unavailable`: a worker without a valid inventory answers 503 to
the load balancer and still reports healthy to `ts.release.health`, so it never
blocks a release. As on main, the stored Swarm admission determines the
release-health checks: managers require service and JetStream health; workers
require their mesh node to have started and skip both manager-only checks.

Peer routing is a separate layer on top of main's request path. An ingress
edge enters it only when the request's service has at least one ready peer and
the local service is not preferable (not ready, draining, or its port held by
the executor for a stopping task), and only when it holds the peer credential.
In every other case, including every host without a ready peer, the request
takes main's path unchanged: the same handler order (including the NetBird
dashboard), the same refused-dial and handoff waits, the same errors. A peer
hop is always served on main's path by the host it reaches.

Inside the layer the edge rotates the request over the ready peers and keeps
its own backend as the last candidate, reached through main's local transport.
A request moves to the next candidate only when a peer failed before
answering and resending is safe, as in Go's own transport: none of its body was
read yet, and either the connection was never made or the method is GET, HEAD,
OPTIONS or TRACE. Any response from a peer, whatever its status or headers, is
returned to the client. The failing peer is marked down and gets no requests
until it next advertises ready services. Every edge advertises its ready
services each interval (5 seconds in production) and again at once when they
change, so a peer that becomes unready or starts draining is withdrawn
immediately. A peer counts for new requests and for readiness only while its
last advertisement is at most two intervals old, so a peer that falls silent
stops counting one interval after it misses an advertisement. A peer whose
edge this edge cannot connect to (the dial is refused, unreachable or times
out, or the TLS handshake fails or is reset) stops counting for every route
until an advertisement from it arrives after the failure. Once a connection
to the peer exists, nothing that follows counts against the peer: a client's
request body that is shorter than declared or malformed, headers the
connection refuses to carry, and any error after request bytes were written
cost that client main's 502 and leave the peer counting. HTTP status codes and slow
responses never change whether a peer counts: a 503 from a backend through a
healthy peer is returned unchanged and the peer keeps receiving requests, and
a request that outlives the 30-second header budget costs main's 502 without
excluding the peer. A peer's backend health reaches other edges only through
its own advertisements, which it repeats at once when its ready services
change. The accepted bound: a peer that stops advertising while its backend
fails still counts for at most two advertisement intervals (10 seconds in
production). None of this touches
a request already sent to a peer: it is bounded only as on main. Ordinary HTTP shares a 30-second
response-header budget across the layer and its local fallback, starting when
the first request finishes writing. Request uploads and response bodies are
not subject to this timer. As on main, gRPC has no response-header deadline.
WebSocket and other upgrades preserve bidirectional traffic and client
half-close through a peer. Routes on port 8080 use the fenced regional
writer router from every host, so SQL writes from any edge reach the region's
writer.

A malformed TerraBase secret-references label never clears the request-proof
secret: the manager logs the error and keeps publishing the last good
reference. A changed reference is applied on the next inventory pass.

## Which services run on every host

Replication is declared per service in code (`everyNodeServices` in
`internal/swarmruntime/service.go`). Today only `whoami` runs one task on every
joined host of its region, with SwarmKit `MaxReplicas: 1` so two replicas never
share a host. TerraBase keeps its own one-per-node placement. Every other
regional service, including `ts-auth` and `ts-dashboard`, runs exactly once, on
the region's manager; worker edges reach it through the manager's edge. Every
rendered service carries a non-nil SwarmKit placement, so an update of an
existing task never meets a missing placement in the SwarmKit updater.

## Every host runs the edge

Every host starts the edge for HTTP, HTTPS and Postgres. Every host that holds
a SwarmKit manager certificate of its region reads services from SwarmKit every
5 seconds and publishes the edge inventory (routes, readiness routes, admitted
regional nodes and the TerraBase request-proof secret reference) on the mesh
subject `ts.mesh.worker.<region>.edge.inventory`. It signs the inventory with
its SwarmKit node key (`/var/lib/ts-orch/swarm/certificates/swarm-node.key`)
and sends its node certificate chain with it, with the region, an issue time
and a generation that only grows. It signs a new generation when the inventory
changes and at least every hour, and republishes the latest signed inventory
every 5 seconds, so a worker that missed a message converges on the next one.

Trust comes from the regional join, not from the release. A follower accepts an
inventory only when:

- the certificate chains to its own region's SwarmKit root CA
  (`swarm/certificates/swarm-root-ca.crt`) and is valid now, so a self-signed,
  expired or other-region certificate is refused;
- the certificate carries the `swarm-manager` role and the follower's own
  cluster organization;
- the certificate's node ID is in the region's current manager list, which the
  SwarmKit dispatcher pushes to every node's agent over its mTLS session and
  SwarmKit keeps in `swarm/state.json`;
- the signature over the inventory verifies against that certificate, the
  issue time is not in the future and the generation is newer than the last
  one from the same manager.

Anything else is refused, counted in `ts_orch_mesh_edge_inventory_refused_total`
and logged once per reason. A node the region admits as a manager, including one
promoted by `ts-orch member promote`, publishes as soon as it holds its manager
certificate, with no release. A node the region demotes or removes leaves the
manager list: its inventories are refused from then on and the follower drops
the ones it holds from that node at once, falling back to the newest inventory
of a current manager. `ts_orch_mesh_edge_inventory_publisher{node="<id>"}` names
the manager whose inventory the follower serves, and
`ts_orch_mesh_edge_inventory_trusted{node="<id>"}` names every current manager
whose inventory the follower holds.

The follower writes the newest accepted signed inventory to
`/var/lib/ts-orch/edge-inventory.json` and verifies it again after a restart
against the certificates and manager list on disk, so losing the manager does
not withdraw its routes, even across a worker restart. An inventory issued more
than 24 hours ago is stale: the worker drops its routes and answers 503. A
worker outside the mesh, or whose region lists no manager, has no inventory and
answers 503.

Releases install on workers before their manager. For one release a follower
also starts from a persisted inventory in the format the previous release
wrote (publisher `ts-<region>-1` with a pinned TLS key), which its previous
release had verified, so a worker that upgrades before its manager keeps
serving until the manager publishes a certificate-signed inventory. The next
release removes that carry-over.

Each host decides its own ready services by probing every readiness route on
loopback. A worker's edge readiness and release health count a route as
servable when the worker would send its requests to a ready peer, using the
same choice as request routing (credential held, a listed peer advertising the
service ready, and the local service not preferable); every other route is
probed on loopback exactly as on main, so a worker that can serve a route
neither locally nor through a peer reports "backend unavailable". Health never
contacts a peer. No host needs the manager control socket for readiness. The regional
writer router on a worker discovers the region's nodes from the inventory, so
ownership-bound traffic still reaches its owner from any host. The Postgres front
proxies to the local TerraBase task that runs on every node.

## Journey

The regional E2E lane starts six host processes (two per region), each in its
own network namespace on a shared bridge, with its own node identity and a
SwarmKit certificate from its region's CA: a manager certificate on
`ts-<region>-1` and a worker certificate on `ts-<region>-2`. Each has its own loopback, mesh node, edge, stand-in
applications for two public hostnames and Postgres, and a TerraBase stand-in on
its internal port that answers the writer status and SQL writes only on
`ts-<region>-1`. The worker of each region gets its routes only from the signed
mesh inventory. Every host first serves every hostname and Postgres locally and
answers a bare 200 on public `/edge/ready`; SQL writes on the port-8080 route
from the worker edge reach the writer.

In the first region a malformed secret-references label keeps the last good
proof reference, and the worker refuses an inventory signed by itself, one that
claims the manager's name with its own key, a manager envelope with a changed
route and a replay of an older manager inventory. Then the manager stops, the
worker keeps serving, restarts cold with the manager still down and serves
again from its persisted inventory; restarted once more without any inventory,
it answers 503 and its release health stays clean.

In the second region an unready manager forwards every request to its worker
and its release health names the unready backends. When the worker is lost the
manager serves its own running backend, and once the worker restarts cold and
advertises ready the manager forwards to it again; SQL writes from the
restarted worker reach the writer.

In the third region, with a ready peer, the unready manager forwards HTTP and
a WebSocket to it. A DELETE answered by the peer is never sent again, even when
the client or the backend sets a header the edge once used as a marker. With the
peer that never answers, a DELETE already sent on a connection is answered
main's 502 at 30 seconds and is not resent, and a request on a held stop-first
port waits for its replacement. A 31-second gRPC call through a peer whose
announcements stop mid-call completes as on main.

In the second region, while the third runs its long calls, a worker whose own
application is down is ready only through its manager as a fresh ready peer.
When the manager falls silent, the worker's readiness and release health turn to
"backend unavailable" within three advertisement intervals, and a new request
no longer reaches the manager. When the manager becomes unready, the same
happens within one interval of its withdrawal. A request-specific 503 through a healthy
manager leaves the worker ready and the next request reaches the same manager.
When the manager falls silent while its application fails, the worker turns
unready within the freshness bound, and the manager's next ready advertisement
restores it. While a DELETE waits on a peer that never answers, a request whose
peer edge refuses the connection falls back to main's local path and the peer
stays excluded until its next advertisement; once the DELETE gets main's 502 at
30 seconds, the peer still serves other routes. A gRPC request that declares more body than it
sends, an Upgrade request with a malformed chunked body, and a gRPC request
whose headers fill the ingress's limit and overflow the peer's once forwarded
each get 502, and the worker keeps forwarding to its manager and stays ready. A peer that accepts but never
answers costs main's 502 at 30 seconds, not more. With no ready peer, a
draining manager, a peer hop to it, an unheld backend that restarts while the
request waits, a host without the peer credential, a host whose readiness probe
hangs, and the NetBird dashboard all behave exactly as on main, and a worker
without the credential, a ready peer or its local backend is not ready.

The fleet runs in its own CI lane (`fleet.sh`); the regional lane keeps the
SwarmKit, peer-file and metadata steps below.

The same lane updates an existing manager-pinned `whoami` service through the
real SwarmKit manager and a joined worker to one task per node, and checks that
`ts-auth` renders one replica on the manager. Production workload images and
ACME issuance are not part of this lane.
