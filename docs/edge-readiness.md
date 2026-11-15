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

Release health joins the edge's infrastructure conditions (listeners, routes,
bootstrap, ingress, backends) on every host. The one exception is a worker's
`edge inventory unavailable`: a worker without a valid inventory answers 503 to
the load balancer and still reports healthy to `ts.release.health`, so it never
blocks a release.

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
until it next advertises ready services. A peer that stops answering is
detected by its own liveness: an attempt is abandoned once the peer has not
advertised for three advertisement intervals, the same window that keeps it
listed as a peer (15 seconds in production). The whole layer, fallback
included, is bounded by main's 30-second response header bound, so a request
never waits longer than it would have on main. WebSocket and other upgrades
pass through a peer unchanged. Routes on port 8080 use the fenced regional
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

Every host starts the edge for HTTP, HTTPS and Postgres. The region's manager
reads services from SwarmKit every 5 seconds and publishes the edge inventory
(routes, readiness routes, admitted regional nodes and the TerraBase request-proof
secret reference) on the authenticated mesh subject
`ts.mesh.worker.<region>.edge.inventory`. It signs the inventory with its node
TLS identity (`/var/lib/ts-orch/node/tls.key`) as `ts-<region>-1`, with the
region, an issue time and a generation that only grows. It signs a new
generation when the inventory changes and at least every hour, and republishes
the latest signed inventory every 5 seconds, so a worker that missed a message
converges on the next one.

A worker accepts an inventory only when the signer is `ts-<region>-1` in its
adopted node list ([node enrolment](node-enrolment.md)) for that region, the
signature verifies against the listed key, the issue time is not in the future
and the generation is newer than the one it holds. Anything else, including an
inventory signed by any other node, is refused and logged once per reason. The
worker writes the last accepted signed inventory to
`/var/lib/ts-orch/edge-inventory.json` and verifies it again after a restart,
so losing the manager does not withdraw its routes, even across a worker
restart. An inventory issued more than 24 hours ago is stale: the worker drops
its routes and answers 503. A worker outside the mesh, or whose node list does
not list the manager yet, has no inventory and answers 503.

Each host decides its own ready services by probing every readiness route on
loopback. No host needs the manager control socket for readiness. The regional
writer router on a worker discovers the region's nodes from the inventory, so
ownership-bound traffic still reaches its owner from any host. The Postgres front
proxies to the local TerraBase task that runs on every node.

## Journey

The regional E2E lane starts six host processes (two per region), each in its
own network namespace on a shared bridge, with its own node identity and one
node list naming all six. Each has its own loopback, mesh node, edge, stand-in
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
peer stopped (SIGSTOP), a DELETE already sent on a connection is answered 502
within the peer's liveness bound and is not resent, and a request on a held
stop-first port waits for its replacement. A peer that accepts but never
answers costs main's 502 at 30 seconds, not more. With no ready peer, a
draining manager, a peer hop to it, an unheld backend that restarts while the
request waits, a host without the peer credential, a host whose readiness probe
hangs, and the NetBird dashboard all behave exactly as on main.

The fleet runs in its own CI lane (`fleet.sh`); the regional lane keeps the
SwarmKit, peer-file and metadata steps below.

The same lane updates an existing manager-pinned `whoami` service through the
real SwarmKit manager and a joined worker to one task per node, and checks that
`ts-auth` renders one replica on the manager. Production workload images and
ACME issuance are not part of this lane.
