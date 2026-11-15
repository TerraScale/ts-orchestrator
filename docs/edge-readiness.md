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
reachable local Postgres backends. HTTP readiness follows the same routing as
public requests, so a service that runs on another host passes through that
host's ready edge. Missing dependencies return 503. The endpoint bypasses
service routing and cannot be answered by another host on behalf of the edge
being checked. Draining returns 503 immediately and withdraws the edge's
advertised ready services.

Release health counts only the edge's process health: all four listeners bound.
A worker without a valid inventory answers 503 to the load balancer and still
reports healthy to `ts.release.health`, so it never blocks a release.

For HTTP services, each ingress edge rotates requests over its local ready
service and peer edges advertising that service as ready. An authenticated peer
hop terminates at the chosen host without another balancing hop. A peer whose
dial fails is skipped for 15 seconds, or until it next advertises ready
services, whichever comes first. While the executor holds a local port for a
stopping task, the edge sends new requests to a ready peer, and holds them for
the replacement only when no peer is ready. When neither the local service nor a
peer is marked ready, the edge probes the local readiness route once before
answering 503, so a task that just became ready (for example after a rollback)
is served before the next 5-second readiness refresh. Mesh announcement freshness bounds
peer retention. Routes on port 8080 use the fenced regional writer router from
every host, so SQL writes from any edge reach the region's writer.

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
mesh inventory. From each ingress the lane checks an exact 6/6 spread for every
hostname, Postgres, a bare 200 on public `/edge/ready`, and SQL writes on the
port-8080 route from the worker edge reaching the writer.

In the first region the worker refuses an inventory signed by itself, one that
claims the manager's name with its own key, a manager envelope with a changed
route and a replay of an older manager inventory. Then the manager stops, the
worker keeps serving, and the worker restarts cold with the manager still down
and serves again from its persisted inventory. In the second region the worker
stops, the manager serves alone, and once the worker restarts and advertises
ready the manager balances to it again at once. The third region checks
withdrawal of unready services, readiness through a peer, drain to 503, and 503
with no ready backend.

The same lane updates an existing manager-pinned `whoami` service through the
real SwarmKit manager and a joined worker to one task per node, and checks that
`ts-auth` renders one replica on the manager. Production workload images and
ACME issuance are not part of this lane.
