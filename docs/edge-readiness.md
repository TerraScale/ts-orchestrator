# Edge readiness and regional backend selection

External load balancers can probe `GET /edge/ready` on HTTP port 80 using the
host address directly. No Host header or TLS SNI is required. HTTPS port 443
serves the same endpoint when the client supplies a routed hostname and trusts
its certificate. `HEAD` is also accepted; other methods return 405.

A 200 response means this edge has its four listeners, routes, usable trusted
certificates for its served names, HTTP readiness responses, and reachable local
Postgres backends. HTTP readiness follows the same routing as public requests,
so a stateless service can pass through another ready edge. Missing dependencies
return 503. The endpoint bypasses service routing and cannot be answered by
another host on behalf of the edge being checked. Draining returns 503
immediately and withdraws the edge's advertised ready services.

For stateless HTTP services, each ingress edge rotates requests over its local
ready service and peer edges advertising that service as ready. An authenticated
peer hop terminates at the chosen host without another balancing hop. A peer
whose dial fails is skipped for 15 seconds. While the executor holds a local port
for a stopping task, the edge sends new requests to a ready peer, and holds them
for the replacement only when no peer is ready. Mesh announcement freshness
bounds peer retention. The API front on port 8080 continues to use the fenced
regional writer router.

## Every host runs the edge

Every host starts the edge for HTTP, HTTPS and Postgres. The region's manager
reads services from SwarmKit every 5 seconds and publishes the edge inventory
(routes, readiness routes, admitted regional nodes and the TerraBase request-proof
secret reference) on the authenticated mesh subject
`ts.mesh.worker.<region>.edge.inventory`. A worker follows that subject and keeps
the last valid inventory, so losing the manager does not withdraw its routes. It
reads the request-proof secret from Vault with its instance principal, like its
TerraBase task. A worker outside the mesh has no inventory and answers 503.

Each host decides its own ready services by probing every readiness route on
loopback. No host needs the manager control socket for readiness. The regional
writer router on a worker discovers the region's nodes from the published
inventory, so ownership-bound traffic still reaches its owner from any host. The
Postgres front proxies to the local TerraBase task that runs on every node.

## Journey

The regional E2E lane starts six host processes (two per region), each in its
own network namespace on a shared bridge. Each has its own loopback, mesh node,
edge and stand-in applications for three public hostnames and Postgres. The
worker of each region gets its routes only from the mesh inventory. From each
ingress the lane checks an exact 6/6 spread for every hostname and checks
Postgres. Then it stops one host process (the manager in one region, the worker
in another) and checks that the survivor still answers `/edge/ready` and serves
every hostname and Postgres. The third region checks withdrawal of unready
services, readiness through a peer, drain to 503, and 503 with no ready backend.
The applications are lane stand-ins; production workload images and ACME
issuance are not part of this lane.
