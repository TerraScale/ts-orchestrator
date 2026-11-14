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
peer hop terminates at the chosen host without another balancing hop. Local
service advertisements come from task readiness probes; a failed inventory probe
withdraws the local ready set. Mesh announcement freshness bounds peer retention.
The API front on port 8080 continues to use the fenced regional writer router.
Postgres forwarding and certificate distribution are unchanged by this selection.

The regional E2E lane exercises two edge instances for each of three regions,
with real mesh TLS identities and trusted public certificates. It checks an exact
6/6 distribution from each ingress, withdrawal of an unready local backend,
readiness through a peer, drain health, and serving after a peer edge stops.
Its application backends are lane stand-ins. This proof does not start production
workload declarations or make a worker host run an edge. Worker route discovery,
placement across hosts, and full HTTP/Postgres host-loss qualification still need
their implementation and journey coverage before enabling every public backend.
