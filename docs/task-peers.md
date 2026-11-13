# Task region, node and peers file

Every service task the mesh applies gets `TS_REGION` and `TS_NODE`. Services
require peers by default; `dependencies: ["peers"]` makes that requirement
explicit. They get `TS_PEERS_FILE` and its read-only mount. A service declaring
`dependencies: []` has no mesh prerequisite. ts-orch sets these variables; a
spec that sets any of them as env or as a secret name is refused. Unknown or
repeated dependencies are refused.

| Variable | Value |
|---|---|
| `TS_REGION` | This host's region token, from OCI IMDS (`gru`, `sjc`, `fra`) |
| `TS_NODE` | This host's node name, its hostname (`gru-1-ctl-1`), `[a-z0-9-]{1,63}` |
| `TS_PEERS_FILE` | `/run/ts-orch/peers/peers` |

## Peers file

One line per region the service targets (own region included) whose node
answered the last mesh ping round, sorted, `\n` terminated:

```
<node> <region> <netbird-ipv4>
```

- Host path: `/run/ts-orch/peers/<service>/peers`; the directory is bound
  read-only at `/run/ts-orch/peers` in the task, so the atomic rename that
  replaces the file is visible inside.
- The mesh writes a complete generation containing the host at its current
  mesh address before it applies a service with a peers dependency, and
  rewrites it only when its content changes. Task preparation independently
  refuses empty, malformed or stale local-address generations.
- Each node pings every region every 5 s (`ts.mesh.ping`; the reply carries
  the node's `wt0` IPv4). Admitted identities persist independently in the
  private mesh state, never seeded from `peers`. Missing replies do not
  authorize membership removal: incomplete generations are refused and the
  last complete file remains. An explicit desired `regions` change admits a drain.
- The own line needs the host's `wt0` IPv4. Peers-dependent services stay
  blocked until it exists. Tracking records the dependency before checking
  the interface, so the next peer observation can write its file.
- `ts-orch service apply` without a running mesh (this host only) sets none of
  the three variables and refuses an explicit peers dependency.

Ports 9095 (health) and 9096 (metrics) belong to NetBird.
The loopback `127.0.0.1:9097/metrics` exporter aggregates every targeted region's
authenticated mesh reports. `ts_orch_peer_topology_*` exposes mismatch, expected
count, rejected generations and observation age; missing reports fail
closed. Reports are bound to the expected topology digest, and
monitoring uses an immutable desired snapshot independently of SwarmKit RPCs.
Install the accompanying monitoring configuration through the rollout owner.
Both peer-topology alerts hold for 30 seconds. With five-second scrape,
evaluation and grouping intervals, a sustained mismatch or unavailable exporter
reaches the capped, deduplicating relay within 45 seconds under healthy
monitoring; aging evidence first crosses its 30-second threshold, so its
notification budget is 75 seconds. Shorter restart gaps do not page. These
are configuration budgets, excluding provider delivery latency.

Validation after the release: on an isolated cell, drop a peer from its file
and verify the mismatch within 60 seconds, then apply an authorized placement
drain and verify agreement. Never modify a production peers file. Record
expected/file agreement on each recovered production region, the loaded
Prometheus rule and one synthetic deduplicated notification.

## Host boot order

A host keeps its SwarmKit admission, service declarations, container images and
service data on persistent storage. The agent restores local tasks from that
state without waiting for the mesh or a mesh-carried store. The mesh management
service uses its local configuration and data and declares `dependencies: []`.
It starts where it is placed; the host client can then connect and create
`wt0`. On other hosts the client connects to the management service remotely.

Services declaring `dependencies: ["peers"]` wait for the host mesh address and
a nonempty, valid peers generation containing that host at its current address.
The writer recreates `/run/ts-orch/peers` from the durable admitted topology once
the interface exists. It never publishes a partial generation. A plain agent
restart leaves running tasks in containerd.

The cluster stores the declared dependencies with each service. Inspection
preserves omission, an explicit peers list and an explicit empty list, and
excludes the three task environment variables set by the orchestrator.
Configuration rolls preserve the inspected declaration.

After causal generation and rollback ordering, equal-generation declarations
with a dependencies field rank above declarations without it. Within either
group, deterministic encoded bytes break ties. This is a fixed total order:
merging selects its maximum regardless of arrival order, so a stripped copy
cannot replace a retained explicit list or make the selection flap. An older
binary does not know this rule and can still drop the field; apply the new
declaration only after every mesh node runs the release that understands it.

After installing that release:

1. Verify every mesh node runs it.
2. Read the management service with `ts-orch service inspect netbird-server`.
   Carry its current `TS_ORCH_NETBIRD_CONFIG_SHA256` environment value and
   configuration into the management declaration, set `dependencies: []`,
   retain its management region placement, and apply it with
   `ts-orch service apply -f <declaration.json>`:

   ```sh
   sudo ts-orch service inspect netbird-server |
     jq '.spec | .regions = ["gru"] | .dependencies = []' > netbird-server.json
   sudo ts-orch service apply -f netbird-server.json
   ```

3. On every mesh node, check the management entry in
   `/var/lib/ts-orch/mesh/desired.json` has `"dependencies":[]` and the
   expected configuration digest. Check again after a minute; both must remain.
4. Reboot a host without the management service and verify recovery and its
   peers view. Then reboot the management host and verify the management
   service, mesh interface and dependent services recover in that order.

A host without the management service that reboots while the management host
is down waits for that host to return.
