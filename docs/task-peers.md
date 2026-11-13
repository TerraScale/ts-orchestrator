# Task region, node and peers file

Every service task the mesh applies gets `TS_REGION` and `TS_NODE`. Services
require peers by default; `dependencies: ["peers"]` makes that requirement
explicit. They get `TS_PEERS_FILE` and its read-only mount. A service declaring
`dependencies: []` has no mesh prerequisite and cannot request a peers file mount.
The exact name `netbird-server` is reserved for the management service. Its name
is its identity: the binary always treats it as dependency-free, regardless of
stored dependencies, and gives it no peers file or `TS_PEERS_FILE` variable.
ts-orch sets these variables; a spec that sets any of them as env or as a
secret name is refused. Unknown or repeated dependencies are refused.

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
  requires a present, nonempty, well-formed file with this host's own address
  and region correct. The file lives under `/run`, a memory filesystem: a
  reboot removes it, so a surviving generation was written since this boot.
  There is no age threshold; remote addresses are as fresh as the writer's
  last successful round.
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
service, named `netbird-server`, uses its local configuration and data. The
binary exempts that reserved name when admitting tasks, restoring stored tasks,
and reconciling declarations. An old task carrying `TS_PEERS_FILE` starts with
that variable removed and without its peers mount. It starts where it is
placed; the host client can then connect and create `wt0`. On other hosts the
client connects to the management service remotely. The management server
remains one host's task and its data stays on that host.

Services declaring `dependencies: ["peers"]` wait for the host mesh address and
a nonempty, valid peers generation containing that host at its current address.
The writer recreates `/run/ts-orch/peers` from the durable admitted topology once
the interface exists. It never publishes a partial generation. A plain agent
restart leaves running tasks in containerd.

The cluster stores the declared dependencies with each service. Inspection
preserves omission, an explicit peers list and an explicit empty list for other
services. For `netbird-server` it always reports the effective empty dependency
list, even if storage still contains an old peers dependency. Configuration
rolls preserve these effective dependencies. Inspection excludes the three
task environment variables set by the orchestrator.

After causal generation and rollback ordering, equal-generation declarations
with a dependencies field rank above declarations without it. Within either
group, deterministic encoded bytes break ties. A higher-generation declaration
from an older node may still omit the field and is accepted. Management recovery
does not depend on that field: a host running this release recovers from both
today's old stored declaration and task and a later stripped declaration.

For any other service that declares an empty dependency list, a stripped
higher-generation declaration restores the default peers dependency. That
service then waits for a valid peers file it does not need and its task can be
replaced once. It cannot recreate the management cycle, because management
starts first. Applying the declaration again from an upgraded node restores the
empty list. The upgrade to this release replaces the running management task
once, when reconciliation first compares it with the effective declaration;
connections relayed through that host are interrupted for that moment.

Before an intentional reboot:

1. Verify the running agent's version on that host includes this release; a
   newly installed binary on disk alone does not establish what is running.
2. Verify `ts-orch service inspect netbird-server` reports an empty dependency
   list on the management host, and `ts-orch service ps netbird-server`
   shows the management task running.
3. After the reboot, verify the management task, mesh interface and dependent
   services recover in that order, and check the dependent services' peers view.

Once this release is running on the management host, reboot recovery needs no
declaration re-apply or other operator action. A host without the management
service that reboots while the management host is down waits for that host to
return.
