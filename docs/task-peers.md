# Task region, node and peers file

Every service task the mesh applies gets three environment variables. ts-orch
sets them; a spec that sets any of them (as env or as a secret name) is refused.

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
- The mesh writes the file (at least the own line) before it applies the
  service, and rewrites it only when its content changes.
- Each node pings every region every 5 s (`ts.mesh.ping`; the reply carries
  the node's `wt0` IPv4). Admitted identities persist independently in the
  private mesh state, never seeded from `peers`. Missing replies do not
  authorize membership removal: incomplete generations are refused and the
  last complete file remains. An explicit desired `regions` change admits a drain.
- The own line needs the host's `wt0` IPv4; without NetBird the mesh does not
  apply the service and retries on its next round.
- `ts-orch service apply` without a running mesh (this host only) sets none of
  the three variables.

The mesh also renews `topology.json` in the bound directory from persisted
desired placement and the separate admission registry. It contains `generation`,
UTC `observedAt`, `regions`, and `peers` (`node`, `region`, IPv4 `address`).
TerraBase checks this manifest against the file, directory and loaded runtime
membership; unknown, mismatched or over-30-second-old evidence refuses client
work and readiness while preserving peer repair traffic. Deploy ts-orch before
the companion TerraBase release; neither deployment is performed by this document.

Ports 9095 (health) and 9096 (metrics) belong to NetBird.
The loopback `127.0.0.1:9097/metrics` exporter aggregates every targeted region's
authenticated mesh reports. `ts_orch_peer_topology_*` exposes mismatch, expected
count, rejected generations, native runtime mismatch and observation age; missing
reports fail closed. Reports are bound to the expected topology digest, and
monitoring uses an immutable desired snapshot independently of SwarmKit RPCs.
Install the accompanying monitoring configuration through the rollout owner.
Five-second scrape/evaluation/persistence/group waits put stale evidence on the
existing capped, deduplicating relay within a minute under healthy monitoring.

Validation after both releases: on an isolated cell, drop a peer from its file
and verify mismatch/refusal within 60 seconds, then apply an authorized placement
drain and verify agreement. Never modify a production peers file. Record native
runtime mismatch=0 and expected/file agreement on each recovered production
region, the loaded Prometheus rule and one synthetic deduplicated notification.
