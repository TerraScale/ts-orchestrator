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
- Each node pings every region every 5 s (`ts.mesh.ping`; the reply now
  carries the node's `wt0` IPv4). A region that stops answering drops out
  within about 10 s and returns on its next answer.
- The own line needs the host's `wt0` IPv4; without NetBird the mesh does not
  apply the service and retries on its next round.
- `ts-orch service apply` without a running mesh (this host only) sets none of
  the three variables.
