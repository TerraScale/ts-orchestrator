# Node operations (TS-632)

ts-orchestrator is the only owner of a cell's servers and of its load
balancer backends. Humans and agents change them with `ts-orch node`, never
with the `oci` CLI, the console or scripts: a hand edit races the leader,
which takes nodes out of rotation for releases and rollouts on its own.

```sh
ts-orch node status  --config operator.json
ts-orch node drain   --config operator.json --node ts-gru-2 --wait 15m
ts-orch node undrain --config operator.json --node ts-gru-2 --wait 15m
ts-orch node reboot  --config operator.json --node ts-gru-2 --wait 30m
ts-orch node resize  --config operator.json --node ts-gru-2 --ocpus 1 --memory-gb 4 --wait 30m
```

Every command is a signed request to the cell's authority leader on the
host registration subject, like `ts-orch rollout`. `status` needs any trusted
signer; the others need the signer's `can_register_hosts` grant. A
command prints the leader's reply as JSON; `--wait D` then polls until the
operation is `done` (exit 0) or `failed` (exit 1, with the reason).

## The flow

The leader runs one operation at a time, oldest first, each in the same
steps, recorded in the `nodeop.<node>` key of `TS_RELEASE_CHANNEL` before
each step starts, so a new leader resumes it:

1. **fence**: take the node's backends out of every set the cell spec's
   `release_fence` names: drain, wait `drain_grace_seconds` (15 s) for
   in-flight requests, then offline, since a drain alone keeps the load
   balancer's pooled connections. Each change waits for the set's quorum
   guard (below). The backends are recorded under `fenced.<node>` before
   the load balancer changes.
2. **act**: only once the node's controller, if it runs one, is in a whole
   JetStream cluster that keeps its quorum without it. `reboot` soft-resets
   the instance; `resize` updates its shape, which OCI applies with a
   restart (a node already at the shape is not restarted).
3. **check**: the instance is `RUNNING` with the requested shape, its host
   agent reports from a new session (the node really restarted), its
   controller is back in a whole cluster, and every role desired on the node
   reports `running` at its desired generation since the action. `running`
   needs the member's `/readyz`: TerraBase answers it only once it has caught
   up with the catalog primary, ts-auth once its storage and keys work.
4. **return**: the backends go back to rotation and the leader waits for
   the load balancer's own health checks to pass. A node that never serves
   stays out and the operation fails; fix it and run `undrain` (which
   releases the failed operation's hold too) or the operation again.

`drain` stops after step 1 and keeps the node out until `undrain`, which
runs steps 3 and 4. The leader finds a node's instance by its display name,
the node's name, in its own compartment. Its instance principal needs `manage
instance-family` there (the reviewed controller policy grants it).

## Who holds a node out

`fenced.<node>` names its holders. The backends return only when the last
one lets go:

| Holder | Set by | Released |
| --- | --- | --- |
| `release` | a service release with a `release_fence` (TS-610) | once the node serves the release |
| `rollout` | the orchestrator's own rollout, before a controller or host step | once the unit proves its release and the node's roles run |
| `operation` | `reboot`, `resize` | at the operation's return step |
| `maintenance` | `drain` | `undrain` |

So a drained node stays out while a release restarts it, and a release
never returns a node an operator took out. `ts-orch node status` lists every
fenced node with its holders.

## Quorum guard

A backend is taken out only while at least `min_serving` backends of other
nodes serve healthy in its set; the cell spec sets it per fenced set, and
zero means 2 (two TerraBase members, two ts-auth replicas). Changes that take
a backend out are serialized in the leader, so two nodes never pass the
guard on the same observation. `ts-orch node` refuses an operation that would
break the guard now; a fence that starts while the guard holds waits
(queues) until it is free, within its operation's 30 minutes. A pool with
only `min_serving` members can therefore never take one out: lower its
`min_serving` in the cell spec first, knowing the set then serves from one.

## Deploys drain first

With a `release_fence`, the orchestrator's self-update (controller and host
rollouts, [continuous delivery](continuous-delivery.md#leader-run-controller-self-update))
takes each unit's node out of rotation before its step: the executor's
gate starts the fence and holds the step until every backend of the node is
offline, one node at a time. The leader returns the node once its unit
proves the release it should run (the target, or the previous one after a
rollback) and every role on the node reports running since this leader
first saw that process. A rollout that ends before stepping a fenced unit returns its node
too. This makes `TS_AUTO_DEPLOY_CELLS` safe for a cell with a release fence.
