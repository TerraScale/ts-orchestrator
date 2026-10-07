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
ts-orch node add     --config operator.json --node ts-gru-4 --wait 30m
ts-orch node retire  --config operator.json --node ts-gru-4 --wait 30m
ts-orch node rename  --config operator.json --node gru-1-ctl-1 --new-name ts-gru-1 --wait 30m
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
runs steps 3 and 4.

`add` brings in a node that has a host grant, an instance and an enrolled
host agent: its act creates the node's missing backends, out of rotation,
in every set whose `role` it has a replica of, then checks and returns them.
(The edge reconciler would add them too; `add` does it now and reports.)

`retire` takes a node out for good. It refuses a node that runs a
controller (a controller leaves the cell through its membership, not this
command) or still has a replica (move it first; the quorum guard applies as
usual). It fences the node, removes its backends from every set, takes a
FULL backup of its boot volume (`<node>-retired-<yyyymmdd>`, tags
`terrascale-host-node`, `ts-node-operation` and `delete-after`, seven days
later), terminates the instance with its boot volume and waits until it is
gone. Remove the node's host grant from the cell spec afterwards; until
then the edge reconciler reports its missing instance. The leader finds a node's instance by its display name,
the node's name, in its own compartment. Its instance principal needs `manage
instance-family` there (the reviewed controller policy grants it).

`rename` gives a node a new name (TS-609 renames `gru-1-ctl-N` to
`ts-gru-N`), in place. First switch its host grant with one root-signed
generation: `ts-orch service grant-host --node ts-gru-1 --private-ip <its
address> --roles ... --environment ... --controller controller-a` replaces
the old name's grant at that address (`--controller` names the controller
slot whose VM it is; rename refuses a controller node without it). Then
`rename` fences the node at that address, renames its instance, its boot
volume (`<name> (Boot Volume)`) and its primary VNIC's hostname label (the
OS hostname from the next boot; logged and skipped where the leader's
policy cannot update the VNIC), forgets the instance's host enrollment and
reboots it. `host-setup` takes the node from the instance's display name
and enrolls it afresh under the new name. The check waits for that
enrollment, moves every role desired on the old name to the new one,
withdraws them from the old name and retires it, then waits for the roles
to run as usual; the node returns after the load balancer's health checks.
The node's NATS server name, certificate CN and TerraBase member name do not
change (`gru-1-ctl-N` stay internal peer IDs): its TerraBase member is the
one `TERRABASE_PEERS` lists at its address, with the same data and
certificate.

## Who holds a node out

`fenced.<node>` names its holders. The backends return only when the last
one lets go:

| Holder | Set by | Released |
| --- | --- | --- |
| `release` | a service release with a `release_fence` (TS-610) | once the node serves the release |
| `rollout` | the orchestrator's own rollout, before a controller or host step | once the unit proves its release and the node's roles run |
| `operation` | `reboot`, `resize` | at the operation's return step |
| `maintenance` | `drain` | `undrain` |
| `health` | the edge reconciler, for a replica that does not serve | once the node serves |

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

## The edge reconciler

A `release_fence` set that names a `role` belongs to the leader's edge
reconciler: every 30 seconds it makes the set the role's replicas, each in
rotation only while it serves. Every change runs under the node's fence
lock after the set is read again, so it never races a fence or a restore.

- A replica without a backend gets one, created out of rotation and held
  for `health`; it joins once its node serves.
- A replica whose host has reported it `starting`, `stopped` or `failed`
  for 20 seconds is taken out of that set (only), held for `health`, under
  the quorum guard. A late or missing report is no evidence: the load
  balancer's own health check covers it, so a NATS hiccup cannot make the
  set flap.
- A node held for `health` returns once every role on it reports running at
  its desired generation and its backends pass the load balancer's checks.
- Hand edits are undone: a backend put back in rotation while its node's
  record keeps it out goes out again; a backend taken out with no record is
  held for `health` and returns once its node serves; a backup or weighted
  backend becomes a plain one. Each correction is a decision
  (`oci_drift_corrected`).
- A backend whose node has no replica is removed once it serves nothing.
  A backend that is no node of the cell, one that serves healthy without a
  replica, and a granted node whose instance is missing, renamed or not
  running outside a node operation are left alone and recorded once as a
  `held` decision for an operator: they are ambiguous.

Sets without a `role` keep their membership (only fences change them), and
a set whose role reads no replica with a host grant is never emptied.

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
