# Zero-downtime TerraBase rollouts (TS-571)

Status: design note. Slices 1 to 4 are implemented: the L7 backend-set
reconciler, seats as backends, `running` needs `/readyz`, and one seat at a
time behind its drain (`controller.terrabase_seats`). Slice 5, the
acceptance under load, is **PROPOSED**; see the risks at the end.

## Problem

A TerraBase release is an outage today:

- The public load balancer's `terrabase` backend set lists only the members
  in the regional plan's `public_api.terrabase_members` (gru-1: `gru-1-db-1`).
  `oci-region public-api apply` writes it; nothing follows the members.
- `operator terrabase-release` submits one delivery intent for every member.
  The delivery service writes every member's host desired in one pass, so
  every host stops its member at the same moment.

## Goal

A release restarts one seat of a quorum group at a time. Before a seat
restarts, the load balancer stops sending it requests; it gets them back only
after it serves the new release and has caught up with its peers. The load
balancer returns no 5xx during the release (acceptance: under load in e2e,
then on gru-1).

## Design

### 1. L7 backend-set reconciler (`internal/ociresource/lb`, slice 1)

The public API is an OCI flexible (L7) load balancer, so it gets its own
`ociresource` kind, `lb-backends`, beside the NLB one (`nlb-backends`). A
spec names the load balancer, one backend set and its backends; each backend
is `ip:port` plus a `drain` flag.

- Ownership: the load balancer must carry the controller's ownership tags for
  the key, or the controller reports it foreign and never touches it. The tags
  name one key, so one load balancer has one reconciled backend set; the
  `ts-auth` set stays with `public-api apply`.
- A spec in which no backend serves (none, or all drained) is refused unless
  it sets `allowEmpty`.
- Order: create, undrain, drain, remove; one OCI work request at a time, each
  fenced by the authority epoch. The serving set never drops below the new
  spec's serving backends while a plan applies.
- Health guard: before it drains or removes a serving backend, the reconciler
  reads the set's health and holds the rest of the plan
  (`ErrNoHealthyBackend`) unless a backend the spec keeps serving already
  reports `OK`. A backend the same plan created does not count.
- The reconciler owns the set: every listed backend is weight 1, neither
  backup nor offline. `drain` in the spec is the only way to take one out of
  rotation.
- Drain flips do not restamp the ownership tags, because OCI serializes
  every work request and a flip is on a rollout's critical path. The next
  pass that changes nothing else restamps them.

TS-563 owns service discovery and LB sync; it can fold this kind and the NLB
kind together. The spec stays a plain backend list so that is mechanical.

### 2. Backends are the signed seats (slice 2)

A seat is one member the signed workload profile's `TERRABASE_PEERS` names.
On every OCI reconcile pass the authority leader publishes the `terrabase`
backend set: every seat at the profile's client port, drained when it is in
the cell's drain set (slice 4). Seats are not removed when a host report is
late: the load balancer's own `/readyz` check keeps a seat that does not
serve out of rotation, and a NATS hiccup cannot make the backend set flap.

Implemented: `oci_reconcile.public_lb` publishes the seats every pass (see
[OCI reconcile](oci-reconcile.md)). Its optional `seats` list keeps gru-1 at
`gru-1-db-1` until TS-561 replicates the catalog. The drain set is slice 4.

`public_api.terrabase_members` seeds the set when `public-api apply`
creates the load balancer. When the plan names `orchestrator_owner`, apply
stamps the controller's freeform ownership of
`<CELL>/lb-backends/public-terrabase` on the load balancer, keeping its other
tags and refusing one another owner claims; its converge step then no longer
rewrites the set's backends (it compared `ip:port` only and would clear drain
flags), and its readback accepts planned members only, drained or not, with
one serving. A plan without an owner hands nothing to the controller, so
apply keeps converging and checking the set against the seed; on a load
balancer that already carries ts-orchestrator ownership it is refused
before any change. Ownership is validated and stamped before apply changes
anything else.

The controllers' instance principal needs `use load-balancers` in the
network compartment.

### 3. Serving means caught up (slice 3)

The host reports a member `running` only after `/healthz` answers and its
client `/readyz` answers 200 over the member's TLS listener, verified
against the member CA, the path the load balancer checks. TS-561 makes `/readyz`
answer 200 only once the member has caught up with its peers. The release
gate (`terraBaseReady`) counts `running`, so it tightens with it.

TS-561 must keep `/readyz` about the member's own catch-up, not its peers'
liveness: with two seats (gru-1) the surviving seat has to keep serving reads
and writes while its pair restarts, or no drain order can avoid 5xx.

### 4. One seat at a time: a restart permit (slice 4)

The host agent already asks the controller for a `cycle` before it replaces
a process, and waits quietly until the cycle is `active`; it asks again
just before launch. The controller grants a `terrabase` cycle that replaces a
running member only when the seat holds a restart permit. Delivery, receipts,
generations, authority epochs and the CLI rollback stay as they are. Every
restart path that goes through `cycle` is covered; the host's
certificate-renewal restart stops the member directly and must move onto
`cycle` before slice 4 is enabled.

Implemented (slice 4a): `host.ControllerConfig.RestartGate` is asked once
per new cycle, when the controller would open it, and a grant holds across
the request's compare-and-set retries; the host's revalidation before launch
resolves the cycle it holds and is not asked again. A cycle it
does not grant is answered `held`, and the host keeps the running member and
reports it `waiting` at the new generation. Managed members stop their
workload before they ask, so the gate never sees them; their drain receipts
order their restarts. Nothing sets the gate yet.

Implemented (slice 4b): `internal/seatrollout` keeps one record per seat in
the replicated `TS_TERRABASE_SEATS` bucket: a drain flag with its time, the
highest desired generation the seat may restart into, and the authority
epoch of the write. Writes are fenced and compare-and-set; a record that does
not decode, names another seat or breaks its invariants fails every reader
closed. `public_lb` publishes drained seats drained, and `Store.Granted` is
the restart gate for static TerraBase members. Nothing writes records yet.

A leader-only seat controller (`seatrollout.Controller`, slice 4c) hands
out permits. Every tick it reads the seat records, each seat's desired and
report, and the load balancer's backends, and takes at most one step per
seat:

1. Pending seats are those whose host does not report their desired
   generation `running`. At most one seat of a replication group is in
   flight, the rule `rollout.PlanWaves` applies to quorum groups; all C#
   members form one group today, so seats go one at a time. Seats the load
   balancer does not serve go first; restarting them costs no capacity, so
   they get their permit without a drain.
2. Drain: a serving seat is marked drained, but only while another seat
   serves healthy and undrained on the load balancer, and the reconciler's
   health guard refuses the last healthy one again.
3. Restart: once the load balancer shows the backend drained and a grace
   (`DefaultDrainGrace`, 15 s) for in-flight requests has passed since it
   first did (the load balancer may apply a drain late), it grants the
   permit. The host stops the member with SIGTERM, which drains what is
   left, and starts the new release.
4. Serve: it waits for the host to report the seat `running` at the target
   generation, which includes its `/readyz` (slice 3), and to keep doing so
   for `DefaultSettle` (10 s). It does not rely on the load balancer's health
   for a drained backend, which may be stale or not checked.
5. Undrain: the seat returns to rotation. The next seat drains only once the
   load balancer shows this one undrained and healthy.

A seat that never serves after its permit holds its group: the other seats
keep the old release until a newer desired generation, such as the CLI's
rollback intent, supersedes the permit; the rollback then restarts that
seat first, since it serves nothing. Everything is level-triggered from the
records and observations, so a new leader resumes where the old one stopped;
a seat a deposed leader left drained stays drained until its step finishes.
Only the authority leader writes, and every write is fenced by its epoch.

Implemented (slice 4c): the controller and its tests. Implemented (slice
4d): `controller.terrabase_seats` turns it on: the controller opens the seat
records, sets them as the host restart gate and runs the seat controller on
the leader; with `public_lb` it reads the load balancer's backends and wakes
the OCI reconcile runner after every step (`ociresource.Runner.Wake`), so a
drain applies at once instead of on the next pass. `terrabase-release` waits
five minutes per seat when that exceeds its ten-minute default.

The drain set is generic. Host reboots for OS updates (TS-570) and
self-healing (TS-568) can drain a seat through it before they restart its
host.

### 5. Acceptance (slice 5, PROPOSED)

A load test drives requests through a load balancer that honours drain and
`/readyz` while `terrabase-release` runs, and fails on any 5xx; then the same
release on gru-1, with both members in the backend set once TS-561 ships.

## Risks to verify

- The host's certificate-renewal restart (`terraBaseRunningReport`) stops the
  member without asking the restart gate, so it is neither drained nor
  serialized with a release. It happens about once per member every 90 days,
  staggered one to seven days by node, and ends once TerraBase reloads
  renewed certificates (TS-464). Routing it through the seat controller needs
  a new host signal and is follow-up work.

- Whether OCI keeps health-checking a drained backend (step 4 needs it);
  check on gru-1 before slice 4 relies on it.
- Keep-alive reuse: a drained backend keeps its open connections, and a member
  that closes idle connections on SIGTERM races the load balancer reusing
  them. Step 2 waits for in-flight requests to end; e2e must show no 502.
- Seats of one release run old and new versions side by side, so TerraBase
  replication must stay compatible across one release.
- If `terrabase-release` dies mid-release, the remaining seats still move one
  at a time, but nothing rolls a failing release back until an operator
  submits a new intent.

## Out of scope

Managed members (placement-published desired) keep their own drain receipts;
scale-in and member replacement are separate work.
