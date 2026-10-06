# Zero-downtime TerraBase rollouts (TS-571)

Status: design note. Slice 1 (the L7 backend-set reconciler) and the
controller half of slice 2 (`oci_reconcile.public_lb`) are implemented; the
rest is **PROPOSED**.

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

**PROPOSED:** `public_api.terrabase_members` is removed. `public-api apply` creates the
`terrabase` backend set and stamps the ownership tags, and its converge step
stops rewriting that set's backends (it compares `ip:port` only and would
clear drain flags).

The controllers' instance principal needs `use load-balancers` in the
network compartment.

### 3. Serving means caught up (slice 3, PROPOSED)

The host reports a member `running` only after `/healthz` answers. It will
also require the member's client `/readyz` to answer 200 over the member's
TLS listener, the path the load balancer checks. TS-561 makes `/readyz`
answer 200 only once the member has caught up with its peers. The release
gate (`terraBaseReady`) counts `running`, so it tightens with it.

TS-561 must keep `/readyz` about the member's own catch-up, not its peers'
liveness: with two seats (gru-1) the surviving seat has to keep serving reads
and writes while its pair restarts, or no drain order can avoid 5xx.

### 4. One seat at a time: a restart permit (slice 4, PROPOSED)

The host agent already asks the controller for a `cycle` before it replaces
a process, and waits quietly until the cycle is `active`; it asks again
just before launch. The controller grants a `terrabase` cycle that replaces a
running member only when the seat holds a restart permit. Delivery, receipts,
generations, authority epochs and the CLI rollback stay as they are. Every
restart path that goes through `cycle` is covered, including the host's
certificate-renewal restart.

A leader-only seat controller hands out permits:

1. Pending seats are those whose desired generation is above the one their
   host reports. `rollout.PlanWaves` puts the seats of one replication group
   in separate waves, so a quorum pair never restarts together. Non-serving
   seats go first; restarting them costs no capacity.
2. Drain: the seat enters the drain set (KV) and the controller applies it at
   once. It waits until the load balancer shows the backend drained and the
   member reports no request in flight, at most 100 s (Cloudflare's proxy
   timeout). The reconciler's health guard refuses to drain the last healthy
   seat.
3. Restart: it grants the permit. The host fetches the artifact first, then
   stops the member with SIGTERM, which drains what is left, and starts the
   new release.
4. Serve: it waits for the host to report the seat `running` (slice 3: caught
   up) at the target generation, then for load balancer health checks taken
   after the new process started to pass while the seat is still drained.
   Older `OK` results can predate the restart.
5. Undrain: the seat leaves the drain set before the next wave.

Everything is level-triggered from KV and observations, so a new leader
resumes where the old one stopped. A seat a deposed leader left drained
stays drained until its step finishes. A newer desired generation supersedes
a pending permit, so the CLI's rollback intent rolls back one seat at a time
too. `terrabase-release` scales its gate wait with the seat count.

The drain set is generic. Host reboots for OS updates (TS-570) and
self-healing (TS-568) can drain a seat through it before they restart its
host.

### 5. Acceptance (slice 5, PROPOSED)

A load test drives requests through a load balancer that honours drain and
`/readyz` while `terrabase-release` runs, and fails on any 5xx; then the same
release on gru-1, with both members in the backend set once TS-561 ships.

## Risks to verify

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
