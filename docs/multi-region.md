# Multi-region foundation

Status: foundation only. Every piece below is off by default; a controller
without the new configuration blocks behaves exactly as before. Nothing here
creates OCI resources.

## Topology

Each region stays its own NATS/JetStream cluster with its own operator. When
`nats.embedded.interregion.enabled` is set:

- The JetStream domain is the cell name (`gru`, `sfo`, `fra`).
- Regions link by NATS leafnodes over mutual TLS, never gateways. The links
  form a tree rooted at the global home region (GRU): each spoke dials one
  parent, the hub by default or another spoke for a shorter path
  (`natscell.LeafTopology`). Leafnode loop detection forbids cycles.
- Every leaf connection binds the dedicated interregion account on both sides.
  The system and cell accounts must set `LeafNodeConn = 0`; the server then
  refuses a leaf user of either account.
- A remote authenticates with a leaf user of the parent's interregion
  account, issued by that child's scoped signing key under the parent's
  operator. The remote pins that account key (`peer_account`). The user
  carries no permissions or limits of its own: the scoped key's template
  (leafnode-only, the child's subtree permissions below) replaces them, and a
  remote refuses credentials that would override it. A user signed by the
  account identity key gets the account's deny-all defaults.
- A region with a leaf listener names each direct child's subtree
  (`nats.embedded.interregion.subtrees`, child to the regions reached through
  it, `LeafTopology.Subtrees`); listener and subtrees are configured together.

## Subject contract

`natscell.InterRegionContract` lists every subject that may cross, as explicit
exports and imports between the cell and interregion accounts:

| Direction | Subject | Type |
| --- | --- | --- |
| out | `ts.orch.v1.<cell>.region.health` | stream |
| out | `ts.orch.v1.<cell>.query.>` | service |
| in, per peer | `ts.orch.v1.<peer>.region.health` | stream |
| in, per peer | `ts.orch.v1.<peer>.query.>` | service |
| out / in, per peer | `ts.orch.v1.<cell>.obs.region`, `ts.orch.v1.<cell>.obs.decisions` (exact subjects) | service |
| home out, per peer | `ts.interregion.v1.<peer>.global` (fixed delivery subject) | stream |
| home out, per peer | `$JS.API.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-<peer>` as `ts.interregion.v1.<home>.jsapi.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-<peer>` | service |
| home out, per peer | `$JS.FC.TS_GLOBAL_CONTROL.global-mirror-<peer>.*` | service |
| spoke in | the three home subjects above for its own mirror only | |

No consumer-create, stream, account or wildcard JetStream API subject is ever
exported. A JetStream consumer-create request carries its own
`deliver_subject`, which the home region would resolve in its cell account, so
exporting it would let a peer push home-stream records onto any hub-local
subject (an earlier revision did, and a review probe delivered onto
`ts.orch.v1.gru.placement.apply`). Instead the mirror uses durable sourcing:
the home region itself creates one durable push consumer per peer
(`globalcontrol.MirrorConsumerConfig`, ack policy flow control) whose delivery
subject is that peer's fixed contract subject, and the peer's mirror
(`Mirror.Consumer`) only resets that consumer and acknowledges through its
flow-control replies. A peer can never choose where the home region delivers.

Only the region summary and decision query observability services cross,
as exact request/reply subjects; member snapshots and the raw journal stream
stay regional. Both responders decode requests strictly and bound every
filter. `regionlink` links every interregion peer through the cell
connection, so peers no longer show as `not_linked`.

The interregion account's default leaf permissions deny everything. Each
direct child gets one scoped signing key whose template is
`InterRegionContract.ChildLeafPermissions(child)`, and startup verifies there
is exactly one such key per child with exactly that template. Accepted leafs
are always children in the tree, so each roster contract subject is allowed
only in the direction it travels from that child, for its own subtree alone
(transit included): a child may send its subtree's health, query and
observability requests to any region, and its subtree's mirror resets/acks;
it may receive any health, requests for its subtree's query and observability
services and its subtree's mirror feeds, plus the `_R_.>` service-reply
namespace NATS creates for the contract's service imports. A child can never
speak for the accepting region, the global home or a sibling's subtree, take
a sibling's requests, reset or acknowledge a sibling's mirror consumer, or
send a mirror feed. The hub closes any leaf
link that publishes anything else, so one peer cannot relay onto another
peer's subjects (for example, forge another region's mirror feed). Regression tests replay the
review probe from a peer cell and over a raw leafnode connection with a valid
leaf credential.

Known limit: NATS exempts inbound `_R_` publishes from leaf permission
checks, and a child must receive `_R_` deliveries for its own replies, whose
prefix is random per server start. A child that subscribes to `_R_.>` can
therefore see replies to other regions' requests through its hub, and could
only forge one by guessing an in-flight request's random reply token before
the real responder answers (service exports are singleton responses).

A mirror's own region can still reset its consumer to any sequence, including
one ahead of what the mirror stored, which would skip home records for good.
The home stream can never lose a record, so a mirror reader
(`globalcontrol.OpenMirror`) checks on every read that the mirror holds a
gap-free prefix of the home stream and otherwise fails closed with
`globalcontrol.ErrMirrorGap`; recreate the mirror to recover. Reopening the
home stream deletes the `global-mirror-<peer>` consumers of removed peers.

Startup, and every later cell claim replacement, verify the installed account
JWTs, including the default leaf permissions and child signing keys, against
this contract exactly. The embedded resolver reports `IsTrackingUpdate`, so
the server ignores `$SYS.REQ.ACCOUNT.<account>.CLAIMS.UPDATE` (routed or
client-sent); each broker installs a replacement only through
`Runtime.ApplyCellClaim`, after the pinned-operator, contract and issued-at
checks.
Commands, agent traffic, control logs, inboxes and broker subjects never cross
a link. Subjects are built by `internal/protocol`; a test rejects `ts.` string
literals elsewhere.

## Global state

`controller.global` (`enabled`, `home`) turns on the global control plane:

- In the home region, a global-scope `authority.Runtime` holds the
  `ts.control.global.lease` lease in the regional control log, and
  `globalcontrol.Writer` writes the region roster and database directory to
  `TS_GLOBAL_CONTROL` (`ts.global.v1.>`). Writes are fenced in the stream
  itself: a new leader appends a term barrier (`ts.global.v1.term.current`)
  right after its lease `Guard`, and every record append is a whole-stream
  compare-and-set on the last sequence at which the writer saw its own term
  plus a per-subject compare-and-set, with a `Ts-Global-Epoch` header that
  must match the record. A leader that passed its `Guard` and then paused can
  never commit after a newer term's barrier.
- The home region also creates the durable mirror consumer of every
  interregion peer. A pre-existing consumer under a peer's name that delivers
  anywhere else is refused, never adopted.
- Every other region opens a verified read-only mirror of that stream through
  the interregion contract. During a partition each region keeps serving
  from its mirror; only global changes stop.

### Credentials

Only the home region's controllers may publish the global subjects
(`natscell.GlobalControllerPublishes`: `ts.control.global.>` and
`ts.global.v1.>`). Bootstrap material issues them when its config sets
`globalHome: true`; Lab NKey controller grants use `global: true`. Every other
region's controller keeps its regional grants and reads the mirror through the
JetStream API it already has.

Before the global lease starts, the home controller checks its credentials
(`natscell.ValidateGlobalControllerPermissions`) and refuses to start with
`ErrMissingGlobalGrants` instead of retrying a denied publish forever.
Material is immutable, so making a region the global home (or rotating an
existing home onto the new grants) means generating new material with
`globalHome: true`, rolling the controllers onto it, and only then enabling
`controller.global`. Turning `globalHome` off again needs the same rotation.

## Region lifecycle

`internal/regionlifecycle` is the state machine from the region auto-start
review: Proposed, Approved, Admitted, one journaled step per effect up to
Active, then RetireProposed, RetireApproved and reverse steps to Retired, plus
Held, RollingBack and Rejected. Approvals are Ed25519-signed protocol
envelopes from configured approvers, bound to the exact proposal digest and
proposal generation. Spending steps need a cost admission younger than 15
minutes; admission also enforces the region maximum and the global monthly
ceiling. Records live in the `TS_REGION_LIFECYCLE` KV bucket and are advanced
with compare-and-set under the global lease. The step intent, with a
deterministic create key used as the OCI retry token and ownership tag, is
stored before each effect; after a crash the driver observes before retrying.
Every effect is fenced: the intent is stamped with the leader's epoch by a
compare-and-set before `Execute`, and the lease is guarded again immediately
before it; a recovered intent is re-claimed through `Machine.ClaimStep`,
which re-checks approval expiry and admission freshness. A region that fails
after the seed launch is removed through `ProposeFailedRetire` and the signed
retirement path; its pending intent is settled by observation before any
teardown step. Approvals can be renewed in flight (`RenewApproval`,
`RenewRetireApproval`). The global home counts toward the region maximum and
the budget, budget sums saturate instead of wrapping, and a held unapproved
proposal takes no slot.

`internal/regionplanner` turns unplaceable placement intents, classified OCI
capacity and limit errors, and latency rollups into proposals. It only
proposes; a human or policy approval is always required. With
`controller.region_planner` enabled (global home only, off by default) it runs
on the global leader and feeds its budgets to the insight engine;
`controller.rollouts` likewise opens the rollout store for the dashboard and
insights.

## Not yet done

- Effectors for the lifecycle steps (subscription, foundation, image,
  material, seed, link, public API, teardown), and their wiring into a global
  leader loop.
- Issuing interregion account JWTs, per-child scoped signing keys and leaf
  credentials in `internal/bootstrapmaterial`, bound to the signed ledger, and taking leaf
  remote URLs only from the reviewed private-peer receipt.
- Granting controllers publish rights on peer `query` subjects, signed region
  health heartbeats (`internal/regionhealth`), and directory-gated placement
  admission.
- Home-region transfer and cross-region disaster recovery.
- Fencing admission across records: each lifecycle write is a per-record
  compare-and-set under the lease, so during a lease handover an old leader
  and the new one could each admit a different region against the same fleet
  snapshot and together exceed the region maximum or the ceiling.
- `TS_GLOBAL_CONTROL` records written before the `Ts-Global-Epoch` header
  existed read as corrupt. Global control is off by default; a region that
  ever enabled it must recreate the stream (there is no migration).
