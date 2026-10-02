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
- A remote authenticates with a leaf-only user of the parent's interregion
  account, issued under the parent's operator. The remote pins that account
  key (`peer_account`). The user carries no permissions of its own, so the
  account's deny-by-default leaf permissions (below) apply; a remote refuses
  credentials that would override them.

## Subject contract

`natscell.InterRegionContract` lists every subject that may cross, as explicit
exports and imports between the cell and interregion accounts:

| Direction | Subject | Type |
| --- | --- | --- |
| out | `ts.orch.v1.<cell>.region.health` | stream |
| out | `ts.orch.v1.<cell>.query.>` | service |
| in, per peer | `ts.orch.v1.<peer>.region.health` | stream |
| in, per peer | `ts.orch.v1.<peer>.query.>` | service |
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

The interregion account also carries deny-by-default leaf permissions
(`InterRegionContract.LeafPermissions`, installed as the account's default
permissions). Accepted leafs are always children in the tree, so each roster
contract subject is allowed only in the direction it travels from a child,
transit included: a child may send its subtree's health, query requests and
mirror resets/acks, and receive health, its subtree's query requests and
mirror feeds, plus the `_R_.>` service-reply namespace NATS creates for the
contract's service imports. A child can never speak for the accepting region
or the global home, and can never send a mirror feed. The hub closes any leaf
link that publishes anything else, so one peer cannot relay onto another
peer's subjects (for example, forge another region's mirror feed). Regression tests replay the
review probe from a peer cell and over a raw leafnode connection with a valid
leaf credential.

All children of a hub share its interregion account and so the same leaf
permissions: a child can also reset or acknowledge a sibling's mirror
consumer. NATS accepts a reset to any sequence, including one ahead of what
the mirror stored, and the mirror then skips those home records for good. The
home stream can never lose a record, so a mirror reader
(`globalcontrol.OpenMirror`) checks on every read that the mirror holds a
gap-free prefix of the home stream and otherwise fails closed with
`globalcontrol.ErrMirrorGap`; recreate the mirror to recover. Per-peer leaf
users would remove the sibling reach altogether and are a follow-up.

Startup, and every later cell claim replacement, verify the installed account
JWTs, including the default leaf permissions, against this contract exactly.
Commands, agent traffic, control logs, inboxes and broker subjects never cross
a link. Subjects are built by `internal/protocol`; a test rejects `ts.` string
literals elsewhere.

## Global state

`controller.global` (`enabled`, `home`) turns on the global control plane:

- In the home region, a global-scope `authority.Runtime` holds the
  `ts.control.global.lease` lease in the regional control log, and
  `globalcontrol.Writer` writes the region roster and database directory to
  `TS_GLOBAL_CONTROL` (`ts.global.v1.>`). Each write calls `Guard` right
  before a per-subject compare-and-set publish.
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

`internal/regionplanner` turns unplaceable placement intents, classified OCI
capacity and limit errors, and latency rollups into proposals. It only
proposes; a human or policy approval is always required.

## Not yet done

- Effectors for the lifecycle steps (subscription, foundation, image,
  material, seed, link, public API, teardown), and their wiring into a global
  leader loop.
- Issuing interregion account JWTs and pairwise leaf credentials in
  `internal/bootstrapmaterial`, bound to the signed ledger, and taking leaf
  remote URLs only from the reviewed private-peer receipt.
- Granting controllers publish rights on peer `query` subjects, signed region
  health heartbeats (`internal/regionhealth`), and directory-gated placement
  admission.
- Home-region transfer and cross-region disaster recovery.
