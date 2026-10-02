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
  key (`peer_account`).

## Subject contract

`natscell.InterRegionContract` lists every subject that may cross, as explicit
exports and imports between the cell and interregion accounts:

| Direction | Subject | Type |
| --- | --- | --- |
| out | `ts.orch.v1.<cell>.region.health` | stream |
| out | `ts.orch.v1.<cell>.query.>` | service |
| in, per peer | `ts.orch.v1.<peer>.region.health` | stream |
| in, per peer | `ts.orch.v1.<peer>.query.>` | service |
| home out | `$JS.API.CONSUMER.CREATE.TS_GLOBAL_CONTROL[.>]` as `ts.interregion.v1.<home>.jsapi.CONSUMER.CREATE.TS_GLOBAL_CONTROL[.>]` | service |
| home out | `$JS.FC.TS_GLOBAL_CONTROL.>` | service |
| home out, per peer | `ts.interregion.v1.<peer>.global.>` | stream |
| spoke in | the three home subjects above, for its own delivery prefix | |

Startup, and every later cell claim replacement, verify the installed account
JWTs against this contract exactly. Commands, agent traffic, control logs,
inboxes and broker subjects never cross a link. All subjects are built by
`internal/protocol`; a test rejects `ts.` string literals elsewhere.

## Global state

`controller.global` (`enabled`, `home`) turns on the global control plane:

- In the home region, a global-scope `authority.Runtime` holds the
  `ts.control.global.lease` lease in the regional control log, and
  `globalcontrol.Writer` writes the region roster and database directory to
  `TS_GLOBAL_CONTROL` (`ts.global.v1.>`). Each write calls `Guard` right
  before a per-subject compare-and-set publish.
- Every other region opens a verified read-only mirror of that stream through
  the interregion contract. During a partition each region keeps serving
  from its mirror; only global changes stop.

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
