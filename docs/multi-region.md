# Multi-region foundation

Required contract: every admitted region serves, all regions are discovered
automatically and every feature is always on. The current foundation still
guards fabric/global/planner behavior with configuration blocks and a region
subscription switch. TS-796 owns removal and automatic provisioning; this
document inventories the existing implementation without certifying completion.

## Topology

Each region stays its own NATS/JetStream cluster with its own operator. Its
servers follow the [static names](region-bootstrap.md#static-names) of
`internal/naming` (`gru-1-ctl-N` in GRU, `ts-<region>-N` elsewhere); the JetStream
domain and NATS cluster name stay the lower-case cell token (`gru`). The
existing interregion path, still guarded by `nats.embedded.interregion.enabled`,
has these transport properties:

- The JetStream domain is the cell name (`gru`, `sfo`, `fra`).
- Regions link by NATS leafnodes over mutual TLS, never gateways. The links
  form a tree rooted at the global home region (GRU): each spoke dials one
  parent, the hub by default or another spoke for a shorter path
  (`natscell.LeafTopology`). Leafnode loop detection forbids cycles.
- A remote tries its URLs in the configured order, never shuffled: the
  parent controllers' private peering addresses first, then their NetBird
  addresses. The URLs are IPs, so the remote pins `server_name`, a DNS name
  the parent's leaf certificate must carry, and verifies every URL against
  it. A leaf listener binds `0.0.0.0`: controllers have no public IP, and
  the one port serves both the VCN and the NetBird interface.
- NATS has no leafnode-only ping setting, so an interregion server pings
  every connection every 10 s and closes it after 3 unanswered pings. A
  silently dropped path fails over to the next URL in about 30 to 40 s
  (plus 2 to 3 s per further dead URL), instead of minutes. Routes
  (otherwise 30 s and 2 pings) and bridged clients get the same faster
  stale detection. NATS moves on round robin and never fails back: the link
  stays on a NetBird URL until that connection drops too.
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
- `nats.embedded.interregion.topology` carries the whole reviewed tree
  (`hub`, `parents`). When it is set, startup derives this region's view from
  it and refuses any other: `peers` must be every other region of the tree,
  `subtrees` exactly this region's children and their subtrees, `remotes`
  exactly one link to the parent (none at the root), and `global_home` the
  hub. Without it only the region's local view is checked, as before.

## Link (TS-803)

Regions form a star rooted at the global home (`natscell.LinkHome`, GRU). A
region with `nats.embedded.link` set uses it instead of the interregion block;
the two are never set together. The interregion account is being removed by
TS-803: the block above is the old contract and is deleted in the next slice.

- The home listens on `LinkPort` (7422) and needs no list of regions. Every
  other region dials the home's three controllers with one leaf remote.
- Each leaf binds the cell account on both sides (`LocalAccount` is the spoke's
  cell, the user is the home's cell account), so no interregion account, export
  or import exists.
- Every cell account carries one link signing key, the link signer (its public
  key is `LinkSigner` in the material config). `natscell.LinkScope` is its
  scoped template: one role `link` for every region, so a new region needs no
  re-signing.
- A spoke's link user is `natscell.IssueLinkUser`: tagged `cell:<cell>`, issued
  for the home's cell account, with no permissions or limits of its own.
- The template alone decides what crosses (see Links in `region-agnostic.md`).
  Replies to relayed requests need the `*.inbox.>` and `_INBOX.>` publish
  grants, because a leaf's response permission does not carry them.

## Interregion material

`ts-orch bootstrap generate-interregion-material --material-directory
<controller material> --config <reviewed config> --config-sha256 <digest>
--directory <new private dir> --out <public inventory> [--cell-jwt FILE]
[--interregion-ca-cert FILE --interregion-ca-key FILE]` issues a region's
interregion credentials from its controller material
(`bootstrapmaterial.GenerateInterRegion`). The reviewed config is
`{"topology": {"hub": "gru", "parents": {...}}, "listenPort": 7422}`; the
port is required exactly when the region has children. Into a new
owner-only directory it writes:

- `interregion.jwt`: the interregion account, signed by the regional
  operator: exactly the contract's exports and imports, deny-all default leaf
  permissions, `DisallowBearer`, no JetStream, and one scoped signing key per
  direct child whose template is that child's subtree permissions,
  leafnode-only.
- `cell-interregion.jwt` and `system-interregion.jwt`: the cell and system
  accounts reissued with the contract and `LeafNodeConn = 0`. The cell claim
  starts from `--cell-jwt`, the claim the brokers hold, when one was applied
  after the material (a [role claim](broker-claim-rotation.md#role-claim)):
  it must be this material's cell account signed by its operator, and its
  signers (host and role), limits and expiry are kept. Without the flag it
  starts from the material's `cell.jwt`. Either way it is issued strictly
  later. Apply it with `broker-claim-apply` first; the brokers' `cell.jwt`
  and `system.jwt` then carry these two files' bytes.
- per child, `child-<cell>.seed` (its scoped signing key, kept for rotation)
  and `leaf-<cell>.creds`: one leaf-only user that key issued, with no
  permissions or limits of its own. These credentials are pairwise: each
  parent/child link has its own, and they go to that child only, which
  installs them as `leaf-<parent>.creds`.
- `interregion-ca.pem`: the one interregion CA, an EC P-256 root that
  issues leaves directly, name-constrained to
  `.interregion.terrascale.internal`. The hub creates it with
  `interregion-ca.key`; every other region passes the hub's two files
  (`--interregion-ca-cert`, `--interregion-ca-key`, which must be an
  owner-only `0600` file) and holds the certificate only.
- per controller slot, `interregion-tls-<slot>-cert.pem` and
  `interregion-tls-<slot>-key.pem`, with the DNS name
  `leaf.<cell>.interregion.terrascale.internal`: server and client
  certificates in a region with children, client-only otherwise.

Before anything is written, the claims pass the same contract verifier the
server runs at startup, and the credentials pass the dialing side's check.
The material is immutable like the controller material: a second run with
the same input (the cell claim and CA included) returns it, any other input
is refused. Its metadata (`interregion.json`, also the public inventory)
records each file's SHA-256 and purpose, the controller material digest it
was issued from, the digest of `--cell-jwt`, and `ledgerDigest`, the SHA-256
of the whole record, which is the value the deployment's signed bootstrap
ledger records for this material. Files of purpose `owner-only`
(`interregion-ca.key`, `child-<cell>.seed`) are never published.

A child's remote (`bootstrapmaterial.LeafRemote`) lists the parent
controllers' private addresses first, then, given a reviewed NetBird
inventory, their NetBird addresses. Both lists start at the parent
controller with the child slot's index (`controller-b` dials the parent's
`controller-b` first), so the child's brokers spread over the parent's. Its
`server_name` is `leaf.<parent>.interregion.terrascale.internal`.

- The private addresses come from the reviewed private-peer receipt: its
  exact bytes must hash to the reviewed digest, and it must be a passing,
  unexpired `oci_private_peer_foundation_configuration_readback` of exactly
  the parent/child peering that allows the parent's leaf port. Every address
  is inside the parent subnet the receipt observed.
- The NetBird addresses come from the output of `ts-orch netbird
  inventory`, also pinned by digest. It must show the managed network range
  (`10.200.0.0/16`), for every parent controller exactly one connected
  `<parent>-servers` peer registered from the controller's private IP with
  an address in that range, and the enabled fabric policy
  `<child>-servers-to-<parent>-servers-fabric` accepting TCP on the leaf
  port. Any other inventory is refused, never skipped. Without one the
  remote has the private addresses only. The URLs only say where to dial:
  mutual TLS and `server_name` authenticate the parent either way.
- The credentials file must be byte-identical to the parent's issued
  `leaf-<child>.creds`.

`ts-orch bootstrap render-interregion-config --material <public inventory>
--slot <slot> --out FILE` writes one controller's
`nats.embedded.interregion` block (`bootstrapmaterial.RenderInterRegion`),
with every file in the controller credential directory
(`/var/lib/terrascale-orchestrator-secrets`). A child adds
`--parent-material <parent's public inventory> --leaf-credentials <its copy
of leaf-<child>.creds> --receipt FILE --receipt-sha256 HEX`, and optionally
`--netbird-inventory FILE --netbird-inventory-sha256 HEX`. The block passes
the broker's startup check (`natscell.InterRegion.Validate`). It is a
separate command because `render-controller-config` renders the whole
signed config from the manifest candidate and its own reviewed inputs; the
block is merged into the controller config the material generation pins.

## Subject contract

The dashboard link checks a version-1 remote `obs.region` response, with a
1.5-second timeout. A connected leaf alone does not make that check green.
Controllers hold the local `obs.>` subscription and the publish patterns
`ts.orch.v1.*.obs.region` and `ts.orch.v1.*.obs.decisions`. They are valid
whatever regions exist, so a new region needs no credential change. This
leaves remote snapshots, raw journals and mutations unexported. Verify
TerraBase replication separately; dashboard summary success proves control
plane request/reply traffic, not database catch-up.

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

The current global control plane still consumes `controller.global`
(`enabled`, `home`), a TS-796 guard-removal gap. Its authority behavior:

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
- Regional leaders heartbeat on `region.health` every 10 seconds. The home's
  global leader keeps the roster from those heartbeats (a region silent for
  10 minutes leaves it), and every region follows the roster for its links,
  planner peers and, at the home, its mirror consumers. Only heartbeats whose
  cell matches their subject count.
- The home region also creates the durable mirror consumer of every
  interregion peer. A pre-existing consumer under a peer's name that delivers
  anywhere else is refused, never adopted.
- Every other region opens a verified read-only mirror of that stream through
  the interregion contract. During a partition each region keeps serving
  from its mirror; only global changes stop.
- The stream also relays signed documents (`globalcontrol.Document`): the
  exact bytes an operator submitted for one cell, as `ts.global.v1.<kind>.<cell>`.
  The writer only orders and fences them; each record counts its own
  generation, and the target region verifies the bytes with its own trust
  before it acts. Regions follow their documents with an ordered consumer on
  their local stream or mirror (`Reader.Follow`), so a change arrives within
  seconds, and recheck them every few seconds. The first kind is `cellspec`:
  [`ts-orch apply` for another region](cell-spec.md#apply-to-another-region).
  [NATS fabric](nats-fabric.md) has the naming rules and when to use which
  pattern.

### Credentials

Only the home region's controllers may publish the global subjects
(`natscell.GlobalControllerPublishes`: `ts.control.global.>` and
`ts.global.v1.>`). Fresh bootstrap material derives this role from
`catalog.Bootstrap`; all other regions retain regional authority and read the
home mirror through the JetStream API. Linked credential issuance checks the
home in the signed topology.

Before the global lease starts, the home controller checks its credentials
(`natscell.ValidateGlobalControllerPermissions`) and refuses to start with
`ErrMissingGlobalGrants`. Existing controllers require a current-root signed
credential rotation to acquire these grants. Global control runs automatically.

## Region lifecycle

`internal/regionlifecycle` is the state machine from the region auto-start
review: Proposed, Approved, Admitted, one journaled step per effect up to
Active, then RetireProposed, RetireApproved and reverse steps to Retired, plus
Held, RollingBack and Rejected. There are no signed approvals: the region
planner approves its own proposals inside the budget guardrails of
docs/capacity.md (TS-804); until those land, proposals stay Proposed. Spending steps need a cost
admission younger than 15 minutes; admission also enforces the region maximum
and the monthly budget headroom. Records live in the `TS_REGION_LIFECYCLE` KV
bucket and are advanced with compare-and-set under the global lease. The step intent, with a
deterministic create key used as the OCI retry token and ownership tag, is
stored before each effect; after a crash the driver observes before retrying.
Every effect is fenced: the intent is stamped with the leader's epoch by a
compare-and-set before `Execute`, and the lease is guarded again immediately
before it; a recovered intent is re-claimed through `Machine.ClaimStep`,
which re-checks admission freshness. A region that fails after the seed launch
is removed through `ProposeFailedRetire` and the retirement path; its pending
intent is settled by observation before any teardown step. The global home
counts toward the region maximum, budget sums saturate instead of wrapping,
and a held unapproved proposal takes no slot.

`internal/regionplanner` runs on the global home's leader every 10 minutes and
decides from load and budget: it adds a region when a serving region has been
saturated for an hour, and removes an idle one. The rules, guardrails and
their numbers are in code and summarized in docs/capacity.md (TS-804). It
approves its own proposals inside those guardrails, so nothing waits for a
signed approval. Proposal IDs carry the target proposal generation
(`<cell>-g<generation>-<hash>`), so no two attempts on one cell ever share a
proposal ID. Its latest decision, holds included, is saved in the
`TS_REGION_PLANNER` bucket for the dashboard.

### Region operations loop

`internal/regionops` is the global leader's loop, run every
10 minutes while the controller holds the global lease. Each tick it:

1. runs the planner;
2. admits an Approved region at its proposal's estimated price under the region maximum and the budget headroom, and
   readmits an in-flight region before it starts a new spending step once
   its admission is in the last third of its TTL. A refused readmission
   blocks that step even while the older admission is still fresh. A
   journaled (recovered) spending intent is observed first: an existing
   effect is recorded regardless of budget, and an absent one is re-run
   only after a successful readmission. The price is the planner's estimate,
   not a live quote; the admission is re-evaluated against the current fleet each
   time;
3. calls `Driver.Advance` once per region whose next step has
   an effector, and resumes a Held region only when an observation finds
   its pending effect (an absent effect stays held for an operator).

Waits (stale admission, no effector, an OCI effect in progress) and refusals
are journaled once per region and reason.

The only effector so far is the subscription (always on): the home's
instance principal subscribes the tenancy to the proposal's catalog region
(`catalog.Entry.OCIRegionKey`, for example `SJC`), with the step's create key
as the `opc-retry-token`. An accepted but not yet READY subscription holds
the step, and the loop completes it once a later observation finds it READY.
Every other step waits, journaled.

## Not yet done

- Effectors for the remaining lifecycle steps. Foundation (inspect then
  provision) and image import can reuse `internal/ociregion` and
  `internal/ociregion/imageimport`, but those are operator tools built on
  plan files and an admission inventory, not on lifecycle records; they need
  a record-to-plan mapping and ownership tags by create key first. Material,
  seed, link, public API, handoff, activation and teardown are not started.
- Appending interregion material's `ledgerDigest` to the OCI bootstrap
  ledger as its own record kind, and rendering controller configuration
  (cell/system JWT paths, listener, subtrees, topology, remotes) from the
  material.
- A latency signal source (TerraBase client latency rollups).
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
