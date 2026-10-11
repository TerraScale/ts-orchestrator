# NATS fabric

Status: design note for TS-562 and the features that build on it (TS-563
apps and machines, TS-564 Machines API, TS-565 autoscale, TS-566 dedicated
tenants, TS-567 volumes, TS-568 self-healing). Slice 1 (relayed signed
documents, cross-region `ts-orch apply`) is implemented; the rest of this page
is the naming and pattern contract those features use. Change it in the same
PR as the code that needs the change.

## Topology

- One NATS and JetStream cluster per region (the **cell**, token `gru`,
  `sfo`, ...). JetStream quorums never span regions.
- Regions link by mutual-TLS leafnodes in a tree rooted at the global home
  (GRU), bound to a dedicated interregion account
  ([multi-region](multi-region.md#topology)). Only the subjects of
  `natscell.InterRegionContract` cross a link; everything else stays in its
  region by construction, not by convention.
- Each region keeps working during a partition: regional state is local, and
  global state is read from the region's local mirror. Only global writes
  stop.

## Naming rules

Every subject, stream and bucket name is built in `internal/protocol` (a
test rejects `ts.` literals elsewhere), so permissions and the interregion
contract derive from the same builders.

- **Tokens** are lowercase `[a-z0-9_-]`, at most 63 bytes
  (`protocol.ValidateSubjectToken`). A cell token is the lowercase region
  (`protocol.RegionToken`). A caller-controlled identity (machine ID, tenant
  name, node ID) never enters a subject raw: use `protocol.HashToken`, or a
  token the feature validates against this rule.
- **Entity IDs and KV keys** are canonical uppercase 26-character ULIDs,
  without type prefixes ([entity IDs](entity-ids.md)). Node names and symbolic
  region/role/index labels keep their naming contracts. Validate entity IDs
  before using them in a record key or an entity-bearing subject.
- **Wire format**: strict JSON (`protocol.DecodeStrict`), bounded sizes, and
  `protocol.Envelope` (Ed25519, scoped to region, kind, actor, operation,
  generation and epoch) for every signed request.

| Root | Shape | Scope | Use |
| --- | --- | --- | --- |
| `ts.orch.v1` | `ts.orch.v1.<cell>.<family>.<verb...>` | regional | Requests, commands, telemetry (`protocol.Regional`) |
| `ts.control` | `ts.control.<cell\|global>.>` | regional | Authority leases and journal in `TS_CONTROL_LOG` |
| `ts.global.v1` | `ts.global.v1.<kind>.<key>` | global | Records in `TS_GLOBAL_CONTROL`, mirrored everywhere |
| `ts.interregion.v1` | internal | link | Mirror plumbing only; never publish to it |
| `ts.broker` | `ts.broker.<cell>.>` | regional | Broker ticket and fence RPCs |

Families under `ts.orch.v1.<cell>`:

| Family | Crosses a link | Meaning |
| --- | --- | --- |
| `query.<verb>` | yes, as a service to every peer | Read-only request/reply. Responders decode strictly, bound every filter and never mutate. Cross-region reads (status fan-in, inventory) use it. |
| `obs.region`, `obs.decisions` | yes, exactly these | Region summary and decision journal queries |
| `region.health` | yes, as a stream | Region health heartbeat |
| `command.<verb>` and verbs such as `host.register`, `placement.apply` | never | Mutations, answered by the regional authority leader |
| `obs.<leaf>` (others), `observation.<leaf>` | never | Regional telemetry |
| `agent.<hash(node)>.<family>.<leaf>` | never | Host agent RPC |
| `rollout.proof.<hash(unit)>` | never | Signed health proofs |

New features add verbs under these families, for example
`ts.orch.v1.<cell>.command.machine.start` or
`ts.orch.v1.<cell>.query.machine.list`. Never add a new root.

## Streams and buckets

Names are `TS_<NOUN>` in upper case, one per feature slice. A KV bucket
`TS_<NOUN>` is stored in the stream `KV_TS_<NOUN>`. Everything is file
storage with the cell's replica count, and is regional unless listed as
global. Keys are lowercase tokens separated by dots, most general first
(`<app>.<machine>`). Register a new name here in the PR that adds it.

| Name | Kind | Scope | Holds |
| --- | --- | --- | --- |
| `TS_CONTROL_LOG` | stream | regional | Authority leases (regional and global scope), control journal |
| `TS_GLOBAL_CONTROL` | stream | global: home writes, every other region mirrors | Region roster, database directory, term barrier, relayed documents |
| `TS_SERVICE_SET` | KV | regional | The adopted cell spec (`current`) |
| `TS_TRUST_ROOTS` | KV | regional | The cell's root chain |
| `TS_ROLLOUTS` | KV | regional | Desired release, generations, rollout records, steps |
| `TS_HOST_STATE` | KV | regional | Host registrations, sessions, desired state and reports |
| `TS_DELIVERY_*`, `OBJ_TS_ARTIFACTS` | stream, KV, object | regional | Signed artifact delivery |
| `TS_REGION_SUGGESTIONS` | KV | home only | The information-only region suggestion and its saturation and idle clocks ([capacity](capacity.md)) |
| `TS_DECISIONS` | stream | regional | Decision journal |
| `TS_OCI_COST` | KV | regional | The region's OCI cost report (`report`), refreshed hourly by the authority leader ([OCI cost](oci-cost.md)) |
| `terrabase_backup_leases` | KV | regional, memory, 15 s TTL | TS-633's backup shipper leases, used by TerraBase members ([role identities](#role-identities)) |

A configuration bucket that a rebuilt region must get back also goes into
`kvsnapshot.Buckets`, which snapshots it to OCI Object Storage and restores
it on boot (TS-559). That list is `TS_SERVICE_SET`, `TS_TRUST_ROOTS`,
`TS_HOST_ENROLLMENT`, `TS_ROLLOUTS` and `TS_OCI_DESIRED` today.

## Role identities

A role ts-orch places can get its own NATS user (TS-651), so its members
use regional KV buckets without any controller credential. Buckets of a
role are named `<role>_<noun>` in lower case (`-` written `_`), unlike
ts-orch's own `TS_` names. `roleidentity.Grants` lists each role's buckets
and its settings prefix; today only `terrabase` has one.

- **Signer.** The cell account has one scoped signer, role `role`. Its key
  is derived from the host NATS issuer seed (`roleidentity.Signer`), so
  every controller can issue role users without new material. Its template
  grants publish on `$KV.{{tag(kv)}}.>` and the bucket stream's
  `STREAM.INFO`, `STREAM.MSG.GET` and `DIRECT.GET`, and subscribe on
  `_INBOX.>`. Each user carries one `kv:<bucket>` tag per granted bucket, so
  adding a bucket to `Grants` needs only a controller release. Tags are
  lower case, so a role can never name a `TS_` bucket.
- **Queries (TS-668).** A grant's `Queries` are query verbs its members
  answer in their own cell and ask in every cell: users get one
  `query:<verb>` tag each and a `cell:<cell>` tag, and the template allows
  publish on `ts.orch.v1.*.query.{{tag(query)}}.>`, subscribe on
  `ts.orch.v1.{{tag(cell)}}.query.{{tag(query)}}.>` and one response per
  request. The interregion contract carries the query family as a service,
  so a request reaches another region's members over the links. TerraBase
  has `terrabase-wan` (TS-643's cross-region pulls) and `terrabase-stats`
  (TS-806's live database stats detail).
- **Observations (TS-806).** Role users with `obs` tags publish their cell's `obs.<leaf>` (TerraBase: `obs.terrabase`); adding a leaf changes the role scope, so it ships with a cell account re-sign.
- **No stream API beyond reads.** A stream create request names any
  subjects, so a role that could create its bucket could capture
  controller traffic. The leader creates each granted bucket before it
  issues the role's credentials.
- **Replies.** Role users share NATS clients' default `_INBOX` prefix (the
  NATS.Net default TerraBase uses), so one role can see another role's
  JetStream replies. ts-orch's own users reply on private prefixes. Give a
  role confidential replies by moving the template to
  `_INBOX.{{subject()}}.>` once its clients set that prefix.
- **Client certificate.** The host TLS issuer signs it, as it signs host
  certificates, with the URI
  `spiffe://hosts.<cell>.terrascale.internal/roles/<role>/<node>`. It
  expires with the JWT, after 48 hours.
- **Delivery.** A host whose current desired runs the role asks the leader
  (`agent.<hash>.role-identity`) with a fresh nkey and P-256 key, and writes
  the files described in
  [TerraBase's role files](terrabase-runtime-contract.md#role-files).
- **Required transport trust.** The leader issues nothing until the
  brokers' cell account holds the signer. A region founded from material
  generated since TS-663 holds it from the start; a cell founded before
  needs [the role claim](broker-claim-rotation.md#role-claim) once.
- **Live.** gru-1 since 2026-10-07: the
  [delivery record](evidence/ts-651-role-identity-gru-1-20261007.md).

## Which pattern to use

1. **Desired state of one region** (apps, machines and volumes in that
   region): a regional KV bucket. The authority leader writes it after an
   authority `Guard`, by compare-and-set on the revision. Every controller
   reacts to a KV watch, and the change hot-reloads without a restart. This
   is how the cell spec works (`specRegistry.Run`).
2. **State every region needs** (signed releases, fleet policy, another
   region's spec): a **global document** in `TS_GLOBAL_CONTROL`, as
   `ts.global.v1.<kind>.<cell>`. Its author signs it, and the home region's
   global leader only orders and fences it (`Writer.PutDocument`). Each
   region follows its own record (`Reader.Follow`: an ordered consumer on
   its local mirror, plus a recheck). Before acting, the region verifies the
   bytes against **its own** trust, so the relay never widens authority. A
   region keeps serving its mirror during a partition and catches up on heal.
3. **Reading across regions** (rollout status fan-in, `ts-orch rollout
   status` for every region, inventories): request/reply on
   `ts.orch.v1.<peer>.query.<verb>`. The reply is telemetry, never
   admission evidence. Controllers still need publish grants on peer `query`
   subjects (planned in slice 3).
4. **Changing another region**: never a raw command across a link. Use a
   global document that the target verifies (2). Slice 3 defines signed
   cross-region commands (pause, rollback) the same way: an envelope scoped
   to the target region, verified by the target's leader against its own
   trusted signers.
5. **Host agents**: regional only, on their `agent.<hash>` subjects or
   through a regional KV the agent watches.

## Global documents

Shipped kind: `cellspec` (the relay request for
[cross-region apply](cell-spec.md#apply-to-another-region)). Planned kinds:
`release` (TS-560's `releasechannel.Channel`, slice 2) and `policy` (fleet
rollout policy).

To add a kind:

1. Add the `Kind` constant and allow it in `validDocument`
   (`internal/globalcontrol/document.go`).
2. The payload must verify itself, at most 64 KiB, with signatures and
   expiry the target can check against its own roots or trusted signers.
   The record's generation counts payloads only. Ordering and replay checks
   (a document generation that only moves forward) belong to the verifier.
3. The home region writes it only from its global leader
   (`global.authority.Current().CanMutate()`, `PutDocument` with that
   epoch). When the payload carries a generation, the home's handler
   refuses one older than the document already waiting, through
   `PutDocument`'s `admit` check, which the append is conditional on, as
   `relayCellSpec` does.
4. The target follows it with `Reader.Follow`, using an **idempotent**
   apply that acts only on its authority leader and logs a refusal once.
5. Add a two-region test like
   `natscell.TestRelayedCellSpecReachesTheSpokeThroughPartitions`: arrival
   within the target, partition and heal, and a tampered document refused.

Documents are keyed by target cell. A fleet-wide key is added with the
first fleet-wide kind.

## Targets and semantics

- **Config**: live in every region in under 30 s. A mirror delivers in
  well under a second (about 150 ms in the two-region test); a leader
  change is covered by the follower's 10 s recheck.
- **Releases**: start everywhere within seconds of CI publishing them
  (slice 2).
- **Partitions**: a region serves its last mirrored state. A document
  whose signature expires before it arrives (a cell spec lives 24 h) is
  refused and must be signed again.
- **Rollouts**: all at once by default, with automatic rollback on failed
  health. Quorum roles (NATS controllers, TerraBase members) never drop
  below quorum (slice 4, built on `internal/rolloutexec`).

## Slices

1. Relayed signed documents and cross-region `ts-orch apply` (done).
2. Release announcements as `release` documents, which replace each
   region's head-bucket poll in the TS-560 consumer.
3. Status fan-in over `query`, and signed cross-region pause and rollback.
4. All-at-once rollout policy with quorum guards.
5. Host agents react to watches for config hot reload.
