# Region-agnostic multi-region (TS-803)

Status: design for TS-803. It replaces the TS-774 approach (per-controller
credentials that list exact peers, per-cell release trust and the serial
identity re-key transaction). Each section names the slice that implements it.

Target: 20 regions with no code or manual setup per region (hard limit 32).
Features build on the [registry and subject interface](region-registry.md).

Adding a region must never require a change in any other region: no
re-issued credential, re-signed account, edited inventory, IAM statement or
release grant. Removing a region is equally automatic.

## Why GRU and SFO did not link

| Root cause | Fixed by |
| --- | --- |
| Telemetry aggregation was a config switch that was off. | Always on since TS-796 (#360). |
| Controller NATS credentials listed exact peer subjects, so every new region meant re-issuing credentials in every region. The serving credentials predate even those grants. | [Role and pattern permissions](#nats-roles-and-subject-patterns) |
| The interregion account listed every peer's subjects, one signing key per child and a reviewed leaf tree, all signed offline per region. | [One link, one link signer](#links) |
| Release trust was per cell: SFO's cell spec did not list the CI key GRU trusts, so SFO refused every CI claim (`the claim does not verify in this cell`). | [One release identity](#trust) |
| Every signed scope bound a per-cell deployment ID chosen at founding. GRU and SFO still carry pre-ULID IDs (`ts-550-gru-refound-6`, `ts-640-sfo-found-1`), which current binaries refuse, so no release since TS-754 can reach them. | [Derived identity](#trust) and the [one-time adoption](#one-time-adoption-of-gru-and-sfo) |
| Deploy limited regions to a compiled GRU/SFO/FRA allowlist, scoped the update delegation to listed cells and needed a hand-written IAM statement per region. | [Deploy targets](#deploy-targets) |
| Nothing exercised two or more regions before merge. | [Tests](#tests) |

## Rules

1. **One trust root.** Every region verifies everything with the same baked
   root keys (today one key, Vault `gru-1-trust-root-private-key`, public PEM
   SHA-256 `54842681…`, already baked into all six controllers).
2. **One release identity.** The root delegates release signing to one CI
   release key with one global delegation. Every region checks every release
   the same way; no cell lists release signers.
3. **Identity is derived, never chosen.** A cell's deployment and cluster IDs
   are pure functions of its environment and cell token, so a region has no
   identity to generate, copy or migrate.
4. **Credentials name roles and subject patterns, never peers.** A credential
   is valid whatever regions exist.
5. **Regions discover each other.** NetBird membership admits a node; the
   region registers itself in the global registry; every region follows the
   registry.
6. **Deploy targets are the registry.** No region list exists anywhere else.

## Trust

Slice: trust root.

### Release delegation

The root signs one release delegation (a trust envelope with a fixed global
scope, cell `global`, like today's binary update delegation). It names the CI release key and, in its payload, the
environments, roles and repositories the key may release, and lasts at most
31 days. CI ships it with every orchestrator release channel and every
service claim. A controller admits a claim when:

- the claim's envelope signature verifies with the delegated key;
- the delegation verifies with the cell's current roots and is unexpired;
- the claim's role, repository and environment are in the delegation;
- the claim names this cell (the per-cell claim binding is unchanged, so a
  claim for SFO can never be replayed into GRU).

Cell-spec `signers` keep operator-request authority (who may send operator
commands), but no longer grant release rights; `releasers` are deleted.

The binary update delegation loses its `cells` list: it authorizes the
orchestrator binary in every cell of its environment.

The cell-spec leaf delegation becomes global in the same way: the root
delegates ordinary amendments for every cell of an environment to the release
leaf. Root-only (widening) amendments are unchanged.

The root chain identity is the environment alone, so one rotation statement
rotates every region.

### Derived identity

`trust.DeploymentID(environment, cell)` and `trust.ClusterID(environment,
cell)` derive canonical ULIDs (`entityid.Derive`). Founding and the one-time
adoption use them, so re-founding a region can never mint a new identity and
no region carries an identity anyone chose.

## NATS: roles and subject patterns

Slice: NATS permissions. Every user is issued by a scoped signing key whose
template is one of these roles. `{{tag(cell)}}` is the user's own cell.

| Role | Publish | Subscribe |
| --- | --- | --- |
| controller | own cell `ts.orch.v1.<cell>.>`, `ts.control.<cell>.>`, JetStream/KV/object APIs, broker ticket/fence; **`ts.orch.v1.*.obs.region`, `ts.orch.v1.*.obs.decisions`, `ts.orch.v1.*.query.>`** | own regional services, own `obs.>`, own inbox; responses allowed |
| host | `{{subject()}}`-scoped agent subjects (unchanged) | unchanged |
| role (service) | `ts.orch.v1.*.query.<verb>.>` from its query tags, its KV tags | `ts.orch.v1.{{tag(cell)}}.query.<verb>.>`, `_INBOX.>`; one response per request |
| link (leaf user) | see [links](#links) | |

The global-home grants (`ts.control.global.>`, `ts.global.v1.>`) are part of
the controller role in every region; only the global lease holder uses them.

TerraBase's WAN keeps `ts.orch.v1.*.query.terrabase-wan.>` (publish), its own
cell's subject (subscribe) and one response per request (TS-677).

### Links

Regions link by mutual-TLS leafnodes in a star rooted at the global home
(GRU, `catalog.Bootstrap`). The separate interregion account is removed: a
leaf binds the cell account on both sides, and the leaf user's role template
alone decides what crosses.

- Every cell account lists one global **link signer** (an account signing key
  whose seed lives in OCI Vault) with role `link`.
- A region that is not the home mints its own leaf user at startup with the
  link signer, tagged `cell:<own cell>`, issued for the home's cell account,
  and dials `ts-<home>-<n>.nb.ts.internal:7422` for each home controller. The
  home's leaf certificate name `leaf.<home>.interregion.terrascale.internal`
  and the interregion CA are unchanged.
- The home always listens on 7422 and accepts any leaf user the link signer
  issued. It needs no list of regions.

The link role, from the leaf's point of view:

| Direction | Subjects |
| --- | --- |
| leaf may send | requests `ts.orch.v1.*.query.>`, `ts.orch.v1.*.obs.region`, `ts.orch.v1.*.obs.decisions`; its own `ts.orch.v1.{{tag(cell)}}.region.health`; its own global-mirror reset and flow-control acks; responses |
| leaf may receive | requests for its own cell only (`ts.orch.v1.{{tag(cell)}}.query.>`, `.obs.region`, `.obs.decisions`); every region's `region.health`; its own global-mirror feed; replies to its own users |

A region can therefore never take another region's requests, speak for
another region's health, or touch another region's mirror. Commands, KV,
JetStream, control logs and broker subjects never cross. Each spoke also
denies the regional-only families on its remote, so the home cannot push them
either.

Deleted: the interregion account and its contract, per-peer imports and
exports, per-child signing keys, `LeafTopology`/subtrees, per-pair leaf
credentials, `generate-interregion-material`, `render-interregion-config`, and per-peer
controller telemetry grants (controllers hold `ts.orch.v1.*.obs.*` patterns).

## Discovery

Slice: discovery.

- Every regional authority leader publishes a heartbeat on its own
  `ts.orch.v1.<cell>.region.health` every 10 s: cell, OCI region and
  environment. The link template lets a region publish only its own subject,
  so the heartbeat is authenticated by the link credential.
- The home's global leader keeps the roster (`TS_GLOBAL_CONTROL`,
  `roster/current`, `globalcontrol.Roster`): a region is added on its first
  heartbeat and removed after 10 minutes without one. The home is always in
  the roster.
- Every region follows the roster from its mirror (`Reader.Follow`). Links
  (`regionlink.Links`), `/v1/regions/<region>`, the dashboard, the planner's
  peers, the home's per-region mirror consumers and the TS-796 link probe all
  read that live list. Nothing reads a configured peer list.
- A node's region is inferred from where it runs (OCI instance metadata); its
  NetBird membership admits it (TS-796).

## Deploy targets

Slice: deploy targets.

- The home's global leader publishes the roster to Atlas every 10 s with the
  Vault publish key; `release deploy` keeps discovering serving cells from
  Atlas `/v1/discovery`. Publishing is always on. Atlas lists the roster's
  regions; the spec's `atlas.regions` only overrides display details.
- A cell token is the OCI short region code (legacy alias `sfo` for
  `us-sanjose-1`) and maps to its OCI region through the OCI SDK's region
  table (`common.StringToRegion`), not a compiled allowlist, so any OCI region
  is a valid target.
- One tenancy-level IAM statement lets the CI deploy group write
  `releases/*` in every `*-head` bucket; no statement names a region.
- CI scripts set no home OCI region.

## One-time adoption of GRU and SFO

Slice: adoption. It runs once per region and is then deleted with the TS-774
re-key code. Nothing is re-founded: instances, NATS server names, Raft IDs,
stores, broker and account keys and Vault material stay. NATS keeps quorum
because only one controller is down at a time.

What forces the order (audited on main):

- A current controller exits before READY when `TS_SERVICE_SET/current` holds
  a spec signed for another identity, but starts normally when the key holds
  a spec for its own identity.
- Old and current controllers each treat the other's lease format as corrupt
  and stop leading; neither ever acquires over it.
- Host registrations written by old controllers fail the current identity
  check (`entityid.Derive("host", cell, node)`), and obsolete
  `retired.*`/`retirement-*` keys in `TS_HOST_STATE` stop a current controller
  at startup.

Steps per region, GRU first:

1. **Issue.** Offline, with the root key from Vault, issue the region's records
   under its derived identity: one material generation (existing NATS, TLS and
   Vault material, the link signer, role-pattern controller credentials), three
   signed controller configs and accepted identities, and the next cell-spec
   generation, root-signed with the current content.
2. **Replace shared records.** `ts-orch adopt records` writes the new
   `TS_SERVICE_SET/current`, `TS_TRUST_ROOTS/material-generations` and
   `TS_TRUST_ROOTS/chain` with compare-and-set and deletes the obsolete host
   retirement keys. Running old controllers keep their verified copies and
   keep serving.
3. **Roll the followers.** Stop one follower, install the binary and its local
   records, start it and wait for NATS quorum; then the next. They follow; the
   old leader still serves hosts.
4. **Hand over the lease.** `ts-orch adopt lease` appends one root-signed
   barrier lease under the new identity, compare-and-set on the log head and
   retried on the old leader's renewals. The old leader stops leading and a
   new controller takes the lease within seconds.
5. **Roll the last controller.**
6. **Hosts and releases.** Hosts re-register under the new identity, then the
   next CI release reaches the region. This is TS-677's TerraBase cutover
   window, announced on TS-677 before step 4.
7. **Delete old trust material.** Remove the legacy accepted-install, anchor,
   manifest and chain files, the interregion account files and the pinned
   per-peer credentials.

## Tests

- A three-region in-process test (home plus two spokes) with production-issued
  role credentials and the link signer: requests and observability in every
  direction, health of every region, a spoke cannot answer for another, and a
  fourth region joins and leaves with no change to the other three's inputs.
- CI runs it on every PR.

## Coordination

- TS-796 (#375) owns the always-on link probe, self-heal and WAN evidence; its
  supervisor reads `regionlink.Requester.Regions()`, which the registry feeds.
  Its reconnect callback reconnects this region's link leaves.
- TS-773 owns the TerraBase deploy; TS-677 owns the TerraBase cutover and is
  told before the first release that reaches both regions.
