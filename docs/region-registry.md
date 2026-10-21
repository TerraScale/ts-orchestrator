# Region registry and cross-region subjects (v1)

Status: interface contract from TS-803 for features that span regions
(TS-804 capacity and region creation, TS-805 global dashboard, TS-806
TerraBase telemetry, TS-807 OCI cost, TS-808 production logs). Build on these
names only; the design is in [region-agnostic](region-agnostic.md). Sized for
20 regions, hard limit 32.

A new region must never need code, configuration or a manual step in any
other region. Nothing below lists regions; everything reads the registry.

## Region identity

- A region is one OCI region. Its **cell token** is the lowercase OCI short
  region code (`gru`, `fra`, `lhr`, `nrt`, ...), with one legacy alias:
  `sjc` is OCI `us-sanjose-1` (`sjc`). Tokens match
  `protocol.RegionToken`.
- `OCIRegion` is the OCI region identifier (`sa-saopaulo-1`).
- A region's deployment and cluster IDs are derived from environment and cell
  (`trust.DeploymentID`, `trust.ClusterID`); nobody chooses them.
- The **global home** is `gru`. It owns `TS_GLOBAL_CONTROL`, the roster and
  the link hub.

## Registry

**Heartbeat** (every regional authority leader, every 10 s):

| Subject | `ts.orch.v1.<cell>.region.health` |
| --- | --- |
| Payload | `{"version":1,"cell":"sjc","oci_region":"us-sanjose-1","sent_at":"<RFC3339>"}` (`globalcontrol.Heartbeat`) |
| Auth | The link credential lets a region publish only its own subject. |

**Roster** (written only by the home's global leader, read everywhere):

| Record | `TS_GLOBAL_CONTROL`, subject `ts.global.v1.roster.current` |
| --- | --- |
| Payload | `globalcontrol.Roster`: `{"generation":N,"home_region":"gru","regions":[{"cell","oci_region","state":"active"}]}`, sorted by cell |
| Read | `globalcontrol.Reader.Roster(ctx)` on the home stream or the region's local mirror; poll every 10 s or follow the stream |
| Rules | A region joins on its first heartbeat and leaves after 10 minutes of silence. The home is always present. At most 32 regions. |

The roster is the only list of regions. Links, `/v1/regions/<cell>`, the
dashboard, the planner, the home's mirror consumers, the link probe and
deploy targets (through Atlas `/v1/discovery`) all derive from it.

## Cross-region subjects

Only these cross a region link. Everything else (commands, KV, JetStream,
control logs, host agents, broker) stays in its region.

| Subject | Kind | Use |
| --- | --- | --- |
| `ts.orch.v1.<cell>.obs.region` | request/reply | Region summary (version 1). Dashboard rollups (TS-805). |
| `ts.orch.v1.<cell>.obs.decisions` | request/reply | Decision journal query. |
| `ts.orch.v1.<cell>.query.<verb>.>` | request/reply | Read-only services. New cross-region reads add a verb here. |
| `ts.orch.v1.<cell>.region.<name>` | publish | Region broadcasts: a region publishes only its own, every region receives all. `region.health` is the heartbeat above; `region.rollup` is TS-805's dashboard rollup. |
| `ts.interregion.v1.<cell>.global` and `$JS.gru.API.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-<cell>` | mirror plumbing | `TS_GLOBAL_CONTROL` mirror; never publish to it. |

New features use a new `query` verb with a version token, for example:

| Owner | Verb |
| --- | --- |
| TS-805 dashboard rollups | `obs.region` today; add `query.rollup.v1` if a summary field is not enough |
| TS-806 TerraBase per-database telemetry | `query.terrabase-telemetry.v1` |
| TS-807 OCI cost | `query.cost.v1` |
| TS-808 production logs | `query.logs.v1` (bounded, filtered server-side) |

Responders decode requests strictly (`protocol.DecodeStrict`), bound every
filter and result, never mutate, and answer once.

## Who may send what

Credentials name roles and subject patterns, never regions.

| Role | Cross-region publish | Cross-region subscribe |
| --- | --- | --- |
| controller | `ts.orch.v1.*.obs.region`, `ts.orch.v1.*.obs.decisions`, `ts.orch.v1.*.query.>` | own `ts.orch.v1.<cell>.query.>`, `obs.>`, every `region.health` |
| service role (TerraBase, ts-auth, ...) | `ts.orch.v1.*.query.<verb>.>` for its query tags | own `ts.orch.v1.<cell>.query.<verb>.>` |
| link (leaf user) | requests and its own `region.>` broadcasts; replies | requests for its own cell only; every region's `region.>` broadcasts; its mirror feed |

A new service gets cross-region reach by adding a query tag to its role
identity, never a per-region grant.

## Fan-out at 20 regions

- Read the roster, then request every region in parallel with a per-region
  timeout (1.5 s for `obs.*`). Never loop sequentially.
- A region that times out is `unknown`, not `down`, unless TS-796's probe
  says so. Show partial results.
- Cache per region (a few seconds) and share one fan-out per page.
- Keep replies small: each region summarizes itself; only drill-down
  requests return detail.

## Topology limits

- Links form a star at the home: 19 spokes × 3 controllers = 57 leaf
  connections at 20 regions (limit 160). Spoke-to-spoke traffic transits the
  home; latency-sensitive replication between two spokes pays that path.
- If the home is unreachable, regions keep serving from local state and
  their global mirror; only global writes and cross-region reads stop.
- JetStream never spans regions.

## Releases

One root-delegated release key signs every region's claims. Claims stay
per cell. A new region trusts the same baked root and needs no signer entry
anywhere.
