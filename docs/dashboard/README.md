# Operator dashboard

The dashboard is served by every controller on its private, authenticated
observability listener (`observability.dashboard: true`). It only reads
providers; it never changes control-plane state.

## Pages

| Page | What it shows |
|------|---------------|
| `/` Global | Every region side by side (health score, quorum, leaders, versions, capacity, TerraBase, rollouts, open problems, latest decisions), KPI tiles with sparklines, the world map with inter-region links, what needs attention, the merged decision timeline and the 1h/24h summaries. |
| `/region?r=<region>` | One region. This member's region shows live members, charts, every member's readiness checks and events; another region shows the summary it answers over the region link. |
| `/insights` | Ranked needs-attention list across regions: why each insight fired, its evidence against the threshold (charted when it is a history metric), the entity link and the suggested command. Toasts and the top-bar badge update live; browser notifications are opt-in. |
| `/decisions` | The merged decision journal, filterable by region, kind, actor, status and subject; `?id=` opens a decision's whole chain with its signals, gates, rule and rejected alternatives. |
| `/releases` | Each release's journey (CI qualified, signed, staged, canary, soak, batches, complete or rolled back) per region, and the version matrix of regions × units with drift highlighted. |
| `/rollouts`, `/ci` | Rollout phase diagrams, release history, known-bad releases, managed TerraBase updates, qualification runs. |
| `/topology` | Server-rendered SVG, one column per region (every catalog region the region view lists) and one box per node (`ts-<region>-<n>` with its private address): the ts-orch controller (build, authority and meta leader), the host agent, each role its host grant places (TerraBase member, ts-auth, ...) with its release digest and verified host report, TerraBase seats serving, the node's fence and active node operation, and its load balancer backends (from the fence records, not a live load balancer read). Arcs left of the nodes join nodes that replicate a TerraBase partition (tooltip: partitions and the latest replication lag). **Services + NATS** (`nats=1`) adds each controller's NATS server with connections and peers, the route mesh, the other nodes' client sessions, JetStream health (streams, KV buckets, store, streams with offline replicas or lag) and the links between regions; a region without a leaf link is drawn red. Colors come only from evidence: an unproven route or client connection is grey and dashed, a link between two other regions is unknown. Every box links to its node, member, region or NATS page. Another region shows what its summary carries (no per-server NATS counts, no replication arcs). |
| `/members`, `/nats`, `/terrabase`, `/storage`, `/oci`, `/events` | Host time series, fleet heatmap and capacity; NATS rates, lag and backlog; seat grids, stage history and time-to-full forecasts; volumes, capacity treemap and backups; OCI rates, latency, 429s and inventory; the live event stream with search and chart click-through. |

The OCI page also counts the managed fleet by OCI lifecycle state from the
latest complete placement Observe sweep of each region: instances in the
fleet's identity scope (owned or withheld), and the retained data volumes and
volume attachments of the hosts it verified. Unattached retained volumes are
not listed by the sweep. The same counts are exported as
`ts_orch_oci_fleet_resources{region,kind,state}`.

### Detail pages

The list pages, the topology, insights and the decision journal link to one
page per entity. Each shows the entity's live state and charts, the open
insights that name it, a timeline and table of the decisions about it (at
least the last day; a week for rollouts and volumes) and the newest
decision's whole chain; picking a decision opens its chain in place.
A decision is about the entity when its subject or summary names the
entity's ID as a whole identifier (`gru-c1` does not match `gru-c10`); a
host page also lists the placement decisions whose `host_node` is the host,
and a partition page those whose database and partition are its own. Host
and partition pages read up to 1000 of the region's decisions of the last
day and narrow them, so in a very busy region the history can be partial,
which the page says.

| Page | Entity |
|------|--------|
| `/members/{id}` | An orchestrator member: role, lease, build, readiness checks, CPU, memory, disk and NATS traffic. |
| `/terrabase/{db}/{partition}` | A TerraBase partition: seats with stage, host and update phase, serving vs desired seats over time, and the **placement hold history** (each hold reason as the hold journal recorded it, once per 15 minutes while re-asserted). The placement reconciler does not journal a hold's clearing yet, so a hold that is no longer re-asserted simply stops recurring; a `hold_cleared` decision about the partition is shown when one is recorded. A hold that names only a seat ID that another partition also has is flagged. |
| `/rollouts/{id}` | A release rollout (phase diagram, deadline) or a managed TerraBase update by operation ID (artifact, progress chart). |
| `/volumes/{id}` | A block volume: state, since when, host. |
| `/regions/{r}/hosts/{h}` | A host: the seats and volumes placed on it in this member's region. Hosts of another region show that region's decisions and insights only. Host agents do not report their CPU and memory to the controller yet, so the host charts stay empty. |

Path values are validated like the query parameters; anything else is a 404.

The NATS page's leadership timeline shows authority lease changes, JetStream meta leader elections and quorum losses and recoveries, as the controllers journal them. NATS, TerraBase and Storage with another region selected label their live sections as this member's region; only their decision timelines follow the selection. Pages that only show this member (Hosts, OCI, Events, Rollouts) and the all-region pages (Releases, Qualification, Topology) send the region switcher to that region's overview. Empty histories say whether nothing happened or the query failed or was partial.

Every page carries the time range (`range=15m|1h|6h|24h`), the selected
region (`r=`) and the live toggle (`live=0`) in its URL. Ctrl/⌘+K or `/`
opens the command palette.

## Local preview with fake data

```sh
nice -n 19 make dashboard-preview   # http://127.0.0.1:8099/
```

This runs `cmd/ts-dashboard-preview`, which builds only with the
`dashboardpreview` tag and serves the dashboard over `internal/dashboard/devfake`:
a moving three-region world (GRU, SFO, FRA) driven through the real history
sampler, insight engine, region provider and summarizer. The orchestrator
binary never links it; a test enforces that.

## Screenshots

Taken from the preview with headless Chromium.

![Global view](global.png)
![Global view, dark](global-dark.png)
![Needs attention](insights.png)
![Decision chain](decision-chain.png)
![Releases and version matrix](releases.png)
![Topology](topology.png)
![Region](region.png)
![TerraBase](terrabase.png)
![Hosts](hosts.png)
![Member detail](member-detail.png)
![Host detail](host-detail.png)
![TerraBase partition with placement hold history](terrabase-partition.png)
![Rollouts](rollouts.png)
![Release rollout detail](rollout-detail.png)
![Managed update detail](managed-update-detail.png)
![Volume detail](volume-detail.png)
![OCI fleet by lifecycle state](oci.png)
![NATS, dark](nats-dark.png)
![Releases, dark](releases-dark.png)
![Global view on a phone](global-mobile.png)
