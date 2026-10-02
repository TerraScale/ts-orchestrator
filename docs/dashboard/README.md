# Operator dashboard

The dashboard is served by every controller on its private, authenticated
observability listener (`observability.dashboard: true`). It only reads
providers; it never changes control-plane state.

## Pages

| Page | What it shows |
|------|---------------|
| `/` Global | Every region side by side (health score, quorum, leaders, versions, capacity, TerraBase, rollouts, open problems, latest decisions), KPI tiles with sparklines, the world map with inter-region links, what needs attention, the merged decision timeline and the 1h/24h summaries. |
| `/region?r=<region>` | One region. This member's region shows live members, charts and events; another region shows the summary it answers over the region link. |
| `/insights` | Ranked needs-attention list across regions: why each insight fired, its evidence against the threshold (charted when it is a history metric), the entity link and the suggested command. Toasts and the top-bar badge update live; browser notifications are opt-in. |
| `/decisions` | The merged decision journal, filterable by region, kind, actor, status and subject; `?id=` opens a decision's whole chain with its signals, gates, rule and rejected alternatives. |
| `/releases` | Each release's journey (CI qualified, signed, staged, canary, soak, batches, complete or rolled back) per region, and the version matrix of regions × units with drift highlighted. |
| `/rollouts`, `/ci` | Rollout phase diagrams, release history, known-bad releases, managed TerraBase updates, qualification runs. |
| `/topology` | Force graph of regions, controllers (NATS routes), hosts (leaf connections) and TerraBase seats; click a node for details. |
| `/members`, `/nats`, `/terrabase`, `/storage`, `/oci`, `/events` | Host time series, fleet heatmap and capacity; NATS rates, lag and backlog; seat grids, stage history and time-to-full forecasts; volumes, capacity treemap and backups; OCI rates, latency, 429s and inventory; the live event stream with search and chart click-through. |

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
![Rollouts](rollouts.png)
![NATS, dark](nats-dark.png)
![Releases, dark](releases-dark.png)
![Global view on a phone](global-mobile.png)
