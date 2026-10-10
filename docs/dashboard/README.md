# Operator dashboard

The dashboard is served by every controller on its private, authenticated
observability listener without an enable setting. It only reads
providers; it never changes control-plane state.

## NetBird access

Use the existing NetBird connection on delta, beta or mariogk-dev and open a
topology URL below. Enter the
region's dashboard token on `/login`; the browser keeps a read-only session
until sign-out or a dashboard token change, including across controller
restarts. TCP 9463 is
private: the NetBird operator policy and host firewall admit it through `wt0`,
and it has no public listener or OCI ingress rule. The signed cell spec's
`dashboard.token` enables the listener in place; never re-found a serving cell
to change access ([listener contract](../observability.md#on-the-netbird-address-cell-spec)).

LINKS: controller topology URLs (verified from mariogk-dev, 2026-10-07 23:03 UTC):

| Controller | By NetBird IP | By NetBird DNS |
|---|---|---|
| GRU 1 | http://10.200.87.215:9463/topology | http://ts-gru-1.nb.ts.internal:9463/topology |
| GRU 2 | http://10.200.38.135:9463/topology | http://ts-gru-2.nb.ts.internal:9463/topology |
| GRU 3 | http://10.200.168.164:9463/topology | http://ts-gru-3.nb.ts.internal:9463/topology |
| SFO 1 | http://10.200.112.213:9463/topology | http://ts-sfo-1.nb.ts.internal:9463/topology |
| SFO 2 | http://10.200.122.37:9463/topology | http://ts-sfo-2.nb.ts.internal:9463/topology |
| SFO 3 | http://10.200.63.195:9463/topology | http://ts-sfo-3.nb.ts.internal:9463/topology |

### Fetch the regional tokens

Run with the operator's `~/.oci/config` ([Vault access](../secrets.md#read-a-secret)).
This writes owner-only files without printing the tokens:

```sh
mkdir -p "$HOME/.config/ts-orch"
dashboard_token() {
  oci --region "$1" secrets secret-bundle get-secret-bundle-by-name \
    --vault-id "$2" --secret-name "$3" \
    --query 'data."secret-bundle-content".content' --raw-output | base64 --decode
}
(
  set -euo pipefail
  umask 077
  dashboard_token sa-saopaulo-1 \
    ocid1.vault.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr7ebplea4ua3memgthsupcfn3crg6d56vipsw7o2butchdrx3urmq \
    gru-1-orch-dashboard-token > "$HOME/.config/ts-orch/dashboard-gru-token"
  dashboard_token us-sanjose-1 \
    ocid1.vault.oc1.us-sanjose-1.grvmmkplaacx6.abzwuljrzcofqki6a5podtjnhvyiol7yqehrd77tp2hoeynxp5wozv54mq6a \
    sfo-1-orch-dashboard-token > "$HOME/.config/ts-orch/dashboard-sfo-token"
)
```

Read the appropriate file locally to enter its token in the login form; never
put it in a URL, command argument, ticket or PR. Each token is shared by that
region's three controllers. Token rotation is picked up within five minutes.

### Check every controller from this device

Run this only on delta, beta or mariogk-dev with NetBird already connected
and both token files available. Build once with `nice -n 19 make build`:

```sh
scripts/check-dashboard-access.sh \
  --gru-token-file "$HOME/.config/ts-orch/dashboard-gru-token" \
  --sfo-token-file "$HOME/.config/ts-orch/dashboard-sfo-token"
```

The thin wrapper runs `ts-orch dashboard check`. It reads current IPs from
`netbird status --json`, requires all six controllers, and curls `/healthz`
and all fourteen authenticated dashboard pages by IP and native DNS: 180
requests total. It returns 0 only when every response is HTTP 200 from the
expected NetBird IP, every page has rendered content, each topology has at
least three distinct nodes, and each `/members` table has at least three
distinct observed controllers. Missing-member placeholders do not count.
This catches missing telemetry grants even when the
dashboard returns HTTP 200. Response bodies are bounded to 2 MiB and are
never printed. Legitimately empty resource lists do not fail the check.
Native DNS may connect to the intended peer's IPv4 or IPv6 address reported
by NetBird; an address belonging to another peer fails the check.
It bypasses HTTP proxies, refuses redirects, does not override DNS, and passes
tokens to curl through stdin. IP replacement needs no script edit. Each
request has a five-second timeout (override with `--timeout 10s`). Allow about
five minutes for the fleet check while regional requests time out.

Never run checks, SSH, NetBird login/up, browser automation or SSO prompts on
`mariogk-desktop`. The wrapper rejects hosts outside delta, beta and
mariogk-dev. Use plain HTTP over NetBird for acceptance; if remote access to
an allowed operator host is needed, use `netbird ssh --no-browser`.

Use `NB='sudo -n netbird-wt0'` on a NixOS dev VM or set `NB` to the connected
client command and `TS_ORCH` to an existing binary. For the host-network
automation container, use `NB='sudo -n podman exec -i ts-netbird-ops netbird'`.
A failed DNS curl (exit status 6) needs NetBird DNS enabled for that peer; a
failed TCP curl (7 or 28) needs the listener, operator policy and `wt0`
firewall inspected before changing anything. An HTTP 401 needs the current
token for that region. Do not add public ingress or hide a DNS failure with
`curl --resolve`.

### TS-740 strict acceptance checker

Run `nice -n 19 bash scripts/check-dashboard-netbird` locally on delta, beta
or mariogk-dev (`NB='sudo -n netbird-wt0'` on the NixOS dev VM). Other
source hosts are rejected before any network command.
It checks A/AAAA peer identity, TCP 9463 and HTTP over IPv4, IPv6 and native
DNS, fetching regional tokens privately from OCI Vault. All DNS answers must
belong to the intended peer; HTTP responses must report that peer's address.
Every authenticated request, including direct IPv4, requires one inventory
peer matching the controller FQDN and expected IPv4. Missing, mismatched or
ambiguous inventory suppresses token requests while retaining unauthenticated
probes and expected-IP listener diagnostics. The selected connected client's
local address must identify one kernel WireGuard interface. Before each token
request, the selected route must use that interface; curl binds to it with
`--interface if!<name>`. Missing interfaces, disconnected clients, ambiguous
addresses and routes through another device fail closed. `NB` wrappers and
alternate interface names are supported through discovery from client status
and local interface addresses.
Authenticated name requests run only after DNS and the native-name health
probe pass, and use `curl --resolve` to pin that validated DNS result for
credential safety. Failed native DNS is never replaced with inventory values. Failed controllers
get a bounded `netbird ssh --no-browser root@<expected-IPv4>`
listener query using `ss -ltnp` directly, even when native DNS fails; it never starts an
SSO browser or establishes a new NetBird login.

TS-740 still requires topology JSON with a nonempty `nodes` array. The current
`/topology` browser page returns HTML/SVG, so this strict checker returns 1
even when transport and authenticated HTTP 200 pass. Resolving that acceptance
contract requires an explicit COS decision.

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
| `/regions/{r}/hosts/{h}` | A host: its seats and volumes, host CPU/memory/disk history and per-service CPU/memory history over the selected range, including `14d`. Resource charts use authenticated host reports collected by the local region's authority leader. Hosts of another region show that region's decisions and insights only. |

Path values are validated like the query parameters; anything else is a 404.

The NATS page's leadership timeline shows authority lease changes, JetStream meta leader elections and quorum losses and recoveries, as the controllers journal them. NATS, TerraBase and Storage with another region selected label their live sections as this member's region; only their decision timelines follow the selection. Pages that only show this member (Hosts, OCI, Events, Rollouts) and the all-region pages (Releases, Qualification, Topology) send the region switcher to that region's overview. Empty histories say whether nothing happened or the query failed or was partial.

The NATS route RTT panel reads the embedded broker's existing PING/PONG
measurements through `Routez`. Each directed server pair shows the maximum
positive RTT across its pooled and dedicated connections, with measured/total
connection coverage. Unset readings remain unavailable; old snapshots are
marked stale. Snapshot time is collection time: NATS does not expose the last
ping's timestamp. Current peer inventory is bounded to 128 rows; the history
chart is bounded to 64 series, with visible completeness warnings.
`/v1/snapshot` carries `nats.route_rtts`; `/metrics` exports
`ts_orch_nats_route_rtt_seconds`, `ts_orch_nats_route_connections`,
`ts_orch_nats_route_measured_connections` and `ts_orch_nats_route_rtts_truncated`.
The existing `/v1/history` API uses the same names without `ts_orch_` and
labels RTT/coverage by `member`, `server` and `peer`. These observations cover
the local cell; global dashboard fan-out remains TS-794 work.

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
