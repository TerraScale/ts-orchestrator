# Operator dashboard

The [zero-configuration contract](../zero-configuration.md) is required production policy.
Configuration fields, manual bootstrap paths and dated observations below are
legacy implementation inventory, not feature/region activation or credential-copy
instructions. Removing runtime guards and completing automatic NetBird admission,
region inference and OCI Vault provisioning/delivery remain TS-796. Integrity,
authorization, quorum, residency and destructive-operation safeguards still apply.

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
and it has no public listener or OCI ingress rule. The current listener still depends on a cell-spec
`dashboard.token` reference; automatic listener/credential provisioning is pending
TS-796. Never re-found a serving cell to change access ([listener contract](../observability.md#on-the-netbird-address-cell-spec)).

LINKS: controller topology URLs (verified from mariogk-dev, 2026-10-07 23:03 UTC):

| Controller | By NetBird IP | By NetBird DNS |
|---|---|---|
| GRU 1 | http://10.200.87.215:9463/topology | http://ts-gru-1.nb.ts.internal:9463/topology |
| GRU 2 | http://10.200.38.135:9463/topology | http://ts-gru-2.nb.ts.internal:9463/topology |
| GRU 3 | http://10.200.168.164:9463/topology | http://ts-gru-3.nb.ts.internal:9463/topology |
| SJC 1 | http://10.200.112.213:9463/topology | http://ts-sjc-1.nb.ts.internal:9463/topology |
| SJC 2 | http://10.200.122.37:9463/topology | http://ts-sjc-2.nb.ts.internal:9463/topology |
| SJC 3 | http://10.200.63.195:9463/topology | http://ts-sjc-3.nb.ts.internal:9463/topology |

### Automatic operator credential delivery

OCI Vault must provision and deliver read-only operator credentials automatically.
Do not extract tokens into local files or copy them through login/setup recipes.
The current bearer/session consumer and acceptance checker's token-file inputs
are TS-796 delivery gaps; this document does not implement the replacement.
Keep private transport, operator authorization and token-free logs/URLs.

### Check every controller from this device

The current checker below requires its legacy token-file inputs. Automatic
credential delivery is pending; do not manually extract production tokens to
satisfy it. Its allowed-host, private-network and identity checks remain binding:

```sh
scripts/check-dashboard-access.sh \
  --gru-token-file "$HOME/.config/ts-orch/dashboard-gru-token" \
  --sjc-token-file "$HOME/.config/ts-orch/dashboard-sjc-token"
```

The thin wrapper runs `ts-orch dashboard check`. It reads current IPs from
`netbird status --json`, requires all six controllers, and curls `/healthz`
and all fourteen authenticated dashboard pages by IP and native DNS: 180
requests total. It returns 0 only when every response is HTTP 200 from the
expected NetBird IP, every page has rendered content, each topology has at
least three distinct nodes, and each `/members` table has at least three
distinct observed controllers. Missing-member placeholders do not count.
This catches missing telemetry grants or incomplete collection even when the
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
| `/` Global | Every region from the in-memory global view (TS-805, [global-view](global-view.md)): KPI tiles, world map, region table with stale badges, region × region link matrix, top databases by replication bandwidth and recent errors. Drill down to `/regions/<cell>`. |
| `/region` | This region's live members, charts and checks, with its events. Other regions open `/regions/<cell>`, the global view of that region. |
| `/insights` | Ranked needs-attention list across regions: why each insight fired, its evidence against the threshold (charted when it is a history metric), the entity link and the suggested command. Toasts and the top-bar badge update live; browser notifications are opt-in. |
| `/decisions` | The merged decision journal, filterable by region, kind, actor, status and subject; `?id=` opens a decision's whole chain with its signals, gates, rule and rejected alternatives. |
| `/releases` | Each release's journey (CI qualified, signed, staged, canary, soak, batches, complete or rolled back) per region, and the version matrix of regions × units with drift highlighted. |
| `/rollouts`, `/ci` | Rollout phase diagrams, release history, known-bad releases, managed TerraBase updates, qualification runs. |
| `/topology` | Server-rendered SVG of this region: one column of nodes (`ts-<region>-<n>` with its private address), each with the ts-orch controller (build, authority and meta leader), the host agent, each role its host grant places (TerraBase member, ts-auth, ...) with its release digest and verified host report, TerraBase seats serving, the node's fence and active node operation, and its load balancer backends (from the fence records, not a live load balancer read). Arcs left of the nodes join nodes that replicate a TerraBase partition (tooltip: partitions and the latest replication lag). **Services + NATS** (`nats=1`) adds each controller's NATS server with connections and peers, the route mesh, the other nodes' client sessions and JetStream health (streams, KV buckets, store, streams with offline replicas or lag). Colors come only from evidence: an unproven route or client connection is grey and dashed. Every box links to its node, member or NATS page. Below the graph, every other region links to its `/regions/<cell>` view with its health. |
| `/members`, `/nats`, `/terrabase`, `/storage`, `/oci`, `/events` | Host time series, fleet heatmap and capacity; NATS rates, lag and backlog; seat grids, stage history and time-to-full forecasts; volumes, capacity treemap and backups; OCI rates, latency, 429s and inventory; the live event stream with search and chart click-through. |

The Capacity page (`/capacity`, Infrastructure) shows the monthly OCI budget,
the capacity document with each region's nodes, wanted nodes, allowance and
pressure, this region's node scaling status and the current region
suggestion (information only: regions change only on `ts-orch region create|remove`). The budget is set there from the home region's dashboard: the form
posts to `/capacity/budget`, and the home's global leader writes it to
`TS_GLOBAL_CONTROL`. Other regions show the budget read-only and the suggestion
note that it runs in the home region.

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

## Dashboard fixtures

```sh
nice -n 19 mise exec -- go test ./internal/dashboard/devfake
```

The moving three-region fixtures (GRU, SJC, FRA) drive the real history sampler,
insight engine, region provider and summarizer in tests. All fixture sources
live in `_test.go` files; executable builds cannot import them.

## Screenshots

Historical screenshots of fixture data, taken with headless Chromium.

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
