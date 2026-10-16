# Cluster CLI and dashboard contract

Source contract and remaining acceptance, 2026-10-16. The shared observation
interfaces below are implemented in the refactor branches. They do not establish
live fleet coverage, automatic operator authorization or runtime qualification.

## One operational interface

`ts-orch` is the complete cluster CLI for the human operator and AI agents.
The same binary runs controllers and host roles and serves the dashboard.
Every supported cluster operation must have a CLI path, including observation,
planning, application, progress, failure diagnosis and recovery. Normal operations
must not require a separate management script or a provider console.

1. Reuse feature services and authenticated APIs for both CLI and dashboard;
   never execute CLI shell strings from HTTP handlers or maintain UI-only logic.
2. Provide readable output and versioned structured JSON, documented help,
   explicit units/timestamps, meaningful exit codes and bounded requests.
3. Return operation IDs for long-running changes, with inspect/resume semantics
   that preserve idempotency and leadership/ownership fencing after interruption.
4. Apply the same identity, authorization and audit rules to humans and AI
   agents. Dashboard access is currently read-only; future mutation controls use
   separately authorized operations. Preserve plan/diff and destructive approval.
5. Discover region, resources and production credentials automatically through
   the existing discovery and OCI Vault contract. First tenancy authorization
   remains a prerequisite; CLI completeness does not bypass approval gates.

The current command inventory is in [cli.md](cli.md). Proposed output and
operation contracts above are acceptance requirements, not invented working
commands. Extend existing namespaces instead of building a parallel CLI.

## Implemented observation interfaces

`ts-orch observe --help` documents readable tables and version 1 JSON output.
All requests use the same private bearer-authenticated services as the dashboard;
partial observations are printed and return a nonzero exit status. Requests have
a fixed 15-second deadline, 8 MiB response bound and at most 64 candidate endpoints.

| CLI views | Shared source/API | Dashboard |
| --- | --- | --- |
| `metrics`, `history` | Actual registry and retained history; `/v1/metrics/catalog`, `/v1/history`, `/v1/history/metrics` | `/metric-catalog`, live Datastar updates and ECharts history with text tables |
| `snapshot`, `cluster`, `events` | Existing member collector, regional NATS aggregation and event bus | Existing member, regional, event and feature pages |
| `regions`, `region` | `/v1/regions` and `/v1/regions/{cell}` from the regional global-view cache | Global overview and region detail |
| `nodes`, `node`, `services`, `service` | `/v1/regions/{cell}/nodes[/node[/services[/service]]]` | Node and service drilldowns |
| `volumes`, `volume` | `/v1/regions/{cell}/volumes[/volume]` | Volume drilldowns |

Resource commands select the authenticated endpoint's local region automatically;
`--cell` selects another observed region. Singular node/service/volume views use
`--node`, `--service` and `--volume`. Missing or stale observations cannot establish
that an omitted resource is absent. Known stale resources retain their timestamps;
unknown resources under stale/truncated data remain unknown. A failed volume read
is unavailable. Complete current observations alone establish `not_found`.

The catalog discovers the actual registry, including Go/process families, plus
retained names. It bounds exposition to 1 MiB, 2,048 families, 4,096 current samples
and 64 samples per family. Exceeding a bound is explicit. Current label names are
shown without label values; unsupported description/unit/type/collection metadata
is disclosed. This catalog describes the queried registry, not fleet-wide coverage.
History queries expose pending replay, dropped series, incomplete/truncated data,
source cadence, per-series freshness and gaps. Counter rates require counters.
The maximum query is 14 days and 512 series; dashboard rendering keeps 32 series
and 1,200 points while retaining access through the bounded history API.

Normal zero-configuration operator access still depends on a trusted admitted
endpoint and scoped Vault-token resolver from OCI. The current CLI bridge reuses
existing benchmark configuration or explicit diagnostic `--url`/`--token-file`;
it does not satisfy automatic production access. NetBird discovery alone grants
no authority. Full SwarmKit service observations, regional operation progress and
live function snapshots need their actual authenticated producer wiring before
these interfaces can claim complete runtime or infrastructure coverage.

## Reuse the dashboard stack

The repository already contains Go `templ` components, Datastar server streams,
embedded assets, Apache ECharts and a shared chart specification. Use these
for the requested templates, live interaction and charts. Do not introduce a
second template engine or frontend application.

All dashboard CSS must live in `internal/dashboard/assets/dashboard.css`.
`layout.templ` loads one content-addressed `dashboard.css`, containing the
unchanged pinned Pico base followed by the dashboard overrides. The Pico MIT
notice and original hash remain recorded in asset provenance. Layout and asset
HTTP integration checks cover the consolidated file. No stylesheet imports,
inline page styles or additional CSS files. ECharts rendering options continue
to read shared theme values; the single CSS file owns the visual theme.

Keep assets vendored, pinned and embedded so private dashboard access does not
depend on an external CDN. Use Datastar to patch views; resynchronize from a
fresh snapshot after stream gaps rather than silently losing changes.

## Full visibility: required coverage

Show fleet health first, with region, host, workload and resource drilldowns.
Every owned resource must be accounted for, including failed provisioning,
unplaced workloads, disconnected hosts and retained volumes/backups.

| Area | Required observations | Useful views |
| --- | --- | --- |
| OCI infrastructure and cost | Desired/observed resources, ownership/drift, work requests, API latency/errors/throttling, shape/architecture, quotas, available capacity, CPU/memory, disk space/IO/latency, network traffic, actual billing and labeled estimates. | Fleet map, capacity/utilization time series, resource inventory and cost breakdown. |
| Control plane and networking | Regional leaders/quorum, reconciliation lag/errors, NATS/JetStream traffic, replication lag, pending consumers, NetBird management/signal/relay health, peer reachability, directed link RTT/loss and DNS/TLS expiry. | Topology graph, directed regional link matrix, latency heatmap and event timeline. |
| Workloads and runtimes | Desired/ready/running counts, placement reasons, restarts, request/error rates and latency distributions, saturation, native ARM/x86 compatibility, Wasm execution/queue time, traps, memory/fuel limits and cache activity. | Service/runtime drilldowns, latency percentiles, error rates and rollout overlays. |
| Data, release and recovery | Volume ownership/fencing, database replication/catch-up and backup age, backup/restore success and duration, retained/rollback digests, release phases, health gates and secret/certificate rotation outcomes without secret values. | Storage/backup views, release matrix and deployment/recovery timelines. |
| Observability itself | Collection/stream health, last successful observation, known versus observed sources, missing regions, lost/dropped samples, truncation, retention, history resolution and query limits. | Coverage inventory, freshness indicators, gap markers and correlated logs/events/traces where instrumented. |

Every collected/exported metric family must appear in a searchable catalog in
both interfaces, including Go/process metrics. Expose its description, unit,
counter/gauge/histogram type, safe label dimensions, source, timestamp and
retained resolutions. An operator can inspect current samples and chart
available history; unsupported history must say why. Curated overview charts
do not replace the catalog. Instrument missing lifecycle/runtime observations
as their owning features are implemented and qualified.

Maintain a coverage inventory linking each resource/feature and metric family
to its producer, collection path, CLI/API access and dashboard view/history.
Compare the inventory with registered/exported metric families and discovered
resources to reveal omissions. Reuse the existing registry and collectors;
avoid a second telemetry pipeline or a manually copied list of metric names.
Unsupported, permission-denied, stale, missing, truncated and genuinely zero
values need distinct visible states. A missing sample must not become zero or
a healthy badge. Show per-region freshness and partial results when a region
is unavailable; a global view must not depend on GRU staying reachable.

## Charts and bounded collection

Use existing ECharts line/area plots for trends, heatmaps for link/latency
distributions, stacked bars for cost/capacity, and timelines for rollouts and
recovery. Provide consistent theme colors, units, legends, tooltips, zoom,
shared time ranges and click-through to the associated resource and events.
Use whitespace and clear hierarchy; keep motion restrained and respect reduced
motion. Charts need accessible names plus a table/text alternative and keyboard
access to their drilldowns. Support narrow screens and light/dark themes.

Charts show source timestamps and data resolution. Preserve gaps through
downsampling. Derive rates from counters with reset handling; compute aggregate
percentiles from compatible histogram data, not averages of regional p99s.
Label estimates separately from billed cost, and distinguish forecasts from
observed values. Never fill production views with demo values.

Bound label cardinality, time-series memory, query sizes, streaming fan-out and
browser points using fixed internal budgets and existing history tiers. Show
the available retention/resolution and every data-loss indication. Full coverage
means all relevant metric families and managed resources are observable; raw
samples are retained for a finite, disclosed period. Keep collection regional
so WAN interruption does not stop local observation or serving. Redact secrets
and customer payloads at collection boundaries, with scope-appropriate access.

## Evidence required

1. On the actual GRU/San Jose/FRA milestone, enumerate discovered resources and
   registered/exported metric families and account for each in the coverage
   inventory, including explicit unsupported states.
2. Inspect representative health, resource, metric and release data through
   both interfaces; match region, timestamps, units, source and operation IDs.
3. Exercise live updates, historical ranges and chart-to-event drilldowns;
   retain screenshots and redacted structured CLI output from the same window.
4. Interrupt a region and a telemetry stream. Show partial visibility, marked
   history gaps and reconnect/resynchronization without false healthy values.
5. Measure collector/controller memory/CPU, retained history and dashboard
   responsiveness on the smallest qualified A1 host. Add ARM/x86/Wasm coverage
   as each runtime is admitted. Publish evidence under `benchmark/bench/`.

Local integration checks exercise the implemented source interfaces; retained
results and remaining gaps are in [OBS evidence](evidence/obs-refactor-20261016.md).
Live fleet, browser, cloud, runtime and cost acceptance remain unverified.
