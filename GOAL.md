# ts-orchestrator goal

## Authority

The workspace [GOAL.md](../GOAL.md) remains the sole authority for TerraScale.
This file is its comprehensive, repository-specific projection for
`ts-orchestrator`. It restates every applicable workspace decision and adds
stricter local acceptance criteria. It may not contradict, narrow, or omit an
applicable workspace requirement. If the two files diverge, the workspace goal
wins and this file must be corrected in the same change. This file contains
decisions and acceptance criteria, never progress, dates, commit hashes, or
review records.

## Mission

Build TerraScale's Go orchestrator specifically for TerraBase. It manages the
infrastructure that runs both itself and the TerraBase cluster. GRU is created
first and hosts the single active global master. Every Region, including GRU,
runs its own regional orchestrator from initial admission. Every TerraBase
member machine runs a local `ts-orchestrator` process on that same machine.

The GRU master manages the regional orchestrators. Each regional orchestrator
reconciles its own OCI resources, operates local hosts through `ts-node`, and
coordinates the local TerraBase members through private TBEP. Global policy,
Region admission, control membership, and cross-Region changes remain under
GRU authority. A regional orchestrator is required even when the Region has
only two member hosts and no independent regional JetStream quorum.

## Workspace decision map

This map is an index, not a substitute for the requirements below.

| Workspace decisions | Requirement in this repository |
| --- | --- |
| D-01, D-03, D-06, D-33 | Implement the control plane, CLI, host agent, provider code, and test controller in Go, with embedded NATS JetStream and no Kubernetes-compatible API. |
| D-02, D-34..D-38, D-45, D-46 | Use TBEP only for private placement, health, drain, administration, and test faults. Keep the orchestrator and NATS out of customer data, replication, query, and reactive paths. |
| D-04, D-05, D-52, D-63, D-65..D-67 | Reconcile the OCI and Cloudflare launch estate, bootstrap GRU, expand to GRU/SFO/FRA, support 20 Regions, enforce placement, and keep OCI as the only durable production cloud. |
| D-07, D-47, D-59, D-68, D-69, D-71 | Accept signed candidates from `ts-deploy`, mirror them, and own systemd, Worker, and Snippet activation, health gates, rollback, and release recovery. CI logic remains in `ts-deploy`. |
| D-14, D-20, D-24, D-55, D-58, D-63 | Reconcile DNS, Cache Rules, Snippets, Workers KV, WAF, and capability keys without putting a Worker or the orchestrator on the reactive hot path. |
| D-16, D-21, D-25, D-44, D-51, D-61, D-64, D-76 | Keep free dimensions unbilled within published guards, enforce infrastructure-side limits without inventing usage truth, preserve near-zero idle cost, and automate the Free database lifecycle. |
| D-23, D-61, D-72, D-74, D-75, D-79 | Publish bounded estate state, metrics, logs, SLO burn, rollout state, drill results, and cost observations for the dashboard and status systems. Page only under the stated policy. |
| D-29, D-35, D-37, D-40, D-45, D-52, D-60, D-70, D-71 | Coordinate placement, regional RF=2, backup, restore, export, branching, key lifecycle, and repair while leaving data correctness to TerraBase and never widening residency. |
| D-10..D-12, D-32, D-41, D-47, D-62 | Work on `develop`, delete retired directions, keep `make check` portable and green, and use the workspace tracks and gates. This goal remains complete enough to direct repository work by itself. |
| D-19, D-40, D-49, D-50, D-57, D-73, D-78, D-80 | Do not reintroduce containers, local customer distribution, removed product roles, or query ownership. Preserve the systemd and control contracts needed by current and post-launch product work. |
| D-81 | Qualify the entire repository through the pinned low-resource Firecracker stack, with the CI cadence and evidence limits defined below. |

## Automation boundary

`ts-orchestrator` is TerraScale's Go control plane and our Kubernetes
alternative. It is the single automation authority for OCI and Cloudflare. It
declares the whole estate as typed Go configuration, continuously observes the
real estate, repairs drift, places TerraBase members, manages host software and
identity, and rolls out signed releases. It never serves customer reads,
writes, replication, reactive data, or usage truth.

The system must work end to end. Passing isolated tests while bootstrap,
delivery, repair, or a provider boundary remains unwired is not completion.

## Product and runtime boundary

The orchestrator owns:

- OCI compartments, network, NSGs, compute, block storage, Object Storage and
  lifecycle rules, Vault keys, certificates, instance principals, and the
  resources required to run the launch estate;
- Cloudflare DNS, Cache Rules, Smart Tiered Cache settings, Snippet code and
  rules, Worker routes and traffic promotion, KV placement and Region-health
  maps, WAF and rate rules, Secrets Store capability keys, and certificates;
- Region and host lifecycle, capacity, placement, repair, drain, replacement,
  and safe removal;
- `ts-node`, signed artifact installation, hardened systemd units, service
  restart, version activation, and rollback;
- TerraBase placement intent, peer lists, residency locks, health gates, and
  repair coordination through the private TBEP gRPC control protocol;
- the signed delivery API used by `ts-deploy`, release mirroring, canary and
  rolling rollout state, Worker and Snippet promotion, and automatic rollback;
- control-state durability in embedded NATS JetStream;
- estate-state publication to the control-plane database; and
- infrastructure telemetry, SLO evaluation, restore drills, control-state
  snapshots, and automation audit events.

The orchestrator does not own:

- customer database mutations, SQLite behavior, CRDT merge semantics,
  replication correctness, anti-entropy, reactive sync, or usage accounting;
- Better Auth, organizations, projects, billing, entitlements, MCP product
  policy, or SDK behavior;
- the customer data path or a public query proxy;
- a general workload scheduler, arbitrary customer workloads, or tenant
  compute at launch; or
- Kubernetes, Nomad, ECS, OCI-container, image-registry, or compatible APIs.

TerraBase owns authoritative usage facts. The control-plane database owns the
admin-visible `estate.*` documents. Grafana Cloud owns collected metrics and
logs. JetStream owns orchestrator control state only. NATS never carries
customer documents, WAL frames, CRDT rows, replication traffic, query results,
reactive frames, or usage truth.

## Control-plane topology

- GRU hosts the single active global master and the first regional
  orchestrator. The master manages the lifecycle and authority of every
  regional orchestrator, including its own GRU regional role.
- Greenfield bootstrap starts one co-hosted GRU control replica as a temporary
  JetStream R1. R1 is allowed only before customers and only until SFO and FRA
  are ready.
- `add-region sfo` and `add-region fra` start synchronized candidate replicas.
  After both have caught up and passed identity, storage, and health checks, one
  fenced transition changes control storage from GRU R1 to GRU/SFO/FRA R3. The
  accepted control epoch cannot regress, and the bootstrap authority is retired
  only after the R3 quorum and a post-transition snapshot are verified.
- Launch and production use one permanent global R3, with one replica co-hosted
  in each of GRU, SFO, and FRA. They never downgrade to R1 after promotion.
- There are no dedicated orchestrator machines or servers. Orchestration
  capacity shares TerraBase member hosts at launch and as Regions grow.
- Every TerraBase member host runs `ts-orchestrator` alongside TerraBase.
  A two-member Region therefore starts with two local orchestrator processes.
  Regions 4 through 20 do not join the global R3. Their
  regional orchestrators execute Region-scoped work under GRU-issued authority
  and use the global R3 for authoritative control records.
- A later Region may gain a separate three-replica regional control group only
  after it has at least three eligible hosts. That group handles Region-scoped
  control work; global mutations remain under the permanent global R3. This is
  post-launch capacity work.
- Existing Regions keep serving customer reads, eligible writes, replication,
  and reconnect recovery when the orchestrator or NATS is unavailable.
- Loss of GRU or NATS may stop new global mutations. It must not enter the
  TerraBase correctness path or stop an already admitted data plane.
- Control mutations are fenced, authenticated, idempotent, restart-safe, and
  durably journaled. Missing, stale, conflicting, or unverified authority fails
  closed.

### Same-machine management

Every TerraBase member runs on the same machine as the `ts-orchestrator`
process responsible for its local lifecycle. This applies to initial
bootstrap, Region addition, scaling, and replacement. The GRU master role
also runs on a TerraBase member machine.

Local orchestrator processes coordinate as the Region's orchestrator under
GRU authority. Host-scoped commands target the matching host identity;
Region-wide OCI reconciliation has one fenced mutation owner per operation.
Adding a host-local process does not grant another global master role or
another authoritative JetStream replica.

`ts-orchestrator` manages the local TerraBase instance through private TBEP
and delegates installation, systemd changes, and activation to local
`ts-node`. They run as separate systemd services with bounded resources.
An orchestrator restart must not stop TerraBase. When the entire machine
fails, a surviving authorized controller provisions its replacement and
installs both components before admitting the replacement member.

Bootstrap and VM qualification must verify a local orchestrator on every
member machine, authenticated host identity matching, same-machine TBEP
management, independent process restart, and replacement after joint host
loss. A healthy remote regional controller alone does not satisfy this gate.

### Master and regional responsibilities

One active master means one fenced global mutation authority. The three global
JetStream replicas provide control-state durability; they are not three
independent masters. A NATS storage leader does not automatically become the
application master. Regional authority cannot promote itself to global
master when GRU is unreachable.

| Responsibility | GRU master | Regional orchestrator |
| --- | --- | --- |
| Desired estate | Own the accepted global declaration and revision | Reconcile the accepted Region-scoped declaration |
| Orchestrator lifecycle | Bootstrap, admit, configure, upgrade, replace, and retire regional orchestrators | Report identity, version, readiness, and operation receipts |
| OCI resources | Own shared IAM policy and assign bounded regional authority | Observe and reconcile owned regional compute, network, storage, and identities |
| TerraBase cluster | Coordinate placement policy, residency, cross-Region membership intent, and rollout order | Apply local placement intent, health gates, drain, replacement, and restore coordination through TBEP |
| Cloudflare | Coordinate shared zone policy, routing publication, and release promotion | Supply observed regional health and placement facts |
| State and visibility | Maintain the authoritative estate view and aggregate regional status | Report bounded observations, metrics references, and durable receipts |

Every regional operation carries a Region identity, accepted desired-state
revision, operation ID, and fencing epoch. Credential scope and mutation-time
checks enforce the same boundary. A retry resumes the operation recorded in
the journal. Expired authority, conflicting ownership, or an unavailable
authoritative journal stops new mutations. Reconnection re-observes provider
and host state before resuming work; it never blindly replays queued changes.

Existing TerraBase service continues during master, regional orchestrator, or
NATS loss. Local observation and already admitted service operation may
continue. New control mutations require valid authority and durable recording.
Any future disconnected repair authority must specify its operation limits,
expiry, and reconciliation rules before it is enabled.

GRU is the home of global orchestration state and the consolidated estate
view. Durable replicas and backups protect that state outside GRU. This does
not move customer data out of its residency boundary or change the existing
ownership of usage truth by TerraBase and collected telemetry by Grafana Cloud.

## Capacity and load-balancer publication

Each Region starts with exactly two member hosts and scales as needed from
measured CPU, memory, storage/I/O, queue pressure, and service latency. Declare
sustained thresholds, minimum/maximum capacity, hysteresis and cooldowns in typed
estate configuration. Do not set invented universal utilization targets.

Publish fresh, bounded per-member identity, endpoint, readiness, drain state,
and capacity to `ts-proxy`. Publication uses the exact Worker KV schema and
key layout; a parallel legacy map does not satisfy the consumer. Health is
observed, never inferred from a configured address or a running VM alone.

Scale-out provisions TerraBase and a same-host orchestrator, admits identity,
catches up the required placements, and passes engine and infrastructure gates
before the new member receives traffic. Scale-in drains, proves placement and
RF=2 obligations, and keeps at least two hosts in each Region. Adding a host
neither joins the global control R3 nor creates another SQLite writer for an
existing database file. Recover RF=2 after loss before claiming its durability.

Qualify load redistribution, high-load expansion, recovery probation, failure
during admission, sustained-low-load removal, and stale publication. The REST
proxy must route around failed/overloaded members without changing residency.
Control and reactive data paths retain their separate ownership.

## Launch estate

- Launch Regions are GRU, SFO, and FRA. Design supports 20 Regions, but launch
  implementation, testing, and qualification cover exactly those three.
- Every Region starts with two `VM.Standard.A1.Flex` member hosts at 2 OCPU and
  12 GiB RAM with Balanced block volumes.
- GRU is the OCI home Region and uses the Always Free allocation for one member
  where the tenancy permits it.
- `VM.Standard.E5.Flex` is the automatic amd64 fallback when A1 capacity is
  unavailable. A capacity shortage must not block host replacement or
  `add-region`.
- Placement refuses a Region with fewer than two admitted member hosts.
- Hosts run Ubuntu LTS minimal. Production hosts contain no Docker, Podman,
  containerd, container runtime, production image, or image registry.
- TerraScale-managed services on every member host are `ts-node`, `terrabase`,
  `ts-orchestrator`, and the Grafana agent. Only selected orchestrator
  processes host replicas of the authoritative global control store. The
  base OS still runs normal systemd, networking, time, storage, SSH, and update
  services.
- Every Region has its own object storage for Litestream, release artifacts,
  and control snapshots, with the declared lifecycle rules.
- OCI is the durable source of truth for customer data. Cloudflare provides
  DNS, TLS, WAF, Workers, the reactive Snippet, KV, and authorized CDN copies.
  No other production cloud or PaaS is supported.
- The Cloudflare zone uses Pro plus Workers Paid. The estate may not depend on
  Enterprise, Data Localization Suite, Argo, or Regional Services features.
  Provider prices, quotas, plan limits, and terms are planning assumptions that
  must be reverified against current publications at G1 and G4.
- Cloudflare never carries database replication, backups, or control traffic.
  Those paths stay on OCI or direct member-to-member links.

## Declared estate and reconciliation

The complete desired estate is typed Go configuration in this repository.
It declares:

- Regions, OCI Region identifiers, host counts, primary and fallback shapes,
  CPU, memory, boot volumes, data volumes, and control-replica placement;
- compartments, VCNs, subnets, routing, NSGs, IAM policy, instance principals,
  block volumes, object buckets, versioning, and lifecycle rules;
- Vault software KEKs, per-database DEK policy, certificates, SPIFFE identities,
  trust bundles, and rotation periods;
- DNS records, Cache Rules, Snippet source and bindings, Worker routes and
  deployments, KV maps, WAF rules, rate rules, capability keys, and Secrets
  Store bindings;
- Grafana agent placement and the infrastructure needed for metrics and logs;
  and
- external probes and the objective gates that make a Region eligible to
  serve.

The running reconciler repeatedly observes OCI and Cloudflare, calculates a
deterministic plan, applies changes in dependency order, re-observes, and emits
an audit record and drift observation. It must:

- converge after retries, restarts, duplicate provider responses, and provider
  work requests;
- distinguish absent, creating, healthy, failed, and indeterminate resources;
- use provider idempotency keys and never repeat an uncertain destructive
  mutation;
- delete only resources whose TerraScale ownership and deletion authority are
  proven;
- repair changed or missing resources without console work;
- expose a dry run that shows the exact planned actions without provider
  mutation; and
- alert on drift while continuing automatic repair.

Nothing is clicked in OCI or Cloudflare after the owner completes account,
plan, payment, and initial credential setup. Runbooks cover account-level
provider failures and data-loss decisions, not routine drift.

## Bootstrap and Region lifecycle

`terrascale-orchestrator bootstrap` runs once from the owner's machine with an
OCI API key. From an empty tenancy it must:

1. create and verify the TerraScale compartments and IAM policy;
2. create the GRU VCN, subnets, routes, NSGs, default software Vault keys,
   Object Storage buckets, versioning, and lifecycle rules;
3. create the first two GRU member hosts in separate failure domains, falling
   back from A1 to E5 when required;
4. install only `ts-node` through cloud-init;
5. let `ts-node` fetch and verify the orchestrator and TerraBase artifacts;
6. start the fenced, temporary pre-customer GRU R1 and admit the host identities;
7. configure certificates, DNS, routes, KV, telemetry, and probes; and
8. hand authority to the running control plane without leaving the bootstrap
   API key on a host.

`terrascale-orchestrator add-region <code>` is one declared-estate entry plus a
release. Starting from an empty OCI Region, one command creates storage,
networking, two member hosts, Litestream targets, certificates, routes, health
and placement KV entries, telemetry, and probes. SFO and FRA also receive the
synchronized candidates required for the global R1-to-R3 promotion. Regions 4
through 20 also start and admit their own regional orchestrator, backed by the
global R3. At least three eligible hosts and a separate declaration are needed
for an independent regional R3. The command waits for the regional
orchestrator, member, control, backup, edge-routing, and external-probe gates before
the Region can serve. `--dry-run` is the generated runbook.

Region removal is declarative and fail-closed. It fences new placement and
routing, drains services, proves that placement locks, retention, backup, and
deletion obligations are satisfied, then removes owned resources. It never
widens a database placement lock.

### First-master bootstrap and handoff

Bootstrap must work before TerraBase, the dashboard, regional orchestrators,
and the global quorum exist. Its durable operation journal, artifact trust,
provider ownership proof, and initial identity must not depend on those
services already being healthy. Bootstrap retries use the same estate identity
and operation history, including after a crash between provider creation and
receipt persistence.

Handoff has two distinct boundaries. Once GRU runtime authority is verified,
the owner's provisioning process stops acting as the routine controller and
its API key is never copied to a host. Any remaining bootstrap authority is
limited to completing the pre-customer topology transition. After synchronized
R3 promotion, quorum verification, and the post-transition snapshot, that
remaining authority is revoked. Neither a rerun of bootstrap nor an old host
may establish a second master or return production to R1.

Customer admission requires permanent R3 and the production gates. A healthy
GRU R1 is a bootstrap milestone, not permission to serve customers. Recovery
from a lost first master must preserve the operation journal and accepted
epoch, fence the old identity, and prove ownership before resuming creation.

### Managing the orchestrator itself

The declared estate includes the master's and regional orchestrators' hosts,
embedded NATS storage, identities, certificates, versions, resource limits,
health checks, and backups. Their installation and replacement use `ts-node`.
The master must reconcile a failed regional orchestrator without requiring
that failed process to repair itself.

Control-plane releases replace one replica at a time, preserve quorum and
accepted history, and verify journal and protocol compatibility before
activation. A master restart resumes durable operations. Rollback restores a
compatible binary without restoring an older fencing epoch. A schema change
that prevents binary rollback needs a tested recovery path before release.

A total master or control-store failure requires a documented recovery path
that can run without a healthy orchestrator. Recovery verifies snapshot
integrity, restores acknowledged state under the declared recovery objective,
and fences old controllers before admitting replacements. Regional processes
must reject stale master commands after recovery. No automated recovery may
choose between conflicting durable histories or discard the last known copy.

## Placement and residency

- Each launch Region has RF=2 for every database placed there.
- The orchestrator gives TerraBase placement intent and peer lists. It never
  appoints a database leader or participates in replication.
- A placement lock such as `eu-only`, `br-only`, or an explicit Region list is
  immutable after database creation and cannot be widened.
- Placement, replication destinations, backup targets, restore targets,
  exports, branches, repair, and Region addition must all honor the same lock.
- A joining Region restores from a Litestream snapshot already copied into
  that Region, catches up, and passes TerraBase's proof of equality before it
  serves.
- Infrastructure actions such as drain, replace, `add-region`, and rollback
  stay in the orchestrator CLI. Product actions stay in the dashboard and
  public management API.

### TerraBase lifecycle contract

The orchestrator manages TerraBase membership intent, capacity, configuration,
release versions, backup targets, drain, replacement, and restore scheduling.
TerraBase owns membership acceptance, writer and follower transitions,
replication correctness, catch-up evidence, and permission to serve. An
orchestrator master is never a TerraBase database primary.

Every lifecycle operation must use a pinned, versioned TBEP contract with
mutual authentication, deadlines, idempotency, and durable operation status.
A transport timeout is an unknown result until observed. Host liveness alone
cannot prove replication health, safe removal, successful backup, or readiness
to receive traffic. Unavailable or stale TerraBase evidence fails the relevant
mutation gate closed.

Cluster qualification must cover create, scale out, drain, replace, rejoin,
upgrade, rollback, backup, restore, and safe removal using the real TerraBase
binary. Infrastructure completion and TerraBase readiness are separate gates;
placement and routing are published only after both pass.

## Host agent and systemd runtime

`ts-node` is a static Go host agent installed by cloud-init. After cloud-init
hands off, it is the only component allowed to mutate TerraScale runtime files,
artifacts, units, and service state. It does not replace systemd, the package
manager, kernel services, networking, time synchronization, or the normal base
OS update path. It must:

- download signed release artifacts into
  `/opt/terrascale/<component>/<version>/`;
- verify the ed25519 signature and SHA-256 digest before installation;
- use dedicated service users and hardened systemd system units with
  `ProtectSystem=strict`, narrow `ReadWritePaths`, `NoNewPrivileges`, an empty
  `CapabilityBoundingSet`, `SystemCallFilter=@system-service`, restricted
  address families, and cgroup v2 CPU, memory, and I/O controls;
- coordinate drain before restart, flip an atomic `current` symlink, restart,
  report health and catch-up, and roll back by restoring the prior symlink;
- report host shape, architecture, service versions, health, disk, and measured
  clock offset;
- configure and verify chrony against OCI NTP;
- refuse new TerraBase writes when clock offset exceeds 500 ms; and
- coordinate unattended security-update reboots through drain and health
  gates.

Production releases contain linux/arm64 binaries optimized for Ampere A1 and
linux/amd64 binaries for fallback hosts and local verification.

## Delivery

`ts-deploy` owns CI, builds, checks, signatures, publishing, and candidate
submission. It never owns rollout state or a cluster connection. The
orchestrator exposes the authenticated, signed delivery API and owns every
activation after submission.

Before rollout, the orchestrator verifies the candidate contract, signature,
digest, source revision, target, rollback artifact, and idempotency key. It
mirrors every accepted release artifact into every Region's release bucket.
Rollout cannot begin until all mirrors are verified.

TerraBase delivery order is:

1. deploy one GRU canary host;
2. require drain, process health, external health, and replication/backup
   catch-up gates;
3. continue one host at a time across each Region while preserving RF=2; and
4. roll every touched host back to its exact prior digest if any gate fails.

There is no regional blue-green product stack. TerraBase uses surge capacity
only when replacement-before-removal needs it.

For Cloudflare artifacts, `ts-deploy` builds, signs, publishes, and submits the
candidate. The orchestrator uploads or admits the candidate with its
Cloudflare authority, promotes Worker versions through gradual deployments,
deploys Snippet code and rules, reconciles zone rules, and restores the prior
version on a failed gate. Only the orchestrator holds Cloudflare write scope
beyond the limited Worker-version upload credential used by CI.

Target time from green `develop` to serving is under 15 minutes for TerraBase
and under 5 minutes for Workers.

## Self-healing

Self-healing is the default. The reconciler must automatically handle:

- a failed host by creating a replacement, installing `ts-node`, restoring or
  catching up from the surviving RF=2 member or Litestream, updating placement,
  and updating KV;
- A1 capacity exhaustion by retrying with the declared E5 fallback shape;
- a full or unhealthy disk by draining, expanding or replacing storage, and
  returning the member only after verification;
- expired or soon-to-expire certificates by rotating and reloading them;
- stale Region-health or database-placement KV entries by rewriting or
  deleting them in safe order;
- missing buckets, lifecycle rules, routes, WAF rules, and other declared
  resources through normal reconciliation;
- a failed deployment gate by automatic rollback; and
- a skewed clock by fencing writes, repairing time synchronization, and
  returning the member only after the offset is safe.

The system must never automate an ambiguous data-loss choice. Crypto-shred,
forced removal of the last durable copy, and recovery after provider state
cannot be proven require an explicit owner action.

## Keys, certificates, and secrets

- Each Region has one OCI Vault software KEK. It wraps per-database DEKs stored
  with placement records.
- Capability HMAC keys rotate every 24 hours with one expiry-bucket overlap and
  are delivered to members and Cloudflare Secrets Store by the orchestrator.
- Workload and control identities use TLS 1.3 mTLS and SPIFFE identities.
- Rotation is staged so old and new trust overlap, then the old material is
  removed only after every consumer reports the new generation.
- Secrets never appear in command arguments, logs, metrics, NATS payloads,
  estate declarations, fixtures, dry-run output, or audit records.
- OCI and Cloudflare runtime credentials use the narrowest available instance
  principal or scoped token. The one-time bootstrap credential is removed after
  handoff.
- Crown-jewel rotation procedures cover OCI, Cloudflare, release signing, and
  Forgejo administration before production qualification.

## Backups, drills, and disaster recovery

- The orchestrator runs a daily restore drill against a random sample of
  customer databases and the control-plane database.
- Each drill restores into a scratch branch, verifies checksums and row counts
  against the journal, records the result, and deletes the branch.
- JetStream control state is snapshotted daily to Object Storage in every
  Region. Restore must never regress an accepted control epoch.
- Release artifacts are mirrored into every Region before rollout so a Forgejo
  outage cannot strand an in-progress deployment.
- A failed restore drill is the one explicit durability-page exception to the
  SLO-only paging rule. Other cause-level failures stay on dashboards unless
  they produce customer-visible SLO burn.
- Backup, snapshot, restore, Region-loss, and control-plane-loss drills run
  without using customer traffic as the test mechanism.

## KV, estate publication, and admin visibility

- Region health is written to Workers KV every 10 seconds and on each
  transition.
- Database placement is written on every change. Health is published before
  placement so stale KV fails safely.
- KV uses bulk operations where available, deletes stale keys, counts writes,
  and emits a budget warning without skipping correctness writes.
- On change and at least every 10 seconds, the orchestrator publishes
  `estate.regions`, `estate.hosts`, `estate.databases`, `estate.rollouts`,
  `estate.slo`, and `estate.reconcile` into the control-plane database.
- Estate documents expose Regions, hosts, shape, architecture, health, clock
  offset, disk, versions, placement, replication lag, rollout state, drift,
  SLO burn, KV state, and restore-drill results. They contain no secrets.
- The dashboard reads these documents through the public SDK. The orchestrator
  does not add a private dashboard transport.

## Observability and paging

- Every subsystem emits Prometheus-format metrics and structured logs to the
  Grafana agent on each member host. The agent sends them to Grafana Cloud.
- Metrics have no database, tenant, or view labels. Cardinality is bounded by
  host, Region, and subsystem.
- Logs are structured, sampled above 100 lines per second per host, redacted,
  and retained for 14 days.
- Required observations include Region and host health, disk, clock offset,
  versions, rollout state, reconciliation drift, replication and catch-up
  gates, cache and Worker metrics, origin fills, KV writes, and OCI egress.
- OCI egress warns at the pace corresponding to 8 TiB per Region per month.
- The public SLO is 99.9% monthly API availability per Region, measured by an
  external probe.
- Customer-visible SLO burn is the only general paging signal. Cause-level
  conditions are dashboard alerts. A failed daily restore drill is the sole
  explicit exception because it invalidates the durability proof.

## Free-tier reaper

The orchestrator coordinates the infrastructure side of the Free database
reaper. At 30 days without a request it pauses the database, closes the file,
stops the Litestream stream, and retains the snapshot. At 90 days, and only
after the product has recorded the required notices and current eligibility,
it destroys the DEK and deletes the remaining owned data. Paid databases are
never reaped. One request reactivates a paused database.

## Local sandbox-VM architecture

The entire orchestrator must be testable on a developer machine without OCI,
Cloudflare credentials, or access to a production Region. Local tests use real
Linux virtual machines, real systemd units, real filesystems, real process
boundaries, and the production `ts-node`, orchestrator, and TerraBase binaries.
Mocks remain suitable for unit tests, but they cannot qualify host lifecycle,
delivery, repair, or degraded mode.

The local VM implementation sits behind a narrow `SandboxVMProvider` contract
that covers:

- create, start, stop, reboot, inspect, execute, and delete;
- vCPU, memory, disk, architecture, and boot-image selection;
- deterministic machine identity and separate persistent disks;
- isolated Region networks, stable addresses, DNS, host port forwarding, and
  controlled cross-Region links;
- network partition, latency, jitter, packet loss, bandwidth, and recovery;
- guest-observable disk exhaustion, I/O failure, read-only behavior, missing disk
  at boot, persistence, expansion, corruption while stopped, and snapshot
  restore. The contract specifies the guest result, not an unsupported VMM
  hotplug mechanism;
- guest clock skew or an equivalent injected clock source;
- snapshots or reusable base images for fast clean starts; and
- idempotent teardown that removes every VM, disk, network, forwarding rule,
  and temporary credential created by a test.

Production code must not import a sandbox SDK. The local provider belongs in a
test-only package or executable and implements the same behavioral contracts as
OCI without pretending to be OCI. Provider-specific identifiers never enter
the scheduling, delivery, placement, or repair decisions.

### Required backend: Firecracker

Firecracker on Linux/KVM is the required local qualification backend. SmolVM,
Cloud Hypervisor, QEMU, containers, host processes, and in-memory simulations
cannot substitute for it in `make vm-smoke` or `make vm-test`. A unit test may
still use a fake at one narrow boundary, but every orchestrator behavior must
also pass through the Firecracker stack before it is complete.

Pin and checksum-verify the Firecracker binary, `jailer`, guest kernel, Ubuntu
disk artifact, and Go SDK. CI downloads only versioned release assets whose
published digest is already declared by the repository; it never pipes a
remote installer into a shell. The test controller uses the official
Firecracker Go SDK for supported lifecycle operations and a small typed client
for the pinned Unix-socket OpenAPI when the SDK lacks a current operation. It
does not hide unsupported behavior behind shell command strings.

The Firecracker implementation must prove all of the following:

- an Ubuntu LTS minimal guest can run systemd as the service manager needed by
  production units, with systemd as PID 1 rather than an OCI entrypoint;
- a guest boots with 1 vCPU and no more than 512 MiB configured RAM, with an
  additional 256 MiB control-only smoke profile where the guest supports it;
- six persistent VMs run concurrently, two for each of GRU, SFO, and FRA, with
  the bootstrap R1 first and one control replica co-hosted in each Region after
  the fenced R3 promotion;
- the six-VM stack uses no more than 4 GiB of committed host RSS at idle and no
  more than one host CPU core on average while idle;
- each VM has a persistent writable data disk and preserves it across restart;
- VMs can address one another on stable private endpoints without routing
  traffic through production services;
- tests can partition any Region pair while preserving each Region's local
  network, then restore the link deterministically;
- tests can enforce latency and loss profiles, kill and reboot a VM, fill a
  disk, expire a certificate, and exercise the E5 fallback decision;
- `ts-node` installs the exact hardened production systemd units and performs
  signed install, drain, activation, health, catch-up, and rollback inside the
  guest;
- the test controller can collect bounded logs and diagnostics after failure;
  and
- cleanup succeeds after normal completion, assertion failure, cancellation,
  controller crash, and Firecracker or jailer crash recovery.

Use a reproducibly prepared, checksum-verified Ubuntu LTS raw disk rather than
an OCI image. Each instance receives unique machine identity and cloud-init
seed data. A test-only SSH or vsock control channel may copy binaries, execute
diagnostics, and report readiness; it cannot replace `ts-node` or grant the
orchestrator a production backdoor. Readiness means systemd is running, the
data disk is mounted, time and network configuration are applied, `ts-node` is
healthy, and the expected service has passed its real health gate. A started
VMM process is not a ready host.

The provider owns all host resources below Firecracker:

- one TAP per guest, isolated Region bridges or namespaces, stable addresses,
  DNS, and explicit cross-Region links;
- `nftables` rules for deterministic partitions and `tc netem` rules for
  latency, jitter, loss, reordering, duplication, and bandwidth;
- file-backed or safely mapped Firecracker drives that create the required
  guest-visible outcomes: persistent data across restart, `ENOSPC`, explicit
  I/O failure, a read-only filesystem, a missing disk on the next boot, capacity
  expansion, byte corruption while stopped, and snapshot restore. Tests must
  not depend on undefined or unsupported Firecracker hotplug behavior;
- API sockets, process and jail directories, console logs, metrics, cloud-init
  seeds, temporary credentials, and ownership labels; and
- a cleanup journal written before resource creation so an interrupted prior
  run can be recovered without discovering or deleting unrelated host state.

No Docker daemon or container runtime runs inside or outside a guest as part of
the suite. The Ubuntu disk is test infrastructure and never becomes a
production delivery format. A machine without Linux, KVM, and the required
host networking and block-device capabilities cannot produce a passing VM
qualification; `make vm-doctor` must explain the missing capability. The native
runner architecture receives the full suite, while every release cross-builds
and verifies manifests for both linux/amd64 and linux/arm64. Native arm64
Firecracker qualification becomes mandatory when an arm64 KVM runner exists.
Until then, the real OCI A1 gate qualifies arm64 behavior and local evidence
must say that it covers amd64 only.

## Local test topology and provider fakes

The full local topology contains six host VMs. Bootstrap begins with the two GRU
hosts and the temporary R1. SFO and FRA then join, synchronize their control
candidates, and reach this permanent target:

```text
GRU: gru-member-1 + gru-member-2, control replica on gru-member-1
SFO: sfo-member-1 + sfo-member-2, control replica on sfo-member-1
FRA: fra-member-1 + fra-member-2, control replica on fra-member-1
```

The local environment also runs bounded provider endpoints for OCI and
Cloudflare outside the guest VMs. They implement the real request and response
contracts needed by the orchestrator, including asynchronous work requests,
pagination, etags, rate limits, retries, idempotency, conflicts, timeouts,
indeterminate mutations, and eventual consistency. The local edge component
implements the Snippet capability gate, cache eligibility, cache locking,
immutable response behavior, KV routing maps, and Worker-version promotion
without contacting Cloudflare.

Provider fakes hold no special backdoor into orchestration decisions. Tests
change their observed provider state and verify that the public command,
reconciler, delivery API, or `ts-node` path repairs it.

## Required local VM tests

The repository must provide these commands:

```bash
make vm-doctor    # checks Linux/KVM, pinned Firecracker+jailer, host fault tools, disk, ports, and resource budget
make vm-image     # reproducibly builds or verifies the pinned Ubuntu systemd kernel and raw disk artifacts
make vm-smoke     # boots one small VM and proves exec, systemd, cgroup v2, disk persistence, network, and cleanup
make vm-stack     # starts the six-host GRU/SFO/FRA topology and local provider endpoints
make vm-test      # runs the full orchestrator qualification suite through Firecracker
make vm-clean     # removes only labelled TerraScale Firecracker test resources
```

`make vm-test` must prove:

1. bootstrap from an empty local provider to two healthy GRU members and the
   fenced temporary pre-customer R1;
2. `add-region sfo` and `add-region fra` reach serving state through the real
   command without an unwired stage or manual mutation;
3. the SFO and FRA candidates synchronize before one atomic R1-to-R3 promotion;
   the accepted epoch never regresses, bootstrap authority is retired, the R3
   survives one replica loss, and production cannot downgrade to R1;
4. a fourth two-host Region runs its own admitted regional orchestrator without
   joining the global R3; it reconciles local resources under GRU authority,
   rejects cross-Region and stale-master commands, and cannot form a separate
   regional R3 below three eligible hosts;
5. reconciliation creates missing resources, corrects mutable drift, handles
   eventual provider state, and refuses unowned deletion;
6. `ts-node` installs signed artifacts for the native guest architecture,
   rejects bad signatures and digests, writes the hardened units, persists
   data, and rolls back exactly; amd64 and arm64 manifests are both validated;
7. delivery uses a GRU canary, then one host at a time, preserves RF=2, checks
   drain, health, and catch-up, mirrors artifacts, and rolls back all touched
   hosts after an injected failure;
8. Worker and Snippet candidates promote and roll back through the local edge
   API, with no Worker on the reactive hot path;
9. KV health refresh, placement changes, stale-key removal, safe write order,
   and write-budget observation work at the required cadence;
10. estate documents publish on change and every 10 seconds without secret or
   unbounded-label leakage;
11. a dead host is replaced and caught up; guest-visible `ENOSPC`, I/O failure,
    read-only storage, missing-at-boot storage, expansion, and corruption take
    the declared repair or fail-closed path; an expired certificate rotates, A1
    failure selects E5, and clock skew fences writes;
12. a GRU or full control-plane outage leaves the admitted data plane serving;
13. each cross-Region partition and heal preserves local service and converges
    control state without unsafe duplicate mutation;
14. daily restore-drill orchestration, control snapshot upload, and per-Region
    artifact mirrors execute against persistent local object stores;
15. placement locks survive bootstrap, repair, backup, restore, export, branch,
    and Region changes; and
16. cancellation and failed assertions leave no running TerraScale VM or owned
    test resource after cleanup.

The suite records boot time, ready time, peak and idle host RSS, idle CPU,
per-VM configured memory, disk use, and cleanup time. Tests fail when they
exceed the declared resource budget. Performance numbers from this environment
qualify local orchestration behavior only. They never substitute for OCI and
Cloudflare production gates.

The local OCI and Cloudflare endpoints reproduce provider contracts and error
semantics, but do not pretend to be those clouds. Real-provider qualification
still gates production. Firecracker is mandatory because it proves the host,
systemd, network, disk, process, restart, and failure behavior on which the
orchestrator depends; it is not evidence of OCI or Cloudflare availability.

### Firecracker completion gate for the greenfield refactor

Run the real production orchestrator, `ts-node`, and TerraBase binaries in
Firecracker Ubuntu systemd guests. Each of the six GRU/SFO/FRA member VMs must
run TerraBase and its local orchestrator on the same guest. Exercise GRU-first
bootstrap, regional admission, fenced R1-to-R3 promotion, host-local control,
and a fourth two-host Region with local orchestrators without adding global
storage replicas. The fourth-Region scenario extends the six-VM baseline.

Prove orchestration through the real CLI and service transports, including
provider reconciliation, signed delivery, rollback, master and local process
restart, joint host loss, Region loss, WAN partition and recovery, disk faults,
identity rotation, and control-state and TerraBase restore. Exercise faults
during in-flight operations and verify durable recovery, isolation, and
cleanup. Unit fakes and provider-contract endpoints support this suite but
cannot replace guest execution or real TerraBase readiness evidence.

Run `make vm-doctor`, `make vm-image`, `make vm-smoke`, `make vm-stack`,
`make vm-test`, and `make vm-clean` as the documented workflow requires.
Retain exact binary digests, scenario results, resource measurements, and
bounded failure diagnostics. A missing KVM capability, missing artifact,
skipped scenario, or failed gate is an explicit qualification blocker, never
a passing result. Complete every independently executable implementation and
verification task while recording the remaining external blocker precisely.
Real-provider qualification and production drills remain separate gates.

## Production drills and acceptance

Before G2, the owner must supervise automated GRU bootstrap in the real PAYG
tenancy. The temporary R1 and real Cloudflare zone must converge without manual
estate mutation or console repair, and no customer may be admitted while the
control store remains R1. Before G3, SFO and FRA must be created with
`add-region`; the synchronized candidates must promote control storage to the
permanent R3 without regressing the accepted epoch. Placement-lock proofs must
cover every byte at rest, and the fault matrix must pass.

Required production drills are:

- control-plane loss while the data path continues serving;
- member loss and automatic replacement;
- Region loss and Region rejoin;
- WAN partition and heal;
- full disk and storage repair;
- certificate expiry and automatic rotation;
- A1 exhaustion and E5 fallback;
- clock skew and safe write fencing;
- failed canary and mid-rollout rollback; and
- restore from Litestream and JetStream snapshots.

Launch requires a 7-day soak on the exact release digests, successful rollback
rehearsal in every Region, 14 consecutive daily restore drills, live external
SLO probes and paging, no critical security findings, and the complete
workspace acceptance checklist.

## Greenfield implementation policy

This is a greenfield project. Refactor, redesign, rename, move, or replace any
code, package, command, configuration, persisted format, or internal protocol
needed to complete this goal. Existing code is implementation material, not a
compatibility requirement. Complete the actual production paths and delete
superseded implementations in the same change series.

Do not add or retain compatibility layers, shims, legacy aliases, deprecated
entry points, dual implementations, old-format readers, migration bridges, or
fallback paths whose purpose is to preserve a retired design. Update callers,
contracts, fixtures, tests, and documentation together to the final design.
Do not create a generic framework where a direct TerraBase-specific
implementation meets the requirement. Missing production dependencies must be
implemented and wired, not hidden behind successful stubs or test defaults.

Disposable local fixtures and test state may be regenerated for the new
contract. This policy does not authorize deleting unknown cloud resources,
secrets, customer data, or unrelated work. Idempotency, durable operation
recovery, fencing, backups, and tested release rollback remain requirements of
the final implementation. They do not justify preserving legacy interfaces.

Implementation work must continue through integration and qualification.
A package refactor, interface definition, passing unit suite, or documented
TODO is not completion while a required operational path remains unfinished.

## Refactoring order and completion criteria

Refactoring must produce working operational paths in this order:

1. Define and enforce master, regional orchestrator, storage replica, and host
   agent identities. Remove remote-only Region assumptions. Prove single
   master fencing and regional resource isolation before adding mutations.
2. Complete empty-tenancy GRU bootstrap, restart recovery, runtime handoff,
   SFO/FRA admission, and R1-to-R3 promotion. Inject a crash at every authority
   boundary and refuse premature customer admission.
3. Wire the production process to concrete durable stores, provider clients,
   regional dispatch, TBEP clients, and background services. Required adapter
   absence must produce an actionable startup error, never apparent readiness.
4. Complete TerraBase lifecycle and regional repair paths, then orchestrator
   upgrades, replacement, and full control-state recovery. Verify duplicate,
   delayed, reordered, and indeterminate operations through real process
   boundaries.
5. Remove superseded roles, duplicate policy implementations, obsolete
   adapters, and stale documentation as each replacement passes its gates.
   Replace pre-production journal and wire contracts directly and update all
   consumers together. Do not introduce compatibility readers or migration
   shims for discarded greenfield contracts.
6. Pass portable checks, Firecracker qualification, real-provider drills, and
   launch soak requirements on the intended release. Record measured recovery
   time, acknowledged-state loss, and capacity against declared limits.

Before implementing a lifecycle path, specify its owning controller, required
authority, persisted intent and receipts, provider or TBEP contract, retry and
recovery behavior, and observable success criteria. Before production, declare
control-plane RPO/RTO, regional recovery targets, reconciliation deadlines,
resource budgets, and supported version skew. Unspecified targets and missing
qualification evidence block production acceptance.

Implementation findings and unresolved inputs belong in the
[production readiness guide](docs/guides/production-readiness.md), not as
progress claims in this goal.

## Cross-repository and v1 acceptance

The workspace goal incorporates this repository's current operational topology.
Keep both goals aligned. A 3-, 10-, or 20-Region estate has a minimum of 6, 20,
or 40 member hosts respectively, with a local orchestrator on every host. The
permanent global R3 stays in GRU/SFO/FRA; expansion does not implicitly widen
customer placement or admit another master. Locations beyond launch are chosen
through declared estate configuration, not assumed from illustrative diagrams.

The launch control namespace is `ts.orch.v1`; shared public engine contracts
use `/api/v1` and `terrascale.sync.v1` with MessagePack 1.0. Remove discarded
pre-launch names and compatibility readers together with their callers.
Published release artifacts, not ambient workspace state, identify the exact
TBEP and engine contracts a controller uses.

Prove the real production composition from durable membership/control records
through region dispatch and same-host TBEP to the actual TerraBase binary.
TerraBase decides readiness from replication and catch-up evidence. The host
agent must install the exact artifact that `ts-deploy` builds and signs.
Publication of routing/placement follows both infrastructure and engine gates.

Estate publication uses public SDK/API operations against the control-plane
database with an ordinary scoped credential. It neither depends on a private
dashboard transport nor takes over usage, identity, payments, or query policy.
Required operational adapters, including restoration and key distribution,
are implemented and wired before production acceptance.

## Repository construction requirements

- Go is the only implementation language in this repository. Test guest assets
  and provider fixtures may use data files or shell only when a Go
  implementation would add no behavior.
- Embedded NATS uses `nats-server` as a library. Production does not depend on
  a separately installed NATS service.
- Split packages before they reach 10,000 lines. Keep dependencies acyclic and
  keep provider implementations outside decision packages.
- Delete superseded roles and NATS messages as the launch v1 path replaces them. Delete the
  container supervisor, image and registry types, Dashboard, Database API and
  other retired product roles, Infisical, C# residue, archived phase documents,
  and stale blue-green, Merkle, Project Queue, environment, or container text.
- Do not keep unwired production seams. Wire a complete path or keep it in a
  test-only package with a named acceptance item.
- Fail closed at trust, identity, authority, residency, ownership, delivery,
  deletion, and provider-ambiguity boundaries.
- Never log secret material.
- Tests are the specification for wire formats, NATS subjects, persisted
  records, signatures, CLI output, exit codes, and environment variables.
- `make check` is the portable workspace verification set and CI runs the same
  target unchanged.

## Verification

The portable gate runs on every development machine and CI job:

```bash
make check   # gofmt -l .; go vet ./...; go build ./...; go test -race ./...
```

`gofmt -l .` must print nothing. `make check` must not require KVM, privileged
networking, block-device controls, OCI credentials, or Cloudflare credentials.
A local change is incomplete until this gate passes.

The privileged Firecracker gates run on Linux/KVM:

```bash
make vm-doctor
make vm-smoke
make vm-test
```

`make vm-smoke` is the focused feedback loop for guest-image, boot, Firecracker,
network, disk, and test-controller changes. Documentation-only changes do not
require local KVM. On every push to `develop`, including documentation-only
pushes, CI must run the complete six-VM `make vm-test` after `make check` and
before it builds, publishes, submits, or deploys a candidate. Changes to
bootstrap, Region or host lifecycle, reconciliation, delivery, repair,
networking, storage, identity, or degraded mode are not qualified until that
full suite passes.

The full suite qualifies the native runner architecture. CI cross-builds and
validates manifests for linux/amd64 and linux/arm64 on every release. Native
arm64 Firecracker qualification becomes required once an arm64 KVM runner is
available. Until then, real OCI A1 qualification remains the arm64 gate and the
Firecracker result must not claim arm64 coverage.
