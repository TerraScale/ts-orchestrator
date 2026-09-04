# ts-orchestrator goal

## Authority

The workspace [GOAL.md](../GOAL.md) remains the sole authority for TerraScale.
This file collects every workspace requirement that governs `ts-orchestrator`
and adds the repository's local test requirements. If the two files disagree,
the workspace goal wins and this file must be corrected in the same change.
This file contains decisions and acceptance criteria, never progress, dates,
commit hashes, or review records.

## Mission

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

- GRU is the global authority.
- At launch, one orchestrator control replica is co-hosted on a member host in
  each of GRU, SFO, and FRA. The three replicas form one embedded JetStream R3
  control group across the three Regions.
- There are no dedicated control hosts at launch.
- A Region may move to its own autonomous three-replica regional control group
  only after it has at least three hosts. This is post-launch capacity work.
- Existing Regions keep serving customer reads, eligible writes, replication,
  and reconnect recovery when the orchestrator or NATS is unavailable.
- Loss of GRU or NATS may stop new global mutations. It must not enter the
  TerraBase correctness path or stop an already admitted data plane.
- Control mutations are fenced, authenticated, idempotent, restart-safe, and
  durably journaled. Missing, stale, conflicting, or unverified authority fails
  closed.

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
- A host runs only `ts-node`, `terrabase`, an orchestrator control replica when
  placed there, and the Grafana agent.
- Every Region has its own object storage for Litestream, release artifacts,
  and control snapshots, with the declared lifecycle rules.
- OCI is the durable source of truth for customer data. Cloudflare provides
  DNS, TLS, WAF, Workers, the reactive Snippet, KV, and authorized CDN copies.
  No other production cloud or PaaS is supported.

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
6. start the GRU control replica and admit the host identities;
7. configure certificates, DNS, routes, KV, telemetry, and probes; and
8. hand authority to the running control plane without leaving the bootstrap
   API key on a host.

`terrascale-orchestrator add-region <code>` is one declared-estate entry plus a
release. Starting from an empty OCI Region, one command creates storage,
networking, two member hosts, the co-hosted control replica, Litestream targets,
certificates, routes, health and placement KV entries, telemetry, and probes.
It waits for members, control, backup targets, edge routing, and external probes
to pass before the Region can serve. `--dry-run` is the generated runbook.

Region removal is declarative and fail-closed. It fences new placement and
routing, drains services, proves that placement locks, retention, backup, and
deletion obligations are satisfied, then removes owned resources. It never
widens a database placement lock.

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

## Host agent and systemd runtime

`ts-node` is a static Go host agent installed by cloud-init and the only
component allowed to mutate a host. It must:

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
- disk fill, detach, reattach, expansion, read-only transition, and corruption
  injection where the backend can do so safely;
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
  one control replica co-hosted in each Region;
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
- file-backed or safely mapped Firecracker drives for persistent data, disk
  fill, expansion, read-only and I/O-error transitions, detach and reattach,
  corruption injection, snapshot, and restore;
- API sockets, process and jail directories, console logs, metrics, cloud-init
  seeds, temporary credentials, and ownership labels; and
- a cleanup journal written before resource creation so an interrupted prior
  run can be recovered without discovering or deleting unrelated host state.

No Docker daemon or container runtime runs inside or outside a guest as part of
the suite. The Ubuntu disk is test infrastructure and never becomes a
production delivery format. A machine without Linux, KVM, and the required
host networking and block-device capabilities cannot produce a passing VM
qualification; `make vm-doctor` must explain the missing capability. Native
amd64 and arm64 Firecracker hosts qualify their matching release architecture,
while every release still cross-builds and verifies manifests for both.

## Local test topology and provider fakes

The full local topology contains six host VMs:

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

1. bootstrap from an empty local provider to two healthy GRU members and a
   running control replica;
2. `add-region sfo` and `add-region fra` reach serving state through the real
   command without an unwired stage or manual mutation;
3. the three control replicas form R3, survive one replica loss, and recover;
4. reconciliation creates missing resources, corrects mutable drift, handles
   eventual provider state, and refuses unowned deletion;
5. `ts-node` installs signed artifacts for the native guest architecture,
   rejects bad signatures and digests, writes the hardened units, persists
   data, and rolls back exactly; amd64 and arm64 manifests are both validated;
6. delivery uses a GRU canary, then one host at a time, preserves RF=2, checks
   drain, health, and catch-up, mirrors artifacts, and rolls back all touched
   hosts after an injected failure;
7. Worker and Snippet candidates promote and roll back through the local edge
   API, with no Worker on the reactive hot path;
8. KV health refresh, placement changes, stale-key removal, safe write order,
   and write-budget observation work at the required cadence;
9. estate documents publish on change and every 10 seconds without secret or
   unbounded-label leakage;
10. a dead host is replaced and caught up, a full disk is repaired, an expired
    certificate rotates, A1 failure selects E5, and clock skew fences writes;
11. a GRU or full control-plane outage leaves the admitted data plane serving;
12. each cross-Region partition and heal preserves local service and converges
    control state without unsafe duplicate mutation;
13. daily restore-drill orchestration, control snapshot upload, and per-Region
    artifact mirrors execute against persistent local object stores;
14. placement locks survive bootstrap, repair, backup, restore, export, branch,
    and Region changes; and
15. cancellation and failed assertions leave no running TerraScale VM or owned
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

## Production drills and acceptance

Before G2, GRU must be bootstrapped in the real PAYG tenancy and the real
Cloudflare zone must converge without console repair. Before G3, SFO and FRA
must be created with `add-region`, placement-lock proofs must cover every byte
at rest, and the fault matrix must pass.

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

## Repository construction requirements

- Go is the only implementation language in this repository. Test guest assets
  and provider fixtures may use data files or shell only when a Go
  implementation would add no behavior.
- Embedded NATS uses `nats-server` as a library. Production does not depend on
  a separately installed NATS service.
- Split packages before they reach 10,000 lines. Keep dependencies acyclic and
  keep provider implementations outside decision packages.
- Delete v1 roles and NATS messages when v2 equivalents exist. Delete the
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
- `make check` is exactly the workspace verification set and CI runs the same
  target.

## Verification

```bash
gofmt -l .
go vet ./...
go build ./...
go test -race ./...
make vm-doctor
make vm-smoke
make vm-test
```

`gofmt -l .` must print nothing. Production-facing changes are incomplete
until `make check` passes, and `make check` includes the commands above on the
Linux/KVM qualification runner. Documentation-only and isolated unit-test
changes may use the focused Go verification set during development, but cannot
declare a release qualified. VM architecture changes require `make vm-smoke`.
Changes to bootstrap, Region lifecycle, host lifecycle, reconciliation,
delivery, repair, networking, storage, identity, or degraded mode require the
complete Firecracker-backed `make vm-test`.
