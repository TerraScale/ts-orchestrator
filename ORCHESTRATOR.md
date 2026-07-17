# TerraScale Orchestrator

- Status: Proposed architecture and implementation plan
- Implementation readiness: owner choices 1A–10A are accepted; pure Phase 1 contract tranches may freeze with explicit policy inputs, while measured cost/storage/RPO/RTO targets remain deployment-qualification gates
- Date: 2026-07-13
- Target repository: `TerraScale/TerraScale.Orchestrator`
- Deployment posture: full greenfield; OKE and the live Kubernetes estate are already deleted, and no prior cloud/data/control resource is adopted
- Primary implementation: C# / .NET 10, self-contained single-file Linux artifacts for `linux-arm64` and `linux-x64`
- Primary production architecture: ARM64/AArch64 on OCI `VM.Standard.A1.Flex` Ampere hosts
- Production host model: one `terrascale-orchestrator` process per host, managed by systemd

## Executive decision

Build a TerraScale-specific orchestrator instead of placing another control plane on top of Kubernetes or Nomad.

This is justified only because the product is deliberately narrower than a general-purpose cluster platform. The orchestrator schedules an allowlist of TerraScale services, understands TerraBase safety rules, manages elastic cloud compute and block storage, provides native GitOps and CI/CD, issues workload identity, exposes an operator API/CLI, and exports its complete operational state to Grafana. It will not accept arbitrary workloads or implement a Kubernetes-compatible API, Helm, CRDs, CNI, CSI, a general container registry, a metrics database, a source-control system, a new VPN protocol, or new cryptographic primitives.

The design keeps the parts that already work:

- The full relevant NATS platform—not only queueing—for pub/sub, request/reply, service discovery, regional gateways, replicated JetStream journals, durable consumers, KV compare-and-swap coordination, small signed Object Store bundles, identity/authorization, advisories, and system monitoring.
- systemd and cgroups v2 for host and native-binary lifecycle.
- containerd and runc for OCI containers.
- Forgejo, BuildKit, OCIR, and Forgejo packages for source, builds, and immutable artifacts.
- OCI APIs, KMS/Vault, Object Storage, load balancers, networking, and block volumes as the first provider implementation.
- Pulumi for durable cloud foundation.
- OpenTelemetry, Prometheus, Loki, Tempo, Alertmanager, Alloy/OTel Collector, and Grafana.
- WireGuard through an established VPN implementation rather than a TerraScale VPN protocol.
- TerraBase itself and its typed administrative APIs.

The resulting platform is not a toy scheduler. It is a three-level control plane:

1. A GRU global coordinator accepts signed desired state, releases, policy, and operator actions.
2. Every region has an autonomous, replicated cell controller and local NATS/JetStream state.
3. Every host has an agent that executes fenced operations through containerd or systemd.

SFO and FRA continue serving, restarting workloads, replacing failed nodes, scaling within pre-authorized limits, and expanding storage if GRU or the WAN is unavailable. Global releases and global policy changes stop during that outage unless an audited regional break-glass action is used.

GRU has an additional hard availability contract: any one GRU compute node may disappear without taking down the global authority or the GRU product cell. All critical GRU roles are replicated and failure-domain spread, acknowledged state remains available, load balancers remove the failed endpoint, and the regional autoscaler creates a replacement without operator action. A TCP connection or request executing on the failed machine may require the normal idempotent client retry; there must be no sustained service outage or accepted-state loss.

### mTLS decision

mTLS is required, but it must be applied at trust boundaries rather than indiscriminately.

- Required: controller-to-controller, controller-to-agent, NATS client/route/gateway, secret retrieval, CI worker enrollment, administrative APIs, and cross-region telemetry.
- Required for TerraBase administrative and replication identities where client certificates are already part of the product contract.
- Not required on a permissioned same-host Unix socket; the OS user, file mode, and peer credentials are the identity boundary there.
- Public customer HTTP remains ordinary server-authenticated TLS plus product authentication; requiring customer client certificates would break the public API contract.
- Workload-to-workload mTLS is available as a workload policy and may become the default after application compatibility is proven.

For NATS, mTLS proves the machine/workload transport identity. NKeys, operator/account JWTs, and subject permissions provide NATS-specific authorization. Neither layer replaces the other.

## Confirmed owner decisions

- OKE and all live Kubernetes infrastructure have already been deleted. This is a full-greenfield first deployment, not a Kubernetes-to-orchestrator migration. The new platform starts with new Pulumi state, resource IDs, hosts, volumes, NATS operators/clusters/state, PKI roots, secrets, and desired state; it adopts no prior cloud, data, identity, DNS, or control-plane resource. There is no live legacy ownership transfer, shadow controller, cutover, or reverse-migration path to design. Historical Kubernetes/Flux repositories are read-only behavioral and workaround evidence plus a stale-resource cleanup checklist.
- Every active region has a dedicated three-server orchestrator NATS cluster and a separate three-server TerraScale product NATS cluster. Under decision 8A they may share the three compact-profile hosts, but never share a process, trust root, account, credentials, port, cgroup, or store directory. The cheapest physical-volume layout that passes isolation, recovery, and performance tests is selected automatically during qualification.
- Pulumi is the bootstrap/foundation layer. After a durable handoff, every regional controller owns and repairs that region's concrete nodes, attachments, workload backends, and expandable storage.
- Each region deletes safely unused elastic nodes, creates capacity when needed, replaces failed nodes, and expands storage without depending on GRU.
- Application workloads are limited to TerraScale API, Authentication, Dashboard, and TerraBase. Required first-party platform workloads—both NATS clusters, the orchestrator, OTel/Grafana stack, VPN components, and isolated ephemeral CI runners—are allowed infrastructure roles, not a generic workload API.
- There is no arbitrary customer workload or general-purpose scheduling surface.
- GitOps is native to the orchestrator. Flux is removed, not embedded, emulated, or retained as a runtime dependency.
- Grafana is the operator web console for status, health, capacity, failure, storage, deployments, NATS, cost, and regional state. The orchestrator does not build a second dashboard UI.
- Decision 1A resolves “quorum of three in at least three regions” as three controller candidates backed by a local three-server control-NATS cluster in every region, with no WAN-spanning control quorum.
- OCI is the first production provider and A1 Ampere ARM64 is the primary compute target. The region catalog and provider contract cannot hard-code GRU/SFO/FRA and must support a cloud footprint with at least twenty production regions. Hetzner is excluded by owner decision.
- Local integration uses digest-pinned, rootless Podman containers with a closed image catalog, private pod networking, dropped capabilities, `no-new-privileges`, explicit resource limits, owner labels, and deterministic cleanup. A complete GRU/FRA/SFO qualification topology uses nine isolated node containers on every deployment-bound revision.
- Real systemd-as-PID-1 and OCI A1/IAM/block-volume/storage-performance boundary tests are mandatory in addition to the full container topology; containers cannot qualify systemd, ARM64, cloud autoscaling, or database-storage behavior.

### Requirement reconciliation

Later owner statements take precedence over earlier exploratory requests. This plan therefore applies these explicit resolutions:

| Earlier exploration | Final requirement represented by this specification |
|---|---|
| Embed Flux | Remove Flux completely; implement native GitOps with direct, durable acknowledgement and no Flux runtime or compatibility layer |
| Build a vault and console into the orchestrator | Build the vault policy/PKI/lease capability into the control plane with OCI Vault/KMS root protection under decision 3A; use read-only Grafana as the browser console and keep mutations in the audited operator API/CLI |
| Consider whether mTLS is needed | Use selective mTLS at privileged machine/workload/cross-region boundaries; keep same-host Unix sockets and public customer HTTPS on their appropriate existing identity boundaries |
| Consider Nomad or another lightweight orchestrator | Build the TerraScale-specific C# orchestrator; Nomad and Kubernetes are not runtime dependencies |
| Consider broad cloud alternatives | Ship OCI/A1 first, preserve a provider-neutral interface and a dynamic catalog of at least 20 provider regions, exclude Hetzner, and make another provider an explicit adapter rather than lowest-common-denominator design |
| General container/binary management | Admit only the exhaustive TerraScale/platform role catalog; support both containerd and native systemd execution without exposing arbitrary commands or a generic workload API |
| Plan a Kubernetes/OKE migration | OKE is already deleted; perform a full-greenfield three-region deployment that adopts nothing from the old estate, and keep any stale cloud/IAM/DNS/secret/configuration cleanup outside the new ownership graph |

No resolved item in this table may silently revert to an earlier request. The numbered decisions below are the authoritative owner choices.

## Resolved owner decisions

The owner selected `all A` with reliability first on 2026-07-16. Every A choice below is normative; changing one requires an explicit superseding decision and an architecture review.

| # | Question | A — selected | B |
|---|---|---|---|
| 1 | Regional control topology | Three controller candidates plus three control-NATS servers in **each** region: 9 of each across GRU/SFO/FRA, with independent regional JetStream R3 consensus | Three total controllers/NATS servers, one per region; this creates a WAN quorum and requires rewriting the regional-autonomy invariants |
| 2 | GRU/WAN outage deployments | Regions keep serving, healing, replacing/scaling nodes, expanding storage, and renewing existing identities; freeze new global releases/policy changes | Allow each isolated region to accept independent releases/policy changes |
| 3 | Vault authority | Built-in policy/PKI/lease/rotation service with ciphertext/root protection in OCI Vault/KMS initially | Store envelope-encrypted authoritative ciphertext in a dedicated, isolated vault JetStream account/stream from v1; never ordinary subjects or plaintext |
| 4 | Runtime defaults | Native systemd for TerraBase; containers for API/Auth/Dashboard initially; both supported where useful | Choose a different default split |
| 5 | Elastic data cleanup | Never shrink; retain permanent disks; quarantine a removed elastic TerraBase disk for 7 days after verified backup | Immediately delete explicitly disposable elastic disks after safe topology removal |
| 6 | Provider implementation timing | Finish OCI plus a provider-neutral contract first; OCI's catalog must expose at least 20 usable regions, while GRU/SFO/FRA are the first activated/qualified cells; add another adapter when needed | Require a second complete cloud adapter before the first production deployment |
| 7 | CI/CD bootstrap exception | Keep one minimal independent Forgejo workflow/runner solely to build and recover the orchestrator; all product CI/CD is orchestrator-native | Require even orchestrator recovery CI to run inside the orchestrator, accepting the circular outage dependency |
| 8 | “Dedicated NATS” meaning | Dedicated means independent clusters/processes/security/cgroups/stores; both planes may share benchmarked compact-profile hosts | “Dedicated” meant separate physical compute nodes for control NATS and product NATS, increasing the regional floor |
| 9 | Telemetry during long GRU outage | Export all three OTel signals, spool to a fixed encrypted disk budget, then drop oldest/sample with explicit data-loss alerts; product traffic never blocks | Never drop telemetry, requiring another durable regional telemetry store and an explicit maximum outage/cost design |
| 10 | Container count during autoscaling tests | Nine seed node containers are the exact steady-state topology; explicit tests may add temporary `*-elastic-*` containers and must converge back to 3/cell | Nine is a hard ceiling; replacement can be tested, but real scale-out beyond three cannot be demonstrated in the full-region lab |

The following measurable qualification values remain to be derived and approved from Phase 0 evidence:

- Team size and desired first-production date.
- Maximum three-region pre-user cost. R$80/day is the historical pre-OKE-deletion baseline; Phase 0 must first measure the post-deletion residual OCI bill. Cost can constrain non-safety growth, but cannot reduce R3 state, one-node-failure tolerance, backup/recovery, storage integrity, or security floors.
- Per-member storage SLO: minimum IOPS/throughput and acceptable p95/p99 read/write latency.
- Regional RPO/RTO. SFO/FRA writes continue during a total GRU outage; acknowledged local writes must survive any single-host loss, while cross-region RPO and recovery time remain measured production gates rather than invented constants.

### Owner requirement trace

These IDs seed the implementation registry and prove that every request in the design conversation has a disposition.

| ID | Owner requirement | Specification disposition |
|---|---|---|
| `REQ-O001` | TerraScale—not Periscale—and a production/final platform rather than a toy | Title/scope, production HA, real-system gates, and definition of complete |
| `REQ-O002` | Reduce the historical pre-OKE-deletion OCI cost of R$80/day while preserving future scale | Measure the post-deletion residual bill, then apply compact/growth profiles, budgets, scale-to-zero where safe, provider inventory, and a measured seven-day cost gate; final target still requested |
| `REQ-O003` | Avoid Kubernetes memory overhead and pod limit | One lightweight C# process/host, no sidecars, measured RSS budgets, resource-based admission, and no fixed pod/allocation ceiling |
| `REQ-O004` | Custom tailor-made orchestrator; no Nomad/Kubernetes dependency or arbitrary workloads | Executive decision, closed admitted-role catalog, and explicit non-goals |
| `REQ-O005` | C# self-contained single binary under systemd, including ARM64/A1 | One-binary roles, `linux-arm64` release gate, A1 real execution, bootstrap/self-upgrade, systemd packaging |
| `REQ-O006` | Use NATS as the full communication platform, not only queues | Feature adoption matrix, dual trust planes, regional R3, gateway/leaf strategy, member controller, conformance tests |
| `REQ-O007` | Dedicated orchestrator NATS and separate TerraScale product NATS | Two R3 clusters per region; decision 8A permits benchmarked host sharing while disk layout remains qualification-selected |
| `REQ-O008` | At least GRU/SFO/FRA; GRU global stack; SFO/FRA export OTel to GRU | Target topology, regional autonomy, GRU observability, edge collectors/spool/export |
| `REQ-O009` | GRU remains operational after any one node fails | Explicit capability-by-capability HA/N+1 contract and sequential node-loss acceptance |
| `REQ-O010` | Pulumi bootstraps; then each region creates/deletes/replaces its own nodes and expands storage | Ownership/handoff receipt, compartment-scoped actuator, survival bundle, compute/storage state machines |
| `REQ-O011` | Automatic node and TerraBase storage scaling | Compute autoscaler, expand-only storage controller, TerraBase-specific policy, budget/performance gates |
| `REQ-O012` | Manage containers and native systemd binaries; TerraBase can use either | containerd and systemd executors with one lifecycle contract; decision 4A selects native TerraBase and containerized API/Auth/Dashboard defaults |
| `REQ-O013` | mTLS support, but only where it is actually needed | Selective mTLS decision, workload identity, NATS JWT authorization, rotation/revocation testing |
| `REQ-O014` | Built-in native GitOps; remove Flux | Native GitOps source/reconciler, policy/child ownership, fresh typed manifests, and Flux non-goal |
| `REQ-O015` | Built-in vault, CI and CD | Vault/PKI/policy service with OCI Vault/KMS root protection and immutable promotion/isolated runners with the decision 7A recovery exception |
| `REQ-O016` | Web console without rebuilding Grafana | Read-only immutable/provisioned Grafana replicas plus exact sanitized state projection and audited API/CLI |
| `REQ-O017` | Robust business-logic tests before the first deployment test | Literal whole-product pure Phase 1, requirement trace, exhaustive/model/fuzz/mutation tests, real-NATS L0C, signed evidence gate |
| `REQ-O018` | New repository and reproducible test environment | This repository plan, solution layout, mandatory rootless-container logic/single/cell/full-region labs, and real systemd/OCI gates |
| `REQ-O019` | Cloud global reach of at least 20 regions; not Hetzner | Decision 6A: OCI-first dynamic region/provider contract, initial three active cells, no hard-coded trio, and another adapter only when needed |
| `REQ-O020` | Database/storage performance is a primary constraint | Dedicated TerraBase volumes, IOPS/throughput/latency-aware scheduling/scaling, co-location rejection, destructive performance gates |
| `REQ-O021` | Run complete GRU/FRA/SFO tests in isolated containers | Digest-pinned nine-node container topology, all-server inventory, regional links/faults, progressive full-region gates, and separate production-boundary evidence |
| `REQ-O022` | Implement the orchestrator in parallel with multiple sub-agents | Dependency DAG, exclusive workstream/path ownership, dedicated branches/worktrees, work-package manifests, independent verification, serialized merge train, and exact-tree integration evidence |
| `REQ-O023` | OKE is already deleted; treat deployment as full greenfield and do not plan a migration | New Pulumi/resource/data/identity state, no prior-resource adoption, separate residual-account audit, and first-production gates with no Kubernetes fallback |

An implementation PR may not mark one of these requirements “done” from a unit test alone; it must link the registry entry, implementation intent/adapter, required test layers, operational evidence, and documentation.

## Contract invariants

These invariants are non-negotiable. Invariants 1–3 and the per-region portions of 16/18 implement decision 1A; any superseding choice requires an explicit architecture rewrite before implementation, not an exception during coding.

1. GRU, SFO, and FRA are active cells. GRU is both a global-control cell and a normal API/data cell.
2. A regional cell serves from its last accepted `CellSpec` when GRU, WAN connectivity, Git, or central observability is unavailable.
3. The regional control state never depends on a WAN-spanning Raft quorum.
4. Exactly one fenced writer may advance each desired-state stream, release, deployment, node operation, volume operation, or TerraBase topology operation.
5. Every command is idempotent, generation-bound, deadline-bound, and safe to replay after a crash.
6. Stale leaders and stale agents cannot attach, format, grow, delete, start, stop, publish, or complete an operation.
7. TerraBase keeps at least three permanent members per active production cell, one member per host, one single-writer data volume per member, stable member/volume identity, and application-consistent backups.
8. Scaling never removes permanent TerraBase members `a`, `b`, or `c`. Elastic member scale-in remains disabled until its destructive acceptance suite passes.
9. Storage is expand-only. The orchestrator never pretends that adding a replica increases a database's logical storage capacity.
10. Secrets and private keys never appear in ordinary NATS subjects, desired-state documents, logs, traces, CI output, status metrics, or Grafana.
11. Builds happen once. Production receives the exact tested digest; deployment never rebuilds an artifact.
12. Observability failure never blocks product request processing.
13. Product project/database placement remains owned by the product placement domain until a deliberate ADR moves it. The host scheduler does not create a second source of truth for `Project.Regions`.
14. Durable networking, IAM, root keys, launch templates, and bootstrap generation belong to Pulumi. After the signed handoff, concrete regional nodes, attachments, and workload volumes belong only to the regional orchestrator.
15. Documentation, JSON Schema, validation, generated Grafana dashboards, and test fixtures derive from the same versioned C# contracts.
16. GRU is single-node-failure tolerant. No critical global or GRU-cell capability, authoritative state, credential issuer, ingress path, observability ingest path, or VPN coordination path may have a one-node failure mode.
17. Only allowlisted TerraScale application and required first-party platform roles can be admitted. A manifest cannot invent a new arbitrary workload kind or request unrestricted systemd/container privileges.
18. Every active region has operationally and cryptographically separate orchestrator-control and TerraScale-product NATS clusters, each with three servers and separate stores; decision 8A permits benchmarked host sharing and physical disk layout is the cheapest tested safe layout.

## What “from scratch” means

The orchestration logic is tailor-made. The primitives are not reimplemented.

| Build in TerraScale.Orchestrator | Reuse as a dependency or managed workload |
|---|---|
| Desired/observed-state engine | NATS/JetStream |
| Regional scheduler and placement policy | systemd, cgroups v2, journald |
| Node autoscaler and provider controllers | containerd, runc, OCI image format |
| Volume lifecycle, expansion, and fencing controller | OCI Compute, Block Volume, KMS/Vault, Object Storage, LB APIs |
| TerraBase lifecycle controller | TerraBase server and admin APIs |
| Git/OCI source and reconciliation controllers | Git/Forgejo and OCI registries |
| Release, deployment, and promotion state machines | BuildKit and existing language toolchains |
| Workload identity, policy, PKI automation, and secret delivery | standard X.509/TLS and cloud KMS; no custom crypto |
| Operator API/CLI and generated Grafana dashboards | Grafana/Prometheus/Loki/Tempo/Alertmanager/OTel |
| Service registry, health model, and provider-neutral inventory | DNS, Cloudflare, OCI LB/NLB |
| VPN peer/route policy controller | WireGuard/NetBird or another selected implementation |

This boundary prevents replacing Kubernetes with a private, incomplete clone of every project in the cloud-native ecosystem.

## Repository evidence and greenfield posture

The plan is based on the ten pre-existing TerraScale repositories beside this new repository. Their current worktrees contain existing owner changes and are read-only inputs to this planning/audit turn; they must not be cleaned or reset. They describe behaviors worth preserving and obsolete Kubernetes/Flux workarounds to delete, but they are not a live deployment source or migration surface. Later cleanup is done only through dedicated, repository-local worktrees and reviewed PRs after the corresponding native behavior and regression gate exist.

| Repository | Preserve | Port or retire |
|---|---|---|
| `TerraBase` | Native Linux packaging, systemd unit behavior, storage signals, health, TLS/client-certificate behavior, backup/restore, admin APIs | Add an orchestrator-facing typed admin client/contract; do not fork its storage engine into the orchestrator |
| `Terrabase.Operator` | Spec/status semantics, topology safety, replication ownership, one-member upgrades, autoscaling holds, certificate naming, tests as executable specifications | Port behavioral rules to C#; delete obsolete Kubernetes actors, StatefulSets, PVCs, Jobs, webhooks, cert-manager, and `kubectl` scripts after their rules have matching native tests |
| `TerraScale.Internals` | API/Auth/Dashboard runtime graph, health endpoints, project placement, release manifests, region headers, OTel contract | Add native workload descriptors; fix the missing Auth build target; keep project placement separate from machine scheduling |
| `TerraScale.DotNet` | Public API and queue SDK compatibility, idempotency, preferred-region behavior, errors and receipts | No operator/host APIs in the customer SDK; create a separate operator client if needed |
| `TerraScale.TypeScript` | Public API contract, OpenAPI/route drift tests, Dashboard runtime | Replace hard-coded OCI-specific three-region constants with discovered provider-neutral data without breaking clients |
| `TerraScale.Infrastructure` | Region catalog, VCN/DRG, IAM, KMS/Vault, object storage, Cloudflare, base images, durable-routing patterns | Reuse reviewed source patterns only; create a new Pulumi stack/state and entirely new network, IAM, KMS/Vault, storage, DNS/LB, seed, and orchestrator resources; delete obsolete OKE/CNI/CSI/admission/cert-manager/external-secrets/Kubernetes definitions after behavior gates |
| `TerraScale.Deploy` | Dependency graph, build-once candidates, promotion leases, exact digests, cross-region verification, failure reporting | Move generic release logic into reusable libraries or the new repo; replace Flux/Kubernetes evaluators and shell rollout guards |
| `TerraScale.DevHost` | Local dependency graph, PID/session validation, orphan cleanup, health-driven startup | Keep local-only; do not promote it into the production agent |
| `Terrascale.Documentation` | Public regions, pricing, health, backup/restore, and replication promises | Remove Kubernetes-specific runbooks and reconcile RF1/RF3 and region-catalog claims before launch |
| `Terrascale.Landingpage` | Existing static/web delivery contract | Keep on static/edge hosting outside this orchestrator; it is not in the admitted workload catalog |

The workspace-level `CI_REFACTOR_PLAN.md` and repository-owned `.terrascale/deploy.json` files define the strongest current release direction: feature validation, `develop -> main` release qualification, immutable candidates, and exact candidate promotion. The orchestrator must consume those semantics rather than invent a second CI policy.

### Historical gaps that must not be copied

- The checked-in historical NATS manifest has JetStream but no visible TLS/authentication contract suitable for privileged orchestrator traffic.
- The checked-in NATS R3 and Kubernetes controller spread encoded hidden host/memory floors that conflicted with nominal autoscaler minima.
- Historical Flux configuration has `wait: false`, webhook-plus-forced-reconcile, one-writer suspension, and shell rollout guards to work around controller races and ambiguous acknowledgement.
- Checked-in documentation, HPA manifests, and verifiers disagree about pool and replica counts.
- The historical edge observability configuration uses one shared client certificate rather than a unique workload identity.
- Historical OCI instance-principal secret and autoscaler policies are broader than a workload-aware orchestrator should receive.
- Production VPN routing/ACL/secret lifecycle is not actually implemented, despite assumptions in documents.
- TerraBase automatic PVC expansion is documented, but the checked-in operator does not perform the cloud-volume and filesystem resize.
- The historical operator's checked-in Kubernetes bootstrap and certificate scripts download/use `kubectl`, execute inside pods, and mutate trust on startup. These are not acceptable native-host patterns.
- The Internals deploy descriptor omits an Authentication build target even though Authentication is a production process.
- CI documentation, `AGENTS.md`, and workflow behavior disagree about feature-PR automation and main-branch image building.

### Mandatory workaround-retirement ledger

“Remove all workarounds” is a tracked greenfield cleanup deliverable, not a claim based on selected examples. Phase 0 scans every pre-existing repository and creates `docs/retirement/workaround-ledger.yaml`. Every entry has a stable `WRK-*` ID, repository/file/line or generated-resource evidence, original failure/constraint, semantic behavior that must be preserved, native replacement requirement/state machine, owning workstream, removal phase/PR, regression/L3S scenario, recovery boundary, and proof that obsolete code plus any cloud/IAM/DNS/secret remnant disappeared. CI fails if an identified entry has no disposition or if retired Kubernetes/Flux/Grafana glue returns.

The initial seed ledger is:

| ID | Historical workaround/source | Native disposition and proof |
|---|---|---|
| `WRK-001` | OKE control plane, managed pools, pod/CNI/CSI limits and duplicated controllers in `TerraScale.Infrastructure` | Direct A1 instances, one host agent, measured admission/no pod cap; memory/density/cost and L3S/L4 proof |
| `WRK-002` | Multiple Flux Kustomizations with `wait: false` in regional `reconciliation.yaml` | Typed dependency/health state machines and durable operation acknowledgement; failure/restart replay test |
| `WRK-003` | Flux Receivers/webhook tokens followed by forced `kubectl` reconcile in `TerraScale.Deploy/ServiceReleasePipeline.cs` | One native signed reconcile command journaled before acknowledgement; webhook/NATS/controller-loss tests |
| `WRK-004` | ImageUpdateAutomation writer suspension and `terrascale-rollout-guard` shell/controller coordination | One fenced release writer, immutable candidate and promotion lease; concurrent-publisher/adversarial rollback tests |
| `WRK-005` | `kubectl` rollout guards, polling, shell phase recovery and Kubernetes-context fan-out in `TerraScale.Deploy` | Typed regional deployment operations, explicit checkpoints, idempotent resume and same-digest barrier |
| `WRK-006` | TerraBase StatefulSets/PVCs/Jobs/webhooks/bootstrap scripts in `Terrabase.Operator` | C# TerraBase/member/volume/upgrade/backup state machines; port behavioral tests, then delete obsolete Kubernetes actors |
| `WRK-007` | cert-manager/cainjector and shared edge OTLP client certificate | Regional PKI, unique workload identity, dual-bundle rotation/revocation; captured-output and mTLS identity tests |
| `WRK-008` | external-secrets and broad instance-principal secret access | Closed vault policy/lease delivery and compartment/workload-scoped identities; denial and stolen-node tests |
| `WRK-009` | Kyverno/admission policies used to constrain generic Kubernetes objects | Closed C# role catalog/schema/compiler; invalid role/capability/host-path manifests fail before persistence |
| `WRK-010` | PVC/CSI storage expansion promise without end-to-end cloud/device/filesystem/TerraBase resize | Journaled expand-only provider/device/filesystem/application state machine; crash at every checkpoint in L3S/L4 |
| `WRK-011` | HPA plus Cluster Autoscaler and contradictory pool/replica minima | One scheduler/provider autoscaler with resource/SLO/budget inputs and explicit R3 floors; oscillation/orphan/cost tests |
| `WRK-012` | ServiceMonitor/PodMonitor/kube-state/pod-label discovery and Kubernetes observability glue | Host agent + OTel discovery, stable TerraScale labels, generated targets/dashboards/alerts; full server inventory/cardinality tests |
| `WRK-013` | Kubernetes-local Grafana provisioning/persistence assumptions and dashboard state inferred only from metrics | Immutable replicated Grafana provisioning plus mandatory exact read-only operator projection/data source; one-node-loss and stale-state tests |
| `WRK-014` | Assumed but incomplete production VPN/route/ACL/secret lifecycle | Selected WireGuard implementation plus TerraScale route-policy controller; GRU-control-loss and real OCI UDP/route tests |
| `WRK-015` | Hard-coded OCI three-region constants and inconsistent public/runtime catalogs | Signed provider-discovered region catalog with stable aliases and >=20 eligible-region matrix; SDK/docs compatibility tests |
| `WRK-016` | Missing Authentication build target and conflicting feature/develop/main CI behavior | Exhaustive role/build inventory and one native pipeline graph; affected-change and immutable promotion tests |
| `WRK-017` | Documentation/HPA/verifier disagreement about RF1/RF3, node minima and storage behavior | Generate schemas/docs/dashboards/fixtures from the canonical contract registry; drift becomes a failing test |
| `WRK-018` | Deleted OKE/Flux residual configuration, IAM policies/dynamic groups, webhook tokens, DNS records, load balancers, volumes, public IPs, docs, and runbooks | Outside the new ownership graph, inventory provider and repository truth; remove only a positively identified stale remnant under explicit approval, quarantine unknown ownership, preserve unrelated resources, and prove the new runtime has no Kubernetes parser, credential, endpoint, or compatibility path |

This seed is not the completion claim. The Phase 0 repository scan must add every discovered retry loop, forced reconcile, manual runbook mutation, duplicated source of truth, certificate copy, Kubernetes-only health/discovery assumption, hard-coded endpoint/count, and Grafana/OTel patch. A workaround is “retired” only when its native replacement passes the linked test and its code/resource/config plus secret/IAM/DNS remnants are removed or explicitly documented as an independent external primitive that was never part of the deleted estate.

Cleanup across the existing repositories is its own parallel workstream, not an untracked side effect of the new-repository implementation. For each repository, the integrator creates a `WRK-*`-scoped work package only after the native replacement's contract and tests pass. A cleanup agent uses a fresh repository-local branch/worktree, preserves unrelated owner changes, removes only the approved obsolete paths, runs that repository's compatibility suite plus the linked orchestrator scenario, and opens a separate reviewed PR. The work-package receipt records old/new commits, paths, behavior retained, deleted cloud/IAM/DNS/secret artifacts, rollback of the cleanup PR itself, and proof that no runtime depends on the removed Kubernetes/Flux construct. No agent edits all sibling repositories from one shared checkout.

### Provider selection and lowest-cost proof

OCI is the mandatory first adapter because TerraScale currently uses OCI/A1 and the orchestrator must create and manage the new regional estate there. It is **not** called the cheapest provider without evidence. Phase 0 repeats a normalized provider/TCO and database-performance evaluation across OCI and every serious eligible alternative—including AWS, Google Cloud, and Azure—using current public/negotiated prices and the same production contract. Hetzner is excluded.

Eligibility requires at least twenty usable provider regions, ARM64 compute, API-driven instance lifecycle, performant online-expandable encrypted block storage, object storage, KMS/secrets, load balancing, IAM/workload identity, quotas, billing export, and contractual/operational fit. The comparison models the exact GRU/SFO/FRA topology and includes compute, boot/data/NATS/observability volumes and provisioned IOPS/throughput, snapshots/backups, inter-region and internet egress, public IPv4, NAT/gateways, load balancers, object requests/storage, KMS/secrets, logs/metrics, artifact storage, support, taxes, FX sensitivity, discounts/commitments, idle floor, burst cost, and engineer/operational cost.

For OCI, Phase 0 emits an evidence-backed eligible-region matrix and fails the >=20 claim unless at least twenty rows qualify. Each row records public region/realm, subscription enabled, home/paired geography, availability/fault domains, A1 availability and approved ARM fallback/capacity probe, images, Block Volume size/VPU/IOPS/throughput/online-resize support and benchmark status, Object Storage/KMS/Vault/LB/IAM/DNS/billing API availability, service limits/quota request, inter-region paths/latency/egress price, data-residency constraints, current normalized BRL floor, and qualification timestamp. “Listed on a cloud marketing page” is not a qualified TerraScale region.

Price alone cannot win. The same ARM64 TerraBase/`fio` workload measures p50/p95/p99 read/write latency, fsync tail, IOPS, throughput, noisy-neighbor behavior, online expansion, attach/detach/replacement time, regional capacity failure, and recovery under the compact colocated load. The decision report publishes raw scripts/results, normalized BRL/day and BRL per sustained database transaction/IOPS, assumptions, and sensitivity ranges. OCI remains production-first only if it meets the approved storage/HA SLO and the measured greenfield pre-user TCO is acceptable; the provider-neutral contract preserves a later adapter without weakening OCI-specific correctness.

## Target topology

```text
                            Forgejo / OCIR / Object Storage
                                         |
                                  signed revisions
                                         |
                +------------------------v-------------------------+
                | GRU global authority                             |
                | global controller, operator API, CI/CD, policy  |
                | Grafana + Prometheus + Loki + Tempo + alerts     |
                | VPN coordination and regional telemetry ingest   |
                +------------------------+-------------------------+
                                         |
                    mTLS control-NATS federation / signed CellSpec handoff
                    +--------------------+--------------------+
                    |                                         |
          +---------v----------+                    +---------v----------+
          | SFO regional cell  |                    | FRA regional cell  |
          | control+product    |                    | control+product    |
          | NATS R3 clusters   |                    | NATS R3 clusters   |
          | cell controllers   |                    | cell controllers   |
          | host agents        |                    | host agents        |
          | API/Auth/Dashboard |                    | API/Auth/Dashboard |
          | TerraBase R3       |                    | TerraBase R3       |
          | OTel spool/export  |                    | OTel spool/export  |
          +--------------------+                    +--------------------+
```

GRU also contains the same regional API/Auth/Dashboard, local product NATS, TerraBase R3, and regional OTel collection as SFO/FRA. Global responsibilities are an additional role, not a replacement for the GRU data cell.

### GRU single-node-failure HA contract

GRU runs at least three seed/control/data hosts, spread across distinct OCI fault domains or the strongest independent failure domains available. Extra app/observability nodes may be added, but adding them must not move a critical role onto a new singleton.

| GRU capability | Required topology and one-node failure behavior |
|---|---|
| Global and regional orchestrator authority | Three eligible controller processes on distinct hosts; one active writer per authority with R3 state and fencing; either remaining host can acquire leadership |
| Orchestrator control NATS | Three servers, R3 critical streams/KV, distinct hosts and volumes; one server loss retains quorum and publish/consume availability |
| Product NATS | Three servers, R3 critical streams/consumers, distinct hosts and volumes; one server loss retains product queue service |
| TerraBase | Members `a`, `b`, and `c` on separate hosts and volumes; one member loss retains local quorum/read-write operation according to TerraBase health policy |
| API and Authentication | At least three ready instances or enough independent instances and reserved capacity to lose one with no sustained 5xx; LB health removes the failed backend |
| Customer Dashboard | At least two ready instances on separate hosts; loss of one leaves a ready backend |
| API/Auth-owned metadata, billing, email, and background responsibilities | They remain inside the allowlisted API/Auth processes or an external provider. A new standalone worker is rejected until the owner explicitly adds a first-party role; continuously required API/Auth work follows their HA topology and persists durable work outside process memory |
| Built-in vault/PKI/policy | Three controller replicas over R3 metadata, KMS-protected keys, regional issuer continuity, and no private/authoritative state present only on one disk |
| GitOps and release coordinator | Replicated operation journal and multiple controller candidates; an active reconciliation resumes under a new fenced leader rather than duplicating or abandoning mutation |
| Operator API | At least two ready endpoints behind the private LB/VPN; authentication/control state is shared or reconstructable and no mutation depends on one process |
| OTLP/metrics/log ingest | At least two ingest endpoints on different hosts behind a private LB; collectors retry/spool through endpoint loss |
| Grafana access | At least two immutable/read-only Grafana instances on separate hosts with independently rebuildable local state. Dashboards/data sources are Git-provisioned; loss of one node leaves dashboards reachable, though sessions/preferences on that node may be lost |
| Metrics/log/trace backends | Replicated service or redundant query/ingest replicas with durable object/replicated storage appropriate to the selected backend; a node-local TSDB may not be the only copy needed for operations |
| Alerting | A tested three-peer Alertmanager HA topology or an equivalent redundant design; one host loss still evaluates and routes critical alerts |
| VPN coordination/relay | At least two coordination/API endpoints and two independently placed relays where relays are required; established WireGuard sessions survive coordinator loss |
| Ingress and service discovery | OCI/Cloudflare health checks plus multiple backends; regional registry/DNS data derives from R3 state and remains answerable after one host loss |
| CI/CD | Coordinator remains available; workers are replaceable and carry no unique release state |

GRU uses N+1 capacity planning, not merely replicated process counts. Before production, the surviving nodes must have enough reserved CPU, memory, ports, and network capacity to carry required traffic and control work after the largest single GRU node is lost. Normal placement therefore leaves one-node-equivalent headroom for critical stateless services. The autoscaler replaces capacity, but successful replacement is not required to preserve the initial one-node-failure availability window.

No rollout may simultaneously make GRU dependent on fewer than the required healthy replicas. Node drains, node-generation rotation, certificate rotation, NATS/TerraBase maintenance, and observability upgrades consume disruption budgets and proceed one failure domain at a time.

### Compact and growth placement profiles

The irreducible planned seed floor is three database hosts per region if local RF3 is mandatory. The orchestrator should use those new seed hosts as measured multipurpose capacity instead of creating separate app/tool pools before load exists.

- `compact`: three seed hosts per region. Each runs the agent, an eligible regional controller, one control-NATS server, one product-NATS server, and one TerraBase member. Stateless services may share measured spare CPU/memory. TerraBase always has its own member volume; qualification benchmarks shared-per-host versus per-process NATS volumes and selects the cheapest layout meeting isolation/recovery/SLO gates. Every I/O-heavy subsystem has explicit filesystem/quota/cgroup/IO isolation. GRU adds capacity if benchmarks show the three seed hosts cannot safely absorb observability plus one-node-failure headroom.
- `isolated`: app, data, messaging/control, observability, and CI node classes separate when latency, capacity, or security policy requires it.
- `burst`: ephemeral app/CI nodes scale from zero or a small warm pool. Stateful data nodes scale only through their domain controller.

`compact` is a production placement profile, not reduced correctness. It still uses three controller replicas, three control-NATS servers, three product-NATS servers, three TerraBase members, mTLS, fencing, backups, and the same release gates. In GRU it must additionally preserve the full single-node-failure table and N+1 capacity above. It is permitted only after resource and storage benchmarks prove that co-location does not violate the database SLO or HA headroom. If it fails, the scheduler automatically moves to an isolated class; it does not hide demand by lowering requests.

The cloud must offer at least twenty usable regions; that does not mean TerraScale deploys twenty cells at launch. At twenty active cells, a complete VCN full mesh would require 190 pairings. The provider-neutral topology model therefore distinguishes:

- launch control connectivity: the three control-NATS clusters form a gateway supercluster, which is a gateway full mesh rather than hub-and-spoke; local streams and actions remain regional;
- growth control/telemetry/operator connectivity: select and qualify a hub-and-spoke leaf-node or narrow signed bridge/federation design before expansion beyond the gateway-mesh operating envelope; do not present a NATS gateway mesh as a hub;
- customer request routing: global DNS/edge health routing;
- database/data replication: explicit product-directed links only between selected regions;
- three-region launch compatibility: recreate the required logical GRU/SFO/FRA full mesh entirely from new VCNs, routes, gateways, identities, and endpoints while the scalable topology is proven; no old network resource is reused.

## One binary, several roles

One source tree produces the same signed binary for every role. A host normally runs one process with multiple enabled capabilities so shared clients, caches, telemetry, and configuration do not consume memory repeatedly.

```text
terrascale-orchestrator server    # global/regional controller roles
terrascale-orchestrator agent     # host agent; normally combined with server on eligible hosts
terrascale-orchestrator runner    # isolated CI job worker mode
terrascale-orchestrator ctl       # operator CLI
terrascale-orchestrator doctor    # non-mutating diagnostics
terrascale-orchestrator bootstrap # explicit seed/enrollment workflow
terrascale-orchestrator backup    # control-state backup/export
terrascale-orchestrator restore   # guarded control-state recovery
terrascale-orchestrator lab       # deterministic local/OCI test lab lifecycle
```

The systemd unit selects roles through a small local bootstrap file. Desired workload configuration still comes from the accepted regional state.

Publishing requirements:

- `PublishSingleFile=true`, self-contained `linux-arm64` and `linux-x64` artifacts.
- `linux-arm64` is the primary production RID and a release-blocking lane. `linux-x64` provides development/provider portability, not permission to ship an ARM-untested production release.
- Reproducible, signed build with SBOM, provenance, exact Git tree, and SHA-256 digest.
- Trimming and Native AOT are performance optimizations only after ASP.NET, gRPC, NATS, OCI SDK, systemd, operator-API, and dashboard-provisioning compatibility tests pass. The initial production artifact must not trade recoverability for a smaller headline size.
- The repository may contain many projects and assemblies. “Single binary” is an operational artifact constraint, not permission to create one untestable source project.

### ARM64/Ampere contract

- Pulumi's initial and replacement node templates use approved A1 Ampere images and expose `architecture=arm64` to the regional inventory.
- Every native artifact declares RID, ELF architecture, minimum kernel/glibc requirements, and digest. The agent rejects an architecture mismatch before activation.
- Every OCI workload image is published as an OCI multi-platform manifest with an explicitly tested `linux/arm64` image. GitOps resolves and records the selected platform-specific manifest/image digest.
- The orchestrator, TerraBase, API, Authentication, Dashboard/Node runtime, both NATS clusters, OTel collectors, Grafana stack, VPN components, BuildKit, containerd/runc, and host utilities must all have an approved ARM64 build or image before their descriptor can enter production.
- CI has native ARM64 runners. Cross-compilation and QEMU emulation may provide early feedback, but real A1 execution is required for systemd, containerd, mTLS, NATS, storage, TerraBase, observability, and performance qualification.
- Release sets contain the logical release plus per-architecture digests. Promotion never substitutes an x64 digest on ARM or rebuilds the ARM artifact after qualification.
- Scheduler constraints and autoscaling templates are architecture-aware. A workload with no ARM artifact remains unschedulable with a clear reason; it cannot silently force an expensive x64 pool into an A1 cell.
- Memory, CPU, cryptography, compression, fsync, storage-latency, and startup budgets are measured on A1, since x64 benchmark results are not an A1 capacity plan.

### Bootstrap and orchestrator self-upgrade

The golden image contains a retained A/B slot with the same signed `terrascale-orchestrator` artifact running in restricted `bootstrap/recovery` mode plus host prerequisites; there is no second bootstrap executable. It does not freeze the active production version into every future node. Enrollment returns a signed compatible artifact manifest. Bootstrap mode verifies architecture, digest, signature, provenance, minimum kernel/glibc, cell/bootstrap generation, and N/N-1 protocol/schema compatibility before installing into the inactive slot. The rollback timer invokes the retained old orchestrator slot directly.

The orchestrator uses A/B binary/config slots and a persisted self-upgrade state machine:

```text
UpgradePlanned -> ArtifactVerified -> InactiveSlotStaged -> RollbackTimerArmed
-> ProcessRestarted -> LocalHealthVerified -> RegionalCompatibilityVerified
-> SlotCommitted -> OldSlotRetainedUntilSoak
```

Failure to start, re-enroll, pass local health, or report the expected generation before the timer expires rolls systemd back to the previous slot without relying on the new process. Controllers/agents upgrade one failure domain at a time; N and N-1 must interoperate for commands, snapshots, schema reads, and leadership transfer. An upgrade cannot remove the last controller candidate, reduce either NATS plane below its disruption budget, or proceed without current and rollback artifacts in the regional survival bundle.

Provisional idle budgets, to be replaced by measured gates:

- agent only: at most 100 MiB RSS and less than 0.5% of one core;
- agent plus regional controller: at most 200 MiB RSS and less than 1% of one core;
- GRU global controller plus operator API: at most 300 MiB RSS excluding managed Grafana/observability workloads;
- no per-workload sidecar requirement.

## Core resource model

The internal control schema is versioned, validated, and provider-neutral. It is not a public multi-tenant scheduler API.

Admission accepts only these first-party role families:

```text
TerraScale.Api
TerraScale.Authentication
TerraScale.Dashboard
TerraScale.TerraBase
Platform.Orchestrator
Platform.Nats.Control
Platform.Nats.Product
Platform.Observability.*
Platform.Vpn.*
Platform.CiRunner
```

Each role has a typed descriptor, allowed runtime drivers, ports, capabilities, volume purposes, secret profiles, health contract, placement rules, and scaling controller. Adding another role requires a reviewed code/schema change and ADR; a Git manifest alone cannot turn the platform into a generic workload runner. Internally, the common lifecycle model still avoids duplicating executor logic.

- `Region`: provider identity, cell code, network capabilities, failure domains, enabled roles.
- `NodeClass`: architecture, shape constraints, image, minimum/maximum/warm capacity, labels, cost, bootstrap policy.
- `Node`: immutable provider identity, enrollment identity, capacity, labels, health, generation, drain state.
- `Workload`: desired service, runtime driver, artifact, resources, network, identity, health, scaling, and rollout policy.
- `TaskGroup`: allocations that must share lifecycle or placement.
- `Allocation`: a fenced instance of a workload on one node.
- `Service`: stable discovery name, ports, routing, health, and LB registration.
- `VolumeClaim`: purpose, owner, provider class, performance SLO, retention, expansion policy, and encryption.
- `Volume`: provider ID, region/failure domain, UUID, attachment, mount, size, tier, generation, and fence.
- `Deployment`: exact before/after artifact digests, strategy, gates, evidence, rollback.
- `ReleaseSet`: immutable cross-repository candidate graph and region promotion state.
- `SecretRef`: path, version/lease policy, and intended workload identity; never secret bytes.
- `CertificateProfile`: identity namespace, SAN rules, EKU, TTL, issuer, rotation, and revocation policy.
- `Pipeline` and `Job`: trusted DAG definition and isolated execution record.
- `Operation`: durable state-machine intent, idempotency key, deadline, owner epoch, steps, evidence, and terminal result.
- `Budget`: per-cell and global compute/storage/egress limits with technical and monetary caps.

Each object carries `apiVersion`, stable ID, generation, resource version, ownership, creation actor, and audit correlation ID. Unknown required fields fail closed. Old readers preserve unknown optional fields when round-tripping.

### Exhaustive admitted-role catalog

Admission uses a closed, versioned C# discriminated role catalog, not an arbitrary image, command, or unit name. Version 1 contains only:

| Class | Admitted roles |
|---|---|
| TerraScale product | `Api`, `Authentication`, `CustomerDashboard`, `TerraBaseMember` |
| Control and messaging | `Orchestrator`, `ControlNatsServer`, `ProductNatsServer` |
| Observability in GRU | Immutable/read-only `Grafana` replicas, the selected Prometheus-compatible store, `Loki`, `Tempo`, `Alertmanager`, `OtlpIngest`, and approved synthetic checks |
| Regional observability | `OtelCollector`/`Alloy` from the selected standard descriptor |
| Network | The selected WireGuard coordination/relay implementation and the TerraScale route-policy controller |
| Delivery | `CiRunner` on an isolated runner node class; the controller-side CI/GitOps roles are capabilities of `Orchestrator` |

Each role maps to a built-in descriptor schema, permitted runtimes, artifacts, ports, identities, secrets, capabilities, mounts, probes, network policy, and resource bounds. A manifest may choose only permitted parameters; it cannot supply an arbitrary executable, privileged container, host path, systemd directive, Linux capability, or NATS permission. Adding a role is an owner-approved specification/ADR change with threat-model, resource, ARM64, HA, first-deployment, and test updates.

Email/Stripe emulators are test-fixture dependencies, not production roles. Billing/email/background responsibilities already hosted within `Api` or `Authentication` remain part of those processes. `Terrascale.Landingpage`, Forgejo, OCIR, OCI Object Storage/KMS/Vault/LB, Cloudflare, and operator identity providers remain external dependencies and are not admitted workloads.

## NATS and state correctness

NATS is the primary control fabric. The design must use its native capabilities directly where they fit instead of rebuilding them as ad-hoc HTTP endpoints or pretending every interaction is a queue. “Use all NATS features” means adopt every relevant production feature with an explicit responsibility; it does not mean enable unrelated protocols such as MQTT merely to increase the feature count.

Four replicated systems must not be conflated:

1. Each cell runs three eligible regional controller processes. They do not form a separate consensus protocol; exactly one holds a fenced regional-authority lease recorded in local control JetStream. In GRU, the same replicas may host global and GRU-regional authorities under separate leases and epochs.
2. The cell's three control-NATS servers are the peers/voters for each R3 control stream and KV group.
3. The cell's three product-NATS servers independently host the product queue R3 groups.
4. The cell's three permanent TerraBase members form the database's own replication/quorum system.

Loss, maintenance, capacity, and recovery gates are evaluated independently for all four. “Controller replica,” “NATS server,” “JetStream stream leader/peer,” and “TerraBase member” are never interchangeable terms in code, schema, dashboards, or runbooks.

### NATS feature adoption matrix

| NATS capability | Orchestrator use |
|---|---|
| Core pub/sub | Low-latency observed-state fanout, heartbeats, cache invalidation, live operator-API subscribers, and non-durable hints whose loss is safe |
| Request/reply | Typed control queries, agent capability discovery, readiness/status lookups, bounded command preflight, and regional handshakes |
| NATS service framework and service discovery | Register versioned controller/agent control services, expose endpoints/schema metadata, and observe service latency/error statistics; this complements rather than replaces workload DNS/LB discovery |
| Queue groups | Horizontally distribute stateless controller and CI coordination work where any equivalent worker may act; never use a queue group to choose the single authoritative writer |
| JetStream streams | Durable accepted desired state, releases, operation journals, deployment progress, bounded events, CI records, and audit history |
| Durable pull consumers | Back-pressured, explicitly acknowledged operation execution, CI jobs, exports, and replayable projection builders |
| Retention policies | `Limits` for bounded history, `WorkQueue` for single-consumer jobs, and `Interest` only where all declared consumers must observe the event; every stream documents why |
| Message IDs and duplicate windows | Transport-level suppression layered under operation-level idempotency keys; deduplication is useful but never the only exactly-once claim |
| Expected stream/subject sequence and optimistic concurrency | Reject stale desired-state appends and build safe read-modify-write operations alongside controller fencing epochs |
| JetStream KV | Leader epochs, short leases, ownership claims, small configuration pointers, rollout barriers, and CAS locks; the operation stream remains the durable explanation/history |
| KV watchers | Immediate reconciliation wakeups, policy/trust-bundle refresh, leader changes, and query-projection refresh without aggressive polling |
| JetStream Object Store | Small signed `CellSpec` bundles, schema/protocol packages, trust bundles, diagnostic snapshots, and control-state snapshot chunks |
| Accounts | Hard namespaces for system, global control, regional control, CI, audit/export, operator tooling, product queues, and test environments |
| JWT operators/accounts/users and NKeys | Decentralized identity, scoped publish/subscribe permissions, expiring credentials, account limits, and offline trust roots |
| Imports/exports | Deliberate least-privilege exposure of specific services or streams across accounts; no broad cross-account subject access |
| Subject hierarchy, wildcards, mappings, and transforms | Cell/resource routing, protocol-version transition, blue/green subject switch, compatibility aliases, and prevention of subject-name conditionals in code |
| Headers and status messages | Protocol version, correlation, trace context, generation, fencing epoch, deadlines, error classification, retry hints, and no-responder handling |
| Clustering and R3 JetStream | Local regional consensus/durability without a WAN-spanning quorum |
| Gateways | For GRU/SFO/FRA launch, mTLS full-mesh cluster-to-cluster control connectivity within one control operator domain; explicit known clusters and constrained account traffic |
| Leaf nodes | Optional later support for small/disconnected sites, development labs, and constrained edge locations; not the primary GRU/SFO/FRA backbone |
| Mirrors and sources | Asynchronous audit/DR copies and read-only aggregation where replay semantics are acceptable; never a hidden cross-region multi-writer scheduler store |
| Flow control, consumer limits, max pending, and backoff | Bound slow consumers, redelivery, memory/disk usage, and regional recovery load |
| System account, `$SYS`, advisories, and monitoring endpoints | Server/account/connection/consumer health, auth failures, slow consumers, quorum/leader changes, and Grafana/alert inputs |
| Configuration reload and lame-duck/rolling behavior | Safe certificate/account/config rotation and NATS server maintenance under orchestrator supervision |

NATS Object Store is not the build registry or backup system. Large OCI images/native artifacts remain in OCIR/Forgejo packages; TerraBase backups remain in Object Storage; secret values remain in the vault path. Grafana reads sanitized metrics/logs/traces, and `ctl` talks to the authenticated operator API. Neither receives broad NATS credentials.

### Regional NATS layout

Each region has two local three-server NATS clusters with separate JetStream domains and cryptographic trust planes:

- `orchestrator-control-<cell>` carries controller/agent services, desired and observed state, KV, operations, CI/CD coordination, audit, identity metadata, and regional gateway traffic.
- `terrascale-product-<cell>` carries TerraScale customer/product queue semantics and remains cell-local. It has no implicit WAN gateway to another product cluster.

No JetStream stream spans regions and no regional action waits for a WAN quorum.

The three launch control clusters form one NATS gateway supercluster under one offline control-plane operator trust root, because gateways are clusters within one NATS operator/authentication domain. Each region has separately scoped control accounts, account-signing keys, users, limits, imports/exports, and regional JetStream domain. Product NATS uses a distinct product-plane operator trust root; product clusters remain cell-local and have no product gateway/import/export path between regions. Compromise of an ordinary product credential cannot authorize a control subject, and the control root cannot be reused as a product credential.

Each cluster runs one dedicated `nats-server` process on each of the three seed hosts, with:

- its own systemd unit and cgroup;
- the control or product trust root described above, plus its own system/regional accounts, signing keys, users, permissions, and limits;
- mTLS for clients, routes, and gateways;
- NKeys/JWT subject permissions and account quotas;
- a separate store directory/filesystem and quota from the other NATS cluster and TerraBase; physical block-volume layout is benchmark-selected;
- R3 for correctness-critical streams and KV buckets;
- bounded event/telemetry retention and explicit Object Storage export for audit/backup.

NATS HTTP monitoring has no application authentication boundary. Bind it to loopback or an isolated host-management address, scrape locally, and use authenticated `$SYS` subjects/advisories for remote status. HTTPS may protect the scrape transport but does not make an internet- or workload-exposed monitoring port acceptable.

Under decision 8A, the two clusters may share physical hosts only when cgroup, memory, CPU, port, and storage-performance isolation tests pass. They never share a process, JetStream directory, trust root, account, or subject namespace. The three-volume shared-per-host and six-volume per-process layouts are both tested; the cheapest layout meeting fault, latency, throughput, and recovery SLOs wins. Product tenant queue subjects are never control subjects.

Both `nats-server` clusters and their initial certificates are seed infrastructure. Pulumi/image bootstrap installs two units per seed host—six regional server processes total—before the orchestrator can rely on control NATS. The orchestrator reconciles later configuration, certificates, and rolling upgrades, but it cannot be its own only bootstrap dependency.

### NATS membership, durability, and replacement controller

Both NATS planes have a typed, separately journaled member lifecycle. A server record contains plane, cell, immutable server ID/name, cluster/domain, host and failure domain, store-volume identity, routes/gateways, binary/config/certificate generation, JetStream peer identity, and last membership observation. Replacement first classifies the store as surviving and safely reattachable, lost, or ambiguous; ambiguity holds rather than creating a competing peer.

```text
FailureObserved -> QuorumAndPeerSetRead -> StoreClassified
  -> ReattachSurvivingStore | AuthorizeLostPeerRemoval
  -> ReplacementHostReady -> RoutesAndIdentityPrepared
  -> StartOneServer -> PeerReReplicationVerified
  -> StreamLeadersAndReplicaHealthVerified -> RedundancyRestored
```

- A surviving store is reattached only to the recorded server identity after the old process/attachment is fenced.
- A lost/wiped peer is explicitly removed using the supported NATS administration path and is never restarted as if its old store still existed. With two current peers and the third conclusively lost/fenced, the journaled replacement operation may automatically peer-remove it and add a replacement. With fewer than two current peers, it holds for explicit disaster recovery. The replacement receives a new peer identity and must reach full R3 replication before another membership change.
- Any state with fewer than two current peers blocks ordinary peer removal, replacement, upgrade, scale-in, certificate topology changes, and other destructive membership work unless a tested disaster-recovery procedure explicitly authorizes it.
- Server, route, gateway, account, binary, and certificate upgrades proceed one plane and one failure domain at a time with pre/post snapshots and automatic rollback where the old store/config remains compatible.
- Every critical stream/bucket declares replicas, retention, maximum age/bytes, discard policy, placement, duplicate window, acknowledgement policy, and disk-sync/RPO policy. R3 is not itself a disk-fsync guarantee: Phase 0 selects and benchmarks the control and product `sync_interval` values (including an `always` candidate for critical control state) against the approved latency and acknowledged-write RPO.
- Stream/KV snapshots and restores are exercised for each plane. Product data never enters the control backup and control state never enters the product backup.

### Source of truth

NATS is not treated as a magical substitute for a correctness model.

- Git/OCI is the reviewable source of declared intent.
- The GRU R3 journal is the authority for accepted global revisions, releases, policy, and their signatures.
- Each regional R3 journal is the authority for that cell's accepted `CellSpec`, operations, allocations, volumes, and deployment progress.
- A regional leader serializes mutations. Every leadership acquisition advances a fencing epoch stored with compare-and-swap.
- NATS KV revisions provide CAS for leases, leader epochs, and small coordination records. The operation/event stream is the durable history.
- A local SQLite database is allowed only as a rebuildable query projection and operator-API cache. It is never authoritative.
- Snapshots contain a signed stream position and schema version. Restore replays from that position and refuses an older snapshot over a newer accepted epoch.
- There is no cross-region multi-writer state. GRU hands a signed, monotonically increasing `CellSpec` to a region; the region persists it locally before acknowledging acceptance.

### Subject and stream convention

Example subject roots:

```text
ts.orch.v1.global.desired.>
ts.orch.v1.<cell>.desired.>
ts.orch.v1.<cell>.observed.>
ts.orch.v1.<cell>.command.<node>.<kind>
ts.orch.v1.<cell>.event.<kind>
ts.orch.v1.<cell>.operation.<kind>
ts.orch.v1.global.release.>
ts.orch.v1.global.ci.>
ts.orch.v1.<cell>.audit.>
```

Core streams/buckets:

| Name | Location | Replicas | Purpose |
|---|---|---:|---|
| `GLOBAL_SPEC` | GRU | 3 | Accepted global revisions and compiled per-cell handoffs |
| `GLOBAL_RELEASES` | GRU | 3 | Candidate, release-set, approval, promotion, and rollback journal |
| `CELL_SPEC` | each cell | 3 | Accepted local desired state and generation history |
| `CELL_OPERATIONS` | each cell | 3 | Node, allocation, volume, certificate, and topology operation state |
| `CELL_EVENTS` | each cell | 3 | Bounded observed events and health transitions |
| `CELL_AUDIT` | each cell plus immutable export | 3 | Security/operator mutation audit without secret payloads |
| `ORCH_LEADERS` | each authority | 3 | KV CAS leadership epochs and leases |
| `ORCH_LOCKS` | each authority | 3 | Short operation locks with fencing tokens; never the only operation record |

Every command envelope includes protocol version, cell, aggregate ID, desired generation, writer epoch, operation ID, idempotency key, issue/expiry timestamps, attempt, payload digest, and signature. Agents reject expired, stale, wrong-cell, wrong-identity, or lower-generation commands. Completion requires re-reading the authoritative generation, not merely reporting process exit zero.

### Partition behavior

- GRU unavailable: cell reconciliation, health, restart, reschedule, compute scale-out, storage expansion, certificate renewal from the regional intermediate, and budget-enclosed repair continue.
- One GRU node unavailable: global and regional leadership, both NATS planes, TerraBase quorum, ingress, operator access, secrets/PKI, GitOps, telemetry ingest, Grafana access, alerts, and VPN coordination remain available; the regional provider controller immediately begins fenced replacement.
- Regional NATS loses quorum: running workloads continue. Agents use their last committed allocation but do not accept new mutations. Local systemd restart policy may restart the same digest/config/volume on the same host.
- One regional controller is isolated: it cannot advance the CAS fencing epoch and becomes read-only.
- Two cells are partitioned: neither may originate a global desired generation. Product database replication reports lag; local APIs remain governed by product readiness and placement policy.
- Clock skew: lease validity uses bounded monotonic durations locally plus server timestamps; wall-clock anomalies hold destructive actions and trigger an alert.

## Scheduling and workload lifecycle

The scheduler is regional. It consumes the locally accepted `CellSpec`, node observations, resource reservations, health, and domain-controller constraints.

Placement inputs include:

- CPU, memory, block IO, ephemeral disk, network bandwidth/ports, PIDs/tasks, and huge pages if needed;
- node class, CPU architecture, provider/failure domain, labels and hard constraints;
- affinity/anti-affinity, one-per-host, topology spread, priorities, and disruption budgets;
- attached volume locality and single-writer ownership;
- workload trust level and permitted network/secret zones;
- reserved system/NATS/controller capacity and measured headroom;
- cost and predicted provisioning time.

The initial scoring policy is deterministic constrained least-waste bin packing with explicit tie-breakers. It must output a reason trace explaining every rejection and final choice. Stateful controllers can reserve or veto placement; the generic scheduler never guesses whether a TerraBase/NATS member is safe to move.

There is no Kubernetes-style pod-CIDR or provider-imposed per-node allocation limit. Admission is bounded by measured/reserved CPU, memory, IO, ephemeral disk, PIDs, ports, file descriptors, network bandwidth, security isolation, and an operator safety cap derived from those resources. The cap is configurable by node class and evidence, not a hard-coded “pods per node” constant. The compact A1 test must run the entire first-party regional role mix plus two times the projected stateless replica count without port exhaustion, hidden sidecars, or scheduler refusal unrelated to an exhausted declared resource.

Lifecycle capabilities:

- rolling, canary, blue/green, ordered-stateful, singleton, and replace-in-place strategies;
- startup, liveness, local readiness, dependency readiness, drain readiness, and rollout verification as different probes;
- grace periods, shutdown/drain hooks, watchdog, crash-loop backoff, retry budget, and manual hold;
- cordon, drain, maintenance, node generation rotation, and orphan reclamation;
- stateless horizontal scaling and resource recommendations;
- priority/preemption only for explicitly preemptible allocations; never preempt TerraBase members, NATS quorum servers, or required controller candidates;
- load balancer registration only after readiness and deregistration before drain.

In GRU, the scheduler treats one-node-equivalent HA reserve as unavailable to ordinary placement. It also applies hard anti-affinity to replicas of every critical service and refuses a deployment or drain that would consume the last single-node-failure margin.

`systemd Active=running` is liveness, not readiness. The API/Auth `/health/live` and `/health/ready` distinction, Dashboard stack dependency check, TerraBase `/setup/alive`, and release-level endpoint checks remain distinct.

## Automatic compute autoscaling

The orchestrator must create, enroll, drain, and terminate VPS/VM nodes automatically. It is not enough to resize an abstract scheduler count.

### Ownership boundary

Pulumi creates and versions:

- VCNs, subnets, DRG/RPC/gateways, route/security policy, IAM/dynamic groups, KMS/Vault, Object Storage, DNS/LB foundation;
- golden images or image-selection policy, cloud-init template, node-class launch templates, regional OCI identities/policies, quotas/caps, and the initial three seed hosts per active cell;
- initial independent control-NATS and product-NATS stores/filesystems, selected physical volume layout, configuration, and certificates required to establish the first quorum;
- a versioned, signed `BootstrapBundle` containing region identity, expected bootstrap generation, provider resource IDs, trust roots, node templates, ownership tags, and recovery policy.

After handoff, each regional orchestrator creates and owns:

- every concrete regional compute instance, including replacement seed/control/data nodes, from approved Pulumi templates;
- ephemeral boot volumes, freshly bootstrapped TerraBase and NATS volumes after Pulumi handoff, new workload volumes, and all orchestrator-owned attachments;
- agent enrollment, regional node inventory, workload LB membership, scale-out, drain, scale-in, termination, storage expansion, and orphan audit.

Resources are tagged with owner, cell, node class, immutable template generation, operation ID, lease/fence, retention policy, and cost center. A controller refuses to mutate an unowned or mismatched resource.

Tags are inventory and reconciliation evidence, never authorization to terminate, detach, delete, format, or take ownership. Only the compartment-scoped regional provider-actuator capability receives OCI mutation authority. Every call is derived from an authoritative persisted `Operation` containing the exact operation ID, target OCID (or idempotent create key), compartment, expected observation/generation, desired terminal state, current controller epoch, approvals, and permitted compensations.

Provider correctness assumes crash-stop failures of trusted, signed orchestrator code—not Byzantine execution by a root-compromised host. OCI cannot enforce a NATS lease or fencing token, and delayed IAM/dynamic-group propagation is not a leader-failover fence. Therefore, once a destructive provider step is durably authorized it is irrevocable in the control model: a new leader resumes/re-observes that same operation and terminal target instead of superseding it with a conflicting action. The actuator rechecks authority immediately before a call, uses provider idempotency/work-request identifiers where available, persists the request result, and always reconciles provider truth after timeout. Tests force leadership loss between the last check and the OCI request and prove the late call is either absent or still a safe completion of the already-authorized operation.

Pulumi does not continuously reconcile a regional instance count after handoff. Doing so would create two autoscalers. It continues to version durable foundation, allowed templates, IAM, caps, and bootstrap/recovery generations.

### Bootstrap and ownership handoff

```text
Pulumi foundation applied
-> three seed hosts and two independent NATS R3 clusters started
-> three regional controller candidates enroll
-> regional control journal, PKI, provider access, and backups verified
-> orchestrator records signed HandoffReceipt
-> Pulumi retains/unmanages the freshly created seed nodes and NATS volumes
-> regional ownership tags and fencing epoch activated
-> regional self-management enabled
```

The implementation must use a deliberate Pulumi retain/unmanage mechanism or equivalent state transition so a later `pulumi up` cannot recreate, resize, or delete the freshly bootstrapped resources transferred to the regional controller. Handoff is complete only when both systems agree on the exact inventory and the regional R3 journal contains the receipt. This is a transfer between two owners inside the new greenfield system, never adoption from an earlier estate.

After handoff:

- GRU, SFO, and FRA each use their own compartment-scoped OCI provider identity and make local capacity/storage decisions from local state.
- GRU may distribute signed global policy, allowed templates, release intent, and budget ceilings, but it does not perform ordinary SFO/FRA node or volume mutations.
- Each region creates capacity, deletes unused elastic capacity, replaces failed controller/NATS/TerraBase hosts, rotates node generations, expands storage, and audits orphans even while GRU is unavailable.
- The floor remains three healthy controller candidates, three control-NATS servers, three product-NATS servers, and three TerraBase members per active cell. Self-management cannot reduce any R3 membership below three or remove permanent TerraBase `a/b/c`.
- A region can accept a newly Pulumi-versioned launch template only through a native GitOps plan and rolling node-generation operation.

### Regional survival bundle

Before regional autonomy is marked ready, each cell durably verifies a signed, encrypted, versioned `RegionalSurvivalBundle` containing or referencing everything needed to create and enroll a completely new node without GRU, Git, or the central observability path:

- accepted `CellSpec`, approved node templates/images, bootstrap generation, compatibility window, budgets, and provider OCIDs;
- regional OCI actuator identity path, DNS/LB configuration, NATS routes/accounts/signing capability, regional intermediate issuer, trust bundles, and revocation generation;
- the exact encrypted secret versions required by the accepted and rollback workload generations, with regional decrypt/lease policy and OCI Vault/KMS root protection under decision 3A;
- regionally available, digest-pinned current and rollback orchestrator/native/container artifacts; a GRU-only Forgejo or registry endpoint is insufficient;
- local control/product NATS snapshots, operation journal position, backup locations, runbook generation, and expiry/renewal limits.

The bundle is content-addressed and never contains plaintext secrets or offline root keys. Regional readiness continuously reports freshness, missing artifacts, earliest certificate/secret expiry, and how long the cell can survive disconnected. A release is not accepted by a cell until both its forward and rollback artifacts/secrets are locally available. L3S exercises disconnected replacement with an isolated container and fake provider; L4 repeats the production boundary on A1. Both disconnect GRU, Git, central Vault endpoints, and central registry access, destroy one node, and require that region to create a replacement, enroll it, restore the appropriate NATS/TerraBase member identity, restart allowed workloads, and restore redundancy inside the approved RTO.

Disaster re-bootstrap is a separate, explicit Pulumi mode with a higher `bootstrapGeneration`. It first proves that no viable regional quorum exists and requires recovery authorization; it must never seed a competing cluster beside a merely partitioned one.

### Provider interface

Every mutating provider call requires a `ProviderOperationContext` containing the authoritative operation ID, cell/compartment, controller epoch, target OCID or idempotent create key, expected observation/generation, desired terminal state, approvals, deadline, and idempotency/work-request key. The provider-neutral contract includes:

```text
ResolveCapacity(NodeClass, count)
CreateNode(context, templateGeneration, placement, bootstrapEnvelope)
ReadNode(providerId)
StopNode(context) / StartNode(context) / TerminateNode(context)
CreateVolume(context, claim) / ReadVolume(providerId)
ExpandVolume(context, size) / ChangeVolumePerformance(context, tier)
AttachVolume(context, nodeId) / ReadAttachment(providerId) / DetachVolume(context)
RegisterBackend(context, backend) / DeregisterBackend(context, backend)
ReadLimits / ReadPrices / ReadWorkRequest
ListCompartmentResources(discoveryFilters)
```

OCI is the first complete adapter. Stateful scale-in should use explicitly owned instances rather than blind instance-pool count reduction, because provider-selected termination can choose the wrong data member. Instance pools may be used for truly stateless CI/app classes after their termination behavior is proven.

### Scale-out state machine

```text
DemandObserved
  -> PlanPersisted
  -> BudgetAndQuotaAuthorized
  -> ProviderRequestRecorded
  -> InstanceCreated
  -> InstanceIdentityAttested
  -> AgentEnrolledWithShortLivedIdentity
  -> BootstrapAndDiskChecksPassed
  -> NodeReady
  -> AllocationPlaced
  -> ServiceHealthy
  -> OperationCompleted
```

The provider request is recorded before mutation and uses the provider idempotency token where available. After restart, the actuator resumes the authoritative operation through its recorded work-request/idempotency key and exact OCID, then reconciles provider inventory; tags help discover evidence but cannot establish ownership by themselves. It never issues a second VM because it lost an HTTP response.

Triggers include unschedulable allocations, utilization windows, queue backlog/latency, request concurrency, explicit database-member demand, rollout surge, and predictive warm capacity. Missing or stale metrics hold scale-in and may permit bounded scale-out if demand is otherwise proven.

### Scale-in state machine

```text
CandidateSelected
  -> CostBenefitAndCooldownPassed
  -> Cordoned
  -> StatelessAllocationsDrained
  -> StatefulControllersApproveOrVeto
  -> LBBackendsRemoved
  -> VolumesDetachedOrRetainedByPolicy
  -> AgentRevoked
  -> SpecificInstanceTerminated
  -> BootVolumeDeletionVerified
  -> OrphanAuditPassed
  -> OperationCompleted
```

Scale-in requires sustained low use, replacement capacity, disruption-budget headroom, healthy regional control/NATS quorum, no conflicting rollout/storage/backup/certificate/topology operation, and fresh observations. It never scales seed/control capacity to zero.

### Cost and capacity controls

- Per-node-class min/max/warm counts.
- Per-cell and global maximum OCPU, memory, storage GiB, IOPS/throughput tier, public IP, LB backend, and estimated hourly/daily spend.
- Separate automatic, approval-required, and forbidden bands.
- Hysteresis, cooldown, minimum useful lifetime, and estimated savings greater than the churn/backup cost before scale-in.
- Provider service-limit and regional capacity preflight, with ordered shape/fault-domain fallbacks.
- A cost anomaly controller compares desired owned resources, provider inventory, and billing export; unattached volumes and orphaned boot volumes alert immediately.
- A global emergency budget can stop new non-safety scale-out. It must not terminate healthy stateful members or block a storage expansion needed to prevent data loss.

Phase 0 first records the actual post-OKE-deletion residual OCI bill. The first cost release gate then uses a seven-day three-region billing measurement against the owner-approved target, reporting both incremental cost over that residual bill and comparison with the historical R$80/day pre-deletion baseline. Estimated list prices are not acceptance evidence.

## Storage controller and automatic storage scaling

Storage is a first-class scheduled resource, not a path string in a workload manifest.

### Volume identity and lifecycle

Each `Volume` records:

- owner `(cell, workload, memberTag)` and stable claim ID;
- provider volume ID, availability/fault domain, attachment ID, and encryption key;
- filesystem UUID, filesystem type, partition/LVM layout, mount point, device identity, and observed bytes;
- requested size, provider size, block-device size, filesystem size, used/free bytes, and forecast exhaustion;
- performance tier, VPU/GB or provider equivalent, measured IOPS/throughput/latency, and SLO;
- retention/deletion policy, last verified application backup, generation, active writer fence, and operation ID.

Mount by filesystem UUID and provider-consistent identity, never by a transient `/dev/sdX` name. A recognized volume is never formatted. A new blank volume is formatted only after provider ID, expected owner, blank-device proof, and current fencing token all agree.

Create/attach workflow:

```text
ClaimAccepted -> CapacityAndBudgetChecked -> VolumeCreated -> AttachmentCreated
-> DeviceIdentityVerified -> BlankOrKnownVolumeClassified -> FormattedIfNew
-> MountedWithSafeOptions -> OwnershipAndPerformanceVerified -> Ready
```

Single-writer volumes cannot be attached read/write to two hosts. Detach/reattach requires process stop proof, lease revocation, provider attachment convergence, new writer epoch, and a filesystem/application health check.

### Expansion policy

For TerraBase, “create more storage” normally means expanding each member's existing block volume and filesystem. A new block volume is created for a new member. Adding an unrelated second disk does not automatically extend TerraBase capacity unless TerraBase explicitly supports that layout.

Provisional default trigger, subject to the approved storage/budget SLOs:

- warn at 70%; prepare at 80% sustained for 15 minutes or when forecast exhaustion crosses the lead-time target;
- grow by `max(25 GiB, 25% of current size, forecast headroom)` without exceeding workload, budget, provider, or 32 TiB limits;
- critical alerts at 90% and 95%; safety expansion can cross the ordinary approval band but not a hard provider/account limit;
- never shrink automatically or manually through the orchestrator.

Expansion is serialized against backup/restore, topology, member scaling, upgrade, certificate replacement, detach/reattach, and another storage operation.

```text
ThresholdSustained
  -> ExpansionIntentPersistedWithCAS
  -> TerraBaseAndBackupPrechecksPassed
  -> SafetyBackupOrApprovedRecoveryPointVerified
  -> ProviderExpandRequested
  -> ProviderSizeVerified
  -> GuestBlockDeviceRescanned
  -> PartitionOrLVMExtended
  -> XFSOrExt4FilesystemGrown
  -> BlockAndFilesystemSizesVerified
  -> TerraBaseFreeSpaceAndHealthVerified
  -> MetricsAndCostUpdated
  -> Completed
```

Every step is independently observable and restartable. A crash after the provider grows a volume but before `xfs_growfs`/`resize2fs` resumes at guest discovery; it never requests a duplicate growth or reports success from provider size alone. Because expansion cannot be undone, failure produces a held operation and guided recovery, not an attempted rollback.

OCI supports online block-volume growth, but the guest must rescan the device and extend its partition/filesystem. The implementation must use OCI SDK APIs and native filesystem tools through a narrowly allowed agent operation, not shell text supplied by a workload.

### Performance is part of autoscaling

Capacity and performance scale separately.

- TerraBase and correctness-critical JetStream volumes default to a benchmarked Balanced-or-better class, not Lower Cost merely because it is cheaper.
- The controller may change provider performance settings when sustained latency or queue-depth thresholds violate the SLO, inside budget policy.
- It records the cost effect before actuation and reverses a performance increase only after a stable low-load window.
- Boot, TerraBase data, product JetStream, orchestrator JetStream, observability, and CI cache are separate logical I/O domains with independent filesystems/quotas/cgroup accounting. TerraBase and JetStream never share a filesystem; NATS physical volume co-location is benchmark-selected rather than assumed.
- Database benchmarks cover steady state, fsync p95/p99, compaction, backup, restore, catch-up, node loss, and backlog recovery.

### Deletion and recovery

Permanent member volumes use retain semantics. Elastic-member deletion is allowed only after:

1. leadership transfer if necessary;
2. TerraBase topology removal;
3. quorum and replication re-read;
4. proof that no database references the member;
5. application-consistent backup/retention requirement;
6. matching owner and deletion fence;
7. quarantine or explicit disposable policy;
8. post-delete orphan audit.

Block snapshots are a secondary recovery tool, not a replacement for TerraBase-native full/incremental backup and side-by-side restore tests.

## Container and native-systemd executors

One `WorkloadSpec` has a discriminated runtime payload and common scheduling/lifecycle behavior.

Common fields include immutable artifact digest, command and typed arguments, identity, resources, ports, service names, dependencies, probes, drain hook, volumes, secret/certificate refs, restart/backoff, rollout strategy, placement, scaling, and telemetry.

### OCI container driver

- containerd through its versioned gRPC API; do not shell out to `ctr`, which is an operator/debug tool.
- runc, cgroups v2, namespaces, seccomp, capabilities, read-only root filesystem, explicit UID/GID, PID/task limits, and no privileged default.
- pull by immutable digest, verify signature/provenance, stage before rollout, and retain the previous digest for rollback.
- host networking plus an orchestrator port allocator is the initial low-overhead option; a network-namespace/bridge mode remains available when an allowlisted first-party role needs stronger isolation.
- read-only credential mounts and owned volume mounts; no host Docker socket.
- container exit, OOM, and runtime events flow into the same allocation state machine as native units.

containerd versus Podman/Quadlet gets a short measured spike, but containerd is the default because it provides a stable daemon/API boundary without making systemd unit generation the container API.

### Native binary driver

- artifacts are stored as signed archives or OCI artifacts in Forgejo packages/OCIR and addressed by digest.
- stage under `/opt/terrascale/artifacts/<digest>`; validate hash, signature, ownership, ELF architecture, and declared entrypoint.
- activate through an atomic version symlink only after staging and preflight; preserve the prior version for rollback.
- create systemd units/transient units through D-Bus from an allowlisted typed policy, not arbitrary unit text from Git.
- use `User`/`DynamicUser`, `StateDirectory`, `RuntimeDirectory`, `LogsDirectory`, `LoadCredential`, `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`, capability bounding, `MemoryMax`, `CPUQuota`, `IOWeight`/limits, `TasksMax`, watchdog/notify when supported, and explicit stop timeout.
- supply private keys/master keys as systemd credentials or restrictive tmpfs files, never ordinary environment variables.
- collect stdout/stderr and structured logs from journald into OTel with allocation, digest, node, cell, and service metadata.
- verify PID start time, invocation ID, cgroup, unit generation, and artifact digest before signalling or reclaiming a process.

TerraBase's existing Debian unit provides the baseline: unprivileged `terrabase`, restrictive umask, bounded capability, restart behavior, 300-second stop, and protected settings/master-key/PFX paths. Native and container acceptance lanes must prove identical member identity, data, health, certificate, backup, and upgrade behavior.

### Service discovery and ingress

- The regional controller maintains a strongly versioned registry from healthy allocations; agents do not self-publish arbitrary endpoints.
- Stable service names resolve through a lightweight regional DNS service or generated CoreDNS configuration, backed by the registry.
- OCI NLB/LB and Cloudflare remain provider/edge data planes. The orchestrator reconciles backend membership and health.
- Preserve `X-TerraScale-Forwarded-Region`, preferred/target/serving/edge region headers, trace context, request IDs, client IP policy, retry behavior, and routing loop guards.
- No built-in general service mesh in v1. mTLS-capable services obtain identity directly; a proven proxy is allowed only where an application cannot terminate mTLS itself.

## Identity, mTLS, and the built-in vault

### Trust hierarchy

- Offline/recovery root or KMS-protected root.
- One global administrative intermediate and one regional intermediate per cell.
- SPIFFE-like URI identities such as `spiffe://terrascale.tech/cell/sfo/node/<id>` and `.../workload/<workload>/allocation/<id>`.
- Separate certificate profiles for NATS servers/routes/gateways, orchestrator nodes/controllers, CI workers, TerraBase, telemetry forwarders, operator clients, and workload services.
- Short-lived leaf certificates, automatic renewal around two-thirds of TTL, overlap during rotation, dual trust-bundle rollout for issuer rotation, expiry alarms, and immediate local deny/revocation for compromised identities.

Regional intermediates and the accepted survival policy allow SFO/FRA to renew existing identities and issue replacement-node/allocation identities already authorized by the local `CellSpec`, template, budget, and fenced operation during a bounded GRU outage. They cannot invent a global trust domain, workload role, release, or broader policy scope.

### Enrollment

1. Pulumi/image bootstrap gives a new instance only the minimum provider identity and a single-use, audience-bound enrollment path.
2. The regional controller verifies provider instance identity, expected tagged operation, image/template digest, cell, and nonce.
3. The node generates its private key locally and submits a CSR.
4. The controller issues a short-lived node certificate and NATS credentials scoped to that node.
5. The one-time enrollment authorization is consumed and audited.
6. Workload identities are issued only after a fenced allocation is accepted on that node.

Private keys are generated and retained at the narrowest consumer when possible. The control plane stores certificates, trust, policy, encrypted material, and lease metadata—not a universal copy of every private key.

### Built-in vault contract

The integrated vault surface must support:

- versioned static secrets and references;
- KMS envelope encryption and key rotation;
- policy bound to operator, node, workload, cell, environment, and purpose;
- short-lived leases, renewal, revocation, and one-time delivery;
- PKI issuance and trust-bundle lifecycle;
- dynamic NATS users/NKeys/JWT permissions;
- NATS account/user JWT revocation propagation that actively terminates an existing compromised connection; waiting for a TLS certificate to expire is not immediate revocation;
- audit without values, secret/lease health metadata exported to Grafana, and no reveal endpoint by default;
- atomic credential delivery and application reload/restart policy;
- sealed local cache for last-known-valid operation during bounded backend outage;
- backup, restore, anti-rollback, split-brain behavior, and break-glass recovery.

Recommended v1 keeps long-lived secret ciphertext and root keys in OCI Vault/KMS while the orchestrator owns policy, identity, leases, PKI, rotation, and delivery. A cloud-neutral `IKeyEncryptionKeyProvider` and `ISecretCiphertextStore` permit later providers or a portable sealed backend. Building a new authoritative secret database before the scheduler is proven would put the highest-risk subsystem on the critical path.

No custom cipher or certificate parser is permitted. Use supported .NET cryptography/X.509 APIs and provider KMS operations, with independent security review and fuzzing.

## Native GitOps

Flux is removed. GitOps reconciliation is a native orchestrator subsystem over TerraScale's typed resources, NATS journals, systemd/containerd executors, OCI provider operations, and regional health gates. It does not expose Flux APIs or carry Flux controllers into the new platform.

Required source/reconciliation capabilities:

- Git and OCI artifact sources, credentials by reference, webhook plus polling fallback;
- signed commit/tag/artifact verification and immutable digest resolution;
- versioned manifest schema, JSON Schema, semantic validation, defaults visible in the plan;
- dependency DAG, cycle detection, reasoned ordering, suspend/resume, retry/backoff, timeout, and manual reconcile;
- render/compile desired global state into signed per-cell `CellSpec` objects;
- plan/diff before apply, health gates, drift detection, observed-state comparison, and prune only with ownership proof;
- image/artifact automation with exactly one release writer;
- rolling/canary/blue-green/stateful strategies and explicit rollback;
- global same-digest barrier across SFO, FRA, and GRU;
- webhook acknowledgement only after durable queueing, not merely HTTP 2xx.

Git owns declared roles, releases, policies, templates, bounds, budgets, retention classes, and desired minimum/maximum capacity. It does **not** enumerate ordinary autoscaled children. Concrete controller-created instances, allocations, attachments, replacement peers, and generated/expanded volumes are authoritative regional-journal state linked to a Git policy/template generation. They are neither Git drift nor Git prune targets. Git removal of a parent policy creates a guarded regional retirement operation; it never directly deletes child cloud/data resources.

Reconciliation sequence:

```text
Source revision observed
-> signature and schema verified
-> dependencies resolved
-> immutable artifacts resolved once
-> policy and budget evaluated
-> global plan recorded
-> CellSpecs compiled and signed
-> each cell durably accepts its generation
-> deployments execute with regional health gates
-> global live verification
-> success or rollback recorded
```

Checked-in historical Kustomize/Helm/Flux files are read-only behavioral and workaround evidence, not a supported input format. Native manifests are written afresh from the closed C# role catalog, current application runtime contracts, and reviewed owner policy. No Kubernetes/Helm/Kustomize/Flux reader or converter is built. Helm templating, Kubernetes object emulation, CRDs, Flux APIs, and Flux runtime compatibility are non-goals; obsolete files are removed only after their required behavior is represented by native contracts and tests.

## Built-in CI/CD

The orchestrator becomes the release coordinator and job scheduler. Repository-owned descriptors remain the policy/source for what each repository builds and tests.

### CI model

- Forgejo webhook ingestion with signature verification, durable event ID deduplication, polling/reconciliation fallback, and commit-status reporting.
- Versioned successor to `.terrascale/deploy.json` for dependency edges, PR/release profiles, targets, architectures, artifact retention, and promotion policy.
- Cross-repository affected graph with a human-readable reason for every selected test/build.
- Feature PRs run static/build/test policy without production credentials.
- `develop -> main` runs the full affected release graph and creates immutable candidates.
- `main` promotes the exact qualified candidate and never rebuilds it.
- Multi-architecture images/manifests and native artifacts share candidate/release-set metadata.
- Build caches are content-addressed and untrusted input cannot poison a trusted release cache without verification.

Before the first deployment, reconcile the checked-in policy conflicts and add the missing Authentication target in Internals. The orchestrator must not silently choose between contradictory workflow/docs behavior.

### Worker isolation

- Trusted reusable runners and untrusted PR runners are different node classes, identities, networks, caches, and secret policies.
- Workers are disposable containers or ephemeral VMs and may scale to zero.
- Untrusted builds cannot reach production VCNs, NATS control accounts, Vault, metadata credentials, registries with publish access, or database hosts.
- CI jobs never run on TerraBase production nodes.
- BuildKit runs without exposing a host-wide Docker socket; publish credentials are short-lived and phase-scoped.
- Job logs are redacted, bounded, retained by policy, and linked to trace/audit IDs.

### Release and CD correctness

Retain the existing valuable semantics:

- `release-candidate.json` keyed to exact source tree and dependency inputs;
- `release-set.json` for cross-repository topological promotion;
- immutable image/native/package digests and regional registry replication;
- durable promotion lease, monotonic fencing token, phase journal, idempotent publish, and interruption recovery;
- one global release writer;
- deploy/verify every required region before announcing success;
- rollback by known digest and desired-state generation.

CD hands exact artifacts to the GitOps reconciler. It does not directly mutate processes behind the reconciler's back.

### Self-hosting bootstrap

Under owner decision 7A, the orchestrator does not depend exclusively on a healthy deployed orchestrator to build or recover itself. Keep one minimal, separately reviewed Forgejo bootstrap workflow that can:

- build/test/sign the orchestrator from a pinned toolchain;
- publish both architectures and recovery metadata;
- deploy to an isolated recovery/canary node with an explicit approval;
- restore a broken control plane from signed state backup.

This path has no general product-deployment privileges and is exercised in disaster-recovery tests. Removing it requires an explicit superseding owner decision and an accepted circular recovery dependency in the threat model/runbooks.

## TerraBase domain controller

Port behavior, not Kubernetes implementation.

The C# TerraBase controller owns machine-level TerraBase lifecycle:

- three permanent members and deterministic elastic tags per cell;
- stable identity `(cell, workload, memberTag)`; member `a` is a bootstrap seed, not a permanent assumed leader;
- certificate provisioning/registration, typed admin calls, cluster bootstrap, join, topology read-back, and readiness;
- one-at-a-time upgrades with durable intent, pre/post gates, explicit leader handoff, digest/process-generation proof, pause, resume, and designed rollback;
- volume create/attach/mount/expand/retain and one member per host;
- local cluster health, replication status, backup/restore, and safe decommission approvals;
- CPU/memory member autoscaling from three to ten only after real acceptance.

The existing policy is the starting point:

- scale out when average CPU is at least 70% or memory at least 75% for 15 continuous minutes;
- only one member, then a 60-minute cooldown;
- scale in only after CPU at most 35% and memory at most 50% for 60 minutes, healthy quorum/replication/backups, and no conflicting operation;
- missing/stale metrics are a hard hold for scale-in;
- remove elastic members in reverse tag order and never remove `a`/`b`/`c`;
- storage expansion is independent of member count.

Adding replicas does not necessarily add logical database capacity or rebalance shards. Database/shard placement remains a separate TerraBase/product concern and must expose an explicit capacity signal before the host autoscaler interprets member count as data scaling.

Project placement remains owned by `Project.Regions`, `PlacementGeneration`, and the existing product reconciler. The orchestrator supplies healthy regional TerraBase capacity and executes typed, fenced machine operations. It does not infer customer region selection from host load.

The specified full six-direction GRU/SFO/FRA replication topology, monotonic placement generations, filtered-absence non-deletion rule, local RF3, conflict behavior, and side-by-side restore contract are production acceptance gates.

## Observability and Grafana

Grafana remains the dashboard system. The orchestrator should remove Kubernetes glue, not rebuild mature observability products.

### GRU

- Grafana, Prometheus-compatible metrics storage, Loki, Tempo, Alertmanager, blackbox/synthetic checks, and central OTLP ingest.
- At least two ingest instances on distinct hosts behind a private load balancer; this is mandatory rather than placement-profile optional.
- Grafana and every operationally critical query/ingest/alert path follow the GRU HA table. Git-provisioned dashboards/data sources avoid unique local state; any mutable shared metadata uses an HA backend.
- Select HA modes for the Prometheus-compatible, Loki, and Tempo backends that retain/query operational data after one host loss. Object Storage may provide durable backend data, but query/ingest frontends are still replicated.
- Grafana is the operator web console and is reachable only through the private operator network with operator SSO/RBAC.
- Global alerts for cells, releases, node/volume operations, NATS, PKI, backups, cost, VPN, and synthetic product endpoints.

### SFO and FRA

- One OTel Collector/Alloy agent per host or a measured shared collector per cell.
- hostmetrics, cgroup/systemd/container metrics, journald/file logs, application OTLP, NATS, TerraBase, volume, and orchestrator telemetry.
- Under decision 9A: disk-backed, encrypted where sensitive, bounded queues; retry with jitter; drop-oldest/sample/cardinality controls after the cap and emit an explicit data-loss event/alert.
- asynchronous mTLS export to GRU. GRU failure never changes product readiness.

Replace Kubernetes labels with stable `terrascale.cell`, `cloud.region`, `node.id`, `node.class`, `workload.id`, `allocation.id`, `runtime`, `artifact.digest`, `deployment.id`, and `release.id` attributes. Preserve existing service/version/environment and trace/span correlation.

The orchestrator exports OTLP traces/logs/metrics plus a Prometheus endpoint for its own low-level metrics. Audit events are not ordinary logs and have their own immutable export/retention path.

## Grafana operator console, API, and CLI

Grafana is the web console. The orchestrator does not ship Blazor, React, or another bespoke operator UI.

The orchestrator and supporting collectors export three complementary views:

- Prometheus-compatible instant/current-state metrics for bounded inventories, health, capacity, quorum, storage thresholds, scaling, deployment state, budget, and SLOs.
- Structured lifecycle/audit-safe events to Loki for operation history, placement explanations, failures, holds, reconcile evidence, and release timelines. Secret values never enter these events.
- Distributed traces to Tempo for GitOps, CI/CD, scheduling, provider calls, node enrollment, storage expansion, TerraBase operations, and regional handoffs.

The operator API also exposes an authenticated, read-only, sanitized state projection for Grafana through an approved provisioned data source. It returns bounded inventory/current-generation/status documents with source journal position, observation age, and stale/degraded markers; it never returns secret values or accepts mutations. This exact view is mandatory—it closes the gap between aggregate metrics and “show me exactly what is running” while keeping JetStream authoritative. Prefer a signed existing data-source plugin that passes OIDC/mTLS/ARM64 gates; if none does, build and security-review only the minimal read-only TerraScale Grafana data-source plugin. Falling back to aggregate Prometheus/Loki data alone is not sufficient.

Provisioned, version-controlled Grafana dashboards cover:

- global and regional topology, quorum, availability, capacity reserve, budget, and provider inventory;
- nodes, first-party workloads, health probes, scaling, drains, and placement reasons;
- TerraBase members, replication, backups/restores, capacity, IOPS/throughput/latency, expansion, and held actions;
- both NATS clusters in every cell: server/quorum health, streams, consumers, lag, redelivery, accounts, storage, gateways, and certificate expiry;
- native GitOps revisions, reconciliation, deployments, release sets, CI jobs, artifacts, regional gates, and rollback;
- volume ownership, attachment/fencing, expansion progress, retention, and orphan inventory;
- certificate/secret metadata counts, lease/rotation/revocation health, and access-denial/audit alerts without values;
- VPN/peering/routing, OTLP spooling/ingest, Grafana backend health, and synthetic product endpoints.

Dashboards and alerts are generated/provisioned from the same typed contracts and label catalog as the orchestrator. Prometheus/Loki/Tempo are observability projections, never authoritative control state. A missing metric cannot authorize a destructive action.

The default control boundary is read-only Grafana plus an authenticated operator API and `ctl` for mutations. This avoids disguising Grafana as a transactional control plane. `ctl` provides plan/diff/apply, explicit approvals, watch, JSON output, diagnostics, drain/scale, deployment/rollback, certificate operations, backup/restore, and emergency regional endpoints. Every mutation records actor, plan, safety/budget gates, operation ID, and irreversibility.

If browser-based mutations are later required, implement a small, separately reviewed control surface or tightly scoped Grafana app plugin that calls the same operator API. It must not grant Grafana direct OCI, Vault, or control-NATS credentials. An arbitrary browser shell remains out of scope.

Grafana and the operator API may federate with the established external identity-provider product if suitable, but the greenfield platform creates a new OIDC application/client, credentials, redirect URIs, role mappings, sessions, and offline audited break-glass identities. No prior orchestrator client or secret is reused. Private VPN access, MFA/JIT role mapping, RBAC/ABAC, and rate limits remain mandatory. Optional operator client certificates protect CLI/emergency access.

## VPN, peering, and network control

GRU hosts the selected VPN coordination/control workload and operator entry point. Established regional/data-plane operation must not depend on the GRU coordination service being continuously available.

The orchestrator should manage:

- peer/node enrollment identity and route/ACL desired state;
- regional subnet routes, operator groups, break-glass access, revocation, expiry, and health;
- service discovery and LB backend state;
- mTLS for privileged application protocols independently of VPN encryption;
- topology plans that distinguish control/telemetry, customer ingress, and product replication.

It should not implement WireGuard cryptography or a novel tunnel protocol. Select and host a proven implementation such as NetBird only after testing routes, ACLs, relay behavior, secret lifecycle, failure during GRU loss, and memory cost. Existing DevHost Tailscale code is local-only evidence and is not a production implementation.

## Testing environment

Testing must exercise actual Linux, systemd, cgroups, filesystems, NATS, and failure boundaries. A Docker Compose demo cannot qualify this platform.

### Hard pre-deployment verification gate

No orchestrator commit may start a **system-under-test/server** container, systemd, containerd, disposable-cloud, or regional deployment test until the exact source tree and binary have passed the zero-deployment business-logic gate. L0/L0C run in a credential-free, digest-pinned rootless toolchain container that receives no production or lab mutation credentials and runs no orchestrator server. This is enforced by CI and by `terrascale-orchestrator lab/deploy`; there is no routine `--skip-tests` bypass.

This requirement is interpreted literally: Phase 1 implements the complete pure decision core for **every** scoped domain—control, scheduling, both NATS policies, compute/Pulumi handoff, storage, TerraBase, identity/vault, GitOps, CI/release, Grafana projection, networking policy, budgets, greenfield provisioning/ownership, and self-upgrade—before L1S starts. Later phases add real adapters and integration; they may not hide business decisions inside OCI, NATS, filesystem, systemd, containerd, Git, clock, or network adapters. Any later business-rule change invalidates the evidence and must pass the same L0 gate before the affected adapter may perform a side effect.

“Catch all errors and business logic” means every declared requirement, invariant, branch, transition, error code, recovery checkpoint, and known failure class is traceable and tested before deployment. It cannot mean proving that the Linux kernel, OCI, NATS, filesystems, firmware, or the network contain no defect; hermetic dependency conformance and L1S–L5 real-system/chaos gates cover those boundaries and remain mandatory.

The repository has one canonical requirement registry with stable IDs (for example `REQ-`, `INV-`, `ERR-`, `SM-`, and `SEC-`). Source state machines, schemas, decisions, errors, tests, generated documentation, and acceptance evidence reference those IDs. CI generates a bidirectional traceability report and fails on an untested requirement/invariant/error, an orphan test assertion, an undocumented externally visible error, or a requirement that lacks an owner and acceptance layer.

The zero-deployment suite runs inside its toolchain container without OCI mutations, remote hosts, systemd units, server containers, or a live production-like cluster. It must cover:

- every resource-schema validation rule, default, version conversion, unknown-field behavior, and incompatible-version rejection;
- every declared state-machine transition, hold, timeout, cancellation, retry, compensation, terminal result, and recovery checkpoint;
- leader election, fencing epochs, lease/CAS behavior, duplicate/stale/expired commands, idempotency, snapshot/replay, and split-brain prevention;
- scheduler hard constraints, scoring/tie-breaks, quorum floors, anti-affinity, disruption budgets, GRU N+1 reserve, and explainable rejection reasons;
- regional node scale-out/replacement/scale-in, budget/quota/cooldown/hysteresis, greenfield Pulumi handoff, ownership tags, and orphan decisions;
- volume create/attach/fence/format/mount/expand/detach/retain/delete logic, including irreversible partial-success recovery and wrong-volume rejection;
- TerraBase bootstrap, `a/b/c` permanence, 3->4->3 policy, leader transfer requirements, upgrade/rollback, replication, backup/restore, and conflicting-operation holds;
- dual-NATS account/subject/stream permissions, retention selection, consumer semantics, gateway policy, and separation of control versus product traffic;
- native GitOps dependency planning, signature/digest resolution, drift, staged regional promotion, rollback, and one-writer release rules;
- CI dependency selection, candidate/release-set invariants, trust-zone policy, interrupted promotion, and exact-artifact reuse;
- mTLS/PKI/Vault issuance, authorization, renewal, rotation, revocation, outage, anti-rollback, redaction, and no-secret-output rules;
- Grafana metric/label/dashboard generation, bounded cardinality, alert rules, and proof that observability state cannot authorize mutations.

Required techniques:

- focused unit tests for every business rule and error code;
- table-driven transition/error matrices generated from the state-machine definitions;
- property-based tests for invariants over randomized valid and invalid desired states;
- model-based/state-space exploration of controller, agent, NATS-delivery, and provider interleavings with a deterministic virtual clock;
- concurrency tests that systematically reorder leader changes, messages, callbacks, timeouts, crashes, and restarts;
- fuzzing of manifests, protocol envelopes, NATS headers/subjects, snapshots, provider responses, certificates, and persisted journals;
- mutation testing of correctness-critical projects so tests prove they detect inverted conditions, removed gates, stale-generation acceptance, and unsafe cleanup;
- golden compatibility fixtures for schemas, commands/events, snapshots, `.terrascale/deploy.json`, and generated Grafana assets;
- deterministic replay of every discovered failure seed, checked into a regression corpus;
- static analysis, nullable and warnings-as-errors, dependency/vulnerability/license checks, secret scanning, and architecture-boundary tests.

Pure domain/state-machine methods consume immutable state plus an explicit input and return new state, typed decisions, emitted events, and side-effect intents. They receive virtual clock/ID/randomness and observation interfaces; they cannot reference NATS, OCI SDK, D-Bus, containerd, filesystem, sockets, environment, or wall clock. Adapters execute persisted intents and return typed observations. Architecture tests enforce this dependency direction.

After pure L0 passes, but still before any VM deployment, an unprivileged hermetic conformance lane starts pinned real `nats-server` processes on loopback/temp directories. It validates the generated operator/account JWTs, permissions, imports/exports, gateway mesh, JetStream domains, retention, deduplication, redelivery/backoff, KV CAS/watch, Object Store, advisories, monitoring isolation, snapshots, peer loss/replacement, and N/N-1 client/server compatibility. Fakes model failure schedules; this lane proves the configuration against NATS itself. Its result is part of the pre-deployment evidence.

Minimum evidence thresholds are floors, not substitutes for review:

- 100% of declared state-machine transitions, holds, and terminal paths exercised;
- 100% of enumerated safety/business invariants have at least one positive and one adversarial test;
- at least 90% branch coverage across every correctness-critical control, scheduler, NATS membership/protocol, compute/provider/Pulumi handoff, storage, TerraBase, identity/vault/authorization, GitOps, CI trust/release, budget/cost, greenfield provisioning/ownership, regional survival, and bootstrap/self-upgrade project;
- at least 85% mutation score in those projects, with zero surviving mutant that can violate a safety, authorization, durability, or deletion invariant;
- zero unexplained flaky tests across repeated randomized seeds and concurrency schedules;
- all failure seeds, coverage gaps, surviving mutants, and risk acceptances visible in the evidence report.

The initial reproducibility budget is explicit and may only be raised or changed by ADR with retained historical comparability:

| Lane | Feature-branch/changed-shard minimum | Full deployment-bound/release minimum |
|---|---:|---:|
| Property tests | 1,000 generated cases per property and every saved seed | 100,000 cases per correctness-critical domain |
| Systematic concurrency/model exploration | 10,000 schedules per critical state machine at the bounded three-node model | 1,000,000 schedules plus expanded four-node/partition bounds |
| Fuzzing | 60 seconds per changed parser/decoder target plus the full saved corpus | 30 minutes per target and six hours aggregate |
| Flake audit | Retry no failure blindly; replay its exact seed 100 times after a fix | Ten consecutive clean full L0+L0C runs |
| Mutation | Changed correctness-critical project, with no surviving safety mutant | Full correctness-critical solution |

The right-hand column runs for **every exact source tree that will receive any VM/cloud/deployment credential**, not only the first deployment or a tagged release. Feature-branch minima may provide fast feedback but cannot mint deployment evidence. Signed, content-addressed shard evidence may be reused only when that shard's source, transitive contracts, tests, corpus, dependencies, generators, and pinned toolchain are byte-identical; cross-domain models and the aggregate requirement trace still run for the candidate tree. The first VM candidate, every release, and any change to shared contracts/security/toolchain are cold full runs with no safety-shard reuse.

Generated code, generated schema constants, immutable DTO property accessors, and the composition root may be excluded from branch/mutation percentages only through a checked-in exclusion with generated-code or trivial-wiring proof. State transitions, validators, authorization, ownership, fencing, deletion, retry, compensation, and adapter result classification can never be excluded. Phase 0 pins the .NET test/property/model/fuzz/mutation toolchain and versions in `Directory.Packages.props`; tool changes invalidate baseline evidence.

CI wraps `pre-deployment-evidence.json` in a signed DSSE/in-toto-style attestation bound to the exact Git tree, dependency lock, generated schemas, test binaries, both architecture artifact digests, test counts, requirement trace, transition coverage, branch coverage, mutation results, fuzz corpus, model-check seeds, NATS conformance, analyzer results, and approver. The signing identity/key technology is selected in the Phase 0 supply-chain ADR and protected by KMS or an equivalently isolated CI identity. The first L1S server lab and every later lane verify this attestation before receiving short-lived lab/OCI mutation credentials. Forgejo protected environments and provider IAM enforce the gate, so invoking the CLI directly cannot bypass it. A source, dependency, generated contract, test, or binary change invalidates it.

### Test layers

| Layer | Environment | Purpose | Release authority |
|---|---|---|---|
| L0 | digest-pinned rootless toolchain container; in-process suite and deterministic simulator | all business rules/state machines plus unit/property/model/concurrency/fuzz/mutation/replay tests | mandatory before dependency conformance |
| L0C | same unprivileged toolchain container, no systemd/server-container/cloud mutation | real pinned NATS/JWT/JetStream/gateway behavior and generated configuration | mandatory with L0 before evidence is signed or a server lab starts |
| L1S | one isolated node container | real Linux process/network/filesystem behavior and one-node server/executor contracts, excluding systemd semantics | component integration gate |
| L2S | three isolated node containers, one complete cell | real control-NATS R3 plus product-NATS R3, controller election, node loss, TerraBase `a/b/c`, workloads and rolling operations | regional functional gate |
| L3S | **nine isolated node containers: GRU/FRA/SFO, three each** | all six NATS clusters, three TerraBase groups, all implemented product/platform servers, mTLS, WAN fault fabric, fake provider/storage, HA/chaos | mandatory full-region gate for every deployment-bound integration candidate |
| L1R | full Linux host with systemd as PID 1 | real systemd D-Bus/credentials/cgroups/journald, containerd, loop ext4/XFS | production-runtime boundary gate |
| L4 | disposable OCI A1 Ampere SUT, driven by an isolated rootless-container test coordinator | real ARM64 binary/images and instance/volume/LB/KMS/Vault/IAM/work-request APIs; targeted 1/3-node tests and final multi-region boundary smoke | mandatory provider/ARM/destructive gate |
| L5 | staged first-production deployment and canary | actual telemetry/cost/storage, SFO then FRA then GRU | production gate |

`terrascale-orchestrator lab` creates hermetic test runners and topologies through rootless Podman using digest-pinned images; it never uses Kubernetes. Profiles:

- `logic`: one toolchain container for L0/L0C and deterministic millions-of-event model/replay.
- `single-container`: one isolated node container for fast server/executor development.
- `cell-containers`: three isolated node containers with a complete R3 regional cell.
- `regions-containers`: the mandatory nine-node-container GRU/FRA/SFO topology and injected WAN behavior.
- `oci-cell`: disposable three-node OCI region.
- `oci-boundary`: targeted real OCI/A1/storage tests and the final minimum multi-region boundary smoke, not a duplicate of the full L3S functional matrix.

The container supervisor owns create/start/status/exec/log/copy/stop/delete, deterministic names/ports/directories, deadlines, crash recovery, and unconditional orphan cleanup. Ownership and profile labels prevent one run from removing foreign pods or containers. Images are selected from a closed digest-pinned catalog; workloads cannot request arbitrary images, mounts, capabilities, privileges, or host networking.

Phase 0 records the Podman version, image manifest digests, host kernel/cgroup capabilities, rootless status, network backend, storage driver, and conformance result. Upgrades require a reviewed pin change and a cold L0/L0C/L3S run. Matching-host containers cannot qualify `linux-arm64`; real A1 remains the mandatory ARM boundary.

Container namespaces and overlay storage are deliberate limitations in the evidence model. L3S proves processes, protocols, identities, topology, persistence, restart, and failure logic, but never claims to prove systemd unit semantics, OCI attachment/online expansion, block durability/performance, or A1 behavior. Those claims belong only to L1R/L4.

The DevHost graph becomes the first product fixture: three TerraBase processes, local JetStream, Auth, API, Dashboard, email and Stripe emulators, with the current dependency and health ordering. DevHost tests remain fast product-contract tests; they do not replace the Linux lab.

### Mandatory nine-container regional topology

```text
GRU: gru-0  gru-1  gru-2     full regional cell + global authority/CI/Grafana/OTel/VPN roles
FRA: fra-0  fra-1  fra-2     regional API/Auth/Dashboard/TerraBase/NATS + OTel export
SFO: sfo-0  sfo-1  sfo-2     regional API/Auth/Dashboard/TerraBase/NATS + OTel export

GRU <-> FRA     GRU <-> SFO     FRA <-> SFO
        deterministic host-side TCP/UDP link fabric and fault proxy
```

Every VM starts from the same checksummed `.smolmachine`/OCI-derived base created **before** enrollment, then receives a unique node ID, keys, certificates, overlay/workspace, port map, controller epoch, failure domain, and independent control-NATS/product-NATS/TerraBase data directories. Never snapshot/fork an enrolled node because that duplicates identity. Immutable artifacts are staged before the run; outbound internet is then disabled.

The lab uses a dedicated rootless Podman network only after conformance proves its DNS, isolation, port, and cleanup behavior for the pinned version. A TerraScale link fabric assigns deterministic logical DNS/endpoints and proxies inter-node/inter-region TCP/UDP paths so the suite can inject latency, loss, reset, bandwidth, reordering where supported, one-way/two-way partitions, and restoration by node/cell/link. Container connectivity alone is not evidence of production addressing.

At the final L3S gate, all production roles that fit the closed catalog run concurrently: orchestrator controller/agent on every seed, both NATS servers and one TerraBase member per seed, API/Auth/Dashboard in every cell, SFO/FRA collectors exporting all OTel signals to GRU, and the GRU global/operator/CI/Grafana/metrics/log/trace/alert/VPN coordination roles with their required replica counts. The server inventory is generated from the role catalog; the gate fails if a declared production role is absent, uses a stub, lacks a health/readiness check, has the wrong digest/architecture/config generation, or cannot serve its protocol.

Every phase-integration candidate runs L3S with every capability implemented through that phase. Phase 2 proves seed/identity/dual-NATS/self-upgrade; later phases progressively add executors/workloads, fake-provider autoscaling, TerraBase/storage logic, GitOps/CI, Grafana/OTel/VPN, and greenfield provisioning/recovery. Phase 9 is the complete matrix. Each scenario starts from a fresh nine-node topology; constrained hosts run shards sequentially, while capable hosts may run independent nine-node labs concurrently.

Mandatory scenario groups are:

1. clean nine-node bootstrap, identity/mTLS/authorization, all-server inventory/readiness, dual-NATS R3 and backups;
2. sequential stop/delete/recreate of every one of the nine VMs, with GRU availability and each regional quorum contract checked continuously;
3. every WAN link and whole-cell partition, GRU loss, reconnect/backlog recovery, regional autonomy, and telemetry spool/exhaustion policy;
4. scheduling, exact-digest rollout/rollback, N/N-1/A-B self-update, process crashes, controller/NATS leadership, stale command, unauthorized stale-deployment, and generation-replay attacks;
5. TerraBase `a/b/c`, six replication directions, backup/restore, logical expansion/fencing, 3->4->3 using temporary elastic node containers under decision 10A, and convergence back to three seeds/cell;
6. GitOps/CI/release, provider fake timeouts/duplicates/quota/cost, node scale-out/replacement/in, Grafana exact-state/alerts, OTel export, and VPN policy behavior.

L3S evidence contains exact tree/artifact/image-manifest/Podman/host-kernel digests, topology and port maps, randomized seed, virtual time, server inventory, health timeline, every injected fault, NATS/TerraBase positions, telemetry loss/spool counters, resource peaks, logs/traces, and cleanup/orphan proof. Failed container diagnostics are retained by policy; successful labs are destroyed and a cleanup audit proves no owned pod, container, network, port, or directory remains.

### Required test doubles

- virtual clock and deterministic ID/epoch generator;
- fake NATS delivery wrapper capable of loss, duplication, reordering, delay, redelivery, and stale consumers;
- fake cloud provider with asynchronous work requests, timeouts, quota/capacity failures, duplicate responses, and inventory drift;
- fake executor and real containerd/systemd contract suites;
- fake KMS/Vault plus real OCI integration lane;
- filesystem/block-device harness with loop devices, ext4, XFS, read-only, full disk, latency, detach, and wrong-volume injection;
- TerraBase admin fake for model tests plus real three-member integration and nine-host release gates;
- fake repository/provider remnant inventory for deleted OKE/Flux resources, including stale IAM, DNS, secret, load-balancer, volume, public-IP, webhook-token, and configuration findings; cleanup dry-run/apply/retry proves idempotent absence for positively identified approved remnants and proves unrelated, retained, or unknown-ownership resources are never removed, without becoming a runtime compatibility adapter.

### Chaos and recovery matrix

At minimum, automate:

- interruption before and after every greenfield creation checkpoint: Pulumi network/peering, IAM, KMS/Vault, object storage, disabled ingress/DNS/LB, seed hosts 1/2/3, initial control- and product-NATS quorum, node enrollment, handoff receipt, and Pulumi unmanage/retain transition;
- independent regional partial success in which one cell completes while another fails; retry must reuse or safely reconcile the intended resource IDs, create no duplicate trust roots, cluster/server IDs, streams, volumes, ownership epochs, or DNS/LB targets, quarantine ambiguous partials, clean only proven abandoned resources, and keep public ingress closed throughout recovery;
- kill/restart every controller and agent at every external-operation checkpoint;
- hard-power-off and network-isolate each GRU node in turn under product and telemetry load; require continued global control, GRU reads/writes, operator access, telemetry ingest/query, alerts, and VPN coordination without manual action;
- NATS leader loss, one server loss, quorum loss, stream restore, backlog recovery, and full regional partition;
- GRU global outage while SFO/FRA serve, heal, scale within policy, renew identities, and spool telemetry;
- duplicate, expired, reordered, delayed, and conflicting commands; stale leader/agent fencing;
- leadership loss at every provider-actuator checkpoint, especially after final lease check but before OCI request; late work-request completion and new-leader resume of the same irreversible operation;
- node crash/reboot, cloud API timeout, quota exhaustion, no regional A1 capacity, wrong image, failed enrollment, and orphan VM;
- GRU/Git/central-vault/central-registry outage followed by complete loss and A1 replacement of one regional host using only the regional survival bundle;
- orchestrator N/N-1 mixed-version operation, A/B self-upgrade failure before/after restart, rollback-timer expiry, controller handoff, and one-failure-domain rolling upgrade;
- disk 70/80/90/95%, full/read-only/corrupt signal, high fsync latency, attachment loss, wrong disk, expansion crash at every step, ext4 and XFS online growth;
- TerraBase bootstrap idempotency, 3->4->3, leader transfer, one-at-a-time upgrade, failed upgrade and rollback, quorum degradation, catch-up, six replication routes, conflict, empty-cell rebuild;
- application-consistent full/incremental backup under writes, retention, checksum, object-store outage, side-by-side restore, member/region loss;
- certificate near-expiry, rotation overlap, issuer rotation, revocation, Vault/KMS outage, stolen/stale identity, trust-bundle mismatch, and no secret leakage;
- canary/blue-green/rolling failure, Git/NATS outage during reconcile, controller restart during promotion, exact-digest verification and rollback;
- OTel/GRU outage, bounded spool exhaustion, recovery, and proof that API readiness is unaffected;
- cost-cap, scale oscillation, safe drain, retained/disposable volume behavior, and post-delete orphan audit.

Mocks cannot sign off a destructive state transition. Compute termination, volume expansion/deletion, TerraBase topology removal, certificate rotation, backup/restore, and multi-region release all require a real-system acceptance lane.

### Performance and correctness gates

- Scheduler produces deterministic placement and reason output for at least 10,000 nodes/100,000 allocations in benchmark fixtures, even though launch is smaller.
- A real compact A1 cell runs the full allowed regional role mix and twice the projected stateless replica count with no Kubernetes-style allocation ceiling; admission fails only on a declared measurable resource/security constraint and reports it exactly.
- Regional leader failover target under 30 seconds without duplicate mutation.
- Any one GRU node loss causes at most retryable in-flight request failures: no sustained public/control/operator-API/Grafana outage, no loss of acknowledged NATS/TerraBase/control state, and no manual failover. Automated replacement restores full redundancy.
- Running workloads continue through control-plane restart/quorum loss according to partition policy.
- Node create-to-ready p95 target under five minutes when provider capacity is available; capacity errors are classified, retried, and surfaced.
- Storage expansion begins with safe forecast headroom and verifies provider, device, filesystem, and TerraBase capacity.
- No data corruption, double attachment, duplicate member identity, stale operation completion, or secret bytes in captured NATS/log/trace/metric/Grafana output.
- Both runtime drivers pass the same workload lifecycle contract.
- Database storage SLO passes during steady load, backup, restore, compaction, catch-up, node loss, and colocated compact-profile load.
- Seven-day compact-profile soak demonstrates the approved cost target and no hidden cloud resources.

## Repository structure

```text
TerraScale.Orchestrator/
  ORCHESTRATOR.md
  README.md
  AGENTS.md
  TerraScale.Orchestrator.slnx
  Directory.Build.props
  Directory.Packages.props
  global.json
  src/
    TerraScale.Orchestrator/                  # the only production project
      Contracts/                             # versioned desired/observed models
      Protocol/                              # NATS envelopes, subjects, signatures
      ControlPlane/                          # global and regional state machines
      Scheduling/
      Runtime/
      Messaging/
      Storage/
      TerraBase/
      Security/
      Delivery/
      Operations/
      Providers/
  tests/
    TerraScale.Orchestrator.Tests/             # focused functional decisions only
  schemas/                                  # generated JSON Schemas and examples
  requirements/registry.yaml                # canonical REQ/INV/ERR/SM/SEC registry
  protocols/                                # subject/version compatibility fixtures
  test-corpus/                              # deterministic replay and fuzz regressions
  test-evidence/                            # schemas for trace/evidence/attestations, not CI outputs
  testlab/                                  # pinned Smolfiles/images, 9-node manifests, link fabric, block harness
  packaging/systemd/
  docs/adr/
  docs/work-packages/                       # sub-agent scopes/dependencies/handoffs
  docs/retirement/workaround-ledger.yaml
  docs/runbooks/
  .terrascale/deploy.json
  .forgejo/workflows/bootstrap.yml
```

One production project builds the one executable. Directory and namespace boundaries keep capabilities organized without project-reference ceremony. Production modules communicate through typed contracts and explicit state-machine interfaces, not a network of needless microservices.

The permitted dependency direction is:

```text
Contracts <- pure domain/state machines <- application coordinators <- adapters
     ^                    ^                         ^                  ^
     +------ test models/fixtures -----------------+------------------+

single executable composition root -> wires every implementation; contains no policy
```

Contracts and pure domains do not use infrastructure namespaces or types. Application coordinators may persist/dispatch typed intents through abstractions but cannot call concrete adapters. OCI/NATS/systemd/containerd/Git/filesystem/crypto-provider/Grafana adapters translate intent and observation only.

## Parallel multi-agent implementation model

Implementation is organized for independent sub-agents, not as many agents editing one checkout. The root/integration agent is the contract steward. With the current four-agent concurrency limit, it coordinates up to three active implementation/verification agents at once; additional lanes rotate in dependency waves. If more slots are available later, the ownership model scales without changing boundaries.

### Dependency and integration DAG

```text
G0 owner decisions + SLOs + tool/artifact pins + historical-workaround ledger
 |
 v
F1 contracts + protocols + requirement/error registry + evidence schemas
 |
 +---------------------+----------------------+----------------------+
 v                     v                      v
P1 Core              P1 Messaging          P1 Cloud/Data
authority/ops/       NATS/identity/        provider/handoff/
scheduler/budgets    vault/PKI             storage/TerraBase rules
 |                     |                      |
 +-----------+---------+----------+-----------+
             |                    |
             v                    v
       P1 Delivery             P1 Ops
       GitOps/CI/release       Grafana/OTel/network/operations
             \                    /
              +--------+---------+
                       v
              P1 Verification models
                       |
                       v
              G1 cold full L0 + L0C
                       |
        +--------------+-------------------+
        v                                  v
P2–P5 runtime/NATS/OCI/storage       container supervisor/network/scenarios
        \                                  /
         +--------- per-phase L3S --------+
                       |
        +--------------+-------------------+
        v                                  v
P6–P8 GitOps/CI                  Grafana/OTel/VPN/operator API
        \                                  /
         +--------- full L3S/L4 -----------+
                       |
                       v
       P9 qualification -> P10 greenfield regional bring-up
```

`F1` freezes only the next compatible contract tranche; it does not block every domain until the entire product is written. After a tranche merges, pure domain agents and an independent verification agent work concurrently. No adapter may boot a server or mutate an external system before the aggregate G1 evidence gate.

### Exclusive workstream ownership

| Lane | Exclusive production paths/responsibility | Required independent evidence |
|---|---|---|
| Integration/contract steward | `src/TerraScale.Orchestrator/Contracts`, `src/TerraScale.Orchestrator/Protocol`, requirement registry, schemas/generators, solution/package/build files, composition root, shared test primitives | compatibility fixtures, architecture graph, aggregate evidence/merge result |
| Core | control plane, operation engine, scheduler, budgets/cost decisions | unit/property/model/concurrency tests and placement/operation traces |
| Messaging/security | NATS, identity, Vault, PKI/mTLS, regional trust/survival material | permission/conformance fixtures, revocation, peer recovery, security/fuzz tests |
| Runtime | agent, closed role admission, systemd/containerd adapters, bootstrap/self-upgrade | fake executor plus lifecycle, A/B rollback, L1S/L1R contract tests |
| Cloud | provider abstractions, OCI/Pulumi handoff, actuator, compute autoscaler | provider model/fake, fencing race suite, L4 adapter evidence |
| Storage | generic volume lifecycle/expansion/fencing and filesystem adapters | block model/harness, irreversible-step recovery, L4 destructive evidence |
| TerraBase | TerraBase topology, upgrade, replication, backup/restore/autoscaling | independent admin fake plus real 3-member/L3S/L4 scenarios |
| Delivery | native GitOps, CI/CD, release and artifact promotion | source/reconcile/pipeline models, trust-zone and interruption tests |
| Operations | operator API, exact Grafana projection/plugin, OTel, networking/VPN, stale-resource audit tooling | cardinality/security, link/outage, orphan-cleanup and browser-read tests |
| Cross-repository cleanup | one `WRK-*`-scoped branch/worktree/PR in one existing repository at a time, only after the native replacement gate | repository compatibility suite, linked orchestrator regression/L3S scenario, deleted-path/remnant proof; never edits the current dirty worktrees |
| Verification | container supervisor/link fabric, requirement trace/evidence aggregation, cross-domain adversarial/model/chaos tests | never changes production logic to make a scenario pass; files minimal repro seeds against owning lane |

Each domain lane owns its positive/unit/property/state-machine tests. Verification owns independent adversarial and cross-domain scenarios. Production and verification agents should not be the same agent for a safety-critical transition's acceptance test.

### Sub-agent work package contract

Before spawning an implementation sub-agent, the integrator writes a small work-package manifest containing:

- predecessor commit SHA and contract/schema version;
- requirement/invariant/error/state-machine IDs and exact acceptance scenarios;
- allowed production/test/documentation paths and explicitly prohibited shared paths;
- dependencies/fakes supplied, public contract it consumes, and compatibility version;
- expected implementation, tests, generated evidence, commit(s), and handoff notes;
- commands/shards that must pass and whether the work changes the L3S server inventory;
- threat assumptions, destructive actions prohibited, and unresolved owner decision that must remain configurable.

Every lane uses its own Git feature branch and dedicated worktree. Agents never share a writable checkout. Only the integrator edits/merges `*.slnx`, central package/build files, the canonical registry, generated global schemas, composition root, `ORCHESTRATOR.md`, or `develop`. If a lane discovers a contract gap, it returns an RFC/compatibility fixture to the steward instead of editing shared contracts opportunistically.

### Merge train and evidence reuse

1. The steward merges a small contract tranche and records its digest.
2. Up to three domain/verification agents branch/worktree from that exact digest and work on disjoint paths.
3. Each feature PR runs its owned L0 shard, saved corpus, architecture checks, and relevant L0C slice inside a rootless container.
4. The serialized merge train rebases compatible PRs, creates one exact candidate tree, and runs all impacted shards plus cross-domain models.
5. A deployment-bound candidate runs the full right-hand evidence budget, cold L0C when required, signs the aggregate pre-VM attestation, then creates fresh L1S/L2S/L3S labs.
6. `develop` advances only to the exact commit that passed the required progressive L3S gate. A failed seed becomes a checked-in regression before a fix merges.
7. Content-addressed shard evidence is reusable only under the strict dependency-closure rule above. The first server lab, shared-contract/security changes, and every release are cold full runs.

Test sharding follows domain boundaries:

- L0: contracts/requirements; core/scheduler; NATS/security; cloud/storage; TerraBase; delivery/deployment; operations; cross-domain model/concurrency.
- L0C: control-NATS/gateways; product-NATS/isolation; N/N-1 and peer/snapshot recovery.
- L3S: bootstrap/NATS/mTLS; runtime/rollout/node failure; TerraBase/storage/replication; GitOps/CI/Grafana/OTel/greenfield deployment.

An L3S scenario shard always receives a fresh complete nine-seed topology; it does not delete unrelated regional roles to reduce runtime. Shards may run concurrently only as independent nine-VM labs with separate port/directory ranges. This avoids cross-scenario state while still allowing multiple verification sub-agents to operate in parallel.

## Delivery plan

No phase creates a throwaway alternative architecture. Early phases exercise the same protocols, state machines, binary, and R3 topology that production will use.

Phases are integration gates, not instructions for one agent to work serially. After the steward freezes each compatible contract tranche, the workstreams above execute in parallel on independent worktrees and join only through the merge train. Phase 1 parallelizes pure domains and independent adversarial tests; Phases 2–8 parallelize adapters, domain integration, and the next rootless container scenario tranche. From Phase 2 onward, an integration candidate cannot close a phase until the mandatory progressive nine-node L3S topology passes with every role implemented so far.

### Phase 0 — decisions, threat model, and measurable baseline

Deliver:

- resolve the owner decisions in this document;
- inventory live OCI instances, volumes, attachments, backups, buckets, LBs, public IPs, IAM, Vault, NATS streams/consumers, certificates, workloads, and seven-day utilization/cost; establish the actual post-OKE-deletion residual bill, explicitly prove OKE clusters/node pools are absent, and identify any stale Kubernetes/Flux IAM, DNS, secret, volume, public-IP, load-balancer, webhook, or configuration remnants;
- run the normalized eligible-provider TCO/ARM64/block-storage/TerraBase benchmark and record why OCI remains first or which second adapter is prioritized;
- generate the >=20-row OCI eligible-region matrix and exhaustive cross-repository `WRK-*` retirement ledger with owners/tests/removal phases;
- pin Podman and every image by immutable manifest digest; run nine-container concurrent start, persistence, DNS/link-fabric, port, resource-limit, process-crash, cleanup, storage-limit, rootless-isolation, and matching-architecture conformance before accepting the lab backend;
- define storage, availability, RPO/RTO, security, memory, scale, and cost SLOs;
- ADRs for authority, NATS isolation/topology, provider ownership, runtime drivers, Vault scope, compact profile, networking/VPN, and project-placement boundary;
- select and pin the ARM64 LTS host image/kernel/glibc, production filesystem candidates, NATS server/client and N/N-1 policy, test toolchain, artifact/evidence signing, A1-capacity fallback, VPN, DNS, immutable Grafana provisioning plus metrics/log/trace HA persistence, and regional artifact-mirror design;
- reconcile CI policy conflicts and complete the exhaustive runtime/build descriptor inventory.

Exit gate: every pre-existing account resource is proven outside the new greenfield ownership graph and has an unrelated/quarantine/approved-cleanup disposition; target SLOs and destructive-operation policies are approved; no implementation relies on contradictory documentation.

### Phase 1 — complete pure decision core and zero-deployment proof

Deliver:

- solution skeleton, quality/security gates, reproducible dual-architecture single-file builds;
- versioned resource schema and generated JSON Schema/docs/fixtures;
- command/event envelopes, subject permissions, operation journal, snapshots, leader epochs, fencing and idempotency;
- pure state machines and error catalogs for every scoped domain: authority, scheduler, dual NATS, compute/Pulumi ownership, provider operations, storage, TerraBase, identity/vault, GitOps, CI/release, Grafana projection, networking policy, greenfield provisioning/ownership, self-update, cost, and regional survival;
- deterministic desired/observed-state engine, intent/observation adapter contracts, dependency-boundary tests, and model simulator;
- canonical requirement registry and generated requirement-to-code-to-test-to-evidence traceability;
- complete business-rule/state-transition/error matrices, fakes, property/model/concurrency/fuzz/mutation/replay suites, and regression corpus;
- hermetic real-NATS L0C conformance and signed `pre-deployment-evidence.json` attestation production/verification.

Exit gate: the hard pre-deployment thresholds pass for the exact binary; every registered requirement/invariant/error is traced; property/model tests cannot produce two accepted writers, a stale successful mutation, an unsafe deletion, a quorum-floor violation, or an unauthorized action under explored loss/duplication/reordering/partition/crash scenarios; restored state reaches the same digest. L0C validates the generated NATS contract. No server container, systemd/containerd, or OCI deployment test starts before this gate; only the credential-free L0/L0C toolchain container exists.

### Phase 2 — secure seed, identity/vault foundation, dual NATS, and self-upgrade

Deliver:

- pinned host/bootstrap image, signed artifact verification, A/B orchestrator install, rollback timer, and N/N-1 protocol/schema compatibility;
- rootless container supervisor, digest-pinned image catalog, deterministic link fabric, cleanup journal, and progressive nine-seed L3S harness;
- KMS/Vault backend abstractions with a deterministic lab backend, envelope encryption, policy, leases/audit, regional intermediates, node/workload/operator identities, trust/revocation, and protected credential delivery;
- one offline control operator trust root with regional signing/accounts and a distinct product trust root, generated least-privilege permissions, selective mTLS, monitoring isolation, and both three-server NATS planes;
- typed NATS server/store membership, replacement, peer-removal, durability/sync, snapshot/restore, one-at-a-time upgrade, and rollback adapters;
- regional survival-bundle creation/verification and the first evidence-gated L1S test followed by the L2S seed/NATS/identity cell and progressive nine-node L3S topology.

Exit gate: bootstrap, enrollment, renewal, rotation, revocation, issuer rotation, self-upgrade rollback, one-NATS-server loss/replacement in each plane, backup/restore, regional survival material, and captured-output secret scans pass. No long-lived shared edge identity remains and one failed seed host does not lose either NATS quorum.

### Phase 3 — host agent, both executors, regional control, and scheduler

Deliver:

- host inventory, health/heartbeat, local journal, D-Bus/systemd and containerd clients;
- closed role catalog and unified allowed `WorkloadSpec`, resource controls, probes, credential mounts, ports, journald/OTel, crash-loop behavior, drain and rollback;
- atomic native artifact/OCI-digest staging and identical lifecycle contracts across permitted systemd/container roles;
- regional leadership, accepted `CellSpec`, registry, deterministic scheduler, allocation/deployment state machines;
- health-aware service discovery, DNS/LB adapter, rolling/canary/blue-green/ordered stateful strategies;
- cordon/drain, disruption budgets, reservations, anti-affinity, placement explanations;
- three-node regional HA, control-NATS quorum failure behavior, and no artificial per-node allocation/pod ceiling.

Exit gate: API/Auth/Dashboard and a TerraBase fixture pass the applicable native/container lifecycle contracts; node/controller/NATS failures do not duplicate allocations or mutations; stale commands/orphans are rejected/reclaimed; running services survive control loss; rollout/rollback are exact-digest and health-gated; compact A1-equivalent density passes.

### Phase 4 — OCI/Pulumi handoff, compute autoscaling, and cost control

Deliver:

- provider abstraction and OCI Compute/network/LB/limits/pricing/work-request adapter with isolated regional actuator;
- Pulumi `BootstrapBundle`, exact signed inventory handoff of freshly created resources, deliberate retain/unmanage transition, and disaster re-bootstrap fencing;
- approved ARM64 A1 templates, instance lifecycle/enrollment, node classes, regional self-management, scale decisions, budgets, quotas, approved capacity fallback, and orphan audit;
- production OCI KMS/Vault integration, regionally available artifacts/survival bundle, stateless scale-from-zero, failed compute/controller/NATS-host replacement, and safe node-generation rotation. If that host carried TerraBase, its data volume remains fenced/held and the member is not started until Phase 5 owns the storage/TerraBase recovery adapter;
- provider fake plus real disposable OCI A1 tests.

Exit gate: crash/retry and leadership loss at every provider/handoff checkpoint creates exactly one owned terminal outcome; a new leader resumes authorized destructive work; tags never authorize it; Pulumi cannot fight the post-handoff autoscaler; scale out/in, compute/control/NATS replacement, survival-bundle replacement during GRU/Git outage, and A1 generation rotation pass while any TerraBase disk/member stays safely held; unauthorized/unowned resources are never mutated.

### Phase 5 — storage and TerraBase controller

Deliver:

- volume claims, OCI block adapter, single-writer fencing, create/attach/classify/format/mount/detach/retain/delete;
- real ext4/XFS expansion, performance-tier policy, forecast/cost limits, backup interlocks;
- typed TerraBase bootstrap/topology/certificate/upgrade/replication/backup/restore/scaling controller;
- native systemd and OCI container TerraBase descriptors.

Exit gate: clean three-host bootstrap is idempotent; loss of a combined seed/NATS/TerraBase host is fully recovered from the regional survival bundle and retained member volume; 3->4->3, one-at-a-time upgrade/rollback, every-step crash recovery, wrong-volume fencing, online expansion, backup under load, side-by-side restore, and all six regional replication routes pass. Automatic destructive scale-in remains off until this gate passes in SFO soak.

### Phase 6 — native GitOps reconciler

Deliver:

- Git/OCI source controllers, signatures, schema/render/compile, dependencies, diff/plan/apply, drift, health, suspend/retry/prune/rollback;
- explicit Git parent policy versus journal-owned autoscaled-child semantics;
- fresh native desired-state manifests derived from the closed role catalog and reviewed application/runtime contracts; no Flux/Helm/Kustomize reader or converter;
- global-to-cell signed handoff and same-digest barrier;
- elimination replacements for Flux wait/webhook/reconcile/image-writer/rollout-guard workarounds.

Exit gate: Git/NATS/controller failure at every phase resumes deterministically; HTTP acknowledgement means durable acceptance; one writer advances artifacts; rollback restores the known generation/digest; Git prune cannot delete an autoscaled child or data resource.

### Phase 7 — CI/CD and isolated runners

Deliver:

- Forgejo integration, repository descriptor v2, affected dependency graph, pipeline DAG, runner autoscaling/isolation, caches/artifacts/logs;
- immutable candidates, release sets, promotion leases/fencing/journal, registry/package replication and live verification;
- evidence-gated deployment credentials and the decision 7A independent orchestrator bootstrap/recovery workflow.

Exit gate: representative changes across all repositories select the correct graph; no duplicate build occurs; interrupted publish/promotion recovers; an evidence or direct-CLI bypass receives no mutation credentials; untrusted jobs cannot access production; the exact candidate rolls SFO->FRA->GRU and rolls back on a forced gate failure.

### Phase 8 — Grafana console, operator API, observability, VPN, and HA backends

Deliver:

- HA operator API/CLI, OIDC/RBAC/audit/break-glass, exact read-only state projection, and generated Grafana dashboards/alerts;
- immutable/read-only Grafana replicas and the selected HA Prometheus-compatible/Loki/Tempo/Alertmanager/query/ingest design;
- Grafana stack as GRU workloads, host/systemd/container discovery, regional bounded OTel spooling and mTLS export;
- selected VPN coordination workload plus route/ACL/identity controller, regional DNS/LB integration, capacity/cost dashboards, and runbooks.

Exit gate: sequential loss of either of two Grafana instances and every observability/VPN endpoint proves the approved GRU degradation policy; telemetry outage/exhaustion and VPN-control outage never block product readiness; read-only Grafana cannot authorize a mutation; operator API security and alert/runbook drills pass.

### Phase 9 — full three-region qualification and clean-room deployment rehearsal

Deliver:

- full GRU/SFO/FRA nine-node L3S and targeted disposable OCI A1 L4 environments with six NATS clusters, three TerraBase R3 groups, real endpoints, survival bundles, and selected HA backends;
- a from-zero rehearsal of Pulumi foundation creation, nine-seed bootstrap, signed regional handoff, native desired state, product-data initialization, regional replication, staged release, rebuild, and orchestrator-generation rollback without any Kubernetes endpoint or credential;
- nine-node chaos, GRU/WAN/Git/Vault/registry outages, every-GRU-node sequential failure, capacity/volume autoscaling, backup/restore, cost and storage performance qualification;
- a provider/repository audit rehearsal that treats any OKE/Flux remnant as an orphan requiring explicit disposition, never as a source to adopt;
- signed go/no-go evidence and per-cell first-deployment, rebuild, rollback, and disaster-recovery runbooks.

Exit gate: the clean-room deployment is reproducible; the nine-node chaos matrix, real A1/provider/storage destructive gates, GRU and edge-disconnection survival, greenfield ownership/fencing, telemetry/VPN outage, alert/runbook drills, security review, cost/storage SLO, and multi-region product compatibility suite all pass.

The nine-node matrix includes sequential failure of every GRU host while the full global and regional workload is active. Phase 9 cannot pass if any critical GRU service is singleton, loses its only durable state, requires manual promotion, or lacks one-node-equivalent capacity headroom.

The complete functional/HA/chaos topology is L3S in nine isolated node containers; mandatory L1R/L4 provide real systemd and targeted OCI A1/IAM/storage plus multi-region boundary evidence. To avoid paying for a duplicate full cloud estate, the exact nine-node, three-region OCI topology is first assembled in Phase 10 with public ingress disabled. Those resources remain an unexposed qualification environment until the full cloud soak and production gates pass. A boundary failure tears down or repairs the affected new generation and repeats the gate before exposure; it never weakens the container matrix or turns untested resources public.

### Phase 10 — greenfield three-region production bring-up

OKE and the live Kubernetes estate are already absent. This phase never looks for a running legacy controller, imports Kubernetes objects, waits for a cutover, or offers Kubernetes as rollback. Historical repositories remain read-only behavioral specifications. Every production resource and authoritative byte is created afresh by this plan. Any pre-existing cloud/IAM/DNS/secret/configuration/data artifact belongs outside the new ownership graph: it is unrelated, quarantined, or an independently approved cleanup target, and is never imported, attached, decrypted, replayed, or adopted.

Pulumi operations may prepare the three durable regional foundations concurrently after one reviewed preview, while each regional bootstrap and handoff is independently fenced and evidenced. Product exposure remains staged so a defect does not spread to all regions at once.

Order:

1. Re-run the OCI account inventory and prove there are no OKE clusters or node pools. Mark every pre-existing instance, volume, attachment, backup, bucket, load balancer, public IP, IAM/dynamic-group policy, Vault secret, DNS record, certificate, and Flux webhook token as outside the new greenfield ownership graph. Classify it only as unrelated/quarantined or a positively identified cleanup candidate; there is no “adopt” or “retained foundation” outcome.
2. Generate a cleanup-only plan for positively identified stale resources, show every destructive action, receive explicit approval, apply it, then re-inventory. Unknown ownership stays quarantined and the new design selects collision-free names/routes; unrelated resources are untouched. Cleanup receipts are separate from the new Pulumi stack and cannot seed it.
3. Review the exact Pulumi preview, cost forecast, quota/capacity probes, networking/peering plan, destructive actions, and signed `BootstrapBundle` for GRU, SFO, and FRA. Apply only the durable foundation under explicit production approval.
4. Create three A1 seed hosts in each region, establish identity and both regional NATS R3 planes, write and restore-test initial control-state backups/survival bundles, then complete the signed Pulumi-to-regional-controller handoff independently for each cell.
5. Prove each empty cell can operate, replace one failed seed, reject stale bootstrap generations, and reconcile provider truth without GRU, Git, or the other cells.
6. Initialize each product-NATS plane and fresh TerraBase `a/b/c` group, create dedicated data volumes, verify backup/restore, then establish and validate the six directed GRU/SFO/FRA replication paths. Regenerate the complete regional survival bundles with the final stateful identities/artifacts and restore-test them before any application or traffic is admitted.
7. Deploy the GRU HA global authority, operator API, native CI/CD, vault/PKI services, Grafana/Prometheus/Loki/Tempo/Alertmanager/OTel ingest, and VPN coordination with anti-affinity and one-node reserve. Sequentially fail every GRU host before proceeding.
8. Deploy API, Authentication, Dashboard, and regional OTel collectors first in SFO, then FRA, then the GRU product cell using one signed release set and exact architecture-specific digests. Run public-contract, SDK, synthetic queue/database, routing, mTLS, and telemetry-export tests at every regional gate.
9. Exercise automatic compute scale-out/replacement/scale-in, TerraBase 3->4->3, online storage expansion, certificate rotation, interrupted release recovery, and artifact/generation rollback. Rollback means returning to a previously healthy orchestrator generation/digest; there is no Kubernetes fallback.
10. Run at least a seven-day full-topology soak with database load, sequential node failures, WAN/GRU outages, billing reconciliation, storage-performance SLOs, backup/restore, telemetry-spool exhaustion, and a zero-orphan audit.
11. Enable public DNS/customer traffic only after the signed production gates and an explicit owner approval. With no users, initialization and synthetic validation precede exposure; later staged releases retain the SFO -> FRA -> GRU order. Emergency traffic withdrawal back to closed ingress is tested before enablement.
12. Record the final provider inventory and normalized BRL/day. It must prove the declared resources, owners, handoff generations, backups, and cost; OKE, Flux runtime credentials, and unowned cloud resources must remain absent.

## Production acceptance gates

### Platform

- Three controllers/cell, R3 critical state, independent cell operation, signed snapshot/restore, no split writer.
- Every resource in the new platform was created by the greenfield Pulumi/orchestrator flow, has exactly one mutation owner and a signed ownership generation, and is traceable to the new stack. No pre-existing resource may enter that graph; an unknown or stale account resource stays outside it and is quarantined rather than adopted or deleted.
- Failure/restart at every first-creation and Pulumi-handoff checkpoint resumes idempotently, including independent partial success by region, without duplicate resources, trust roots, NATS identities, streams, volumes, or ownership epochs.
- Two consecutive clean-room L3S deployments from the same signed contracts/artifacts converge to equivalent declared state, and the closed-ingress Phase 10 cloud assembly matches that contract. A fresh environment depends on no historical OCID, certificate root, Kubernetes secret, NATS cluster/server identity, stream position, or hidden manual state.
- Public DNS and ingress are default-deny until the signed enablement action after all gates; premature enablement is rejected, and tested emergency withdrawal closes traffic without destroying state.
- The exact `linux-arm64` release and every selected platform image pass real A1 Ampere execution, failure, storage, and performance gates; no x64-only production dependency remains.
- GRU passes one-at-a-time failure of every node with global control, regional product traffic, both NATS planes, TerraBase, vault/PKI, GitOps, operator API, Grafana/query/ingest/alerting, and VPN coordination still usable; the failed capacity is recreated automatically.
- Every external mutation has persisted intent, idempotency, fencing, timeout, evidence, and restart recovery.
- Both execution drivers support the same resource, identity, health, rollout, logging, volume, and rollback contract.
- Compute scale-out/in, quota/capacity failure, node generation, LB registration, and orphan audit pass in real OCI.
- mTLS and least-privilege NATS subjects are mandatory for production control traffic.
- Memory/CPU and seven-day cost gates pass without reducing declared safety margins.

### TerraBase and storage

- From three clean hosts: issue identities, create/mount three independent Balanced disks, start `a/b/c`, bootstrap once, join twice, and rerun safely after controller/agent reboot.
- Two actors cannot own one `(cell, member)`. Stale epochs cannot start a process, attach/grow/delete a disk, change topology, rotate a cert, or complete an operation.
- Member tag, provider volume ID, filesystem UUID, and data survive host replacement.
- One-at-a-time upgrade proves pre-gates, leader handoff, artifact/process generation, all databases online, resume from every checkpoint, automatic rollback and rollback-failure handling.
- Real ext4/XFS expansion survives crashes between cloud expand, rescan, partition/LVM, filesystem grow, and verification. It never shrinks or formats a known disk.
- Real 3->4->3 holds on stale metrics, never removes `a/b/c`, safely drains/transfers/removes/re-reads topology, and handles retained/deleted volume policy.
- GRU/SFO/FRA all six directed replication paths, WAN loss/reorder/duplication, placement generations, conflicts, empty-cell recovery, chosen RPO/RTO, and local availability during GRU loss pass.
- Full/incremental application backups during writes, retention, checksum, region/member loss, and side-by-side restore pass. A block snapshot alone cannot satisfy this gate.

### Release and product compatibility

- API region/routing headers, health/liveness/readiness, request IDs, trace context, public SDK behavior, queue at-least-once/dedup/DLQ, and customer placement semantics remain compatible.
- Product queue NATS remains cell-local; the orchestrator does not silently turn it into global WAN NATS.
- Fresh product-NATS initialization proves the configured cell-local endpoint, subjects, permissions, stream/consumer configuration, backups, and client compatibility before any public traffic is enabled.
- Project placement and storage epoch semantics have one source of truth.
- Immutable candidate promotion traverses SFO, FRA, GRU with required soaks and exact digest; gate failure stops and records evidence.
- Git/NATS/controller outage never rolls a healthy workload to an unrequested version.
- Customer Dashboard remains separate; operator allocation, exec, secret, and host APIs do not enter public SDKs.

## Risks and controls

| Risk | Control |
|---|---|
| Scope expands into a private Kubernetes clone | TerraScale-owned workload scope, explicit non-goals, ADR review for every new resource kind |
| NATS messaging mistaken for consensus design | Regional R3 journal, one writer, CAS fencing epochs, signed generations, deterministic restore/model tests |
| Bootstrap cycle | Pulumi creates fresh seed hosts and both NATS clusters, then explicitly transfers those new resources to the regional authority; recovery path is separately tested |
| Partial greenfield creation leaves duplicate/orphaned foundation, trust, or NATS identities | journal every create/handoff checkpoint; deterministic IDs/idempotency; per-region partial-success tests; quarantine ambiguity; approved cleanup plus re-inventory before retry |
| Historical cloud remnants collide with new IAM, DNS, LB, volume, or naming state | inventory and ownership proof before apply; delete only positively identified approved remnants; choose collision-free generations; never adopt an unknown resource |
| Public traffic reaches an incompletely qualified cell | default-deny DNS/LB/ingress, signed enablement only after all production gates and soak, synthetic preflight, and tested emergency withdrawal |
| Regional split brain | No edge-originated global generations, epoch fencing, cell authority, signed handoff, destructive holds under uncertain quorum |
| Scheduler bug damages a database | TerraBase controller veto/reservation, one member per host, real destructive tests, SFO->FRA->GRU rollout |
| Volume is double-attached/formatted/deleted | Stable identity, provider tags, filesystem UUID, single-writer fence, known-volume no-format rule, quarantine and multi-step approval |
| Auto-expansion creates uncontrolled cost | forecast, max size, technical/monetary bands, performance SLO, alerts, audit and hard account cap |
| Built-in vault weakens security | decision 3A external OCI KMS/Vault root protection, no custom crypto, security epic/gate, short-lived identities, independent review and recovery drill |
| CI executes hostile code near production | ephemeral isolated workers, separate network/identity/cache, no production metadata/secrets, signed phase-scoped publishing |
| Single binary becomes a monolith | strict project/module boundaries, state-machine interfaces, one composition root, contract and architecture tests |
| Self-hosted CI cannot repair itself | decision 7A independent signed bootstrap/recovery workflow, minimal privileges, and regular recovery exercise |
| Compact profile harms database latency | dedicated TerraBase disks plus decision 8A NATS process/store/cgroup isolation, full colocated storage benchmark, automatic transition to isolated class |
| Nominal replicas still leave a GRU singleton or insufficient capacity | generated HA dependency audit, hard anti-affinity/disruption budgets, one-node reserve accounting, sequential power-off qualification of every host |
| Greenfield runtime diverges from public behavior | reuse existing E2E/OpenAPI/SDK/SLO suites, synthetic three-region compatibility checks, and staged SFO -> FRA -> GRU release gates |
| Twenty-region networking becomes quadratic | provider-neutral topology graph; gateway full mesh only for the initial three cells; qualified leaf/bridge hub-and-spoke growth mode; explicit product replication links |

## Explicit non-goals

- Kubernetes API, CRDs, controllers, Helm runtime, kubelet, CNI, CSI, admission webhooks, or Kubernetes workload compatibility.
- Nomad compatibility or a layer over Nomad.
- Arbitrary customer code or a general-purpose workload admission API.
- A new database, Raft implementation, message broker, container runtime, source-control server, registry, build engine, metrics/log/trace backend, dashboard engine, cryptographic primitive, or VPN protocol.
- Cross-region synchronous scheduler consensus.
- Parsing, importing, or emulating historical Kubernetes manifests.
- Automatic database storage shrink.
- Automatic deletion of permanent database volumes.
- Treating systemd active state as application readiness.
- Putting plaintext secret values/private keys in Git or ordinary NATS subjects/streams. Decision 3A keeps authoritative ciphertext/root protection in OCI Vault/KMS; ordinary subjects and streams never contain secret values.
- Exposing internal operator capabilities through TerraScale's customer SDKs.
- Replacing Grafana or the customer Dashboard.

## Initial ADR backlog

1. Global versus regional authority and outage mutation policy.
2. Dual dedicated regional NATS topology, host co-location isolation, bootstrap, upgrade, and recovery.
3. JetStream streams, KV CAS, snapshot/restore, fencing, and audit retention.
4. Pulumi/provider ownership and exact resource tags/IAM.
5. Direct OCI instances versus instance pools by node class.
6. Unified workload schema and systemd/containerd driver contract.
7. Host network/port allocation versus namespaced network roadmap.
8. Compact co-location performance and promotion to isolated node classes.
9. Volume identity, filesystem layout, fencing, expansion, performance, retention, and deletion.
10. TerraBase topology, upgrade, backup, replication, and autoscaling controller contract.
11. Root/intermediate PKI, workload identity namespace, certificate TTL, revocation, and disconnected renewal.
12. Built-in vault backend and disaster recovery.
13. Native GitOps schema, fresh typed desired state, historical-behavior review, and complete Flux removal.
14. CI trust zones, release graph, bootstrap/recovery path, and artifact signing.
15. Service registry, DNS, ingress/LB, region headers, and routing ownership.
16. VPN implementation and scalable twenty-region connectivity.
17. Operator OIDC/RBAC/break-glass/API and Grafana threat model.
18. Project placement versus host scheduling boundary.
19. Three-region cost/SLO target and provider portability contract.
20. Provider-actuator crash-stop threat model, irreversible-operation fencing/resume, and OCI credential boundary.
21. Regional survival bundle, artifact/secret availability, disconnected node replacement, and maximum survival window.
22. Golden-image bootstrap, N/N-1 compatibility, and A/B orchestrator self-upgrade/rollback.
23. Requirement/error registry, pure decision dependency rules, test toolchain, evidence attestation, and deployment-credential gate.
24. Greenfield OCI inventory, stale-resource quarantine/approved cleanup, partial-create recovery, initial trust/NATS/TerraBase seeding, independent regional partial success, Pulumi handoff, cleanup-PR sequencing, ingress activation/withdrawal, and first-production rollback boundaries.

## Definition of complete

The orchestrator is ready for its first production deployment only when:

- GRU, SFO, and FRA run production workloads from the same signed single binary and native schema;
- the primary production artifact and every managed workload are qualified on real OCI A1 Ampere ARM64 hosts, with architecture-specific digests preserved through GitOps and promotion;
- GRU has no critical single-node dependency and passes failure of every node in turn while serving product and operator traffic; automatic replacement returns it to full redundancy;
- each cell is autonomous under the documented failure policy and has tested state backup/restore;
- compute and storage scale automatically within approved safety/cost limits;
- TerraBase runs safely as either native systemd or an OCI container, with the selected production default, stable storage, backups, upgrades, replication, and recovery;
- mTLS identities, NATS authorization, secret policy/delivery, rotation, revocation, and audit pass security review;
- GitOps and CI/CD preserve build-once, immutable promotion, staged regional verification, rollback, and interruption recovery;
- the operator API/CLI, Grafana, OTel, VPN, alerts, and runbooks support normal and emergency operation;
- two consecutive from-zero L3S deployments and the closed-ingress OCI assembly reproducibly converge from the same contracts/artifacts, recover every partial-bootstrap checkpoint, and depend on no historical OCID, identity root, Kubernetes secret, NATS ID/position, or hidden manual state;
- public DNS/ingress remains closed until a signed post-soak owner action, and emergency traffic withdrawal is proven before enablement;
- all production gates pass on real Linux and OCI, not only mocks;
- the measured three-region cost meets the approved target while database performance meets the approved SLO;
- provider inventory proves OKE remains absent, no Flux/Kubernetes runtime credential or compatibility path exists, and no stale infrastructure resource is silently owned by the orchestrator;
- every `WRK-*` cleanup item is either closed by its separately reviewed repository/provider cleanup evidence or has an explicit owner-approved risk acceptance and expiry.

## Primary source anchors

These files are the starting executable specifications. Paths are relative to this repository in the current workspace.

- Regional topology and ownership: `../TerraScale.Infrastructure/infra/regions/regions.yaml`, `../TerraScale.Infrastructure/docs/cluster-map.md`, `../TerraScale.Infrastructure/AGENTS.md`.
- Historical checked-in NATS/storage/observability behavior: `../TerraScale.Infrastructure/gitops/platform/nats/base/nats.yaml`, `../TerraScale.Infrastructure/gitops/platform/storage/oci/`, `../TerraScale.Infrastructure/gitops/observability/` and regional cluster overlays.
- Historical OCI node-generation/autoscaling/IAM behavior and workaround evidence: `../TerraScale.Infrastructure/src/TerraScale.Infrastructure/OkeResources.cs`, `InfrastructureSettings.cs`, and CLI/verifier projects.
- Historical checked-in mTLS ingest behavior: `../TerraScale.Infrastructure/src/TerraScale.Infrastructure/ObservabilityIngestTls.cs` and GRU regional ingest manifests.
- Release semantics: `../TerraScale.Deploy/src/TerraScale.Deploy.Cli/Services/ServiceReleasePipeline.cs`, `../TerraScale.Deploy/src/TerraScale.Deploy.Cli/Services/FluxNotificationBarrier.cs`, tests, and every `.terrascale/deploy.json`.
- Local runtime graph: `../TerraScale.DevHost/src/TerraScale.DevHost/DevStack.cs`, `../TerraScale.DevHost/src/TerraScale.DevHost/DevStackEnvironment.cs`, and `../TerraScale.Internals/docs/DevHost.md`.
- Product regions/replication: `../TerraScale.Internals/docs/databases/regions-and-replication.md` and the project placement implementation.
- Queue contract: `../TerraScale.Internals/docs/queue/architecture.md` and `src/Core/TerraScale.Queue/`.
- Health/OTel/runtime contracts: Internals ServiceDefaults, API/Auth programs, Dashboard health/OTel files, and deploy Dockerfiles.
- TerraBase operator behavior: `../Terrabase.Operator/api/v1/`, `pkg/upgrade/`, `pkg/autoscaling/`, `pkg/replication/`, and `docs/autoscaling.md`.
- Native TerraBase unit: `../TerraBase/scripts/linux/pkg/deb/assets/terrabase/debian/terrabase.service` and `../TerraBase/docs/linux.md`.
- Public compatibility: `../TerraScale.DotNet/src/`, `../TerraScale.TypeScript/src/`, their E2E tests, and `../Terrascale.Documentation/src/content/docs/`.

External implementation references must use primary documentation, including NATS TLS/JWT/JetStream behavior, systemd D-Bus/credentials/cgroup semantics, containerd APIs, OCI Compute/Block Volume/KMS/Vault APIs, OpenTelemetry protocol/security, and the selected VPN implementation.

Initial primary external anchors:

- NATS [JWT/operator security](https://docs.nats.io/running-a-nats-service/nats_admin/security/jwt), [gateway topology](https://docs.nats.io/running-a-nats-service/configuration/gateways), [JetStream administration](https://docs.nats.io/running-a-nats-service/configuration/clustering/jetstream_clustering/administration), and [monitoring security warning](https://docs.nats.io/running-a-nats-service/configuration/monitoring).
- Pulumi [`retainOnDelete`](https://www.pulumi.com/docs/iac/concepts/resources/options/retainondelete/) as one primitive when transferring freshly bootstrapped resources from Pulumi to the regional controller—not as sufficient handoff correctness by itself and never as a path to adopt an old resource.
- Grafana [high-availability setup](https://grafana.com/docs/grafana/latest/setup-grafana/set-up-for-high-availability/) and [provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/); TerraScale deliberately uses multiple immutable/read-only provisioned replicas to avoid a new mutable metadata database while keeping dashboards reachable after one node loss.
- OCI [Ampere A1 Compute](https://docs.oracle.com/en-us/iaas/Content/Compute/References/arm.htm) and [dynamic-group propagation behavior](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingdynamicgroups.htm); IAM propagation is never used as a leader fence.
- [Podman](https://docs.podman.io/) provides the rootless local container runtime. TerraScale pins every workload image by manifest digest, permits only a closed catalog, records runtime/network/storage-driver identity in evidence, and never grants privileged mode, host networking, or arbitrary host mounts.
