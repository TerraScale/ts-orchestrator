# Architecture decision boundaries

> Living summary of proposed ADRs and non-negotiable boundaries. Full ADR text remains under [`docs/adr/`](../adr/).

Specification authority: [`docs/architecture/orchestrator.md`](../../docs/architecture/orchestrator.md). Owner decisions: [`docs/decisions/`](../decisions/).

## Executive boundary

TerraScale builds a **product-specific orchestrator**, not a general cluster platform. It schedules an allowlist of TerraScale services, understands TerraBase safety, manages elastic compute/storage, provides native GitOps/CI/CD, issues workload identity, and projects state to Grafana. It does **not** implement Kubernetes compatibility, Helm, CRDs, arbitrary workloads, or a second customer dashboard.

## Three-level control plane

1. **GRU global coordinator** — signed desired state, releases, policy, operator actions.
2. **Regional cell controllers** — autonomous R3 control-NATS / JetStream state per region.
3. **Host agents** — fenced operations via containerd or systemd.

SFO/FRA continue serving during GRU/WAN loss; global releases freeze (decision 2A). Any one GRU node may fail without sustained service outage or accepted-state loss.

## Contract invariants (condensed)

1. Active cells GRU/SFO/FRA; GRU is global + product cell.
2. Region serves last accepted `CellSpec` when GRU/WAN/Git/central observability is down.
3. No WAN-spanning control Raft quorum.
4. Exactly one fenced writer per desired-state/release/deployment/node/volume/TerraBase operation stream.
5. Commands are idempotent, generation-bound, deadline-bound, replay-safe.
6. Stale leaders/agents cannot attach, format, grow, delete, start, stop, publish, or complete.
7. TerraBase: ≥3 permanent members/cell, one per host, one single-writer volume/member, stable identity, consistent backups.
8. Never remove permanent members a/b/c; elastic scale-in disabled until destructive suite passes.
9. Storage expand-only; replicas ≠ capacity.
10. No secrets/keys in ordinary NATS subjects, desired state, logs, traces, CI, metrics, Grafana.
11. Build once; deploy exact tested digests.
12. Observability failure never blocks product traffic.
13. Product placement (`Project.Regions`) is not host scheduling.
14. Pulumi owns durable foundation; after signed handoff, regional orchestrator owns concrete nodes/volumes/attachments.
15. Docs/schemas/dashboards/fixtures derive from versioned C# contracts.
16. GRU single-node-failure tolerant for every critical path.
17. Closed admitted-role catalog only.
18. Dual dedicated NATS planes per region (decision 8A host co-location allowed).

## ADR 0004 — Pulumi vs regional provider ownership (proposed)

- Pulumi: durable networking, IAM, KMS/Vault roots, object storage, DNS/LB foundation, images/launch templates, caps, bootstrap generations, seeds, initial dual-NATS stores, signed bootstrap bundle.
- Handoff: journaled signed `HandoffReceipt` + explicit retain/unmanage; only then regional self-management.
- Regional actuator: replacement/elastic compute, post-handoff volumes, attachments, LB membership, drain/scale/terminate, expansion, orphan reconciliation.
- Tags are inventory evidence, never mutation authority.
- Historical OCI estate is not adopted (`REQ-O023`).

## ADR 0013 — Native GitOps / Flux removal (proposed)

- Fresh TerraScale schema only; no Kubernetes/Helm/Kustomize/Flux readers or dual-run period.
- Git owns parent intent (roles, releases, policies, bounds); journals own accepted revisions and concrete regional state.
- Controller-created children are not Git prune targets.
- Sequence: observe revision → verify signature/schema → resolve dependencies → plan → journal → apply with durable ack at configured checkpoint → health gates.
- Preserves WRK-002..005 behaviors (ordered deps, fenced reconcile, build-once promotion, resumable multi-region progress) without Flux/kubectl.

## ADR 0018 — Placement vs scheduling (proposed)

- **Product placement** owns `Project.Regions`, `PlacementGeneration`, drain/replication/routing/storage-epoch semantics.
- **Host scheduling** owns machine allocation inside an already-selected cell (resources, topology, stateful vetoes).
- Orchestrator may consume a typed placement projection; missing/stale/filtered observation is hold, never region removal.
- No second source of truth for residency from load, tags, or host inventory.

## ADR 0020 — Provider actuator fencing (proposed)

Crash-stop model for trusted code + ordinary provider faults (not Byzantine hosts):

1. Persist `Prepared` intent (not yet authorized).
2. Evaluate fresh observation, ownership, generations, approvals, budget, deadline → `Held` or proceed.
3. Atomic `AuthorizedForProviderCall` is the irreversible commit of exact action/payload/target/idempotency key.
4. Adapter dispatches only from that record; timeout = outcome unknown, not failure.
5. Recovery resumes the **same** authorized operation; leadership change changes executor, not terminal intent.
6. Late completions that do not match the authorized operation are quarantined.

## Selective mTLS

Required at controller/agent, NATS client/route/gateway, secret retrieval, CI enrollment, admin APIs, cross-region telemetry. Not required on permissioned same-host Unix sockets. Public customer HTTP remains server TLS + product auth. NATS mTLS is transport identity; NKeys/JWTs/subject permissions are authorization — neither replaces the other.

## What is built vs reused

| Build in Orchestrator | Reuse |
|---|---|
| Desired/observed-state engine | NATS/JetStream |
| Scheduler + placement policy | systemd, cgroups v2 |
| Node autoscaler + provider controllers | containerd/runc |
| Volume/TerraBase lifecycle | OCI APIs, TerraBase admin |
| Native GitOps + release machines | Forgejo, BuildKit, OCIR |
| Identity/PKI automation | X.509, cloud KMS |
| Operator API/CLI + Grafana projection | Grafana/OTel stack |
