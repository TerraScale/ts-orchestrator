# ADR 0013: Native GitOps schema and complete Flux removal

- Status: Proposed
- Date: 2026-07-13
- Owner lane: Delivery
- Readiness entry: `docs/adr/readiness-index.yaml` entry for native-gitops, ADR 13 (`native-gitops`)
- Depends on: ADR 1, ADR 6, ADR 14, ADR 18, ADR 24
- Traces: `REQ-O014`, `REQ-O017`, `REQ-O023`, `INV-002`, `INV-004`, `INV-005`, `INV-011`, `INV-013`, `INV-015`, `INV-017`, `WRK-002`, `WRK-003`, `WRK-004`, `WRK-005`

## Context

The owner decision is a clean break: GitOps is native to the orchestrator and Flux is removed rather than embedded, emulated, or retained as a runtime dependency (`ORCHESTRATOR.md:52-61`). The greenfield deployment adopts no Kubernetes or Flux resource, state, identity, secret, or API (`ORCHESTRATOR.md:54-60`, `ORCHESTRATOR.md:162-180`). Historical repositories remain read-only evidence of behavior and workarounds, not an input contract (`ORCHESTRATOR.md:182-220`).

ADR readiness classifies this record as draft-ready but identifies three missing bodies of proof: the fresh schema and compatibility fixtures, complete historical behavior reconciliation, and cleanup-PR sequencing tied to native replacement gates (`docs/adr/readiness-index.yaml` entry for native-gitops). This proposal states the boundary and the evidence required to accept it; it does not claim those proofs exist.

The retirement ledger records the behavior that must survive without preserving its implementation:

| Ledger item | Historical constraint | Behavior to preserve | Native replacement evidence |
|---|---|---|---|
| `WRK-002` | Flux reconciliation could acknowledge before dependencies were healthy because readiness waiting was disabled. | Ordered dependencies, asynchronous progress, health gates, restart-safe acknowledgement. | Typed dependency and health state machines; a journaled receipt acknowledged only at the configured durable checkpoint; dependency failure and restart at every checkpoint in L0/L3S (`historical WRK-002 in archive `docs/retirement/workaround-ledger.yaml``). |
| `WRK-003` | A webhook was followed by forced `kubectl` reconciliation and polling. | Prompt triggering, durable acceptance, safe replay, and a visible rejection/failure. | One signed, generation/deadline/idempotency/fence-bound reconcile command journaled before acknowledgement; webhook, NATS, controller, duplicate, and stale-writer failures in L0/L3S (`historical WRK-003 in archive `docs/retirement/workaround-ledger.yaml``). |
| `WRK-004` | Suspended regional image writers and rollout-guard coordination approximated exclusive publication. | Build once, exact-digest promotion, one release writer, and safe rollback. | A fenced writer, promotion lease, and compare-and-swap generation over the immutable digest; concurrent-writer, lease-expiry, partial-promotion, and adversarial rollback proof (`historical WRK-004 in archive `docs/retirement/workaround-ledger.yaml``). |
| `WRK-005` | Deployment progress was assembled through `kubectl`, context fan-out, polling, and shell recovery. | Cross-region progress, explicit failure, exact-digest convergence, timeout, and resumability. | Typed regional operations with durable checkpoints, idempotent resume, and a global same-digest barrier; crash, timeout, WAN-loss, partial-convergence, and retry proof (`historical WRK-005 in archive `docs/retirement/workaround-ledger.yaml``). |

The audited release contract independently requires immutable candidates, a fenced promotion lease, resumable external-operation boundaries, and promotion without rebuilding. Existing `flux-*` strategy strings are rollout evidence only and are not compatibility contracts (``docs/guides/phase0-evidence.md` and historical audit in `docs/archive/docs-historical-full.tar.xz``).

## Proposed decision

### Fresh native contract only

Define a versioned TerraScale desired-state schema directly from the closed C# admitted-role catalog and reviewed product/runtime contracts. Publish JSON Schema, semantic validation, visible defaults, plans, fixtures, and generated documentation from that same versioned contract (`INV-015`).

The source adapter accepts only:

- Git revisions and OCI artifacts identified by immutable revision/digest after signature verification;
- fresh native manifests conforming to a supported TerraScale schema version; and
- credential references, never credential values.

It does not parse, import, translate, emulate, or silently ignore Kubernetes objects, Helm values/templates, Kustomizations, Flux resources, or historical `flux-*` strategy names. No compatibility reader, converter, dual-read period, shadow Flux controller, or fallback to `kubectl` is introduced. Unsupported formats fail with a typed, non-mutating validation error before a plan can be accepted (`ORCHESTRATOR.md:924-959`).

Historical sources are reviewed into a behavior matrix. Each behavior is either represented by a native typed contract plus tests, explicitly rejected as obsolete with rationale, or held as an open gap. Copying a historical resource shape or field name is not proof that its behavior was preserved.

### One owner for each state class

Git is authoritative only for declared parent intent: allowlisted roles, releases, policies, templates, bounds, budgets, retention classes, and desired minimum/maximum capacity.

The accepted global journal is authoritative for signed accepted revisions, global plans, releases, policy generations, signatures, and rollout result. Each regional journal is authoritative for its accepted `CellSpec`, operations, concrete instances, host allocations, attachments, replacement peers, generated/expanded volumes, and deployment progress (`ORCHESTRATOR.md:538-549`).

Ordinary controller-created children are linked to their parent policy/template generation but are not written back into Git, Git drift, or Git prune targets. This prevents Git and a regional controller from becoming concurrent owners of the same concrete resource. Removing a Git parent records a guarded regional retirement intent; the appropriate domain controller then proves ownership, safety, retention, dependency, and fencing preconditions before any child cleanup (`ORCHESTRATOR.md:941-959`).

ADR 18 supplies the separate customer project-placement boundary. A GitOps plan may carry deployment and capacity policy but cannot author or infer `Project.Regions` from workload or host state.

### Durable reconciliation and rollback

Use this mandatory sequence:

```text
source revision observed
-> signature and schema verified
-> dependency graph resolved and cycles rejected
-> immutable artifacts resolved exactly once
-> policy and budget evaluated
-> global plan durably recorded
-> signed per-cell CellSpecs compiled
-> each cell durably accepts its generation
-> regional deployment operations execute with typed health gates
-> global same-digest live verification completes
-> success or an explicit rollback generation is durably recorded
```

Webhook HTTP success means the signed command is durably queued, not that reconciliation or deployment succeeded. Commands and operations are generation-, deadline-, idempotency-, and fencing-bound (`INV-004`, `INV-005`). Exactly one fenced writer advances each source revision, release, deployment, and rollback (`INV-004`). A replacement leader resumes from the durable journal rather than reconstructing progress from Git, process state, or telemetry.

Rollback is a new explicit desired generation pointing to a previously qualified immutable digest. It follows the same acceptance and health gates. It never rebuilds or mutates an artifact (`INV-011`). When Git or GRU is unavailable, a region serves and repairs from its last accepted `CellSpec`; it does not accept an unseen global generation (`INV-002`).

### Drift, prune, and deletion

Drift comparison is scoped by the resource's authoritative owner and generation. A plan may repair a declared parent or a declarative, orchestrator-owned leaf. It may not classify journal-owned autoscaled children, generated volumes, product placement records, or foreign/unproven resources as Git drift.

Prune produces a typed retirement operation rather than a direct delete. The operation must prove exact ownership, generation/fence, retention policy, absence of protected data/quorum/placement dependencies, and domain-controller authorization. Unknown, ambiguous, stale, or filtered observations hold safely. Tags are evidence, never deletion authority.

## Cleanup sequencing

Cleanup is not part of this ADR branch and is never bundled ahead of replacement proof. The sequence is:

1. Inventory every historical behavior and artifact against `WRK-002` through `WRK-005`, with immutable source citations.
2. Implement the fresh native contracts and pure reconciliation decisions. Pass L0 schema, dependency, signature/digest, plan/diff, drift/prune, health, rollback, and one-writer tests, including adversarial ownership and crash cases.
3. Pass L3S from the exact integration tree: restart at every acknowledgement/deployment checkpoint, source/webhook/NATS/controller/WAN loss, duplicate and stale writers, partial regional convergence, same-digest verification, rollback, and proof that Git prune cannot delete journal/data children.
4. Record one reviewed replacement-evidence packet per `WRK-*`, mapping preserved behavior to native implementation, test IDs, exact source/binary digests, and captured results.
5. Open a first owning-repository PR that stops and removes the historical runtime writer or trigger path while leaving its authority unrevoked solely for a bounded, declared rollback window. During that window the old credential is sealed from ordinary runtime use, activation requires explicit operator approval plus the recorded fence/generation transition, and monitoring must detect any attempted use. The native replacement remains the primary writer throughout. This PR must state its rollback preconditions, expiry, fence transition, and proof that a restored historical writer cannot overlap the native writer. Before authority revocation, rollback may restore that writer only through this explicit fenced procedure; merely reverting or redeploying its artifact is forbidden.
6. After the native replacement passes its declared soak and the runtime-writer rollback window closes, record a reviewed cutoff stating that historical-writer restoration is retired. Then use separate repository and, where applicable, explicitly authorized provider cleanup changes to revoke the old credentials, RBAC/IAM/Vault authority, webhook tokens, endpoints, and DNS. Each change must prove the native identity remains valid and define rollback as a forward fix or issuance of new, narrowly scoped, fenced authority. After revocation, rollback must never blindly restore an old artifact, credential, secret version, permission, endpoint, or writer authority.
7. Only after runtime removal and authority revocation evidence is accepted may a separate owning-repository PR delete passive Flux/Kubernetes manifests, bootstrap resources, rollout glue, and documentation. Its rollback can restore passive review/history material only; it cannot recreate runtime authority or make the historical controller executable. Each PR targets that repository's `develop`, cross-links the replacement packet and preceding cleanup evidence, and records the exact cutoff reached.
8. After every cleanup stage, run read-only repository/provider inventories and native deployment regression. Close an item only when its ledger `cleanup_proof` is satisfied and the evidence distinguishes runtime writer absence, authority/credential revocation, and passive-manifest absence. Any positively identified cloud cleanup requires its own explicitly authorized provider operation; absence from Git is not proof of cloud deletion.
9. Finally enforce negative CI scans for Flux API resources, Flux controllers/receivers, Kubernetes/Helm/Kustomize readers, `kubectl` rollout/reconcile code, legacy webhook secrets/endpoints, packaged Kubernetes credentials, and attempts to restore authority after its recorded cutoff.

For `WRK-002`, stop its active reconciliation path only after native dependency/health acknowledgement passes; revoke its controller authority after the bounded rollback window; then delete passive Kustomizations/bootstrap sync. For `WRK-003`, remove the receiver/forced-reconcile runtime path only after durable signed command acceptance passes; then revoke webhook credentials and endpoints; then delete passive configuration. For `WRK-004`, stop image automation/rollout-guard writers only after fenced single-writer promotion passes; then revoke their publication authority; then remove suspend toggles and passive resources. For `WRK-005`, stop rollout/context/polling/shell execution only after typed resumable regional deployment and same-digest proof passes; then remove Kubernetes credentials; then delete passive recovery/configuration artifacts. Every arrow is a separate evidence boundary, and stages may be separate PRs or provider changes even when they concern the same ledger item. Failure at any gate leaves that item open; it does not authorize a temporary compatibility reader or an unfenced historical writer.

## Alternatives considered

### Embed or retain Flux

Rejected. It contradicts `REQ-O014`, retains the runtime and acknowledgement problems being retired, and creates two reconciliation authorities.

### Import or convert historical Kubernetes, Helm, Kustomize, or Flux inputs

Rejected. A converter would turn implementation residue into a permanent public schema, mask missing behavioral analysis, and create a second contract surface. The platform is greenfield and does not need an in-place migration reader.

### Dual-read or shadow reconciliation during transition

Rejected. Two readers can disagree on defaults, ownership, prune, and generation, while shadow controllers can still observe or mutate inconsistently. Replacement correctness is established in L0/L3S before separately reviewed cleanup.

### Put every concrete child in Git

Rejected. Autoscaled instances, allocations, attachments, peers, and volumes are regional recovery state. Writing them into Git creates control-loop latency and competing ownership, and makes ordinary controller activity appear as drift.

### Let CI/CD mutate deployments directly

Rejected. CD supplies exact artifacts and release intent to the native reconciler. Bypassing it would evade durable acceptance, regional gates, fencing, resumption, and audit.

## Consequences

Positive consequences:

- one typed desired-state contract and no Kubernetes/Flux compatibility burden;
- direct durable acknowledgement and deterministic restart instead of webhook/poll inference;
- explicit parent/child ownership prevents unsafe drift and prune;
- exact-digest promotion, fenced writers, and rollback preserve the valuable historical release semantics; and
- retirement is reviewable per repository and per workaround rather than inferred from a bulk deletion.

Costs and risks:

- Phase 6 must implement source, schema, planning, journaling, health, drift, pruning, promotion, and recovery behavior that Flux previously supplied;
- historical behavior review and replacement evidence must be complete before cleanup, so repository retirement is intentionally later than schema drafting; and
- ADR dependencies remain proposed, so acceptance waits for their compatible authority, workload, CI, placement, and greenfield-cleanup contracts.

## Acceptance evidence required

This ADR may become Accepted only when all of the following are reviewed against one exact integration tree:

- fresh C# resource contracts, generated JSON Schema/docs, unknown-field/version/default behavior, and golden native fixtures; no compatibility reader exists;
- a complete historical-behavior disposition for every Flux/Kubernetes delivery finding, including `AUD-SRC-006` and `WRK-002` through `WRK-005`;
- L0 positive and adversarial tests for dependency/cycle planning, signatures, immutable digest resolution, ownership-aware diff/drift/prune, durable acknowledgement, fencing, idempotency, staged promotion, rollback, and restart at every state-machine checkpoint (`ORCHESTRATOR.md:1114-1163`);
- L3S Git/OCI/webhook/NATS/controller/WAN failure and recovery at every reconciliation checkpoint, exact-digest SFO/FRA/GRU convergence, stale-writer rejection, and safe rollback (`ORCHESTRATOR.md:1561-1571`);
- evidence that a Git parent removal cannot directly delete a journal-owned child, data resource, project placement, or unproven cloud resource;
- per-item replacement packets and separately reviewed cleanup PRs satisfying each ledger cleanup proof; and
- repository/provider scans proving no Flux runtime/API/credential/endpoint, Kubernetes credential, or compatibility path remains in the new platform (`ORCHESTRATOR.md:1734-1755`).

Until then, status remains Proposed and no sibling cleanup is authorized.
