# ADR 0018: Project placement versus host scheduling boundary

- Status: Proposed
- Date: 2026-07-13
- Owner lane: Integration/contract steward
- Readiness entry: `docs/adr/readiness-index.yaml` entry for placement-boundary, ADR 18 (`placement-boundary`)
- Depends on: ADR 10, ADR 13, ADR 15
- Traces: `INV-005`, `INV-007`, `INV-008`, `INV-009`, `INV-013`, `INV-017`, `WRK-022`

## Context

TerraScale has two distinct kinds of placement:

1. **Product placement** decides the customer data-residency and service geography of a project: which regional cells belong to `Project.Regions`, at which `PlacementGeneration`, with which drain, replication, routing, storage-epoch, and filtered-absence semantics.
2. **Host scheduling** decides which eligible machine in one already-selected regional cell runs a concrete allowlisted workload/member/allocation, subject to resources, topology, stateful vetoes, safety reserves, and health.

Conflating these decisions would let infrastructure load move customer data, or make the product reconciler compete with the host scheduler. Contract invariant `INV-013` therefore states that product project/database placement remains in the product placement domain and the host scheduler does not create a second source of truth for `Project.Regions` (`ORCHESTRATOR.md:139-160`).

The audited product snapshot at TerraScale.Internals commit `3643df207f9f1129c9f677148e6890d436339141` is concrete evidence of the existing product contract:

- `docs/databases/regions-and-replication.md:3-6`: a project selects regions and its databases, queues, and project-scoped authentication inherit them; child resources cannot widen or narrow residency;
- `docs/databases/regions-and-replication.md:54-83`: `Project.Regions` is desired state, `PlacementGeneration` is monotonic, transition/final generations are CAS-bound, selected cells create/update, removed cells drain before deletion, and filtered/untagged uncertainty fails closed;
- `docs/databases/regions-and-replication.md:87-114`: selected cells replicate bidirectionally and all directed paths are independently qualified;
- `docs/databases/regions-and-replication.md:125-159`: catalog changes cannot implicitly move stored placement, and routing remains within healthy selected origins; and
- `docs/databases/regions-and-replication.md:195-233`: removal drains accepted queue work before project data deletion, re-selection cancels drain, and project-auth storage epochs/region sets fence writers.

The target specification preserves this explicitly: the orchestrator provides regional TerraBase capacity and typed fenced machine operations but does not infer customer region selection from host load; monotonic generations, filtered-absence non-deletion, storage epochs, six directed replication paths, conflicts, and restore remain acceptance gates (`ORCHESTRATOR.md:1012-1039`, `ORCHESTRATOR.md:1659-1666`).

ADR readiness identifies the still-missing evidence: golden placement compatibility fixtures, an explicit storage-epoch/filtered-absence ownership map, and cross-repository approval before any source-of-truth move (`docs/adr/readiness-index.yaml` entry for placement-boundary). This record preserves the current owner; it does not move that authority.

## Proposed decision

### Product placement has one authoritative owner

The TerraScale product placement domain remains the sole authority for:

- canonical project region membership in `Project.Regions`;
- monotonic logical `PlacementGeneration` and its transition/final CAS phases;
- selected, draining, blocked, removed, and re-selected regional placement state;
- customer data-residency validation, plan entitlement, catalog availability, and placement errors;
- creation/catch-up/drain/deletion eligibility for each regional project database;
- all directed external-replication intent, conflict policy, and filtered-absence handling;
- queue-region drain completion and project-auth authority/storage epoch tied to the placement generation; and
- routing eligibility among healthy selected cells.

The current product reconciler continues to advance that state. Neither GitOps, the global coordinator, a cell controller, the provider controller, the TerraBase machine controller, nor the generic scheduler may independently write, derive, repair, normalize, default, or prune project placement.

The orchestrator may consume a versioned, typed projection of product placement solely to enforce downstream constraints and report status. It must preserve the project generation and observation completeness in that projection. Missing, stale, filtered, conflicting, or future-version observations cause a hold; they never mean region removal. There is no dual write and no reconstructed fallback from tags, host inventory, Git manifests, registry endpoints, traffic, telemetry, or current database copies.

### Host scheduling has one authoritative owner

Within a cell that product placement has already selected, the regional scheduler is the sole authority for concrete host allocations. It consumes the locally accepted `CellSpec`, node observations, declared reservations, health, security zones, and domain-controller constraints. It chooses an eligible host using deterministic constrained least-waste scoring with explicit tie-breakers and a reason trace (`ORCHESTRATOR.md:591-619`).

The scheduler owns:

- admission and concrete allocation identity/generation;
- CPU, memory, IO, disk, PID, port, file-descriptor, bandwidth, and huge-page constraints;
- architecture, node class, failure domain, affinity/anti-affinity, topology spread, priority, disruption budgets, and GRU N+1 reserve;
- volume locality and already-proven single-writer attachment constraints;
- workload trust/network/secret-zone eligibility; and
- host cordon/drain/replacement placement of an otherwise-authorized workload.

Scheduler output is a persisted, fenced machine intent. It cannot change `Project.Regions`, `PlacementGeneration`, project replication topology, project storage epoch, or customer routing eligibility. Host pressure may produce `CapacityUnavailable`, a reason trace, and a capacity request. It cannot solve capacity pressure by adding/removing a project region or treating an unselected region as spillover.

### Domain controllers own their safety decisions

The generic scheduler does not decide whether a TerraBase or NATS member is safe to create, move, replace, attach, drain, or remove. The relevant domain controller owns stable member/volume identity, quorum/topology, leader handoff, replication/catch-up, backup, and decommission authorization. It may reserve or veto a host placement; the scheduler selects only among allowed candidates (`ORCHESTRATOR.md:593-605`).

For TerraBase specifically:

- the **product placement domain** owns which project databases/replication relationships should exist in the cell;
- the **TerraBase domain controller** owns machine-level member, shard-capacity, volume, topology, upgrade, backup, and repair operations; and
- the **regional scheduler** owns the concrete eligible host allocation after those constraints are supplied.

Adding a machine/member does not increase logical database capacity by assumption and never changes project geography (`INV-009`; `ORCHESTRATOR.md:1026-1037`).

### GitOps and catalogs carry policy, not a second placement truth

Native GitOps may declare regional service roles, capacity bounds, routing/catalog policy, and templates. It may distribute a product-placement schema or a reference to the product authority, but no Git manifest enumerates customer `Project.Regions` as authoritative desired state. Git prune cannot remove a project copy.

The dynamic region catalog defines which cells are available for new selection and supplies canonical metadata. It does not retroactively edit stored project placement. An unavailable or temporarily unknown stored region remains part of the existing placement until the product placement domain advances its generation.

`WRK-022` requires catalog-aware selection to distinguish absent preference from invalid/unavailable input while preserving only an explicitly approved default. The orchestrator must not reproduce the historical behavior that silently maps invalid regions to GRU (`historical workaround ledger WRK-022 in `docs/archive/docs-historical-full.tar.xz` (path `docs/retirement/workaround-ledger.yaml`); see also `docs/guides/architecture-boundaries.md``). Catalog/default cleanup belongs to separate owning-repository work after golden compatibility fixtures and approval; no SDK or documentation file is changed by this ADR.

## Boundary protocol

The integration contract must distinguish these immutable records:

| Record | Authoritative writer | Required identity/version | Permitted consumers |
|---|---|---|---|
| `ProjectPlacementIntent` | Product placement domain | project ID, exact `Project.Regions`, logical `PlacementGeneration`, document/CAS version, catalog/policy version | product reconciler, routing, compatibility projection |
| `ProjectRegionPlacementObservation` | Product placement reconciler for that project/cell generation | project, cell, placement generation, phase, observation completeness/freshness, replication/drain/storage epoch | operator projection, capacity/domain controllers; never a replacement desired-state writer |
| `CellSpec` workload/capacity policy | Native GitOps global authority | cell, desired generation, source revision/signature, immutable artifact/template/policy generations | regional controller/scheduler/domain controllers |
| `DomainPlacementConstraint` | TerraBase/NATS/workload domain controller | stable member/workload/volume identity, operation generation/fence, required/vetoed domains and safety reason | regional scheduler |
| `HostAllocation` | Regional scheduler under the current regional fence | cell, allocation and desired generations, node, resources, domain-controller constraint generation, reason trace | host agent and relevant domain controller |

No record is accepted as a lossy substitute for another. In particular, a `HostAllocation` cannot update `ProjectPlacementIntent`; a `ProjectRegionPlacementObservation` cannot create a host allocation; a `CellSpec` cannot default customer regions; and resource tags cannot authorize any of these mutations.

Normal sequencing is:

```text
product placement CAS accepts Project.Regions generation
-> selected cell product reconciler establishes/catches up product data and emits exact-generation state
-> GitOps/cell policy authorizes the required allowlisted regional role and capacity bounds
-> TerraBase/workload domain controller emits safety constraints or a hold
-> regional scheduler selects an eligible host and persists a fenced HostAllocation
-> host agent executes the allocation
-> domain and product reconcilers verify readiness before routing/placement advances
```

Region removal reverses product readiness first: the product placement domain advances the generation, stops new origin work as specified, completes exact-generation queue/replication/data drain, and authorizes project-copy deletion. Host drain or low load cannot initiate this sequence. Host allocation cleanup occurs only after the product/domain authority says the workload or member is no longer required and all normal ownership/retention/fencing gates pass.

## Failure behavior

- **Host exhaustion:** hold or request orchestrator-owned capacity in the same selected cell. Never spill the project into another region.
- **Host/node loss:** the domain controller and scheduler repair machine placement within the cell. `Project.Regions` is unchanged.
- **Missing/stale/filtered product observation:** hold destructive placement/data actions. Absence is not deletion authorization.
- **Catalog authority unavailable:** use the last accepted catalog for validation policy while preserving stored project regions; do not normalize to GRU.
- **GRU/Git/WAN unavailable:** each cell serves from its accepted `CellSpec` and accepted product placement state. No cell invents a new global/project placement generation.
- **Conflicting generation or storage epoch:** reject/hold the stale writer and surface a typed reason. Host success cannot override the product fence.
- **Insufficient TerraBase capacity:** report the explicit product-capacity signal and create safe same-cell machine capacity if authorized. Do not interpret member count as logical shard capacity or change customer geography.

## Alternatives considered

### Let the scheduler optimize customer region placement

Rejected. Resource/cost pressure is not customer residency intent. This would violate `INV-013`, make placement nondeterministic under load, and risk silent data movement.

### Copy `Project.Regions` into Git and reconcile from both systems

Rejected. It introduces two desired-state writers, incompatible generation/CAS semantics, disclosure and scale concerns, and unsafe Git prune behavior.

### Infer project placement from databases, replication tags, hosts, routing, or telemetry

Rejected. Those are incomplete observations. Filtered absence, outages, and draining states make inference unsafe; observation cannot replace the product intent and generation.

### Let the product reconciler choose machines directly

Rejected. It would duplicate scheduler resource, topology, reserve, security-zone, and host-health logic. The product domain supplies required regional capacity and safety constraints; the scheduler owns concrete host selection.

### Move product placement into the orchestrator now

Rejected for this proposal. There is no approved cross-repository contract, golden compatibility proof, or migration/authority transfer plan. Any future move requires a new deliberate ADR, owner approval, an explicit single-writer cutover, storage-epoch and filtered-absence proof, and independently reviewed owning-repository changes. This ADR provides no dual-read bridge.

## Consequences

Positive consequences:

- customer residency and replication remain stable under infrastructure load and failures;
- the scheduler stays explainable and regional without becoming a product database authority;
- TerraBase/NATS safety remains with controllers that understand topology and storage identity;
- every mutation has one authoritative writer and one generation/fence domain; and
- GitOps, host repair, and autoscaling cannot accidentally prune or widen customer placement.

Costs and risks:

- the product-to-orchestrator projection and capacity signal must be explicitly versioned and tested rather than inferred;
- operator views must correlate multiple authority records without presenting a projection as writable truth; and
- cross-domain workflows require durable correlation and typed holds when either authority is stale, which is more explicit work than sharing a mutable record.

## Acceptance evidence required

This ADR may become Accepted only after all of the following are reviewed against one exact integration tree and the pinned product snapshot or an explicitly approved successor:

- a reviewed ownership map for project intent, placement generation/phases, replication/drain, storage epoch, routing eligibility, domain constraints, cell policy, and host allocation, naming exactly one writer for every field and transition;
- golden compatibility fixtures for `Project.Regions`, monotonic `PlacementGeneration`, transition/final CAS, disabled/unknown stored regions, empty positive-generation drain, filtered absence, re-selection, queue drain, project-auth storage epoch, and routing within selected cells;
- L0 positive/adversarial proof that host load, cost, host loss, drain, Git change/prune, catalog fallback, telemetry, tags, stale observations, or a forged allocation cannot mutate or infer customer placement;
- L0 proof that a product region change cannot bypass generation/storage-epoch fences or directly choose a host, and that a scheduler cannot bypass domain-controller veto/quorum/volume constraints;
- L3S all six directed GRU/SFO/FRA replication paths, WAN loss/reorder/duplication, conflict convergence, empty-cell recovery, region addition/removal/re-selection, filtered-absence non-deletion, same-cell host loss/reallocation, and unchanged project placement under host pressure (`ORCHESTRATOR.md:1655-1666`);
- a typed, versioned product capacity signal proving that the host autoscaler never treats raw member count as logical project/database capacity;
- `WRK-022` compatibility and cleanup evidence showing absent preference, invalid alias, unavailable region, stale catalog, explicit GRU choice, and approved default are distinct and no invalid input silently becomes GRU; and
- explicit cross-repository owner approval and a separate ADR/PR sequence before any future movement of the product source of truth. There is no compatibility reader or dual-writer transition in this proposal.

Until that evidence exists, status remains Proposed and the current product placement owner remains unchanged.
