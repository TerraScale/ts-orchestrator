# ADR 0004: Pulumi and regional provider ownership

- Status: Proposed
- Date: 2026-07-13
- Decision owner: Cloud
- Readiness entry: `4 / pulumi-provider-ownership`

## Context

TerraScale needs Pulumi to establish durable cloud foundation without leaving Pulumi and the regional orchestrator as competing reconcilers. The platform is greenfield: the new ownership graph may not adopt an OCID, identity root, data resource, or control resource from the deleted OKE estate (`REQ-O023`). The checked-in residual inventory does not weaken that rule: OCI discovery failed before scoped queries ran, so OKE absence and residual resource counts remain unproven, not empty ([Phase 0 evidence guide](../guides/phase0-evidence.md)).

The specification already separates durable foundation from concrete regional resources. Pulumi creates and versions networking, IAM, root protection, image and launch templates, caps, bootstrap generations, initial seeds, initial dual-NATS stores, and the signed `BootstrapBundle`. After a deliberate handoff, the regional controller owns concrete nodes, workload backends, eligible attachments, and orchestrator-created volumes ([specification, lines 627-640](../../docs/architecture/orchestrator.md#L627-L640)). This is the boundary expressed by `REQ-O010` and `INV-014` ([requirement trace, lines 122 and 156](../../docs/architecture/orchestrator.md#L122-L156)).

The historical estate is evidence only. Its Pulumi stack still contains OKE assumptions and concrete regional identifiers; `WRK-001` preserves the durable-foundation boundary while replacing OKE capacity, and `WRK-018` requires unknown resources to be quarantined rather than adopted or deleted (historical WRK-001 / WRK-018 in `docs/archive/docs-historical-full.tar.xz`).

## Proposed decision

Use an explicit two-owner lifecycle:

1. **Pulumi foundation owner.** Pulumi exclusively creates and versions durable network/routing/security foundation, regional IAM capabilities, KMS/Vault roots, object storage, DNS/LB foundation, approved images and launch templates, quotas/caps, bootstrap/recovery generations, seed hosts, and the initial dual-NATS storage needed to establish regional authority.
2. **Handoff transaction.** A regional controller may assume ownership only through the proposed `SM-PULUMI-OWNERSHIP-HANDOFF`: establish both NATS quorums, enroll controller candidates, verify the regional journal/PKI/provider access/backups, persist a signed `HandoffReceipt`, make Pulumi retain or unmanage the exact transferred inventory, activate the regional fencing epoch, and only then enable self-management ([specification, lines 650-663](../../docs/architecture/orchestrator.md#L650-L663)).
3. **Regional actuator owner.** After the receipt is durable and both owners agree on the exact inventory, the cell exclusively owns concrete replacement and elastic compute, ephemeral boot volumes, post-handoff NATS/TerraBase/workload volumes, attachments, workload LB membership, node generation, drain/scale/termination, expansion, and orphan reconciliation.
4. **No count reconciliation by Pulumi after transfer.** Pulumi continues to version foundation, allowed templates, IAM, caps, and bootstrap/recovery generations, but does not reconcile transferred regional instance counts ([specification, line 648](../../docs/architecture/orchestrator.md#L648)). A changed template enters a region through a reviewed native GitOps plan and rolling generation operation, not through Pulumi replacing region-owned instances.
5. **Positive ownership is mandatory.** Resource tags are inventory and reconciliation evidence. They are never authority to adopt, terminate, detach, delete, format, or otherwise mutate. Mutation requires the compartment-scoped actuator capability plus the persisted, fenced operation described by ADR 0020 ([specification, lines 642-646](../../docs/architecture/orchestrator.md#L642-L646)).
6. **Disaster bootstrap is distinct.** A higher `bootstrapGeneration` and recovery authorization are required, after proving no viable regional quorum exists; it may not seed a competing cluster beside a partitioned one ([specification, line 685](../../docs/architecture/orchestrator.md#L685)).

This is a proposed direction, not an accepted contract. The exact Pulumi retain/unmanage mechanism, tag schema, IAM statements, receipt schema, transferred resource-type matrix, and crash checkpoints remain open.

## Safety invariants

- One resource has exactly one active lifecycle owner. Pulumi and a regional actuator never concurrently reconcile the same transferred resource.
- A transfer is between owners in the new greenfield system. Historical or merely discovered resources cannot enter it.
- A missing, invalid, stale, partial, or inventory-mismatched receipt holds self-management; it does not trigger best-effort adoption.
- A tag match cannot establish mutation authority. `ERR-PROVIDER-OWNERSHIP-MISMATCH` must be a typed hold for absent or mismatched positive ownership evidence.
- The exact resource inventory and bootstrap generation are bound into the signed receipt and regional journal. Retries resume the same handoff; they do not create a second ownership lineage.
- Handoff receipts and correlated evidence obey `SEC-NO-SECRET-OUTPUT`; they identify secret/key versions without containing secret values or private key material.
- Foundation changes cannot bypass the accepted regional desired-state and rolling-generation path.
- Regional autonomy preserves the applicable quorum, permanent-member, and storage invariants. This ADR does not select owner questions 1, 3, 5, or 8, nor does it define their unresolved SLOs.

## Alternatives considered

### Continuous Pulumi reconciliation of regional capacity

Rejected because Pulumi and the orchestrator would become two autoscalers with incompatible observations and failure recovery. A late `pulumi up` could recreate, resize, or delete a resource already controlled by a regional operation.

### Orchestrator owns all foundation from first boot

Rejected because it creates a circular bootstrap and recovery dependency and moves durable networking, root trust, IAM, and template-generation responsibilities across `INV-014` without an approved replacement authority.

### Import or adopt the historical OCI estate

Rejected. Full greenfield deployment is `REQ-O023`, and the residual inventory is currently incomplete. Unknown or old resources remain unrelated, quarantined, or separately approved cleanup targets.

### Tags determine ownership

Rejected. Tags are mutable and eventually observed metadata. They support discovery and mismatch detection but cannot prove authority or fence a leader.

### Handoff by operator convention only

Rejected. An undocumented order or manual runbook cannot prove agreement after a crash. The journaled signed receipt and an explicit Pulumi state transition are required.

## Consequences

- Foundation and regional reconciler code need disjoint, machine-checkable resource-type and action matrices.
- Handoff must be modeled as a crash-resumable state machine, not a deployment script.
- Pulumi state/history and the regional R3 journal must retain correlated, sanitized evidence of the same transfer without exposing secrets or private keys.
- Template evolution becomes a versioned input to regional GitOps and node-generation workflows.
- Greenfield collision checks and a separate approved cleanup process are mandatory before any mutation.
- Regional autonomy can proceed during GRU loss after handoff, subject to the still-open authority, survival-window, storage, RPO/RTO, and budget decisions.

## Unresolved inputs and evidence

The readiness map labels this draft-ready but requires exact OCI IAM/tag schemas, a primary-source Pulumi retain/unmanage spike, and fresh-resource crash-recovery evidence; it also depends on ADRs 1, 20, and 24 ([readiness index, lines 47-57](readiness-index.yaml#L47-L57)). Acceptance remains blocked on:

- the exact per-region compartment policy, dynamic-group/workload identity design, action and resource-type allowlists, and explicit deny/hold behavior;
- the exact required/free-form tag namespace and immutable-versus-observed field rules;
- proof of the selected Pulumi retain/unmanage operation across preview, apply, refresh, rollback, import rejection, and crashes;
- a complete resource-type handoff matrix, including which seed boot/NATS volumes transfer and which foundation resources never do;
- owner questions that determine regional authority/topology, vault custody, elastic volume retention, and physical NATS isolation;
- approved cost, storage performance, regional RPO/RTO, security, and survival-window targets;
- repaired read-only OCI evidence. Current account discovery is authentication-blocked and proves no resource absence ([OCI audit, lines 34-50](../audits/oci/phase0-residual-inventory.md#L34-L50)).

## Required verification before acceptance

- **Review:** exact ownership/action matrix, tag schema, IAM policy, receipt schema, Pulumi primary-source behavior, and independent security review.
- **L0:** model every handoff checkpoint, duplicate/reordered callbacks, stale bootstrap generation, mismatched inventory, partial Pulumi state transition, competing owner, and forbidden adoption. Prove `INV-004`, `INV-005`, `INV-006`, and `INV-014`.
- **L3S:** perform two from-zero handoffs from the same signed contracts, crash both sides at every checkpoint, resume the same lineage, and replace a node from the survival bundle while GRU/Git are disconnected.
- **L4:** use only fresh disposable OCI resources after the exact-tree pre-deployment gate; prove a later Pulumi run cannot mutate transferred resources and the regional actuator cannot mutate foundation or unowned resources.
- **L5:** retain a signed inventory/receipt trail across the production soak and verify no drift creates dual ownership.

No SUT cloud instance or OCI mutation is authorized by this ADR. The repository's exact-tree pre-deployment evidence gate remains mandatory ([specification, lines 1114-1122](../../docs/architecture/orchestrator.md#L1114-L1122)).

## Traceability

| Kind | Stable/proposed ID | Disposition in this ADR |
|---|---|---|
| Requirement | `REQ-O010` | Defines bootstrap-to-regional ownership transfer. |
| Requirement | `REQ-O023` | Forbids adoption of the deleted estate. |
| Invariant | `INV-004` | One fenced writer per node/volume operation. |
| Invariant | `INV-005` | Handoff and provider commands are replay-safe and generation/deadline bound. |
| Invariant | `INV-006` | Stale leaders cannot mutate or complete operations. |
| Invariant | `INV-014` | Assigns durable foundation to Pulumi and concrete post-handoff resources to the cell. |
| Security rule | `SEC-NO-SECRET-OUTPUT` | Keeps credentials and private keys out of receipts, journals, tags, and evidence. |
| Proposed state machine | `SM-PULUMI-OWNERSHIP-HANDOFF` | Defines the crash-resumable transfer; not yet in the canonical registry. |
| Proposed security rule | `SEC-PROVIDER-MUTATION-AUTHORITY` | Tags never authorize; only scoped capability plus persisted operation may mutate. |
| Proposed error | `ERR-PROVIDER-OWNERSHIP-MISMATCH` | Holds mutation on absent/mismatched ownership proof. |
| Proposed gate | `REQ-GATE-PHASE4` | Requires exact-one-owner outcome across every provider/handoff crash checkpoint. |

The canonical registry currently contains the requirement/invariant IDs but lacks semantic anchors, while the state-machine/security/error/gate IDs above are registry-audit proposals rather than frozen IDs ([registry audit, lines 30-57](../audits/registry/registry-audit.json#L30-L57); [registry audit, lines 67-98](../audits/registry/registry-audit.json#L67-L98)).
