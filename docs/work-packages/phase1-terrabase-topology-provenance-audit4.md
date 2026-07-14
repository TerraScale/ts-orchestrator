# Phase 1 TerraBase topology provenance audit 4

## Basis and scope

- Exact central basis: `dc51519e35515b191cdbca039c5d20251e2353ec`.
- Bounded internal requirement: pure accepted topology output provenance for the existing add/remove contract.
- Excluded: active reconciliation policy; every previously integrated audit-4 domain; TerraBase clients, processes, storage, networks, NATS, VMs, cloud resources, deployment activity, and all external effects.

## Requirement mapping

- `ORCHESTRATOR.md:146-150`: one fenced, replay-safe TerraBase topology operation and protected permanent-member/scaling safety.
- `ORCHESTRATOR.md:1016-1033`: typed topology read-back, replication-aware add/remove, safe decommission, and the existing 3-to-10 policy boundary.
- `ORCHESTRATOR.md:1120-1152`: every branch and terminal result must be tested and pure methods must return typed decisions and intents.

## Proven counterexamples

Three executable tests failed before production changed:

- post-add and post-remove topology observations with the same scope and position produced equal decisions, erasing the semantic planner route;
- successful add decisions accepted different loss evidence but compared equal;
- successful remove decisions accepted different follower/leader-transfer evidence but compared equal.

All three used a generic scoped subject and discarded the accepted topology evidence.

## Narrow correction

`TerraBaseTopologyIntentSubject` now retains a fixed, non-unknown `TerraBaseTopologyPlanKind` (`Add` or `Remove`) and the exact accepted `TerraBaseTopologyEvidence` reference. Scope, member kind, and replication position are projections of that retained evidence. Every non-hold add/remove branch uses one such exact subject; action, target, code, trace, validation, and precedence remain unchanged. Every hold remains subject-free.

## Proof inventory

- Exact evidence reference and plan kind across all six successful add outcomes and all five successful remove outcomes.
- Cross-kind separation and all three original collision regressions.
- Independent sensitivity for all 10 evidence-scope leaves and all 20 remaining topology-evidence leaves.
- 1,000 unique culture-stable replay cases plus multiple real evaluation-order permutations of the complete successful branch inventory.
- Unchanged four-entry whole-file-pinned Delivery/TerraBase replay corpus compatibility.
- Exact allowlists for seven public decision origins and every decision/base/concrete-subject/evidence/scope/trace/collection return route, accessor, record clone, constructor boundary, default decision, value copy, and concrete topology-subject clone basis.

## Deferred owner and external boundaries

This correction does not invent the clean bootstrap/join, elastic tag/rank ordering, six-direction replication/placement, restore-conflict, or terminal rollback-failure contracts listed by the prior audit. Those require a steward-owned compatible contract tranche. Threshold/SLO and owner choices remain unresolved. Real TerraBase administration, systemd/container execution, storage recovery, L3S, L4, and production qualification require later adapters and real-system evidence.
