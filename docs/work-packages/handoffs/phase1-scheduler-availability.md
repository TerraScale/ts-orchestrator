# Phase 1 scheduler availability handoff

Branch: `phase1/scheduler-availability`

## Implemented boundary

The availability evaluator is a pure hard-policy layer. Callers explicitly provide
service/replica/node/failure-domain identities, observation completeness, desired,
minimum-available, quorum, maximum concurrent disruption and required-domain counts,
criticality, one-per-host policy, reserve resources, and whether that reserve must be
preserved. No topology, count, cost, timing, SLO, or reserve default exists.

Placement, node drain, and replica maintenance are closed action types. Placement
checks desired count, every still-allocated replica for one-per-host conflicts,
projected available failure domains, and all eight reserve dimensions. Drain counts
every available service replica on the target node. Maintenance requires one exact
currently available target. Disruption arithmetic is checked and quorum is the exact
caller value; the evaluator never computes an implicit majority.

Observation completeness is explicit because an absent whole observation cannot be
inferred from the remaining records. Duplicate IDs, conflicting duplicate records,
missing node/domain identity, wrong service identity, and an incomplete set hold
before policy arithmetic. Exact duplicates and conflicts are separately visible.

Every decision contains the same 20 ordered reasons. Codes/outcomes are closed enums
and observed/required values are unsigned counts only; constructors are internal and
there is no caller text/secret channel. Observations are ordinally ordered, so output
is invariant to enumeration order and culture.

## Verification coverage

Focused TUnit coverage includes explicit 2-of-3 quorum, second loss, one-at-a-time
maintenance, last-domain margin, placement anti-affinity, unavailable allocations,
multi-replica drain, exact reserve boundary and one-unit shortage in each of CPU,
memory, block IO, ephemeral disk, bandwidth, PIDs, file descriptors and huge pages,
explicit reserve consumption, duplicate/conflicting/missing observations, wrong
service, zero/maximum/overflow counts, invalid targets, defensive copying, all
three-replica permutations under `en-US`/`tr-TR`/`ar-SA`, unknown enums, canonical
identity validation, fixed trace order, and secret-safe trace reflection.

## Intentional limitations

- Criticality is an explicit classification, not permission to invent topology or
  reserve policy. The caller separately supplies one-per-host, domain, and reserve
  disposition inputs.
- Stateful move/volume/quorum semantics beyond supplied counts remain domain-
  controller vetoes. The evaluator does not decide TerraBase or NATS move safety.
- Product/project geography is not represented or inferred (`INV-013`).
- Resource capacity must already reflect caller-owned reservations/headroom. This
  layer only proves preservation of the supplied additional reserve.
- This is L0 pure-policy evidence only. It does not freeze draft registry entries or
  establish deployment/adapter evidence.
