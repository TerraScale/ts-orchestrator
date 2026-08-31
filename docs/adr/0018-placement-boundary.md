# ADR 0018: Separate database placement from host scheduling

- Status: Accepted
- Updated: 2026-08-30
- Authority: workspace D-05, D-06, D-18, and D-25

## Context

Database geography is a customer and product decision. Host placement is a
regional infrastructure decision. Combining them would let node pressure move
customer data or let two reconcilers write the same placement state.

## Decision

Each database owns its selected region set. Launch selection is limited to
GRU, SFO, and FRA. The stored selection advances through a monotonic generation
and remains authoritative when a catalog observation is missing or stale.
Absence is never a removal instruction.

Within an already selected region, the regional scheduler chooses a concrete
host for an authorized workload. It considers allocatable resources,
architecture, failure domain, affinity, volume locality, disruption budgets,
host health, and domain-controller constraints.

The responsibilities are separate:

| Decision | Owner |
| --- | --- |
| Selected database regions and placement generation | Product placement controller |
| TerraBase Member identity, membership, catch-up, repair, and retirement | TerraBase controller and TerraBase |
| Concrete host allocation inside one selected region | Regional scheduler |
| Node fleet capacity | Regional autoscaler |

The scheduler cannot add or remove a database region. It cannot treat an
unselected region as spillover. A capacity shortage produces a typed hold and
a same-region capacity request.

The generic scheduler also cannot decide that a TerraBase or NATS member is
safe to move or remove. The owning controller supplies the required topology,
quorum, replica-health, and volume constraints before scheduling.

## Failure behavior

- Host exhaustion requests capacity in the selected region.
- Host loss repairs machine placement without changing database geography.
- Missing, stale, filtered, or conflicting placement state holds destructive
  work.
- A catalog outage preserves the last accepted database selection.
- A stale placement or membership generation cannot be repaired by a
  successful host allocation.

## Consequences

Every placement mutation has one writer. Autoscaling remains regional and
cannot silently change residency. Cross-domain workflows need explicit typed
holds when product placement, TerraBase membership, or scheduler observations
are incomplete.
