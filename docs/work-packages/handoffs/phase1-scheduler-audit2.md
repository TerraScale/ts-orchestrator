# Phase 1 scheduler capacity/completeness audit handoff

## Defect and correction

The availability evaluator previously treated all resource rows as not applicable
when `ReserveDisposition.MayConsume` was selected. Those rows combined two distinct
questions: whether the placement itself fit and whether an additional reserve
remained. As a result, a placement could request more of a resource than the target
reported available and still return `Admitted=true`.

The evaluator now keeps the original twenty trace rows and IDs unchanged, appends
`CapacityCpu` through `CapacityHugePages` as IDs/rows 21 through 28, and evaluates
available-versus-requested resources for every placement. Reserve rows retain their
existing remaining-versus-reserve semantics. `MayConsume` makes only reserve rows
not applicable. Maintenance and drain make both resource groups not applicable.
Held and invalid-target paths use the same explicit twenty-eight-code order as normal
evaluation; they no longer derive the surface with an enum range or `Skip` rule.

## Evidence

- The pre-fix regression requested CPU 2 from a target reporting CPU 1 with a
  consumable reserve and observed `Admitted=true`; the corrected result rejects the
  exact `CapacityCpu` row with observed 1 and required 2.
- A 1,000-seed property rotates the shortage across all eight dimensions, proves
  exact-fit admission, exact one-dimension rejection, independent reserve
  applicability, and exact observed/required values.
- A 1,000-seed surface property covers placement, maintenance, drain, incomplete
  evidence, and invalid targets while requiring the stable twenty-row prefix plus
  the eight appended capacity rows exactly once and in exact order.
- A 1,000-seed caller-hold property inventories all five `CandidateVetoCode` values,
  including the previously omitted `VolumeLocalityMismatch`, and binds the exact
  rejection reason.

## Non-claims

This is pure L0 scheduler evidence only. It selects no reserve, quorum, topology,
weight, node-class, criticality, or disruption default; does not authorize a
stateful move; does not establish deployment evidence; and performs no provider,
runtime, NATS, network, filesystem, process, or wall-clock action.
