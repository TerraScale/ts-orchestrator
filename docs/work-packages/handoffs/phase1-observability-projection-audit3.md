# Phase 1 observability projection checkpoint audit

## Finding

The Grafana projection decision previously checked that desired state and inventory
shared one candidate generation and inventory sequence. It did not receive the
last projection checkpoint accepted by the authoritative journal. Replaying an
older, internally exact request could therefore authorize create, update, or
delete changes after a newer projection had been accepted.

## Contract correction

`GrafanaProjectionRequest` now requires the current accepted generation and
sequence. A candidate generation or sequence below either accepted high-water
mark is rejected. Equality remains valid for idempotent replay, and a forward
candidate remains valid when every existing inventory, scope, access, generation,
and ownership rule also passes.

The append-only decision codes are
`ProjectionGenerationNotRollback = 18` and
`ProjectionSequenceNotRollback = 19`. Inventory completeness and candidate
exactness remain first in the trace; the two checkpoint decisions precede scope,
access, observed-generation, and ownership decisions. `ProjectionExact` appears
only on an authorized result. The authorized intent retains the exact request,
including both accepted checkpoint values.

## Evidence and boundary

The focused unit and property coverage exercises independently stale generation,
independently stale sequence, both stale, equality, and forward progress. It pins
the exact trace order and numeric catalog, observed/required values, exact request
retention, and 1,000 deterministic checkpoint cases. Projection replay
fingerprints include both checkpoint fields and the full reason trace.

This pure contract does not read or persist the journal, contact Grafana, or
perform backend I/O. A downstream coordinator must supply the trusted accepted
checkpoint and atomically advance it with accepted projection work. This audit
does not claim adapter, Grafana HA, operator API, deployment, or production
qualification completion.
