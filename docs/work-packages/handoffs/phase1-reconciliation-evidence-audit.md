# Phase 1 reconciliation dependency-evidence audit

## Finding and correction

An eligible reconcile intent previously retained the target resource's complete
observation, but each converged dependency proof retained only desired identity,
generation, and digest. Two otherwise identical plans whose dependency
observations had different observation IDs or freshness sequences therefore
produced equal adapter-facing intents.

`DependencyProof` now has internal construction and retains the exact completed
dependency observation: identity, kind, generation, digest, observation ID,
freshness sequence, and condition. Proofs remain ordered by dependency identity.
The planner constructs them only from dependency steps already classified as
exactly converged, so every emitted dependency condition is `Ready`.

The error and reason catalogs, their numeric values, and evaluation precedence
are unchanged.

## Evidence

- A focused regression varies only dependency observation ID and freshness and
  proves that the resulting reconcile intents no longer collide.
- A 1,000-case valid-graph property family compares all seven retained fields,
  ordinal proof order, and the required `Ready` condition.
- Reconciliation replay and cross-operation fingerprints include every proof
  field.
- The accepted-output closure inventory now treats `DependencyProof` as an
  accepted evidence type and enforces its lack of public constructors, setters,
  and deconstruction.

Focused Release verification passed 37 reconciliation tests and 2 accepted-
output construction-closure tests with a warnings-as-errors solution build.

## Boundary

This audit changes only the pure reconciliation output contract and tests. It
does not add persistence, dispatch, NATS, adapter, runtime, or deployment
evidence, and it does not claim that an adapter has persisted or revalidated
these proofs. The caller remains responsible for deriving the freshness floor
from authoritative state.
