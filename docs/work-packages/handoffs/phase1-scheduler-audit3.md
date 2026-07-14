# Phase 1 scheduler observation-generation audit handoff

## Defect and correction

The availability evaluator previously received completeness and structural checks
for a replica observation snapshot but no snapshot generation or accepted-generation
high-water mark. A healthy generation-3 snapshot could authorize maintenance, a
newer generation-4 snapshot could show one replica already disrupting and correctly
reject the same maintenance, and replaying generation 3 would authorize the second
disruption again.

`AvailabilityEvaluationRequest` now requires positive `ObservationGeneration` and
`CurrentAcceptedObservationGeneration` values. The evaluator consumes evidence
already accepted by its caller, so only exact equality can authorize a change. A
lower generation is held as rollback evidence; a higher generation is held because
it has not yet become the caller's accepted snapshot.

## Compatibility and precedence

Availability reason IDs and trace rows 1 through 28 retain their exact numeric
values and order. Two rows are appended explicitly:

- `ObservationGenerationNotRollback = 29`
- `ObservationGenerationNotFuture = 30`

Both rows carry the candidate generation as `Observed` and the accepted high-water
mark as `Required`. Their hold status participates with the five existing evidence
integrity rows before change-target evaluation. For compatibility, the rows are
emitted after the established 28-row prefix: a generation hold makes target row 6
and policy rows 7 through 28 held/not-applicable exactly like other unavailable
evidence, then rows 29 and 30 expose whether the mismatch was lower or higher.
Equal-generation requests leave the first 28 serialized rows unchanged and append
two passed, generation-distinct rows.

## Evidence

- The concrete generation-3/generation-4 replay history now rejects the stale
  generation at row 29 before maintenance arithmetic can authorize it.
- Lower, equal, and higher generations are exercised across 1,000 deterministic
  placement, maintenance, and drain cases, reversed observations, and `tr-TR` and
  `ar-SA` cultures.
- Tests pin enum values 1 through 30, exact trace order, observed/required values,
  zero and null rejection, existing constructor callers, the unchanged 28-row
  equal-generation prefix, and both appended rows in the canonical numeric
  availability signature.
- Existing fixed replay-corpus inputs now supply equal accepted generations. The
  corpus JSON and content hash remain unchanged because its stored expectations are
  classification labels; the canonical decision serializer includes rows 29/30.

## Non-claims

This is pure L0 policy evidence. It does not accept, sign, timestamp, persist, or
replicate an observation generation and does not prove adapter wiring or deployment
evidence. The caller must obtain the current high-water mark from its authoritative
accepted state. No topology, quorum, disruption, reserve, provider, runtime, NATS,
network, filesystem, process, or wall-clock behavior is selected or exercised.
