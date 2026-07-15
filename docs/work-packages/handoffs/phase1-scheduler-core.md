# Phase 1 scheduler core handoff

Branch: `phase1/scheduler-core`

## Implemented boundary

The scheduler is a pure regional decision kernel. It accepts only supplied node
candidates, workload constraints, capacities already reduced by caller-owned
reservations/headroom, and a mandatory caller-supplied least-waste policy. It does
not inspect infrastructure or infer product/database geography, topology safety,
stateful moves, disruption policy, or cloud ownership.

Hard checks run for every candidate in this stable order: caller veto, architecture,
node class, labels, trust/network/secret zones, allowed failure domain, affinity,
anti-affinity, ports, optional caller cap, then CPU, memory, block IO, ephemeral disk,
bandwidth, PIDs, file descriptors, and huge pages. Every check is recorded even when
an earlier check rejects the candidate. Score and selection records complete the
22-item trace; candidates themselves are globally ordered by ordinal ID.

Caller vetoes use a closed `CandidateVetoCode` enum. No arbitrary caller detail can
enter a reason trace, preventing secret leakage and newline/control-character
injection through the veto path. Optional strings distinguish null/absent from an
invalid supplied blank; optional string collections likewise reject blank members.

Resource quantities are non-negative `long` values. Vector addition is checked,
subtraction fails closed on underflow, and exact score calculation uses `BigInteger`.
There is no floating-point/decimal division or overflow-dependent comparison. The
caller supplies every dimension exactly once with a non-negative weight and an
explicit component tie-break order; there is deliberately no production default.
Ranking is weighted waste, then ordered remaining components, then ordinal candidate
ID.

The optional allocation cap is also caller-owned and supplies current and maximum
counts. Admission uses `current < maximum` without increment arithmetic. Omitting it
adds no allocation-count limit.

## Verification coverage

TUnit covers exact-fit and one-unit-short boundaries for all eight resources,
zero-request/zero-capacity, negative values, checked overflow/underflow, near-maximum
weights and quantities, ports and duplicate ports, all label/zone/architecture/class/
failure-domain constraints, affinity/anti-affinity, veto, omitted/present/maximum
caps, least waste, score and ID ties, every candidate permutation, complete trace
order, typed unschedulable output, ambiguous duplicate IDs/facts, and defensive-copy/
no-mutation behavior.

## Limitations intentionally left to callers

- Weight values and component order are contract/policy inputs; this lane selects no
  production weighting.
- Capacities must already subtract system/NATS/controller reservations and HA
  headroom. The kernel neither measures nor guesses them.
- Callers translate topology spread, disruption budgets, volume locality,
  single-writer/stateful safety, and controller decisions into supplied facts,
  candidate sets, reservations, or vetoes.
- Port checks are exact host-port set conflicts. Network namespaces or future port
  scopes require an explicit contract extension.
- This is L0 pure-domain evidence only; it is not deployment or stateful safety
  evidence and freezes no unresolved owner decision.
