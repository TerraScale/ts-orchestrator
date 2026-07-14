# Phase 1 reconciliation policy-provenance audit

- Exact audit base: `7cf23edbfef5d7fa3338be52325d6230667cd61d`
- Requirements: `REQ-O014`, `INV-005`
- Scope: pure reconciliation mutation output, independent L0 evidence, and this note
- External I/O or mutation: none

## Counterexample

Two distinct, valid caller-supplied reconciliation policies authorized the same
drift repair. They differed in allowed-kind and generation-floor collections,
resource/dependency bounds, and freshness floor, but the complete public
`ReconcileResourceIntent` and containing plan were identical. Before repair the
focused executable counterexample failed with both public fingerprints equal to:

```text
1:api:service:2:digest-api:api:service:1:old-api:observation-api:10:Ready::DriftEligible
```

The intent already retained the desired resource, exact target observation, and
exact converged dependency observations. It did not retain the policy that
authorized those observations to become a mutation.

## Narrow repair

`ReconcileResourceIntent.AcceptedPolicy` is a getter-only reference to the exact
`ReconciliationRequest.Policy` instance that passed validation and authorized
drift. The planner supplies it at the sole mutation-intent construction site.
Observe, hold, and converged outputs remain unchanged and expose no policy.

No policy default, boolean authorization alias, flattened duplicate DTO, public
factory, action, error, reason, trace, ordering rule, validation precedence, or
acceptance path changed. No adapter or side effect was introduced.

## Independent evidence

- Eligible mutation paths with zero, one, and two converged dependencies retain
  the exact policy reference; cloned intents retain the same reference.
- Converged, observe, and hold variants expose no policy property.
- Twelve independently admissible variants cover every policy scalar plus
  allowed-kind and generation-floor count/item/key/value sensitivity.
- Desired, observed, dependency, allowed-kind, and generation-floor permutations
  remain canonical across three cultures and exact replay.
- The existing 12-entry reconciliation replay corpus loads through its unchanged
  whole-file SHA-256 gate.
- Reflection closes the exported plan origin and inventories plan, step, base
  and concrete outputs, proofs, policy, request, collections, clones,
  constructors, properties, setters, and deconstruction.

## Requirement mapping and limits

This closes the `REQ-O014` native GitOps requirement that policy evaluation
precedes a recorded plan and the `INV-005` generation-bound crash/replay
boundary. It also satisfies the Phase 1 rule that adapters execute persisted
typed intents rather than reconstructing business authorization from unrelated
caller state.

The policy was already mandatory caller input. Retaining it does not choose an
owner question, provider behavior, retry policy, cost/storage/RPO/RTO target,
role catalog, or rollout default. This audit does not claim persistence, Git,
NATS, adapter, L0/L0C, VM, cloud, deployment, or production acceptance.
