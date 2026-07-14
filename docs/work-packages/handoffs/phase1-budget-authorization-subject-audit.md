# Phase 1 budget authorization-subject audit handoff

## Scope

This pure-policy audit reviewed budget decision outputs for one replay identity
ambiguity after the budget core, policy-completeness, and property/replay
shards. It performed no price lookup, billing query, provider operation,
filesystem access, network access, process execution, or external mutation.

## Executable counterexample

Two otherwise identical valid proposals targeted `node-42` and `node-43`.
Both returned `Automatic`, `IsAuthorized=true`, no approval scope, and the same
public numeric trace and redacted string representation. The accepted output
therefore did not state which resource proposal had passed budget policy.

The same omission covered the proposal's cell, cost center, node class, price
evidence identity, direction, safety purpose, node count, and delta. A replayed
automatic authorization could not be matched to its exact proposal subject
from the typed decision output.

## Correction

Every decision produced through the traced `BudgetDecision.Create` path now
contains a construction-closed `BudgetDecisionSubject`. Its internal
constructor accepts the already validated `BudgetProposal` and retains exactly:

- resource, cell, cost center, and node-class identities;
- price-evidence identity;
- change direction and safety purpose;
- node count; and
- the immutable delta vector.

This applies to automatic, approval-required, forbidden, and emergency traced
held outcomes. Existing early fail-closed decisions created through
`BudgetDecision.Held` remain trace-free and subject-free. For all current
decision paths, `Subject` is present exactly when `Trace` is present.

No decision kind, reason, enum numeric, band boundary, emergency rule, evidence
precedence, or trace field changed. `BudgetApprovalScope` is unchanged.
`ToString()` remains deliberately redacted and does not print resource or other
proposal identities; replay comparison uses the typed subject fingerprint.

## Verification

The audit tests exercise every traced creation return site and assert exact
subject retention. They independently mutate each of the nine subject fields,
prove canonical typed fingerprint inequality, prove identical replay
fingerprint equality, retain the approval-scope contract, and assert subject
construction closure and secret-safe string output. Early invalid-policy,
malformed, wrong-scope, unknown-class, missing-evidence, and arithmetic-held
paths remain subjectless.

## Deliberate non-claims

This closes proposal-subject identity only. It does not prove that a price is
current or correct, establish currency or fixed-point scale, attest a billing
export, bind an evidence producer or verifier, approve a cost/SLO target, or
grant provider mutation authority. It also does not claim structural equality
for `BudgetDecision`; replay equality here means equality of the canonical
typed subject/output fingerprint under the existing trace semantics.
