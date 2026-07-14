# Phase 1 budget authorization basis audit 4 handoff

## Proven gap and correction

The budget engine selected one cell-usage observation, one global-usage observation, one node-class observation, and one price observation under a policy, but discarded those objects when it produced a decision. Two evaluations using different cell/global/node evidence identities and otherwise identical current values returned `Automatic`, `WithinAutomaticBand`, the same nine-field proposal subject, the same public numeric trace, no approval scope, and the same redacted string. The accepted output could not identify which evidence and policy had authorized compute capacity.

Every decision created after successful evidence selection and trace construction now contains a `BudgetDecisionBasis` retaining the exact validated policy and exact four selected observations. This includes non-authorizing approval, forbidden, and traced emergency-held results because basis presence marks the evidence/trace phase, not authorization. Early fail-closed results remain basis-free alongside their existing null trace and subject.

The basis is a sealed construction-closed class with an internal constructor, getter-only exact references, no alternate public factory/deconstructor/clone surface, and an opaque string representation. `BudgetDecisionSubject` continues to bind the proposal separately. No decision arithmetic, band threshold, emergency rule, kind, reason, precedence, trace, approval scope, or enum numeric changed.

## Executable evidence

The regression suite preserves the original legacy-output collision and proves that the new basis fingerprints diverge. It pins exact reference retention across automatic, approval-required, forbidden, provider-limit, emergency-held, and emergency-safety branches; enumerates early basis-null families; exercises evidence identity/value/status/age, price and policy sensitivity; checks permutation and four-culture replay across 1,000 cases; audits the complete public construction surface and redaction; and saves both collision sides in the strict checksum-pinned budget/provider corpus.

## Honest boundary

This closes selected budget policy/evidence provenance only. Exact reference retention does not make an evidence producer authentic, a billing export complete, a price correct, or a policy current; no policy-generation contract was added. A budget decision remains separate from provider authority and cannot itself mutate infrastructure. No provider SDK, billing query, network, filesystem, process, VM, cloud, deployment, or production qualification occurred.
