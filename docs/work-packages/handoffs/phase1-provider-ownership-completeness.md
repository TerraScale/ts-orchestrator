# Phase 1 provider ownership completeness handoff

## Result

The audit proved a durable-authorization forgery path in the previous pure model: `ProviderCallEvidence` carried only a status and optional work-request ID, so accepted-like evidence from one operation could be replayed into another operation and mint a durable authorization for the second context. A pre-fix regression demonstrated that the unrelated request authorized successfully.

The evidence contract now retains the exact public immutable `ProviderOperationContext` it attests. Authorization compares the complete internal fingerprint before it may emit any intent or expose durable authorization. The fingerprint covers operation, cell, compartment, controller epoch, resource kind, action, exact target/create key, expected generation and observation, terminal state, approvals, deadline status and generation, idempotency key, compensations, and closed action parameters. `CallEvidenceMatches` is a distinct stable trace reason; an ambiguous-evidence short circuit still emits the complete trace in the same policy order.

## Adversarial coverage

- 1,000 deterministic cross-operation replay cases rotate accepted-like statuses and all 16 fingerprint dimensions; each case mutates one dimension and requires the exact 15-reason trace order, `CallEvidenceMatches=Rejected`, no intent, no authorization, and no durable capture.
- 1,000 call-lifecycle cases pin `NotCalled`, `Accepted`, `ResponseLost`, and `Completed`, with and without a work-request ID where representable. They prove exact typed mutation/read/observe outputs, no repeat after an accepted-like result, and exact higher-epoch durable resume with evidence still bound to the original context.
- 1,000 closed-action cases inventory every `ProviderAction` and require only its compatible exact typed intent and original context.
- 1,000 handoff cases vary all six proof statuses/scopes plus resource identity, kind, generation, uniqueness, expected/Pulumi/regional exactness, and scope binding. Only the exact fresh-bootstrap tuple enables self-management.
- A later audit found that a fully self-consistent older handoff tuple could still replay after a newer bootstrap generation had been accepted. `HandoffRequest` now requires the current accepted bootstrap generation, and `HandoffGenerationNotRollback=25` rejects lower candidates after inventory/scope checks and before the six proof reasons. Equal-generation retries and greater-generation handoffs remain valid.
- The accepted `EnableRegionalSelfManagementIntent` retains the exact current-generation high-water used by the decision. This keeps forward handoffs authorized against different accepted histories distinguishable at the output boundary. A separate 1,000-case lower/equal/greater property pins the exact ten-reason trace, rejection, forward progress, and output shape.
- Existing property, pinned-corpus, construction-closure, hostile-enumerable, max-plus-one, defensive-copy, ordinary-failure redaction, and fatal-propagation tests remain the non-duplicated evidence for those already-covered branches.

## Evidence boundary

This is pure policy and deterministic test evidence only. It closes the demonstrated stale bootstrap-handoff packet replay in this decision core; it does not establish journal persistence or adapter correctness. No provider, OCI, Pulumi runtime, cloud inventory, network, process, filesystem, NATS L0/L0C, rootless container, ARM64, L3S, L4, deployment, acceptance, mutation, or cost evidence was executed or claimed.
