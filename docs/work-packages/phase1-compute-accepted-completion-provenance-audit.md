# Phase 1 compute accepted-completion provenance audit

- Exact audit base: `f93051a4f324604424b18cb6962f9e47a76c6d42`
- Requirements: `REQ-O011`, `INV-005`
- Scope: pure compute decision output, independent L0 regression evidence, and this note
- External I/O or mutation: none

## Counterexample

Two complete, valid scale-out requests could differ in controller generation,
artifact/template/demand/operation identity, persisted plan and capacity proofs,
provider result, work request, resource/node identity, and completed progress,
yet both publicly returned only an empty intent/error set and
`Completed:Ready`. The exact accepted input could not be recovered from the
decision, so the terminal output was not a sufficient generation-bound replay
receipt.

The executable counterexample was run before the production change and failed
with both public fingerprints equal to `trace:1:Completed:Ready`.

## Narrow repair

`ComputeDecision.AcceptedScaleOutRequest` is a getter-only nullable reference.
`ComputeEngine.DecideScaleOut` attaches the identical validated request to
every error-free decision, including intent-producing and terminal states.
Every held/error scale-out result and every scale-in or survival decision keeps
the property null. One centralized wrapper applies that iff rule after the
existing scale-out core returns.

No action, intent, trace, error, transition, validation order, acceptance path,
policy threshold, public factory, boolean authorization alias, adapter, or side
effect was added. Existing intent payloads and compatibility properties remain
unchanged.

## Independent evidence

- Exact-reference and iff coverage spans all eight defined scale-out states.
- All nine scale-out error families are represented and keep the accepted
  request null; accepted and held scale-in/survival decisions are also null.
- Forty-two independently accepted mutations cover every variable request
  family, nested authority identity, count/resource join, plan/persistence and
  authorization proof, provider observation, and completed progress proof.
- The independent canonical fingerprint is culture-, reflection-discovery-
  order-, and replay-stable. The existing content-addressed storage/compute
  failure corpus remains byte-compatible.
- Reflection exhaustively inventories exported compute decision/intent origins,
  collection/request accessors, record clone, constructors, and setters.

## Requirement mapping and limits

This is the pure L0 boundary required by `REQ-O011` and the generation-bound,
crash-safe replay property in `INV-005`. It strengthens the Phase 1 requirement
that immutable input plus pure decision output be sufficient for deterministic
adapter execution and replay. It does not select an unresolved owner answer,
cost/storage/RPO/RTO target, provider policy, or destructive-operation policy.

This audit does not claim OCI, Pulumi, provider work-request, VM, SmolVM, NATS,
L0C, ARM64, deployment, or full pre-deployment evidence acceptance.
