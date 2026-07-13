# Phase 0 work package: draft cloud ownership ADRs 4 and 20

- Predecessor commit: `ee72a8f`
- Scope: initial ADR backlog items 4 and 20 only
- Allowed paths: `docs/adr/0004-*.md`, `docs/adr/0020-*.md`, lane-owned handoff under `docs/work-packages/handoffs/**`
- Prohibited paths: ADR readiness index/validator, canonical registry, build files, `ORCHESTRATOR.md`, production/sibling source
- Deliverable: proposed, choice-preserving ADR drafts for Pulumi/provider ownership and provider-actuator crash-stop/irreversible-operation fencing. Capture context, safety invariants, alternatives, provisional direction already stated by the specification, unresolved exact IAM/tag/SDK details, consequences, rejected unsafe interpretations, and required L0/L3S/L4 evidence.
- Constraint: `Proposed`, never `Accepted`; do not make cloud calls or turn tags/IAM propagation into a fencing guarantee.
- Verification: exact citations resolve; both drafts trace ADR readiness entries, relevant REQ/INV/SEC/ERR/SM proposals, and explicitly retain owner/SLO dependencies.

