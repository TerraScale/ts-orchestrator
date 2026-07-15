# Phase 0 work package: NATS pins, compatibility, and L0C readiness

- Scope: server/client/CLI candidate pins, N/N-1 compatibility evidence, JWT/TLS/gateway/JetStream capability matrix, and credential-free local L0C readiness.
- Allowed paths: `docs/audits/nats/**`, `testlab/pins/nats-*.json`, lane-owned scripts/tests under `testlab/nats/**`, and a handoff under `docs/work-packages/handoffs/**`.
- Prohibited paths: canonical registry, ADR readiness index, central package/build files, `ORCHESTRATOR.md`, production source, sibling repositories, cloud/VM mutation, and persistent services.
- Deliverable: evidence-backed candidate matrix without selecting the owner-controlled N/N-1 policy; fail closed on missing primary provenance, architecture support, or unexecuted behavior. A bounded ephemeral local NATS process is allowed for read-only/credential-free conformance and must be cleaned up.
- Verification: deterministic validation and adversarial fixtures; if executable checks run, cover process cleanup and label results honestly as local x64 L0C evidence rather than ARM64 or production qualification.

