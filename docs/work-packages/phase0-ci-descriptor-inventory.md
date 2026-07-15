# Phase 0 work package: runtime/build descriptor and CI policy inventory

- Scope: exhaustive read-only inventory of product runtime/build descriptors and conflicting feature/develop/main release rules across sibling repositories.
- Allowed paths: `docs/audits/delivery/**`, lane validation/tests under `tools/phase0/delivery-inventory/**`, and a lane handoff.
- Prohibited paths: sibling edits, canonical registry, shared build files, ORCHESTRATOR.md, workflow execution, credentials, and external mutation.
- Deliverable: pin every cited sibling commit; enumerate roles/build targets/descriptors/workflows and gaps (including Authentication); distinguish observed policy from proposed reconciliation; emit a deterministic machine-readable inventory and adversarial validator.
- Verification: exact path/line/commit provenance and fail-closed completeness checks against the pinned sibling trees.

