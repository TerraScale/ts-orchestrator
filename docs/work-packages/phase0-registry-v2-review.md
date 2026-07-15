# Phase 0 work package: independent semantic registry v2 review

- Scope: independently review integration commit `7deaf74` and the 43 still-missing proposed state-machine/error/security/gate families.
- Allowed paths: `docs/audits/registry-v2-review/**` and a lane handoff.
- Prohibited paths: canonical registry, registry checker/tests, ORCHESTRATOR.md, shared build files, and production code.
- Deliverable: adversarial review of source-digest semantics, owner/evidence modeling, duplicate SEC/INV meaning, co-review gaps, audit migration correctness, and proposed-ID naming/granularity. Provide exact actionable findings and a steward patch plan; do not silently freeze proposed IDs.
- Verification: reproduce current validators, inspect exact source ranges, and label every conclusion as confirmed issue, recommendation, or blocked owner decision.
