# Phase 0 work package: requirement and state-machine coverage audit

- Predecessor commit: `de9be9f`
- Contract version: proposed architecture dated 2026-07-13; owner questions and SLOs remain unresolved
- Requirement scope: all `REQ-O*`, contract invariants, named state machines, security rules, errors/holds, and acceptance layers in `ORCHESTRATOR.md`
- Allowed paths: `docs/audits/registry/**`, lane-owned notes under `docs/work-packages/handoffs/**`
- Prohibited paths: `requirements/registry.yaml`, solution/build/package files, global schemas/generators, composition root, `ORCHESTRATOR.md`, production source, sibling repository files
- Deliverable: independent machine-readable coverage audit comparing the current draft registry with every explicit requirement, invariant, named transition graph, security rule, hold/error class, and acceptance gate in the specification. Propose stable IDs and owners for missing items without editing the canonical registry.
- Evidence standard: every finding cites exact `ORCHESTRATOR.md` lines; distinguish exact requirements from inferred implementation suggestions. Do not declare semantic coverage solely because an ID exists.
- Verification: deterministic parser/checker or checked fixture, unique proposed IDs, canonical owner lanes, acceptance-layer validation, and negative fixtures proving omissions are detected.
- Destructive actions: none; do not start VMs, contact cloud services, or edit sibling repositories.
- Handoff: commit lane changes and report SHA, commands, complete/incomplete counts, and the steward changes recommended for the canonical registry.

