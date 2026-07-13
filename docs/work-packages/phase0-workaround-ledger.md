# Phase 0 work package: historical workaround ledger

- Predecessor commit: `9aaa07e`
- Contract version: proposed architecture dated 2026-07-13; owner questions remain configurable
- Requirement scope: `REQ-O014`, `REQ-O016`, `REQ-O018`, `REQ-O023`, `WRK-001` through `WRK-018`
- Allowed paths: `docs/retirement/**`, lane-owned notes under `docs/work-packages/handoffs/**`
- Prohibited paths: solution/build files, `requirements/registry.yaml`, `ORCHESTRATOR.md`, composition root, sibling repository files
- Inputs: read-only sibling repositories and their local `AGENTS.md` files
- Deliverable: exhaustive evidence-backed YAML ledger with stable IDs, source locations, preserved behavior, native replacement, owner lane, removal phase, regression layer, recovery boundary, and cleanup proof
- Verification: parse YAML; validate every entry has all mandatory fields; report unreadable/missing evidence without inventing it
- Destructive actions: none; no cloud mutations, cleanup, commits, pushes, or edits in sibling repositories
- Handoff: commit lane changes and report commit SHA, validation commands, gaps, and proposed follow-up packages

