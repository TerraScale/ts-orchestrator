# Phase 0 work package: ARM64 host and runtime readiness

- Scope: evidence matrix for ARM64 LTS host image/kernel/glibc, filesystem candidates, systemd/containerd/runc/BuildKit/runtime prerequisites, and L1R/L4 qualification gaps.
- Allowed paths: `docs/audits/runtime/**`, `testlab/pins/arm64-runtime-*.json`, lane-owned scripts/tests under `tools/phase0/runtime-readiness/**`, and a handoff under `docs/work-packages/handoffs/**`.
- Prohibited paths: canonical registry, ADR readiness index, central package/build files, `ORCHESTRATOR.md`, production source, sibling repositories, image downloads, VM/cloud mutation, and an accepted host-image/filesystem selection.
- Deliverable: compare viable candidates from primary sources, bind local observations precisely, identify x64-only evidence and missing ARM64/systemd-PID1/filesystem/runtime proof, and define reproducible L1R/L4 acceptance commands. Keep the ARM64 host-image selection unset.
- Verification: deterministic schema/fixture validation, adversarial negative cases, exact citations, and explicit separation of proposal, local observation, and qualified evidence.
