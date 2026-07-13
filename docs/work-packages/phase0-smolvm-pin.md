# Phase 0 work package: SmolVM pin and host conformance

- Predecessor commit: `9aaa07e`
- Contract version: proposed architecture dated 2026-07-13; question 10 remains configurable
- Requirement scope: `REQ-O018`, `REQ-O021`, `REQ-O022`
- Allowed paths: `testlab/pins/**`, `testlab/conformance/**`, lane-owned notes under `docs/work-packages/handoffs/**`
- Prohibited paths: solution/build files, canonical registry, `ORCHESTRATOR.md`, composition root, production source, sibling repository files
- Inputs: locally installed `smolvm`, libkrun/KVM/host information, upstream metadata only when necessary
- Deliverable: machine-readable pin manifest and non-mutating host conformance script/report covering binary digest/version, architecture, KVM, API availability, and explicitly untested gates
- Verification: run the script locally; deterministic output ordering; no VM creation before the L0 evidence gate
- Destructive actions: none; do not start a SUT VM, mutate cloud state, install software, or replace the installed binary
- Handoff: commit lane changes and report commit SHA, commands, observed limitations, and future nine-VM tests that remain gated

