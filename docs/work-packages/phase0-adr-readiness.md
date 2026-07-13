# Phase 0 work package: ADR and toolchain readiness map

- Predecessor commit: `de9be9f`
- Contract version: proposed architecture dated 2026-07-13; recommendations are not owner decisions
- Requirement scope: Phase 0 ADR backlog items 1-24, tool/artifact pins, host/runtime prerequisites, and open owner/SLO inputs
- Allowed paths: `docs/adr/**`, `docs/audits/toolchain/**`, lane-owned notes under `docs/work-packages/handoffs/**`
- Prohibited paths: solution/build/package files, canonical registry, `ORCHESTRATOR.md`, production source, sibling repository files, installed tools/configuration
- Deliverable: ADR index and readiness matrix for all 24 backlog items with status, controlling owner question/SLO, evidence already available, missing measurement/primary source, dependency, owner lane, and exact exit evidence. Add draft ADR templates only where they preserve unresolved choices rather than selecting them.
- Toolchain audit: non-mutating local inspection of .NET, NATS, containerd, systemd, BuildKit, filesystem tools, SmolVM/KVM, OCI CLI, Pulumi, signing/SBOM, and ARM64 availability. Record absent tools and unqualified versions without installing or changing anything.
- Verification: all 24 ADRs accounted for exactly once; canonical lanes only; every `ready` status backed by local evidence or a primary source; no open owner choice represented as accepted.
- Destructive actions: none; no installs/upgrades, services, VMs, cloud calls, or sibling edits.
- Handoff: commit lane changes and report SHA, commands, readiness counts, blocking decisions, and suggested next work packages.
