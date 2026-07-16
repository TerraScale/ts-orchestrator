# TerraScale.Orchestrator agent rules

The workspace-level `../AGENTS.md` Git policy applies in full: pull latest `develop` before work, implement on `develop`, **commit often** on substantial coherent changes, and **push directly to `origin/develop`**. Do not open pull requests for day-to-day work. Do not create feature branches or worktrees unless the user explicitly asks; when used, branch and worktree are always paired. This repository is independent from every sibling repository.

## Current implementation boundary

- Read `ORCHESTRATOR.md` before changing architecture or production behavior.
- Phase 0 repository/baseline work may proceed. Do not freeze Phase 1 contracts while the numbered owner decisions and measurable cost, storage, RPO, and RTO targets remain unresolved.
- Never start a system-under-test VM, systemd/containerd lab, disposable cloud resource, or deployment test without valid exact-tree pre-deployment evidence. Non-mutating host/tool inspection is allowed.
- Never edit sibling repositories from this checkout. Cross-repository cleanup must be done inside each owning product repo on `develop` (or on a user-requested branch/worktree pair), then committed and pushed to that repo's `develop` after the native replacement gate exists.

## Ownership and dependency rules

- The integration steward exclusively owns the solution/build/package files, `requirements/registry.yaml`, global schemas/generators, composition root, `ORCHESTRATOR.md`, and shared test primitives.
- A sub-agent must have a checked-in work package under `docs/work-packages/`, an explicit allowed-path list, and isolation only when the user requests a branch/worktree pair (otherwise work on `develop`).
- Production dependencies flow from contracts to pure decisions to coordinators to adapters. Contracts and pure decisions must not reference NATS, OCI, D-Bus, containerd, filesystems, sockets, environment variables, or wall-clock APIs.
- Adapters translate persisted intents and typed observations. Do not hide business rules in infrastructure adapters.
- Unresolved owner choices must stay explicit/configurable; do not silently select a recommendation.

## Quality and safety

- Build with warnings as errors and nullable enabled.
- Reference stable requirement/invariant/error/state-machine/security IDs in production behavior and tests as the registry matures.
- No arbitrary workload kinds, executable paths, unit text, privileged containers, host paths, secrets, or cloud ownership inferred from tags.
- Never emit plaintext secrets or private keys to Git, NATS, logs, traces, metrics, test output, or Grafana fixtures.
- Use `apply_patch` for edits and preserve unrelated user changes.

## Sibling repository ownership

- `TerraScale.Infrastructure` and `Terrabase.Operator` are **retired stubs**. Do not revive Kubernetes, Flux, OKE, Helm, or CRDs there.
- Production infrastructure, control plane, native GitOps, host agents, and TerraBase lifecycle for production are implemented **only** in this repository.

