# TerraScale.Orchestrator agent rules

The workspace-level `../AGENTS.md` Git policy applies in full: pull latest `develop` before work, implement on `develop`, **commit often** on substantial coherent changes, and **push directly to `origin/develop`**. Do not open pull requests for day-to-day work. Do not create feature branches or worktrees unless the user explicitly asks; when used, branch and worktree are always paired. This repository is independent from every sibling repository.

## Current implementation boundary

- Read `ORCHESTRATOR.md` before changing architecture or production behavior.
- Owner decisions 1A–10A are accepted. Pure Phase 1 contract tranches may freeze when safety policy remains explicit and configurable; unmeasured cost, storage, RPO, and RTO targets block deployment qualification, not implementation.
- Never start a system-under-test VM, systemd/containerd lab, disposable cloud resource, or deployment test without valid exact-tree pre-deployment evidence. Non-mutating host/tool inspection is allowed.
- Keep the aggregate local container and test workload at or below 24 GiB RAM. Reduce parallelism or run smaller batches instead of exceeding this limit.
- Do not reproduce the full production topology locally. Use three regions with replication factor 1; validating regional behavior is more important than simulating quorum locally.
- Reserve 4 GiB for the host and tooling. An owned Podman lab or bounded validation process may use at most 20 GiB, and topology admission must fail before startup when the sum of declared limits exceeds that budget.
- Run the five test executables sequentially and pass `--maximum-parallel-tests 4` to TUnit. Never run multiple test modules, a test run and a lab, or two labs concurrently in this checkout; use the repository validation lease.
- Do not edit, stage, commit, rebase, or otherwise mutate this checkout while the validation lease is held. Check the lease immediately before a write and defer the write until it is free; exact-tree attestation and an admitted lab must see a stable checkout for their full run.
- Test at the lowest sufficient fidelity: pure business behavior in process; routing, identity, messaging, persistence, health, restart, and reconciliation in the three-region RF=1 lab; quorum only in a targeted one-region R3 component lane; systemd, containerd, storage, and provider boundaries one fixture at a time.
- Reuse one healthy regional lab for sequential fault scenarios when isolation is not itself under test. Do not start a fresh full topology per test, and do not add a second local production-shaped topology system.
- A three-region RF=1 result is regional-development evidence only. It must never be reported as production quorum, host-failure tolerance, systemd, cloud, destructive-storage, or ARM qualification.
- Never edit sibling repositories from this checkout. Cross-repository cleanup must be done inside each owning product repo on `develop` (or on a user-requested branch/worktree pair), then committed and pushed to that repo's `develop` after the native replacement gate exists.

## Ownership and dependency rules

- The integration steward exclusively owns the solution/build/package files, composition root, `ORCHESTRATOR.md`, and shared test primitives.
- Production dependencies flow from contracts to pure decisions to coordinators to adapters. Contracts and pure decisions must not reference NATS, OCI, D-Bus, containerd, filesystems, sockets, environment variables, or wall-clock APIs.
- Adapters translate persisted intents and typed observations. Do not hide business rules in infrastructure adapters.
- The accepted 1A–10A owner choices are normative. Any future unresolved choice must stay explicit/configurable; never replace a recorded decision silently.
- Platform and Authentication public listeners remain REST. Allocate separate non-ingress MagicOnion listener ports, discover Authentication and regional Platform RPC endpoints privately, require workload mTLS with the expected peer identity in production, and make Platform readiness depend on Authentication RPC readiness.
- Treat the customer Dashboard as a separate full-stack application and an ordinary external TerraScale.Platform user. Runtime wiring may supply public Platform/Auth base URLs only; it must not create Dashboard-specific API knowledge, SDK surface, credentials, headers, tenant bypasses, direct TerraBase access, or private operator access.

## Quality and safety

- Build with warnings as errors and nullable enabled.
- Reference stable requirement/invariant/error/state-machine/security IDs in production behavior and tests as the registry matures.
- No arbitrary workload kinds, executable paths, unit text, privileged containers, host paths, secrets, or cloud ownership inferred from tags.
- Never emit plaintext secrets or private keys to Git, NATS, logs, traces, metrics, test output, or Grafana fixtures.
- Use `apply_patch` for edits and preserve unrelated user changes.

## Payment and Polar operator safety gate

- Payment providers remain external, non-admitted workloads; their integration belongs to Platform production adapters. The Orchestrator may bind only the production secret-reference/config admission boundary for Platform workloads, and must never introduce or admit a provider or payment role.
- Do not create or rotate payment providers, catalogs, or webhooks, or create production mounts; do not mutate provider or cloud state without explicit authorization and a live, target-scoped lease.
- Sandbox payment work requires explicit non-production opt-in. Never place raw secrets, card data, or payment payloads in source, reports, logs, or commands.
- Every validation or release handoff is redacted and binds the source revision, owned paths, lease outcome, immutable evidence/artifact/config identity when applicable, and known gaps; exact commands and results must exclude sensitive output.
- A live billing claim requires complete redacted evidence; a partial or skipped flow is not billing evidence.

## Sibling repository ownership

- `TerraScale.Infrastructure` is a **retired stub**. Do not revive Kubernetes, Flux, OKE, Helm, or CRDs there.
- Production infrastructure, control plane, native GitOps, host agents, and TerraBase lifecycle for production are implemented **only** in this repository.
