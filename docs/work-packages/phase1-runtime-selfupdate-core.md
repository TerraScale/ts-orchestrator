# Phase 1 runtime lifecycle and self-update core

## Predecessor

- Contract steward commit: `5315e7d`
- Host image, systemd/container runtime versions, artifact signing technology, health timeouts, compatibility window, and rollback policy values remain explicit inputs.

## Goal

Implement pure admitted workload lifecycle decisions for native systemd/container runtimes plus orchestrator A/B self-update from `ORCHESTRATOR.md:359-390,843-879` and Phase 2/3 lifecycle requirements. It emits typed executor/bootstrap intents only.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Runtime/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Runtime*.cs`
- `docs/work-packages/handoffs/phase1-runtime-selfupdate-core.md`

## Required behavior

- Immutable bounded workload/allocation/node/artifact/digest/signature/config/secret-version/volume/port/health/release/slot/operation identities; positive generations/epochs/attempts; closed native/container runtime and lifecycle/action/error catalogs.
- Only the admitted role/runtime contract can produce an allocation. Native intents select reviewed artifact/unit descriptors; container intents select digest-pinned OCI artifact/runtime descriptors. Shell/unit text, privileged flags, arbitrary capabilities, host paths, mutable tags, and executable caller strings are unrepresentable.
- Lifecycle is restartable desired/observed progression: prepare artifacts/secrets/volumes/ports, stage config, start, distinguish liveness/readiness/dependency health, serve, drain, stop, and clean retained/ephemeral material by explicit policy. Exit zero alone is never readiness.
- Same operation/generation is idempotent; stale/lower epoch or generation rejects, future/conflicting observation holds, lost executor response re-observes, and no second start/stop is emitted without proof.
- Self-update verifies exact signed artifact/protocol/schema N/N-1 evidence and local forward+rollback availability, stages inactive A/B slot, switches once, proves new health, and either commits or deterministically rolls back. It never overwrites the active/only known-good slot or deletes rollback material early.
- Emit closed fetch/verify/stage/mount/start/health/drain/stop/cleanup/switch-slot/commit/rollback/hold intents with typed parameters and stable code/numeric trace; no process command/unit text/container spec blob/secret value/private key/callback/time read/filesystem/network/I/O.
- Defensive copies; culture/permutation/replay determinism; runtime admission matrix; port/volume conflicts; stale/future evidence; lost response; readiness dependency failure; A/B crash at every step; incompatible update; failed rollback; and forbidden-shape/secret-safe tests.
- No systemd/containerd/OCI/process/filesystem/network/clock package, retry/timeout/runtime/release default, or mutation.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`

