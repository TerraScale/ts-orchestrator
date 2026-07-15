# Phase 1 provider ownership and handoff decision core

## Predecessor

- Contract steward commit: `85db082`
- Draft Phase 1 contracts; OCI remains the first candidate adapter but this core is provider-neutral.

## Goal

Implement pure provider operation authorization and Pulumi-to-regional ownership handoff decisions from `ORCHESTRATOR.md:627-727`. The core emits typed intents only and never calls a provider.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Providers/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Provider*.cs`
- `docs/work-packages/handoffs/phase1-provider-ownership-core.md`

## Required behavior

- Immutable bounded provider/cell/compartment/resource/template/idempotency/work-request identities, positive generations/epochs, closed resource/action/terminal-state/approval/compensation catalogs, and explicit deadlines as caller evidence rather than wall-clock reads.
- A provider mutation context binds exact operation ID, regional authority, compartment, controller epoch, target provider ID or create key, expected observation/generation, desired terminal state, approvals, deadline evidence, idempotency key, and permitted compensations.
- Authorize only exact owned scope and current epoch/generation. Tags are typed inventory evidence and never sufficient authority. Mismatched, incomplete, stale, unknown, duplicate, or conflicting evidence holds/rejects before any intent.
- Once an irreversible provider step is durably authorized, a higher-epoch leader may resume/re-observe that same operation and terminal target but may not supersede it with a conflicting mutation or compensation.
- Model the bootstrap handoff receipt: exact inventory agreement, retain/unmanage proof, regional R3 journal receipt, provider/trust/backup readiness, and activated regional fence are all required before self-management. Historical resource adoption is unrepresentable.
- Emit only closed observe/read-work-request/create/start/stop/terminate/volume/backend/handoff typed intents with exact context and no arbitrary payload, callback, executable text, provider choice, SDK object, or I/O.
- Stable closed trace; defensive copies; culture/permutation determinism; tag-only denial; stale/future epoch/generation; duplicate/conflict; lost-response idempotency; late-call leader race; conflicting terminal target; exact handoff inventory; and secret-safe tests.
- No provider SDK, Pulumi runtime, NATS, files, clock, retries, provider selection, or policy defaults.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`

