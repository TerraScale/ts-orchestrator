# Phase 1 fenced operation core

## Goal

Implement a pure operation decision core for `INV-004` and `INV-005`: desired/observed reconciliation, fencing, durable journal decisions, and deterministic replay. It emits intents only and performs no I/O.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/**`
- `docs/work-packages/handoffs/phase1-operation-core.md`

## Required behavior

- Immutable desired and observed inputs with stable aggregate ID, generation/resource version, writer epoch, and observation identity.
- Closed operation states and typed errors. Accept exactly one owner epoch; stale generations/epochs and conflicting idempotency keys hold or reject without emitting mutation.
- Model prepare/authorize/dispatch/observe/terminal checkpoints so an authorized irreversible intent is resumed, never superseded by a conflicting new operation.
- Decisions are append-only journal events plus typed adapter intents. Replaying identical history and input yields structurally identical output and state digest.
- Deadlines and time are explicit inputs. No wall clock, NATS, filesystem, environment, sockets, provider SDKs, or arbitrary callbacks.
- Tests for duplicate/reordered events, stale writer, crash at each checkpoint, deadline edges, conflicting terminal observations, and restoration digest equality.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`
