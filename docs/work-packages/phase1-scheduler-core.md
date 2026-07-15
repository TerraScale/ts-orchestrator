# Phase 1 deterministic scheduler core

## Goal

Implement a pure, deterministic constrained least-waste scheduler kernel from `ORCHESTRATOR.md:593-607`. It schedules only supplied candidates and constraints; it does not own product placement or stateful move safety.

## Allowed paths

- `src/TerraScale.Orchestrator.Scheduler/**`
- `tests/TerraScale.Orchestrator.Scheduler.Tests/**`
- `docs/work-packages/handoffs/phase1-scheduler-core.md`

## Required behavior

- Checked non-negative resource quantities for CPU, memory, block IO, ephemeral disk, bandwidth, PIDs, file descriptors, and huge pages; explicit port-set conflict checks.
- Immutable node/workload inputs including architecture, labels, trust/network/secret zones, failure domain, available capacity after caller-provided reservations/headroom, affinity/anti-affinity facts, and an optional caller-provided safety cap.
- Apply hard constraints before scoring. Never invent a pods-per-node limit and never infer project/database geography.
- Deterministic least-waste score and explicit stable tie-break independent of input enumeration order.
- A complete ordered reason trace for every rejected candidate and the selected candidate; no candidate returns typed unschedulable output.
- Tests for every resource boundary, port collision, zones/labels/architecture, anti-affinity, caller veto, stable tie, permutations, overflow, and no mutation of inputs.

## Verification

`dotnet test tests/TerraScale.Orchestrator.Scheduler.Tests/TerraScale.Orchestrator.Scheduler.Tests.csproj`
