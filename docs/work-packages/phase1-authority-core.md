# Phase 1 regional authority core

## Goal

Implement the pure regional-authority lease/epoch decision state machine described at `ORCHESTRATOR.md:454` and `545-550`. It models KV CAS intents/observations but performs no NATS or clock I/O.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Authority/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Authority*.cs`
- `docs/work-packages/handoffs/phase1-authority-core.md`

## Required behavior

- Immutable authority/candidate/lease identities, positive KV revision and epoch, explicit supplied server time and monotonic lease duration.
- Closed states for follower, acquisition pending, leader, renewal pending, release pending, read-only/held, and fenced; closed typed errors and CAS/read/delete intents.
- Acquisition advances epoch and becomes leader only after an exact matching successful CAS observation. Stale/mismatched/duplicate/out-of-order results never grant authority.
- Renewals preserve epoch and require exact lease/revision ownership. Failure, expiry, uncertainty, or a higher epoch immediately removes mutation authority; a fenced state cannot self-unfence.
- Release is compare-and-delete and never claims success without matching observation. Partition/clock anomaly inputs hold destructive authority.
- Deterministic reducer/replay digest, crash at every intent/result boundary, three-candidate interleaving exploration, stale old-leader commands, overflow, equality-at-expiry, and permutation/duplicate observation tests.
- No wall clock, NATS, filesystem, network, environment, randomness, or policy defaults.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`
