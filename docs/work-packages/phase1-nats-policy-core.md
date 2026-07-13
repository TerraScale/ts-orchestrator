# Phase 1 dual-NATS policy and membership core

## Predecessor

- Contract steward commit: `0a54a0f`
- NATS server/client/sync selections and owner RPO/SLO values remain unresolved and must stay explicit inputs.

## Goal

Implement the pure dual-NATS topology, stream/bucket policy, membership replacement, and partition decision core from `ORCHESTRATOR.md:448-590`. It emits configuration/operation intents only and never starts or contacts NATS.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Messaging/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Messaging*.cs`
- `docs/work-packages/handoffs/phase1-nats-policy-core.md`

## Required behavior

- Immutable bounded cell, cluster, server, account, stream, bucket, peer, placement, operation, and observation identities; positive epochs/generations/sequences; closed control/product cluster and durability/action catalogs.
- Explicit caller policy for independent control/product clusters, exact membership floor, route/gateway peer sets, account isolation, stream/bucket replicas, retention, maximum age/bytes, discard, placement, duplicate window, acknowledgement, disk-sync/RPO classification, and compatibility feature availability. No implicit R3, timing, storage, or sync default.
- Reject any subject/account/stream overlap between control and product planes, cross-plane peer/server identity, singleton critical durability, incomplete/duplicate/conflicting/stale observations, unknown features, and config that loses the declared floor or acknowledged-write policy.
- Pure replacement state machine: observe failed peer, persist exact replacement operation, add/catch up replacement, verify current membership and stream/bucket replicas, then remove the exact failed peer. Never remove first, reuse an unproven identity, or emit two replacements after a lost response.
- Partition decisions preserve regional ownership: a disconnected region may continue caller-authorized local operations at a current regional epoch but cannot claim global authority or accept stale/lower-generation global commands.
- Outputs are closed typed configure/observe/add-peer/wait-catchup/remove-peer/hold intents with exact proofs only. Complete stable numeric/code trace, no arbitrary message, callback, config text, credentials, NATS client/server object, or I/O.
- Defensive copies; culture/input permutation determinism; control/product isolation; N/N-1 feature matrices; 3-peer one-loss replacement; lost response/replay; remove-before-catchup denial; duplicate/conflict/stale/future evidence; partition authority; maximum/overflow; and secret-safe tests.
- No NATS package/process/socket/filesystem/clock, retry loop, version selection, SLO/RPO value, or topology default.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`

