# Phase 1 TerraBase topology and recovery core

## Predecessor

- Contract steward commit: `5315e7d`
- TerraBase release compatibility, replication/lag/backup SLO values, elastic-member policy, and storage thresholds remain explicit caller inputs.

## Goal

Implement pure TerraBase topology, member lifecycle, upgrade, autoscaling, backup, and restore decisions from `ORCHESTRATOR.md:1012-1042` and the TerraBase/storage acceptance gates. It emits typed administration intents only.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/TerraBase/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraBase*.cs`
- `docs/work-packages/handoffs/phase1-terrabase-core.md`

## Required behavior

- Immutable bounded cell/database/member/node/volume/backup/restore/release/operation identities; positive generation/epoch/sequence/byte quantities; closed permanent/elastic, role, health, replication, backup, restore, upgrade, and action catalogs.
- Permanent `a/b/c` membership is explicit and cannot be scaled in or replaced by unnamed count arithmetic. One-node loss retains caller-supplied quorum/replication floors; no two topology mutations overlap.
- Member add/remove/replace binds exact database, node, retained volume, writer fence, replication position, backup/recovery proof, and authority epoch. A retained volume never starts on two members and a new member never adopts an old volume without exact identity/fence proof.
- Scale-out requires sustained caller evidence, placement/storage/budget authorization, unique member identity, catch-up and replication proof before readiness. Scale-in requires sustained low use, topology removal, zero database references, backup/retention, volume disposition, and post-change replication proof.
- Upgrade proceeds one member/failure domain at a time under explicit N/N-1 compatibility and rollback-material proof. Health/readiness, leadership transfer, and catch-up are distinct; process exit never means success.
- Backup acceptance binds exact database generation/topology, full/incremental chain, object digest/location reference, encryption-key reference, application-consistency and verification. Restore is side-by-side, rejects chain gaps/rollback, and requires digest/topology/query verification before promotion.
- Emit closed observe/add/catch-up/transfer/remove/start-with-retained-volume/backup/restore/upgrade/rollback/hold intents and stable code/numeric traces; no SQL/admin command, endpoint, credential, arbitrary payload, callback, SDK, or I/O.
- Defensive copies; culture/permutation/replay determinism; a/b/c protection; one/two loss; split-writer; stale/future/conflicting replication; add/remove crash steps; upgrade N/N-1; backup chain corruption; restore rollback; and secret-safe tests.
- No TerraBase client, network/filesystem/process/clock, topology/SLO/threshold/default release, or mutation.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`

