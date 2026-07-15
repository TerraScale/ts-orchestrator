# Phase 1 TerraBase topology and recovery core handoff

## Delivered

- Bounded typed identities, positive quantities, closed catalogs, evidence scopes, numeric traces, and administration decisions.
- Exact topology evidence binds cell, database, member, node, retained volume, fence, database/topology generations, authority epoch, and operation. Cross-subject replay fails closed.
- Permanent `a`, `b`, and `c` removal protection, caller-proved quorum/replication floors, serialized topology changes, restartable add/remove checkpoints, and conflicting/future replication holds.
- Defensively copied retained-volume writer inventories, split-writer denial, exact volume/fence adoption proof, detached convergence, and strictly increasing authority epochs.
- Restartable one-failure-domain upgrades gated by N/N-1 compatibility, leadership transfer, rollback material, process health, readiness, and catch-up; contradictory post-upgrade proof emits typed rollback.
- Full/incremental backup-chain validation with exact database/topology generation, contiguous parent sequence, digest/object/key references, application consistency, and verification proof.
- Side-by-side restore with source/target generation anti-rollback and distinct chain, digest, topology, query, and promotion gates.
- Closed immutable intent subjects now carry every action-specific administration parameter: topology member/position, retained-volume epoch, current/target release pair, backup request destination/key/parent, accepted segment chain, and restore ID/generations/terminal backup chain.
- Completed backup acceptance emits non-mutating `Verify`; backup mutation is authorized separately from an exact request. Incrementals require a validated exact parent chain and matching terminal backup/sequence.
- Elastic leader removal first emits an exact leadership-transfer intent. Catch-up and transfer are classified as mutations and carry the exact topology subject.
- Upgrade rollback is restartable through rollback-applied and post-rollback-health checkpoints; release-pair replay and contradictory checkpoint order fail closed.

## Boundaries

This is a pure decision core. It contains no TerraBase client, SQL/admin text, endpoint, credential value, arbitrary payload, callback, process, network/filesystem access, clock, thresholds, default releases, or mutation.

## Verification

- `dotnet build TerraScale.Orchestrator.slnx --no-restore` — passed with 0 warnings and 0 errors.
- `dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build -- --minimum-expected-tests 100` — passed (159/159).

## Contract gaps

No gap found inside the assigned pure-core boundary. Real admin/backup adapters must persist each applied checkpoint before replay and preserve the complete typed evidence subject.
