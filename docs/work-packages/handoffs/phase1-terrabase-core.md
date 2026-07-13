# Phase 1 TerraBase topology and recovery core handoff

## Delivered

- Bounded typed identities, positive quantities, closed catalogs, evidence scopes, numeric traces, and administration decisions.
- Exact topology evidence binds cell, database, member, node, retained volume, fence, database/topology generations, authority epoch, and operation. Cross-subject replay fails closed.
- Permanent `a`, `b`, and `c` removal protection, caller-proved quorum/replication floors, serialized topology changes, restartable add/remove checkpoints, and conflicting/future replication holds.
- Defensively copied retained-volume writer inventories, split-writer denial, exact volume/fence adoption proof, detached convergence, and strictly increasing authority epochs.
- Restartable one-failure-domain upgrades gated by N/N-1 compatibility, leadership transfer, rollback material, process health, readiness, and catch-up; contradictory post-upgrade proof emits typed rollback.
- Full/incremental backup-chain validation with exact database/topology generation, contiguous parent sequence, digest/object/key references, application consistency, and verification proof.
- Side-by-side restore with source/target generation anti-rollback and distinct chain, digest, topology, query, and promotion gates.

## Boundaries

This is a pure decision core. It contains no TerraBase client, SQL/admin text, endpoint, credential value, arbitrary payload, callback, process, network/filesystem access, clock, thresholds, default releases, or mutation.

## Verification

- `dotnet build TerraScale.Orchestrator.slnx --no-restore` — passed with 0 warnings and 0 errors.
- `dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build -- --minimum-expected-tests 100` — passed (158/158).

## Contract gaps

No gap found inside the assigned pure-core boundary. Real admin/backup adapters must persist each applied checkpoint before replay and preserve the complete typed evidence subject.
