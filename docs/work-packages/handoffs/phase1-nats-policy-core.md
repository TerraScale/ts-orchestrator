# Phase 1 dual-NATS policy core handoff

## Delivered

- Pure typed control/product plane policies for cells, clusters, servers, peers, placements, accounts, subject roots, streams, buckets, routes, gateways, retention, discard, acknowledgement, disk-sync/RPO classification, and compatibility features.
- Explicit caller bounds and values throughout; there is no R3, storage, timing, sync, retention, or compatibility default.
- Closed scalar-safe identities and enum catalogs with `Unspecified=0` rejected throughout, positive generation/epoch/sequence validation, and overflow-safe arithmetic.
- Subject roots use a canonical lowercase token grammar with an optional terminal `>` only; empty tokens, uppercase, embedded `*`, embedded `>`, and malformed wildcards are rejected before any overlap decision.
- Control/product isolation rejects shared cluster/server/peer/account/stream/bucket/subject authority, product gateways, overlapping account namespaces, and stream/bucket subjects outside their owning account.
- Critical durability rejects singleton or below-floor replicas, non-replicated acknowledgement, and non-strict acknowledged-write classification. Caller-supplied route sets must be unique, known, non-self, and strongly connected; a complete directed mesh is not assumed. Explicit membership floors are validated.
- Configure intents carry the complete immutable typed plane policy rather than generated NATS text or an under-specified flag.
- Lost-peer replacement progression is observation-driven and ordered: observe, persist exact operation, add one replacement, wait for catch-up, verify exact stream/bucket replicas, then remove the exact failed peer. A lost add response that is visible in membership never emits a second add.
- Observed peers must match admitted policy or the exact replacement; unknown peers cannot satisfy membership floors. Failed-process fencing is separate from positive current-peer ownership proof.
- Partition decisions allow only caller-authorized regional work at the exact current regional epoch and accepted global generation during global disconnection. Regional quorum loss holds. Global work requires connectivity, current global authority, and exact global epoch/generation.
- N/N and both directional N/N-1 outcomes are required for every closed compatibility feature; missing, duplicate, unknown, or unavailable outcomes hold.
- Stable numeric/code-only errors and trace, defensive copies, culture/input permutation determinism, and no free-form message, callback, payload, executable data, credentials, NATS object, clock, or I/O.

## Steward-approved contract expansion

The package output list initially omitted the `ReattachSurvivingStore` branch required by `ORCHESTRATOR.md`. The steward explicitly approved a closed `ReattachSurvivingStoreIntent`. It binds:

- exact operation, plane, cell, cluster, recorded server/peer, and replacement placement evidence;
- surviving store identity and positive observed store generation;
- exact observed membership sequence and ownership epoch;
- recorded owner, compatibility proof, and absence of a conflicting active attachment.

Wrong-plane, incompatible, stale/future proof, a conflicting attachment, or any attempted server/peer identity swap holds. Reattachment targets the recorded failed server and peer identity at the replacement placement; it never invents a peer and never enters the remove-peer path. When an observation proves a lost reattach response already restored that same recorded identity and its replicas are healthy, replay completes without emitting another reattach.

## Files

- `src/TerraScale.Orchestrator.ControlPlane/Messaging/MessagingContracts.cs`
- `src/TerraScale.Orchestrator.ControlPlane/Messaging/MessagingPolicyEngine.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/MessagingPolicyEngineTests.cs`

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore -- --no-progress
git diff --check
```

- Solution build: 0 warnings, 0 errors.
- Control Plane suite: 75 passed, 0 failed (15 messaging tests plus 60 existing authority, operation, reconciliation, and snapshot tests).
- All five repository test executables: 183 passed, 0 failed (Contract 8, Control Plane 75, Model 17, Protocol 42, Scheduler 41).

## Deliberate boundaries

- The core does not generate NATS configuration text, contact a server, inspect a store, attach storage, retry, select versions, choose RPO/SLO values, or persist/execute intents.
- Store compatibility, ownership, attachment, and membership observations must come from a separately authenticated adapter/coordinator boundary; this core only validates and freezes that evidence.
- Disaster recovery with fewer than N-1 current owned peers is not authorized here. It holds for a separately tested and explicitly authorized recovery workflow.
