# Phase 1 observability projection and authorization property shard

## Scope

- Adds five deterministic families with exactly 1,000 materially seeded cases each for telemetry label/metric admission and cardinality, Grafana dashboard projection and ownership, alert routing/deduplication, culture/permutation/replay, and duplicate/conflicting evidence.
- Independent oracles bind exact intent/change types plus `ObservabilityDecisionCode` outcomes for stale/future generation, budget exhaustion, secret-bearing labels, scope mismatch, stale inventory, dedupe replay, operation mismatch, and conflicting alert evidence.
- Seeds vary operation, tenant, cell, signal, metric, dashboard, alert, release, and generation identities. Replay verifies exact reconstructed fingerprints rather than intent type alone.
- Telemetry admission is exercised across 1,000 cases and can only produce the closed admit/drop/hold intent family; reflection proves no observability intent is or returns an authority/operation/provider-mutation permit or decision type, and construction checks prove callers cannot create `ObservabilityDecision` or any observability intent.
- Positive admission binds the exact operation/tenant/cell/service/signal/metric/schema/label subject, alert routing binds exact alert/contact, and Grafana drift distinguishes unmanaged from conflicting observed ownership.
- Adds a 17-entry embedded whole-file corpus pinned to SHA-256 `0fd10baee8c38d2a133e1be28f26b169aa25bb6542fc10badeaa00d761965795`, with an 8,192-byte reader and strict shape, canonical ID, bounded seed, closed `(kind,variant,expected)` vocabulary, complete declared-variant coverage, and adversarial parser tests.

## Production hardening

- `ObservabilityGuards.CopyBounded` now manually captures enumeration after `MoveNext` and checks the effective bound before the extra `Current`.
- `ObservabilityTechnicalLimits.MaximumCapturedItems = 4096` is public and explicitly technical, separate from cardinality, retention, alert, and projection policy; the smaller caller `EnumerationLimit` remains authoritative.
- Constructor signatures, null/item validation, and decision behavior are unchanged for valid inputs. Exact maximum succeeds, max+1 and literal endless sources fail before extra `Current`, ordinary iterator failures are generic and secret-safe, OOM/SO/AV propagate from every iterator phase, and dispose mutation cannot change the snapshot.

This is bounded deterministic feature-shard evidence, not full L0 or deployment qualification. It starts no adapter, process, network, VM, or cloud resource.

## Verification

- Focused ControlPlane Release tests: 360/360 passed.
- Full solution Release tests: 541/541 passed.
- Full solution Release build: succeeded with zero warnings and zero errors.
