# Phase 1 storage and compute property/replay shard handoff

## Delivered

- Nine deterministic generated property families execute 1,000 cases each across Storage and Compute capacity, generation/fencing, deletion, scale safety, replay, culture, and survival permutation behavior.
- Independent expected-code and arithmetic/floor oracles bind exact failure reasons and ensure denied cases never emit an unsafe mutation intent.
- A strict eight-entry, maximum-32, maximum-8,192-byte embedded JSON replay corpus rejects wrong version, unknown/duplicate fields, duplicate identities, non-positive seeds, unsupported domains, empty/oversized sets, and content-address drift. Its loader uses a fixed maximum+1 buffer and is regression-tested with non-seekable partial reads, so the byte limit applies before parsing. Every entry invokes the real pure core and reproduces its exact closed error code in file order.
- Authorizing Storage/Compute outputs remain construction-closed and their public observable enums are explicitly finite.
- `RegionalSurvivalBundle` now snapshots its caller enumerables with named technical bounds. Regressions cover exact maximums for both inputs, maximum+1 for both inputs, infinite inputs, a maximum+1 extra-`Current` trap, GetEnumerator/MoveNext/Current/Dispose failures, secret-safe translation, fatal propagation at every iterator phase, and mutation during disposal.

## Compatibility impact

The public constructor signature is unchanged. Callers that supplied more than 4,096 secret-version identities or node templates, infinite enumerables, null elements, or ordinary-failing enumerators previously risked unbounded work or leaked exception details; they now receive a generic `ArgumentException`. No autoscaling, capacity, replica, deletion, or survival-readiness business policy changed.

## Verification

- Locked solution restore passed.
- Full solution build passed with 0 warnings and 0 errors.
- Focused ControlPlane executable suite passed 302/302.
- `git diff --check` passed.

## Non-claims

This is bounded feature-shard evidence. It makes no full-L0, 100,000-case, coverage, mutation, integration, real-provider, destructive-storage, or deployment-authorization claim.
