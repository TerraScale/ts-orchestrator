# Phase 1 storage and compute deterministic property/replay shard

## Goal

Exercise the existing pure Storage and Compute control-plane cores with bounded deterministic generated cases and a fixed replay corpus. This shard strengthens test evidence only; it neither performs provider work nor claims deployment acceptance.

## Scope

- At least 1,000 explicit cases per property for storage capacity arithmetic, owner/generation/writer fencing, deletion authorization, deterministic replay, and culture stability.
- At least 1,000 explicit cases per property for compute capacity gates, generation/controller fencing, scale-in floors, survival-bundle permutation, deterministic replay, and culture stability.
- Independent expected-code and checked/subtraction oracles that do not call production decision helpers.
- Closed observable catalogs and construction-closed authorizing result surfaces.
- A strict bounded embedded JSON replay corpus with an exact SHA-256 content address and saved Storage/Compute safety failures.

## Narrow production hardening

`RegionalSurvivalBundle` previously used unbounded `ToArray()` over two public caller enumerables. The authorized change introduces named 4,096-item technical snapshot bounds for encrypted secret-version identities and node templates. Maximum+1 is detected before reading the extra `Current`; ordinary iterator failures are translated without their text; fatal runtime exceptions propagate; captured values are defensive against mutation during `Dispose`.

These are denial-of-service/input-safety limits, not node, secret, replica, region, or scaling business caps. Existing callers presenting more than 4,096 items now receive `ArgumentException` and must shard or reject that malformed bundle before evaluation.

## Boundaries and non-claims

No cloud/provider, NATS, network, process, filesystem, environment, wall-clock, or nondeterministic random operation occurs. This shard does not claim the 100,000-case full-domain threshold, coverage or mutation targets, adapter conformance, destructive acceptance, L0 completion, or deployment authority.
