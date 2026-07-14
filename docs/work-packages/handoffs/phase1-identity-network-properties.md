# Phase 1 identity and network deterministic property shard handoff

## Scope

- Adds seven deterministic property families with exactly 1,000 explicit cases each across enrollment, certificate lifecycle, authorization/secret lease, route/peer policy, ingress, and culture/permutation/replay behavior.
- Adds a 21-entry embedded replay corpus. The complete resource is limited to 8,192 bytes and pinned to SHA-256 `db16e016adc275b4c962c9b311d1964cb1f12be8ec86895a0f6a97b57ff8f782`; parsing rejects comments, trailing commas, excess depth, unknown/missing fields, excess entries, duplicate identities, and zero seeds.
- Adds independent closed scalar/action oracles and verifies stale, revoked, consumed, missing, duplicate, conflicting, cross-cell, route-leak, and generation evidence fail closed.
- Verifies authorized security intents cannot be publicly constructed and network mutation decisions remain construction-closed; the two public network intent subjects remain typed data only and cannot authorize a decision.

## Production hardening

- Security and networking enumerable inputs now use namespace-local bounded snapshot helpers with a named 4,096-item technical ceiling.
- Existing caller-provided route/prefix/link/cell maxima remain separate input/business constraints and constructor signatures are unchanged.
- Max+1 and infinite inputs reject after `MoveNext` and before reading the extra `Current`. Ordinary `GetEnumerator`, `MoveNext`, `Current`, and `Dispose` failures become generic secret-safe `ArgumentException` values without an inner exception. `OutOfMemoryException`, `StackOverflowException`, and `AccessViolationException` propagate.
- Snapshot tests cover exact maximum, maximum+1, infinite input, extra-`Current`, every iterator phase, dispose mutation, and fatal propagation for both helper families.
- Compatibility impact: no source/binary constructor signature change. Inputs over the technical cap and hostile/failing iterators that previously could run unbounded or leak iterator exceptions now fail closed.

## Verification

- `dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-restore -c Release`: 321/321 passed.
- `dotnet test TerraScale.Orchestrator.slnx --no-restore -c Release`: 502/502 passed.
- `dotnet build TerraScale.Orchestrator.slnx --no-restore -c Release`: succeeded with zero warnings and zero errors.

This is bounded deterministic feature-shard evidence only and does not satisfy the full L0 thresholds. It does not select PKI algorithms, issuer/vault custody, VPN/DNS/LB implementations, retention/lifetime defaults, start external systems, or qualify deployment behavior.
