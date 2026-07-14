# Phase 1 reconciliation property/replay shard

## Goal

Exercise the existing pure desired/observed reconciliation engine with independent generated oracles and a strict deterministic replay corpus.

## Scope

- At least 1,000 materially distinct cases for deterministic dependency ordering and exact output subjects.
- At least 1,000 cases spanning exact, missing, stale, failed, held, future, conflicting, and drifted observations.
- At least 1,000 cases spanning missing dependencies, cycles, dependency holds, duplicate resources, and trace/root precedence.
- Desired, observed, and dependency permutations replay identically across non-English cultures.
- A byte-bounded, whole-file SHA-256-pinned, strict-vocabulary, input-sensitive embedded replay corpus.

## Boundary and non-claims

This shard tests a pure decision engine. It performs no filesystem, network, process, NATS, provider, cloud, deployment, or sibling-repository operation and makes no L0/L0C or production-readiness claim. Caller-controlled collection acquisition hardening remains owned by the accepted-output construction-closure work because it is changing `ReconciliationContracts.cs` concurrently.
