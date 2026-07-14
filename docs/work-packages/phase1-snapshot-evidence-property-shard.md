# Phase 1 snapshot and pre-deployment evidence property/replay shard

## Goal

Exercise the existing signed-snapshot restore and pre-deployment evidence pure cores with deterministic, independently checked generated cases and a strict replay corpus.

## Scope

- At least 1,000 cases per snapshot epoch/position freshness, signed-field corruption, deterministic restore replay, malformed/corrupt/overflow refusal, evidence generation/expiry freshness, and evidence permutation/culture property.
- Restore never moves over a newer accepted epoch or equal/older journal position; replay begins exactly after the authenticated snapshot position.
- Every signed scope/version/position/digest field remains bound by exact scope checks or the opaque signature verifier.
- Strict byte-bounded, whole-file SHA-256-pinned, closed-vocabulary, input-sensitive replay corpus.
- Construction-closed validation, restore-plan, and deployment-evidence authorization outputs.

## Boundary and non-claims

This shard is pure decision testing. It performs no filesystem, network, process, NATS, cloud/provider, deployment, or sibling-repository operation and makes no L0/L0C, cryptographic-algorithm, external-signature, snapshot persistence, deployment-authority, or production-readiness claim.
