# TerraScale Orchestrator documentation

These pages describe the current greenfield Go implementation.

| Document | Purpose |
| --- | --- |
| [Architecture and boundaries](architecture.md) | Regional NATS, authority, host delivery, OCI scope, and current limits |
| [Local development](local-development.md) | Toolchain, build, test, and Firecracker qualification |
| [Build and release](releases.md) | Exact-source CI checks and static Linux binaries |
| [Broker account rotation](broker-claim-rotation.md) | Operator `broker-claim-apply` procedure and receipts |
| [Qualification status 2026-09-26](qualification-status-20260926.md) | Latest migration and qualification status |
| [Production readiness checkpoint](production-readiness.md) | Checkpoint status and open areas |
| [Production readiness plan](production-readiness-plan.md) | GRU canary envelope, acceptance ledger, and gate order |
| [TerraBase runtime contract](terrabase-runtime-contract.md) | Managed-member placement, host, and member-status boundary |
| [TerraBase serving lifecycle plan](terrabase-serving-lifecycle-plan.md) | Proposed managed-Raft serving and retirement direction |
| [Deployment convergence benchmark](benchmarks/deployment-convergence-20260925.md) | In-memory deploy-to-apply latency measurement |
