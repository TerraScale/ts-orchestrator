# TerraScale Orchestrator documentation

These pages describe the current greenfield Go implementation.

| Document | Purpose |
| --- | --- |
| [Architecture and boundaries](architecture.md) | Regional NATS, authority, host delivery, OCI scope, and current limits |
| [Manual regional bootstrap](region-bootstrap.md) | Operator-created regional foundation and controller A, followed by orchestrator-managed peers and workloads |
| [Local development](local-development.md) | Toolchain, build, test, and Firecracker qualification |
| [Build and release](releases.md) | Exact-source CI checks and static Linux binaries |
| [Continuous delivery](continuous-delivery.md) | Opt-in TerraBase release automation, signed image replacement design and human trust decisions |
| [Broker account rotation](broker-claim-rotation.md) | Operator `broker-claim-apply` procedure and receipts |
| [Workspace GOAL](../../GOAL.md) | Current cross-repository delivery authority and status |
| [Shared-goal acceptance ledger](evidence/shared-goal-acceptance-20260926.md) | Dated cross-repository gate and evidence snapshot |
| [Qualification status 2026-09-26](qualification-status-20260926.md) | Dated migration and qualification snapshot; not the current gate ledger |
| [Production readiness checkpoint](production-readiness.md) | Checkpoint status and open areas |
| [Production readiness plan](production-readiness-plan.md) | Dated readiness audit, historical canary, and open gate order |
| [TerraBase runtime contract](terrabase-runtime-contract.md) | Managed-member placement, host, and member-status boundary |
| [TerraBase serving lifecycle plan](terrabase-serving-lifecycle-plan.md) | Proposed managed-Raft serving and retirement direction |
| [Deployment convergence benchmark](benchmarks/deployment-convergence-20260925.md) | In-memory deploy-to-apply latency measurement |
