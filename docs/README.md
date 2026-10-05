# TerraScale Orchestrator documentation

These pages describe the current greenfield Go implementation.

| Document | Purpose |
| --- | --- |
| [Architecture and boundaries](architecture.md) | Regional NATS, authority, host delivery, OCI scope, and current limits |
| [Unified CLI](cli.md) | Prefer Go `ts-orch` commands for operational tooling; bootstrap/release migration and remaining scripts |
| [Contributing](../CONTRIBUTING.md) | CLI-first Go feature development, automation boundaries, and verification |
| [Multi-region foundation](multi-region.md) | Feature-flagged interregion leafnodes, global control stream, region lifecycle and planner |
| [Manual regional bootstrap](region-bootstrap.md) | Operator-created regional foundation and controller A, followed by orchestrator-managed peers and workloads |
| [Local development](local-development.md) | Toolchain, build, test, and Firecracker qualification |
| [Build and release](releases.md) | Exact-source CI checks and static Linux binaries |
| [Continuous delivery](continuous-delivery.md) | Opt-in TerraBase release automation, signed image replacement design and human trust decisions |
| [Broker account rotation](broker-claim-rotation.md) | Operator `broker-claim-apply` procedure and receipts |
| [Observability](observability.md) | Private metrics/health listener, structured logs, event bus and cell-wide snapshots |
| [Decision journal](decision-journal.md) | Recording decisions (call pattern for every slice), metric history, insights, summaries and the region view |
| [TerraBase cell autoscaler](cell-autoscaler.md) | Node pressure contract, scaling rules, safety rails and `ts-orch cell-autoscaler` |
| [Workspace GOAL](../../GOAL.md) | Current cross-repository delivery authority and status |
| [Shared-goal acceptance ledger](evidence/shared-goal-acceptance-20260926.md) | Gate index, formal count, live preview entries and current handoff; one evidence file per gate in [`evidence/gates/`](evidence/gates/) and per pipeline lane in [`evidence/pipeline/`](evidence/pipeline/) |
| [Qualification status 2026-09-26](qualification-status-20260926.md) | Dated migration and qualification snapshot; not the current gate ledger |
| [Production readiness checkpoint](production-readiness.md) | Checkpoint status and open areas |
| [Production readiness plan](production-readiness-plan.md) | Dated readiness audit, historical canary, and open gate order |
| [TerraBase runtime contract](terrabase-runtime-contract.md) | C# TerraBase binary: release assets, settings, member certificates, host launch, health gate and drain |
| [TerraBase deployment](terrabase-deployment.md) | Member CA, workload profile and `operator terrabase-release` rollout with automatic rollback |
| [Secrets in OCI Vault](secrets.md) | Naming scheme, compartments and host grants, `ts-orch vault put` and `render`; OpenBao retired |
| [Services](services.md) | Add, update and remove a running cell's services with signed service sets; runbook "Add a service to a running region" |
| [ts-auth deployment](ts-auth-deployment.md) | ts-auth on the gru-1 controllers: placement, Vault secrets and env file, TerraBase tenant, load balancer values and the live runbook |
| [TerraBase serving lifecycle](terrabase-serving-lifecycle-plan.md) | Current health gate, drain and rollback; open replication, membership, serving proof and scale-in work |
| [Deployment convergence benchmark](benchmarks/deployment-convergence-20260925.md) | In-memory deploy-to-apply latency measurement |
