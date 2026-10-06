# TerraScale Orchestrator documentation

These pages describe the current greenfield Go implementation.

| Document | Purpose |
| --- | --- |
| [Architecture and boundaries](architecture.md) | Regional NATS, authority, host delivery, OCI scope, and current limits |
| [Unified CLI](cli.md) | Prefer Go `ts-orch` commands for operational tooling; bootstrap/release migration and remaining scripts |
| [Contributing](../CONTRIBUTING.md) | CLI-first Go feature development, automation boundaries, and verification |
| [Multi-region foundation](multi-region.md) | Feature-flagged interregion leafnodes, global control stream, region lifecycle and planner |
| [NATS fabric](nats-fabric.md) | Orchestrator-to-orchestrator transport: subject, stream and KV naming, which pattern to use, global documents |
| [Manual regional bootstrap](region-bootstrap.md) | Operator-created regional foundation and controller A, followed by orchestrator-managed peers and workloads |
| [Local development](local-development.md) | Toolchain, build, test, and Firecracker qualification |
| [Build and release](releases.md) | Exact-source CI checks and static Linux binaries |
| [Continuous delivery](continuous-delivery.md) | Opt-in TerraBase release automation, signed image replacement design and human trust decisions |
| [Broker account rotation](broker-claim-rotation.md) | Operator `broker-claim-apply` procedure and receipts |
| [Observability](observability.md) | Private metrics/health listener, structured logs, event bus and cell-wide snapshots |
| [Self-healing and automatic maintenance](self-healing.md) | TS-568 design and slices: credential expiry watch, `ts-orch doctor`, renewal, host repair, OS patching, drift and SLOs |
| [Decision journal](decision-journal.md) | Recording decisions (call pattern for every slice), metric history, insights, summaries and the region view |
| [TerraBase cell autoscaler](cell-autoscaler.md) | Node pressure contract, scaling rules, safety rails and `ts-orch cell-autoscaler` |
| [Autoscaling](autoscaling.md) | Replicas on load, node pools of OCI hosts, the cell budget cap and the TS-565 slice plan |
| [Workspace GOAL](../../GOAL.md) | Current cross-repository delivery authority and status |
| [Shared-goal acceptance ledger](evidence/shared-goal-acceptance-20260926.md) | Gate index, formal count, live preview entries and current handoff; one evidence file per gate in [`evidence/gates/`](evidence/gates/) and per pipeline lane in [`evidence/pipeline/`](evidence/pipeline/) |
| [Qualification status 2026-09-26](qualification-status-20260926.md) | Dated migration and qualification snapshot; not the current gate ledger |
| [Production readiness checkpoint](production-readiness.md) | Checkpoint status and open areas |
| [Production readiness plan](production-readiness-plan.md) | Dated readiness audit, historical canary, and open gate order |
| [TerraBase runtime contract](terrabase-runtime-contract.md) | C# TerraBase binary: release assets, settings, member certificates, host launch, health gate and drain |
| [TerraBase deployment](terrabase-deployment.md) | Member CA, workload profile and `operator terrabase-release` rollout with automatic rollback |
| [Managed volumes](managed-volumes.md) | Fly-style OCI block volumes for machines: model, placement, reconciler, migration and cost (TS-567) |
| [Secrets in OCI Vault](secrets.md) | Naming scheme, compartments and host grants, `ts-orch vault put` and `render`; OpenBao retired |
| [Cell spec](cell-spec.md) | A running cell's signed desired state: `ts-orch get`, `diff` and `apply`, root-gated changes, binary levels; runbook "Add a service to a running region" |
| [Apps and machines](apps-machines.md) | The shared orchestration model (apps, machines, regions, node pools) in `TS_APPS`, its invariants and the TS-563 slices |
| [Material generations](material-generation.md) | TS-568 in-place renewal: root-signed generations that pin a cell's renewable material, and `ts-orch bootstrap sign-material-generation` |
| [Settings in the cell spec](settings-in-cell-spec.md) | TS-569 design: raw config digest, versioned config and tolerant record decoding, and moving each mutable setting into a cell spec section |
| [Machines API](machines-api.md) | The controllers' Fly-style REST API: ts-auth token verification, scopes and organization tenancy, endpoints, errors and the planned slices |
| [Image updates in place](image-updates.md) | Host image allow-list and launch image in the cell spec; planned OS package and boot volume replacement slices |
| [Root key rotation](root-rotation.md) | Baked roots as genesis of a KV root chain, the leaked-root threat model and the rotation runbook |
| [Dedicated tenants](dedicated-tenants.md) | A tenant's own TerraBase cluster and ts-auth: model, lifecycle, isolation, endpoints, secrets, backups and metering |
| [ts-auth deployment](ts-auth-deployment.md) | ts-auth on the gru-1 controllers: placement, Vault secret refs, TerraBase tenant, load balancer values and the live runbook |
| [TerraBase serving lifecycle](terrabase-serving-lifecycle-plan.md) | Current health gate, drain and rollback; open replication, membership, serving proof and scale-in work |
| [Generic workloads](generic-workloads.md) | The generic workload spec on apps and machines, artifact kinds, native and OCI runtime drivers, and TerraBase and ts-auth as templates |
| [Zero-downtime TerraBase rollouts](terrabase-zero-downtime-rollouts.md) | TS-571: L7 backend-set reconciler with drain and health guard, seats as backends, one seat at a time through a restart permit |
| [Deployment convergence benchmark](benchmarks/deployment-convergence-20260925.md) | In-memory deploy-to-apply latency measurement |
