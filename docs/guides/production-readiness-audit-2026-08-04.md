# Production-readiness exploration and implementation report

> Historical audit of the architecture implemented on 2026-08-04. It is useful
> for code and evidence gaps, but its R3 TerraBase, dual-NATS, Platform,
> Authentication, MagicOnion, and old placement assumptions are superseded by
> the current architecture. Its development-lane references describe surfaces
> deleted by the repository `GOAL.md` P0 purity sweep on 2026-08-29; they are
> records of what the audit reviewed, not available tooling.

Date: 2026-08-04
Scope: `TerraScale.Orchestrator` on `develop`, including only its owned production-control-plane concerns. Retired Kubernetes/Flux repositories were not used or modified.

## Result

The repository has a substantial Phase 1 decision core and a useful development integration harness. It is **not ready for a first production deployment**: critical OCI, storage, TerraBase, runtime, observability, VPN, and operator-access adapters have not reached the required real-system qualification. No current evidence may be treated as an A1, systemd, R3, backup/restore, or disaster-recovery acceptance result.

This audit also closed a fail-open configuration gap: production `run` and the operator status client now reject a plaintext or anonymous regional control-NATS connection before attempting to connect. They require a `tls://` endpoint, an owner-private NKey seed, and complete mTLS files. The local `check` and `lab` paths remain available for credential-free development evidence; they are not production authorization paths.

No secret material or Polar credential was read, printed, or changed during this audit.

## Evidence reviewed

- Normative architecture and invariants: [`docs/architecture/orchestrator.md`](../../docs/architecture/orchestrator.md), especially the regional-autonomy, dual-NATS, mTLS, native GitOps, Phase 0–10, and production-gate sections.
- Current entry points and runtime configuration: `Program.cs`, `OrchestratorOptions.cs`, `Messaging/NatsRuntime.cs`, `Messaging/GlobalNatsRuntime.cs`, and `Operations/OperatorCli.cs`.
- Pure decision domains and their test suites: authority, operations, scheduling, provider ownership, storage, TerraBase, identity, delivery, observability, networking, runtime, evidence, protocol, and deterministic models.
- Development integration implementation: the former `Development/*` rootless local lab, generated development PKI, NATS topology, and workload wiring (deleted 2026-08-29 by the GOAL P0 sweep).
- Delivery/CI: `.terrascale/ci-v2.json`, `.terrascale/ci.Dockerfile`, Forgejo source/webhook handling, CI runner isolation, and signed GitOps handoff journals.

## Capability map

| Area | Implemented now | Production gap / required gate |
|---|---|---|
| Authority and regional operations | Pure fenced leadership, operation replay, regional NATS journals, global-to-cell signed handoffs, and deterministic adversarial tests exist. | No production three-controller/R3 regional deployment, WAN/GRU outage drill, or real regional survival-bundle recovery. |
| Provisioning and host lifecycle | Provider ownership/handoff decisions, closed role catalog, canonical systemd/containerd plans, and a narrow OCI CI-runner adapter exist. | No Pulumi foundation/retain-unmanage implementation, general OCI compute/block-volume actuator, real containerd gRPC adapter, signed artifact staging/A-B upgrade path, or systemd-as-PID-1 qualification. |
| TerraBase, database branching, backup and DR | Typed topology, member permanence, upgrade, backup-chain, and side-by-side restore planners are well covered as pure logic. | No TerraBase administrative adapter, application-consistent backup implementation, object-store restore, three-member boundary lane, six-route replication, or real retained-volume recovery. Product database/branch placement remains correctly outside this host scheduler. |
| Storage | Typed single-writer, formatting, expansion, retention, and deletion decisions are present. | No OCI Block Volume/device/filesystem adapter or ext4/XFS real destructive recovery evidence. |
| Messaging and security | Global control NATS already requires R3 plus distinct mTLS/NKey identity; regional development PKI and bounded credential-file validation exist. This audit makes `run` and operator status fail closed on regional plaintext/anonymous configuration. | No selected/pinned NATS N/N-1 policy, complete real NATS L0C, production JWT/account provisioning, revocation implementation, or production PKI/Vault/KMS service. |
| Native GitOps and delivery | Forgejo webhook HMAC verification, polling fallback, durable CI/release/candidate journals, source graph, CI runner isolation, and signed cell handoff are implemented. | No complete production workload apply/reconcile path, signed-artifact production trust root, recovery bootstrap workflow, or evidence-gated deployment credential service. |
| Observability and reliability | Bounded OTLP exporter configuration, telemetry/alert/Grafana pure models, and development health probes exist. | No HA Grafana/metrics/log/trace deployment, encrypted regional spool, Alertmanager/OTLP outage drill, or live operator-state data source. |
| Operator surface and internal RPC | `ctl` currently has a read-only NATS status request and now requires mTLS/NKey. Development wiring gives Platform and Authentication isolated loopback MagicOnion ports. | There is no production operator API/OIDC/RBAC/break-glass boundary. There is no production MagicOnion server/configuration, mTLS peer-identity enforcement, private listener policy, or readiness dependency from Platform to Authentication RPC. Development cleartext loopback wiring must not be promoted as production behavior. |
| Network and VPN | Pure routing/exposure decisions and a closed VPN role exist. | No selected/proven VPN implementation, production DNS/LB adapter, private operator ingress policy, or twenty-region connectivity qualification. |

## Highest-priority next work

1. Select and pin the production NATS/JWT/toolchain/host-image/credential-signing inputs, then run the real dual-plane L0C contract before any server or cloud lane.
2. Implement the production regional NATS account/bootstrap configuration and a real mTLS/NKey identity lifecycle; add certificate identity/EKU/SAN and account-permission conformance tests.
3. Deliver the Pulumi-to-regional-controller handoff plus a narrowly scoped OCI actuator with persisted intent, idempotency, fencing, and provider-truth recovery before adding broad autoscaling behavior.
4. Implement real systemd/containerd and TerraBase/storage adapters one boundary at a time; qualify them with L1R/L2S/L4 rather than expanding the local RF=1 lab.
5. Design production MagicOnion wiring in the runtime descriptor: non-ingress port allocation, expected peer SPIFFE identity, mTLS, no Dashboard/SDK/CLI exposure, and Platform readiness on Authentication RPC.
6. Build the operator API/identity/RBAC/audit boundary and its read-only Grafana projection before adding browser mutation capability.

## Explicit constraints retained

- No Kubernetes, Flux, OKE, Helm, CRD, or retired-stub path is a runtime or migration dependency.
- Dashboard remains an external TerraScale user; this repository must not create Dashboard-specific privileged routes or credentials.
- Internal MagicOnion is reserved for TerraScale-owned backend processes and must remain isolated from REST, public health probes, SDKs, CLI, NATS, TerraBase, and third parties.
- The unresolved measurable SLOs (cost, storage performance, RPO/RTO, retention, and regional-survival window) remain deployment gates rather than values inferred by this audit.

## Validation

Focused build and the affected Orchestrator test executable are pending after the configuration change. They must run sequentially under the repository validation lease; no SUT, Podman, systemd, cloud, or production mutation test is authorized by this report.
