# Phase 0 evidence summary

> Historical phase evidence. Preserve its receipts and measured gaps, but do
> not use its old R3, dual-NATS, service-role, or placement assumptions as
> current architecture.

> Consolidated 2026-07-17 from Phase 0 audits, readiness packets, and owner decisions.

Git history retains the former readiness map, owner-decision packet, audit
documents, and retirement ledger.

## Status posture

- Owner choices **1A–10A accepted** on 2026-07-16 with reliability first.
- Numeric cost, storage IOPS/latency, regional RPO/RTO, and related qualification targets remain **evidence-derived deployment gates**, not pure-contract blockers.
- No SUT cloud instance, cloud mutation, or deployment authority before exact-tree L0/L0C evidence.
- ADR readiness: four draft ADRs exist (ownership, GitOps, placement, actuator fencing); remaining backlog items still need measurements, primary sources, or detailed design drafts.

## Owner decisions (normative A choices)

| # | Topic | Selected A |
|---|---|---|
| 1 | Regional control topology | 3 controllers + 3 control-NATS per region (independent JetStream R3); no WAN control quorum |
| 2 | GRU/WAN outage | Regions serve/heal/scale/expand/renew; freeze new global releases/policy |
| 3 | Vault authority | Built-in policy/PKI/lease with OCI Vault/KMS root protection initially |
| 4 | Runtime defaults | Native systemd TerraBase; containers Platform/Auth/Dashboard; both supported |
| 5 | Elastic data cleanup | Never shrink permanent; quarantine elastic TerraBase disk 7 days after verified backup |
| 6 | Provider timing | OCI + provider-neutral contract first (≥20 region catalog); more adapters later |
| 7 | CI bootstrap | One minimal independent Forgejo recovery path for orchestrator; product CI is native |
| 8 | Dedicated NATS | Independent clusters/processes/security/cgroups/stores; may share compact hosts |
| 9 | Telemetry outage | OTel all signals, encrypted spool, drop-oldest with alerts; never block product |
| 10 | Autoscaling lab count | 9 seed containers steady-state; elastic temps allowed then converge to 3/cell |

## Phase 0 evidence streams

### Build and toolchain

- **Build baseline:** pinned .NET SDK 10.0.301 restores/builds; self-contained `linux-x64` and `linux-arm64` publish succeed. Local NixOS x64 apphost embeds a Nix-store interpreter and is **not** portable release evidence. ARM64 publish has not been executed on A1.
- **Historical local toolchain audit (2026-07-13, NixOS 26.11 x86_64):** the Git record observed `dotnet` 10.0.301, `nats-server` 2.14.3, systemd 261, OCI CLI 3.89.1, and Pulumi 3.251.0; containerd/runc/BuildKit/signing tools were often absent. This NixOS audit does not evidence OCI CLI availability on the current Ubuntu preflight host. Presence ≠ pin or qualification.
- **Supply-chain candidates:** versioned candidate set (FsCheck, coverage, Stryker, signing tools, …) recorded as **unselected**. Mutation tool remains candidate-unselected; no mutation score may be claimed.

### NATS readiness

- Server candidates 2.14.3 / 2.12.7; clients `NATS.Net` 3.0.0 / 2.8.2; CLI 0.4.0 — all unselected.
- Digests/URLs pinned for official amd64/arm64 assets where available.
- N/N-1 policy remains null; mixed-version matrix unexecuted.
- Local evidence: credential-free x64 loopback smoke only (pub/sub, request/reply, single-server JetStream, monitoring). Full L0C, ARM64, production durability **not** achieved.

### Product contracts and CI descriptors

- Sibling product repositories inventoried for runtime/build/health/release contracts (API, Auth, Dashboard, TerraBase).
- Authentication build-target gap and other contradictions recorded as inventory, not silently “fixed” by policy invention.
- 156 first-party descriptors across ten repos classified (workflows, deploy.json, Dockerfiles, solutions, locks).
- Observed conflicts (Flux-era strategy strings, hard-coded region trios) are retirement/GitOps inputs, not compatibility contracts.

### Provider / OCI / ARM64

- **OCI residual inventory incomplete:** the removed host preflight could not run an OCI API request. The older record in Git history failed authentication before resource discovery. Neither record proves resource absence or grants cleanup authority.
- **Provider qualification schema** drafted for capability matrices without selecting a second cloud.
- **ARM64/A1 readiness** is a candidate inventory (host image, filesystem, systemd/containerd/runc versions remain null). Local x64 cannot masquerade as ARM qualification.

### Registry and retirement

- Requirements registry v2 review found useful source-anchor baseline but incomplete semantic/evidence validation; steward follow-ups catalogued.
- **Workaround ledger** (`WRK-*`) tracks greenfield cleanup of Kubernetes/Flux/OKE behaviors that must be preserved as native contracts then retired.
- The live requirements registry tree was later removed from the repository; historical registry audit artifacts remain in the archive.

### Mutation foundation

- Fail-closed mutation inventory/policy/report foundation exists without selecting or running a mutation engine.
- Composition-root exclusion proofs are policy-only, not score evidence.
- Thresholds (for example 85% score / zero safety survivors) preserved as requirements, not claims.

## Still open (honest gaps)

1. Owner-approved measurable SLOs: cost, storage performance, RPO/RTO, security TTLs, density, audit retention, survival window.
2. NATS N/N-1 policy selection and full L0C (including dual-plane JWT/TLS/gateway/JetStream).
3. Supply-chain pin selection, internal mirrors, SBOM/signing, mutation engine choice.
4. ARM64 host image + real A1 execution; hermetic non-NixOS publish.
5. Complete OCI residual inventory after successful scoped discovery.
6. Later implementation selections: artifact signing tech, DNS, VPN product, IdP, regional mirror.
