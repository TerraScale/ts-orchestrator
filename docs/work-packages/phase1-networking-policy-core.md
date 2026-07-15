# Phase 1 networking, VPN, DNS, and ingress policy core

## Predecessor

- Contract steward commit: `069fccf`
- VPN implementation, address pools, DNS/LB provider, exposure policy, route priorities, certificate policy, and health thresholds remain explicit inputs.

## Goal

Implement pure network intent, peering/VPN route ownership, DNS/LB backend, and exposure authorization decisions from `ORCHESTRATOR.md:873-879,1096-1110`. It emits typed network intents only.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Networking/**`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Networking*.cs`
- `docs/work-packages/handoffs/phase1-networking-policy-core.md`

## Required behavior

- Immutable bounded cell/network/subnet/node/workload/service/endpoint/route/peer/tunnel/DNS/LB/backend/certificate/operation identities; canonical address/prefix/port values; positive generations/epochs; closed exposure, protocol, route, tunnel, backend, health, and action catalogs.
- Exact desired/observed route and tunnel ownership; reject overlapping/conflicting address spaces, ambiguous longest-prefix ownership, cross-cell authority, stale/future generations, duplicate peers/routes, route leaks, and product/control trust-plane crossover.
- VPN/peering changes are staged and reversible until explicit traffic/health proof. A partition never grants global authority; regional survival routes remain bounded to the caller-approved local policy.
- DNS/LB registration binds exact service generation, admitted endpoint, certificate reference, health/readiness, cell, exposure, and operation. Deregistration precedes drain/termination. Monitoring/admin endpoints cannot be public/workload-exposed.
- Backend health is distinct from process liveness; stale/missing health holds removal/promotion as appropriate. Public exposure requires exact approval and certificate/trust proof; default deny.
- Emit closed observe/configure-route/configure-tunnel/register/deregister/promote/DNS-update/rollback/hold intents with typed parameters and stable code/numeric trace; no config text, key material, credential, command, callback, SDK, socket, or I/O.
- Defensive copies; culture/permutation/replay; prefix overlap; route leak; wrong authority; tunnel partial failure; stale health; backend drain ordering; public admin denial; certificate mismatch; DNS lost response; and forbidden-shape/secret-safe tests.
- No VPN/provider/DNS/LB/network/filesystem/clock package, address/exposure/health/default implementation, or mutation.

## Verification

`dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj`

