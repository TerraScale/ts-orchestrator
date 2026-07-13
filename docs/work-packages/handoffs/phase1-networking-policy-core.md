# Phase 1 networking policy core handoff

## Delivered

- Bounded typed identities, canonical defensive-copy binary addresses/prefixes, ports, positive generations/epochs, closed policy catalogs, stable numeric traces, and exact route/endpoint intent subjects.
- Route/tunnel authorization binds cell, network, subnet, route, peer, tunnel, trust plane, route kind, prefix, generation, epoch, and operation. It rejects stale/future authority, duplicate or ambiguous routes, overlaps, leaks, reflection, trust-plane crossover, and wrong-cell evidence.
- Topology shape is explicit: launch full mesh is rejected beyond three cells, while hub/spoke and explicit replication remain bounded caller inputs. Partition operation cannot acquire global authority and is restricted to an explicitly approved local product route.
- Tunnel changes stage configuration before traffic/health proof and route activation; contradicted proof emits deterministic rollback.
- Endpoint policy binds cell/workload/service/endpoint/node/LB/backend/DNS/certificate/exposure/protocol/port/generation/epoch/operation. Default deny, readiness, backend health, trust, certificate, production gate, owner approval, and tested withdrawal gate public ingress.
- Administration and monitoring endpoints are private-only. DNS lost responses observe convergence without duplicate updates. Deregistration precedes drain. Emergency withdrawal deterministically removes DNS before LB and separates requests from observed convergence.
- Adversarial tests cover replay, stale/future state, forgery, reflection, overlap/leak/crossover, quadratic mesh, partition locality, partial tunnel failure, stale health, public/admin denial, certificate mismatch, registration crash steps, drain ordering, and emergency withdrawal.

## Boundaries

This is a pure policy core. It contains no VPN/provider/DNS/LB client, config text, key material, credential, command, callback, SDK, socket, process, filesystem/network I/O, clock, address pool, health threshold, or default exposure implementation.

## Verification

- `dotnet build TerraScale.Orchestrator.slnx --no-restore` — passed with 0 warnings and 0 errors.
- `dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build -- --minimum-expected-tests 100` — passed (204/204).

## Contract gaps

None found within the pure-core boundary. Adapters must persist request and convergence checkpoints and preserve exact typed subjects; provider-specific address pools, routing priorities, certificates, exposure approvals, and health thresholds remain caller inputs.
