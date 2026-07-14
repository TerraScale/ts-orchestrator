# Phase 1 networking policy core handoff

## Delivered

- Bounded typed identities with no public mutation/clone-forgery path, canonical defensive-copy binary addresses/prefixes, ports, positive generations/epochs, closed policy catalogs, stable numeric traces, and exact route/endpoint intent subjects.
- Route/tunnel authorization binds cell, network, subnet, route, peer, tunnel, trust plane, route kind, prefix, generation, epoch, and operation. It rejects stale/future authority, duplicate or ambiguous routes, overlaps, leaks, reflection, trust-plane crossover, and wrong-cell evidence.
- Topology evidence includes a bounded defensive-copy cell inventory and explicit directed peer links. Launch full mesh requires exactly three cells and every directed non-self pair. Hub/spoke requires exactly one hub, bidirectional links to every inventory spoke, no spoke-to-spoke links, and exact linear edge cardinality; explicit replication remains linearly bounded. Route scopes must name inventory members and non-local routes must prove their adjacency. Partition operation cannot acquire global authority and is restricted to an explicitly approved local product route.
- Tunnel changes stage configuration before traffic/health proof and route activation; contradicted proof emits deterministic rollback.
- Endpoint policy binds cell/workload/service/endpoint/node/LB/backend/DNS/certificate/exposure/protocol/port/generation/epoch/operation. Default deny, readiness, backend health, trust, certificate, production gate, owner approval, and tested withdrawal gate public ingress.
- Administration and monitoring endpoints are private-only. DNS lost responses observe convergence without duplicate updates. Deregistration precedes drain. Emergency withdrawal deterministically removes DNS before LB and separates requests from observed convergence.
- All planner entry points totalize null, malformed observation fields, and out-of-domain enum values into typed non-authorizing decisions. Endpoint process liveness is an enforced registration prerequisite.
- Adversarial tests cover replay, stale/future state, identity and scope forgery, malformed/null evidence, invalid enums, reflection, overlap/leak/crossover, disguised quadratic mesh, missing scope cells, inventory bounds, partition locality, process liveness, partial tunnel failure, stale health, public/admin denial, certificate mismatch, registration crash steps, drain ordering, and emergency withdrawal.

## Boundaries

This is a pure policy core. It contains no VPN/provider/DNS/LB client, config text, key material, credential, command, callback, SDK, socket, process, filesystem/network I/O, clock, address pool, health threshold, or default exposure implementation.

## Verification

- `dotnet build TerraScale.Orchestrator.slnx --no-restore` — passed with 0 warnings and 0 errors.
- `dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build -- --minimum-expected-tests 100` — passed (204/204).

## Contract gaps

No additional gap was proven by this focused locality audit. Adapters must persist request and convergence checkpoints and preserve exact typed subjects; provider-specific address pools, routing priorities, certificates, exposure approvals, and health thresholds remain caller inputs.

## Second policy audit correction

The adversarial audit proved that `RouteKind.Local` was only a caller-supplied label. A scope with `Cell=gru` and `PeerCell=sfo` could therefore bypass the cross-cell adjacency requirement and, while partitioned, emit a remote `ConfigureTunnel` intent when local product policy was proven. Connected operation had the same structural relabeling weakness.

Locality is now an identity invariant: every `Local` route must have `PeerCell == Cell`. A connected relabeled remote route holds with `WrongEvidenceScope`. During a partition, the existing `LocalPolicyRequired` precedence remains first and a policy-proven relabeled remote route holds with `PartitionAuthorityDenied`. Valid self-cell local routes and explicitly linked cross-cell peer routes retain their accepted behavior; a non-local self-cell route remains impossible because valid topology evidence cannot contain a self link.

This correction adds no public member, factory, enum value, numeric code, trace field, or accepted subject field. It preserves the closed inventories and uses the existing denial codes. The policy remains pure and performs no VPN, provider, DNS, load-balancer, socket, process, filesystem, cloud, VM, or deployment operation.

Post-rebase verification on the central candidate:

- locked restore: all projects up to date;
- Release solution build with warnings as errors: 0 warnings and 0 errors;
- focused networking core: 8/8 passed;
- ControlPlane: 534/534 passed;
- all five suites: 733/733 passed (`534 + 24 + 38 + 65 + 72`).
