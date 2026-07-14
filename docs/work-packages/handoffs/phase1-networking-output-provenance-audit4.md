# Phase 1 networking accepted-output provenance audit 4 handoff

## Delivered

- Route accepted subjects retain the exact accepted scope, observed generation and epoch, and complete route evidence.
- Endpoint accepted subjects retain the exact accepted scope and evidence plus the semantic planner route: registration, removal, or emergency withdrawal.
- Legacy subject accessors remain available and derive from the retained scope, preventing two independent representations from drifting.
- Route evidence equality and hashing are structural and culture-independent. Semantic collection ordering is ignored, but duplicate count, typed identity, binary prefix, route ownership, peer linkage, trust plane, topology shape, proof state, and partition state are all preserved.
- Every held networking decision remains non-authorizing and has a null subject.
- Public construction remains closed to the four planner entry points. Decision default/value copy and subject record clone routes cannot add authority or replace retained basis references.

## Verification evidence

- Pre-correction counterexample run: 3/3 failed with accepted-output equality collisions.
- Post-correction focused provenance suite: 11/11 passed.
- Post-correction ControlPlane suite: 654/654 passed.
- Test-project warnings-as-errors build: 0 warnings and 0 errors.
- Strict replay corpus: 25 entries, whole-file SHA-256 pinned.

Final Release solution and five-suite verification are performed after the required exact-central rebase; record those final counts in the coordinating review.

## Boundaries

The implementation remains a pure L0 policy core. It performs no VPN, peering, route, DNS, load-balancer, firewall, provider, network, cloud, VM, process, filesystem, or clock effect. Adapters must durably persist the exact retained scope/evidence and map the fixed semantic plan kind without weakening policy.
