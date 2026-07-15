# Phase 1 networking accepted-output provenance audit 4

## Basis and scope

- Exact central basis: `215fb482a2f29ec96c37f5f7c85ef9ea26de29b5`.
- Bounded surface: pure networking route/tunnel and endpoint decision outputs, deterministic replay, and public construction/accessor/clone closure.
- Excluded: VPN, peering, routing, DNS, load-balancer, firewall, cloud, VM, process, socket, filesystem, clock, or any other external effect.

## Proven counterexamples

The pre-production executable counterexamples exposed three accepted-output collisions:

- two successful `ConfigureTunnel` decisions with the same scope and observations but different accepted route evidence compared equal;
- two successful `Register` decisions with the same scope but different accepted endpoint evidence compared equal;
- successful registration and removal plans over the same scope and evidence produced equal endpoint subjects, erasing the semantic planner route.

All three failed before the correction and pass afterward.

## Correction

- Every accepted route subject retains the exact accepted scope reference, observed generation, observed epoch, and evidence reference. Existing flattened getters are projections of that scope.
- Every accepted endpoint subject retains a fixed plan kind (`Register`, `Removal`, or `EmergencyWithdrawal`) plus the exact accepted scope and evidence references. Existing flattened getters are projections of that scope.
- Route evidence now has structural equality and hashing over every scalar and every captured collection. Routes, approved prefixes, topology links, and topology cells use order-insensitive multiset semantics: permutation is ignored, while duplicate cardinality and every typed leaf remain significant.
- Held decisions retain no accepted subject. No new public factory, public constructor, public setter, or deconstruction route was introduced.

## Proof inventory

Executable proofs cover all five accepted route branches, all five registration branches, all four removal branches, and all five emergency-withdrawal branches. They also cover exact-reference retention, reconstructed evidence equality and hashing, actual multi-entry permutations, duplicate cardinality, every route-evidence scalar and collection leaf, all 15 independently varied route-scope leaves (including destination address, address bit length, and prefix bits), both subject observation ordinals, all endpoint-scope and endpoint-evidence fields, and default/value-copy/record-clone behavior.

A single exact signature allowlist inventories every exported public declared method or accessor returning a decision, base or concrete subject, retained route/endpoint scope, retained route/endpoint evidence, numeric trace, or route-evidence collection projection. It pins the four planner origins, decision and subject accessors, base and concrete record clones, and legitimate input projections; concrete subject clones are invoked and proven to retain the exact basis references.

The strict whole-file-pinned replay corpus now includes route-evidence provenance and endpoint-plan provenance cases. A separate 1,000-case replay proves stable accepted provenance across `tr-TR` and `ar-SA` cultures with unique typed operations and generations.

## Nonclaims

This audit proves only pure decision and intent provenance. It does not configure, persist, observe, or reconcile any concrete network resource. Provider implementation, durable Pulumi reconciliation, credentials, address allocation, routing priorities, certificates, exposure approvals, and health thresholds remain outside this work package.
