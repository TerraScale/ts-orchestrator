# Phase 0/1 provider handoff determinism audit handoff

## Proven gap and correction

The handoff evaluator already compared Expected, Pulumi, and Regional inventories as sorted set-like projections. All proof checks could therefore accept independently permuted inventories. The emitted `EnableRegionalSelfManagementIntent`, however, retained the three original caller orders. Equivalent fully verified handoffs consequently exposed different adapter-facing sequences.

`FreshBootstrapInventory` now applies the evaluator and fingerprint's canonical order at its defensive-copy boundary: resource ID ordinal, resource kind, then generation. This retains the exact caller items but removes enumeration-order ambiguity before either validation or accepted output. Duplicate resource IDs remain visible and continue to hold handoff readiness.

## Deterministic proof

- All six permutations of three distinct items are varied independently across Expected, Pulumi, and Regional: 216 accepted combinations.
- Cases rotate through Turkish, Arabic, and Japanese cultures and emit one exact canonical sequence in all three retained projections.
- Tests prove exact item-reference retention, mutation isolation for all three source arrays, and equivalent independently reconstructed leaves and scope.
- A duplicate-ID raw inventory pins kind and generation comparator tie-breaks while proving the existing duplicate hold and null intent remain unchanged.
- Reflection exhaustively pins the public decision, intent, inventory, scope, trace, leaf, collection-projection, constructor, accessor, immutable-clone, factory, and sole engine-origin surfaces.
- Focused audit tests passed 4/4; provider-prefixed tests passed 32/32; cross-budget provider properties passed 9/9.
- The Release warnings-as-errors solution build passed with zero warnings and errors.
- All five test executables passed 887/887 (ControlPlane 660, Contract 29, Model 44, Protocol 70, Scheduler 84).

## Remaining completion blockers

This correction does not make the draft registry or product complete.

- Owner questions 1–10 and the cost, storage-performance, RPO, and RTO targets remain unresolved.
- The canonical structured trace report remains at 43 gaps, zero linked requirements, and zero acceptance-satisfied requirements; registry and contract promotion are integration-steward work.
- Action-specific cancellation/compensation recovery and broader native GitOps retry/suspend/prune remain future pure-contract tranches rather than policies invented by this audit.
- NATS L0C generated credentials/configuration and real-server conformance, signing technology and protected keys, Pulumi retain/unmanage qualification, OCI/A1/IAM/storage adapters, SmolVM/systemd/containerd labs, deployment, measured cost, and storage-performance evidence require external or later-layer work.
- Networking policy and compute scale-out were explicitly excluded because separate active audits own them.

## Honest boundary

Canonical retained order is not proof that any inventory observation or handoff proof is authentic, signed, durable, or externally enforced. No Pulumi, provider, cloud, filesystem, process, network, NATS, signing, credential, VM, deployment, or other external side effect occurred.
