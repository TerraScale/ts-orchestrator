# Phase 1 runtime health-intent audit handoff

## Scope

This audit reviewed the pure Runtime lifecycle and self-update decisions for one
remaining accepted-output ambiguity after the cleanup-context and self-update
soak-evidence audits. It did not add an executor adapter or perform process,
filesystem, network, containerd, or systemd I/O.

## Proven counterexample

Two authorized self-update requests for the same operation, node, allocation,
and epoch but successive `5 -> 6` and `6 -> 7` updates both produced the equal
output:

```text
CheckRuntimeHealthIntent {
  OperationId = operation-1,
  AllocationId = allocation-1
}
```

The red regression required those outputs to differ and failed with exact
record equality. A persisted health-check work item therefore did not state the
node, fencing epoch, generation, timeout, or required health dimensions that
the adapter must measure.

## Correction

`CheckRuntimeHealthIntent` remains construction-closed and is now created only
from the accepted `RuntimeLifecycleRequest` or `SelfUpdateRequest`. It binds:

- operation, allocation, and node identities;
- the accepted fencing epoch;
- the lifecycle spec generation or self-update target generation;
- the accepted health timeout; and
- a defensive immutable health-dimension list.

Self-update health checks use the canonical enum-order dimensions `Liveness`,
`LocalReadiness`, and `DependencyReadiness`. Lifecycle checks retain the
accepted spec's required dimensions. Identical request replay produces equal
intents and equal hashes, while successive generations no longer collide.

No decision code, error, outcome, or trace precedence changed. The correction
only enriches an intent after the existing authorization and hold/reject gates
have selected health observation work.

## Verification

The focused Runtime suite proves both lifecycle construction paths
(`Started`/`Serving`, including the held-readiness branch) and both self-update
`ProcessRestarted` arms use request-bound construction. It also covers exact
field identity, successive-generation inequality, identical replay equality,
defensive immutability, construction closure, and 1,000 seeded output-scope
cases. Runtime decision serializers include every added field.

## Deliberate non-claims

This closes only the proven health-check execution-scope collision. The intent
does not retain the complete accepted request and this audit does not claim to
bind admission, artifacts, inventory, current-generation high-water marks,
verifier identity, or the full lifecycle/self-update policy provenance. Real
systemd/containerd health collection and production boundary qualification
remain later-phase work.
