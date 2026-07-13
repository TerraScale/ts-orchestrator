# Phase 1 reconciliation core handoff

## Scope delivered

- Pure immutable desired/observed contracts with bounded identity, kind, digest, dependency, observation-freshness, resource-count, and generation-floor validation.
- Closed caller-supplied kind catalog and caller-supplied bounds; the engine contains no domain kinds or policy defaults.
- Deterministic ordinal topological planning independent of desired, observed, or dependency input order.
- Typed `ObserveResourceIntent`, `ReconcileResourceIntent`, `HoldResource`, and `ConvergedResource` results.
- Exact convergence requires a fresh, ready observation with the same identity/kind, generation, and digest.
- Missing and freshness-stale observations produce only `ObserveResourceIntent`, including when a dependency needs reconciliation in the same wave.
- Older-generation drift produces a reconcile intent only when every dependency is exactly converged in the current observed input. A dependency reconcile emitted by this plan is not treated as convergence and cannot unlock same-wave dependent mutation.
- Reconcile intents freeze only resource identity, kind, desired generation/digest, and sorted exact dependency proofs. They contain no callback, arbitrary payload, executable data, or infrastructure behavior.
- Newer observations, same-generation digest conflicts, failed/held observations, missing dependencies, self-edges, cycles, invalid catalogs, generation regression, duplicates, and identity mismatches hold or reject fail-closed.
- Failed/held/missing dependency root identity and reason propagate transitively without being replaced by a generic dependent failure.
- Stable ordinal plan order, error order, trace sequence, fixed reason messages, defensive collection copies, and no input mutation.

## Files

- `src/TerraScale.Orchestrator.ControlPlane/Reconciliation/ReconciliationContracts.cs`
- `src/TerraScale.Orchestrator.ControlPlane/Reconciliation/ReconciliationEngine.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/ReconciliationEngineTests.cs`

## Verification

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo
dotnet run --project tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build --no-restore -- --no-progress
git diff --check
```

- Solution build: 0 warnings, 0 errors.
- Control Plane suite: 44 passed, 0 failed (13 reconciliation tests plus 31 existing operation/authority tests).
- The benchmark-style test plans a reversed and forward 10,000-resource chain non-recursively and compares the complete stable signature.

## Deliberate boundaries

- This core does not own retry, backoff, timeout, suspend/resume, domain health policy, prune, artifact resolution, persistence, adapter execution, NATS, files, clocks, or provider/runtime behavior.
- `MinimumFreshnessSequence` and generation floors are opaque caller evidence. A coordinator/adaptor must derive them from its authoritative journal/observation protocol; this core does not invent freshness or time semantics.
- A cycle-blocked downstream resource receives a typed cyclic hold. The core does not attempt remediation or choose an edge to remove.
