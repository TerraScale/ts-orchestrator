# Phase 1 runtime executor-observation output audit 4

## Goal

Close the proven accepted-output collision where response-lost lifecycle recovery discarded the validated executor node, fencing, generation, action, observation, admission, specification, inventory, and health scope.

## Allowed paths

- `src/TerraScale.Orchestrator.ControlPlane/Runtime/RuntimeModels.cs`
- `src/TerraScale.Orchestrator.ControlPlane/Runtime/RuntimeDecisionEngine.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/RuntimeFourthAuditRegressionTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/RuntimeDecisionTests.cs`
- `tests/TerraScale.Orchestrator.ControlPlane.Tests/Properties/RuntimeLifecycleObservationPropertyTests.cs`
- `docs/work-packages/phase1-runtime-observe-output-audit4.md`
- `docs/work-packages/handoffs/phase1-runtime-observe-output-audit4.md`

## Contract

An authorized `ObserveExecutorIntent` retains the exact validated immutable `RuntimeLifecycleRequest`. Existing operation and allocation identity getters derive solely from that request. Construction remains internal; the existing immutable record-copy route is retained, and no public constructor, setter, deconstructor, flattened constructor, or factory is added. Authorization, traces, codes, numeric values, order, precedence, and every other intent remain unchanged.

## Boundary

The retained request is in-memory recovery provenance. It does not prove an executor query happened, identify a live PID/cgroup/unit invocation, recover a lost response, validate systemd/containerd behavior, authenticate an artifact, or qualify a deployment. This work performs no process, systemd, containerd, filesystem, network, provider, VM, cloud, deployment, or CI-dispatch operation.

## Review closure

Final adversarial review required independent sensitivity for every nested request leaf, real allocation and nested-evidence permutations, and union-output construction closure. The corrected tests share the production-subject fingerprint's conflict projection for single-leaf checks, reverse two inventory entries plus their port/volume and health order, and inventory every exported public method/accessor returning the exact intent, `RuntimeIntent`, or `RuntimeDecision`.
