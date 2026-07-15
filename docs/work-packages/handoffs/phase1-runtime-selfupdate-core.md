# Phase 1 runtime lifecycle and self-update core handoff

- Work package: `docs/work-packages/phase1-runtime-selfupdate-core.md`
- Predecessor: `5315e7d`
- Scope changed: `src/TerraScale.Orchestrator.ControlPlane/Runtime/**`, `tests/TerraScale.Orchestrator.ControlPlane.Tests/RuntimeDecisionTests.cs`, and this handoff
- External/destructive actions: none

## Result

The control plane now has a pure, closed runtime decision boundary for reviewed native-systemd and digest-pinned OCI workloads. Inputs bind workload, allocation, node, operation, epoch, generation, architecture, host image, runtime version, artifact/signature/signing profile, configuration, secret versions, volumes, ports, admission policy, health policy, and complete node-inventory evidence. OCI activation binds the selected platform image digest independently from its manifest-list digest.

Lifecycle decisions progress through one typed fetch, verify, stage, mount, start, health, drain, stop, or cleanup action. Accepted or response-lost executor calls emit observation rather than repeating an action. Serving requires exact liveness, local-readiness, and dependency-readiness evidence; process exit success cannot substitute. Stop, drain, and cleanup remain available as safety actions when health has failed. Cleanup exposes only explicitly ephemeral volume identities, making retained-volume deletion unavailable to the adapter.

Self-update inputs independently bind the desired and observed forward and local rollback artifacts, exact A/B slot orientation, protocol/schema N/N-1 evidence, health/soak durations, compatibility window, and rollback policy. Persisted checkpoints resume deterministically through inactive-slot staging, rollback arming, one switch, health and regional checks, commit, old-slot soak, or local rollback. Later checkpoints revalidate target-generation health. Rollback is observed rather than re-emitted, and completes only with exact old-generation health; failed rollback is terminal and denied.

No runtime decision reads time or performs process, filesystem, network, or other I/O. No command, shell text, unit text, container-spec blob, host path, privileged flag, capability list, secret value, private key, callback, retry, timeout default, runtime default, or release default is accepted.

## Adversarial coverage

The focused tests cover native/OCI lifecycle parity, selected OCI platform digest binding, admission replay, every lifecycle and update checkpoint, future/stale evidence, scoped complete conflict inventory, port/volume conflicts, contradictory process/phase evidence, exit-zero/readiness separation, failed and replayed health, safety stop on failed health, lost executor/update responses, independent artifact-subject substitution, architecture/signature/rollback availability, incompatible protocol/schema evidence, A/B alias and orientation replay, later-checkpoint health regression, rollback convergence, terminal completion, defensive copies, culture/permutation stability, malformed/unknown inputs, forbidden execution/I/O shapes, public intent forgery, and secret-safe traces.

## Validation

```text
dotnet restore TerraScale.Orchestrator.slnx --locked-mode --nologo
dotnet build TerraScale.Orchestrator.slnx --no-restore --nologo
dotnet test TerraScale.Orchestrator.slnx --no-build --no-restore -- --disable-logo --no-progress
git diff --check
```

The focused control-plane project passes 198 tests. The locked whole solution passes 306 tests with zero failures or skips and builds with zero warnings or errors.

## Integration boundary

This package deliberately emits intents only. Executor/bootstrap adapters, persistence/event application, real systemd/containerd behavior, artifact verification implementations, health probe execution, timeout/soak timing, and release policy selection remain downstream work and must preserve the exact typed evidence carried here.
