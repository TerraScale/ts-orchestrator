# Phase 1 provider ownership core handoff

- Work package predecessor: `85db082`
- Branch starting point: `7b1800a`
- Scope changed: provider-neutral ownership/handoff models and engine, provider-prefixed control-plane tests, and this handoff only
- Provider calls, Pulumi operations, files, clocks, retries, and external actions: none

## Result

The control plane now has a pure fail-closed authorization boundary for provider operations. An immutable operation context binds the exact operation, regional scope, controller epoch, existing provider identity or idempotent create key, expected observation and generation, desired terminal state, approvals, caller-supplied deadline evidence, idempotency key, and permitted compensations. Bounded identities support both TerraScale canonical tokens and case-sensitive provider-native resource/work-request identifiers.

Authorization requires complete, unique, consistent evidence; exact regional authority; current epoch or an exact durably authorized irreversible resume; authoritative ownership; expected observation/generation; valid deadline evidence; complete approvals; compatible resource/action/terminal state; and consistent tags when tags are present. Tags remain typed reconciliation evidence and can never supply authority. Every denial has a stable closed numeric trace and emits no intent.

Successful decisions emit one closed typed intent. Accepted or response-lost calls are read by work-request ID when available and otherwise re-observed, so an accepted mutation is never blindly repeated. A higher-epoch leader can resume only the identical durably authorized irreversible context and cannot replace its terminal target or compensation set.

Action-critical inputs are a closed immutable union and are included in that durable identity: node template, placement, and bootstrap-envelope digest; volume size and performance; expansion target; attachment volume and node; and backend identity. Typed mutation intents expose only their matching parameter type. Create authorization additionally requires an exact create-key observation proving absence; unrelated resource observations or an already-resolved create key cannot authorize another create call.

Fresh bootstrap handoff requires exact, duplicate-free agreement among expected, Pulumi, and regional inventories plus verified retain/unmanage, regional R3 journal receipt, provider readiness, trust readiness, backup readiness, and activated regional fence evidence. Every proof carries the exact cell, compartment, bootstrap generation, operation, and expected-inventory fingerprint, preventing cross-cell, stale-generation, or different-inventory replay. Only then is a typed self-management intent emitted with the exact scoped, defensively copied inventory. The model exposes no historical/adoption input.

## Adversarial coverage

Provider-prefixed tests cover tag-only denial; mismatched and duplicate tags; stale/future epochs and generations; expected-observation mismatch; missing authority; wrong scope; incomplete/unknown evidence; approval and action incompatibility; duplicate/conflicting ownership observations; durable higher-epoch resume; conflicting terminal supersession; lost responses; accepted-call no-repeat; leadership loss after acceptance; provider-native identities; exact and defective handoffs; defensive copies; unknown/default values; culture/permutation determinism; and free-text, executable, I/O, and secret-safe surfaces.

## Validation

```text
dotnet restore tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --locked-mode
dotnet build tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-restore
dotnet test tests/TerraScale.Orchestrator.ControlPlane.Tests/TerraScale.Orchestrator.ControlPlane.Tests.csproj --no-build
git diff --check
```

The final local test run completed with 66 tests passed, 0 failed, and 0 skipped. The build completed with 0 warnings and 0 errors.

## Adapter boundary

This package deliberately does not choose a provider, template, placement, retry policy, timeout, approval default, or compensation policy. A later adapter may consume the typed intents, recheck authority immediately before its call, and return typed call/observation evidence; it must not add provider SDK or I/O concerns to this core.
