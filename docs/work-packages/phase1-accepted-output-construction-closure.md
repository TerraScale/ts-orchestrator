# Phase 1 accepted-output construction-closure audit

## Goal

Prevent callers outside the ControlPlane assembly from minting decisions, permits, mutation intents, or intent subjects without passing through the owning pure decision engine.

## Inventory and fixes

- Authority: closed the three `AuthorityIntent` constructors. `AuthorityDecision` and `MutationAuthorityPermit` were already closed.
- Operations: closed both `OperationIntent` constructors and the `OperationDecision` constructor.
- Reconciliation: closed the complete `ReconciliationOutput` hierarchy, including observe, reconcile, hold, and converged outputs, plus the containing accepted step and plan.
- Networking: closed both concrete `NetworkIntentSubject` constructors as defense-in-depth. A subject alone cannot mint a `NetworkDecision`: the decision constructor is private and `Emit` is internal. Closing subjects nevertheless keeps accepted intent payloads assembly-owned and prevents a future public composition path from turning caller-forged subjects into accepted decisions.
- Compute, Delivery, Provider, Runtime, Observability, Security, Budget, Storage, TerraBase, Evidence, and snapshot decisions/intents/permits were already construction-closed.
- Messaging decisions and intents are also construction-closed by the dedicated messaging property shard; the architecture test applies the same checks without an exception.

The architecture test inventories exported `*Decision`, `*Permit`, and `*Intent` types plus the reconciliation and decision-subject hierarchies. It rejects public constructors, setters/init setters, and positional deconstruction on accepted outputs. It also inventories every public static or instance method on every exported ControlPlane type whose return type is protected, and compares exact method kind, declaring type, parameter types, and return type against an explicit reviewed allowlist of pure engine/planner entrypoints. The only non-engine capture entrypoint is `ProviderAuthorizationDecision.CaptureDurableAuthorization`, which derives an exact durable token only from an accepted mutation decision.

Compiler-generated record clone methods are intentionally ignored. Cloning requires possession of an already accepted instance, while the no-public-setter/init-setter guard prevents a `with` expression from changing authority-bearing state; an unchanged clone therefore cannot mint new authority.

## Reconciliation input capture boundary

`ReconciliationTechnicalInputLimits.MaximumCapturedItems` publicly documents a 16,384-item technical snapshot ceiling. It is an acquisition-safety limit, not the `MaximumResources` or `MaximumDependenciesPerResource` business policy. A shared bounded helper now snapshots `DesiredResource.Dependencies`, `ReconciliationPolicy.AllowedKinds`, `ReconciliationPolicy.GenerationFloors`, and both `ReconciliationRequest.Desired` and `.Observed`. It checks the bound after `MoveNext` and before `Current`, copies before exposing the collection, converts ordinary iterator failures (including disposal) into secret-safe `ArgumentException` values without inner exceptions, and permits `OutOfMemoryException`, `StackOverflowException`, and `AccessViolationException` to propagate.

## Compatibility impact

This is an intentional source and binary compatibility break for the Authority, Operations, Reconciliation (including step/plan), and Networking output constructors. Those outputs remain public and read-only for inspection and pattern/property access, but external `new` expressions no longer compile and existing binaries that call the old public constructors must be rebuilt. Rewriting positional records as nominal records also removes their generated public `Deconstruct` methods; external positional deconstruction must change to property access. Equality and public property names/types remain available. No input/evidence DTO, business rule, decision ordering, adapter, or system boundary changes.
