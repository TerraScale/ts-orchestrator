# Phase 1 protocol-negotiation completeness handoff

- Branch: `phase1/protocol-audit2`
- Base: central `chore/phase0-bootstrap` at `1eac098`
- External or destructive actions: none

## Result

The pure N/N-1 compatibility decision now returns an immutable, construction-closed acceptance that binds the exact adjacent current/previous versions and the exhaustive compatibility matrix it proved. Matrix order is canonical by numeric feature and direction and is independent of caller ordering and culture. Rejected compatibility decisions and all other messaging decision families carry no compatibility acceptance. Existing trace behavior and all enum values remain unchanged.

The pre-fix regression demonstrated that fully compatible `2/1` and `1000/999` windows had identical complete public output (`CompatibilityAccepted:Configure`). The accepted output now differs by exact version scope without selecting a wire representation, byte ceiling, signing policy, or compatibility default.

## Evidence

- 1,000 accepted version windows, including the maximum positive `long` boundary, pin the exact 12-item canonical matrix and input/culture/permutation independence.
- 1,000 rejected mutations pin invalid-catalog, incomplete-observation, duplicate-evidence, and compatibility-unavailable precedence and prove acceptance absence.
- Reflection pins constructor/setter/factory/deconstructor/clone closure.
- Existing topology, replacement, and partition property loops pin the new property to `null` outside successful compatibility evaluation.

## Validation

- Focused negotiation audit: 3/3 passed.
- Messaging policy/engine focus: 15/15 passed.
- Complete ControlPlane project: 513/513 passed.
- Complete solution: 712/712 passed.
- Complete solution build: zero warnings and zero errors.
- `git diff --check`: clean.

No external system was contacted or started, and this handoff makes no L0C, NATS, wire-schema, process-interoperability, or deployment-readiness claim.
