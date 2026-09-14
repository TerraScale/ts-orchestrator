# Deploy to Orchestrator handoff

Status: current implementation boundary; the external Deploy candidate schema
is pending DEP-3.

## Current behavior

The code in `src/orchestrator/delivery` accepts bounded Forgejo delivery events,
resolves repository source, builds an internal `DeliveryPlan`, and calls an
in-process `DeliveryHandoff`. The plan and handoff do not define or parse a
signed document submitted by `ts-deploy`.

No machine-readable Deploy candidate migration exists in this repository.
Orchestrator therefore must not claim that it admits a versioned external
candidate handoff, verifies that document's signature, or provides replay
compatibility for such a document. Fixtures without a production parser and
consumer are not a contract.

## Ownership

`ts-deploy` runs inside Forgejo Actions. It owns source inspection, tests,
build, and image publication. Orchestrator owns admission, rollout planning,
regional execution, routing, rollback, and operation history.

The existing in-process handoff carries an internal plan to the delivery
reconciler. It does not grant an authority term or authorize a provider,
runtime, or routing mutation by itself.

## Required machine migration

DEP-3 must add the external handoff as code before this document can describe
it as current behavior. The migration must include:

- one bounded schema shared with `ts-deploy`;
- strict parsing with duplicate-key and unknown-field rejection;
- signature, audience, expiry, source, test, target, and immutable-digest
  checks;
- idempotent replay and conflict behavior backed by the durable journal;
- a translation into the current internal `DeliveryPlan` without granting
  mutation authority; and
- cross-repository fixtures consumed by automated tests on both sides.

The migration must preserve published image digests through promotion and
rollback. It must keep credentials, provider responses, customer content,
benchmark authorization, mutable tags, free-form commands, and rollout
approval out of the handoff.

No external candidate document is currently accepted. Any future parser must
fail closed for unsupported schema versions and must preserve these checks.
