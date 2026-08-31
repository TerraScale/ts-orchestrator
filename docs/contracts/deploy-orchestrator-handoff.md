# Deploy to Orchestrator handoff

Status: target contract for DEP-3 and the Orchestrator v2 delivery path.

## Ownership

`ts-deploy` runs inside Forgejo Actions. It owns source inspection, build,
tests, image publication, and submission of the candidate handoff.

Orchestrator owns admission, rollout planning, regional execution, routing,
rollback, and operation history. A handoff can identify a candidate. It cannot
grant an authority term or trigger a provider or routing mutation by itself.

## Handoff content

The bounded, signed document contains:

- schema version and signing identity;
- source repository, commit, and tree digest;
- Deploy CLI version and executable digest;
- immutable image manifest and platform digests;
- captured dependency lockfile digests;
- the names and results of required CI tests;
- target service, environment, and ordered region list;
- configuration and optional migration revision;
- the retained rollback digest when a previous release exists; and
- operation ID, actor, issue time, expiry, and audience.

The handoff contains no credentials, provider responses, customer content,
benchmark authorization, mutable image tags, free-form executable commands, or
rollout approvals.

## Admission

Orchestrator rejects malformed documents, unknown fields, duplicate keys,
unsupported versions, expired signatures, source mismatch, missing tests,
failed required tests, mutable artifact references, platform mismatch, target
mismatch, or an absent rollback digest for an existing deployment.

Admission verifies the signature and exact values against the current release
policy. It records an admitted candidate with zero live mutation authority. A
separate regional rollout operation must bind that candidate to the current
global release generation and regional authority term before execution.

## Digest discipline

Promotion and rollback reuse the published digest. Neither Deploy nor
Orchestrator rebuilds an image after handoff. The multi-platform manifest and
each selected platform image are checked by digest.

## Replay behavior

The operation ID and candidate digest form the idempotency identity. Replaying
the same signed document returns the same admission outcome. Reusing the
operation ID with different bytes is a conflict and performs no mutation.

## Migration

ORCH-1 moves delivery onto the `ts.orch.v2` subject and envelope taxonomy.
DEP-3 updates the producer and shared corpus to this lean document. The old v1
mapping and the candidate-qualification packet are not compatibility targets.
