# ADR 0020: Provider actuator crash-stop and irreversible-operation fencing

- Status: Accepted safety boundary; provider qualification and unified
  authorization migration pending
- Updated: 2026-08-30
- Scope: OCI compute, volumes, attachments, work requests, Object Storage, and
  other external mutations owned by Orchestrator

## Context

An OCI mutation can outlive the controller leadership and HTTP call that
started it. The control plane may crash after its last authority check, lose a
response, observe an SDK timeout while the request continues, or receive a
delayed work-request completion after another leader takes over. OCI does not
understand a NATS lease or controller fencing epoch.

Avoiding duplicate API calls is not enough. Every external mutation needs one
persisted, authorized terminal intent. A stale actor must not create a
conflicting accepted outcome.

This threat model covers crash-stop failure of trusted orchestrator code and
ordinary provider or network faults. It does not claim safety after an
actuator host or its regional credentials are compromised.

## Decision

Use persisted intent plus same-operation resume as the provider mutation
fence.

The current Go implementation has two related but distinct layers. The
controller authorization layer uses `ProviderOperationContext` and `Authorize`
to validate authority, ownership, generation, approvals, deadlines, and call
evidence before producing a typed `ProviderIntent`. Its durable authorization
value is `DurableProviderAuthorization`; it is not currently serialized as a
record named `AuthorizedForProviderCall`.

The concrete OCI mutation fence used by the provider-neutral resource
adapters (`OCIComputeAdapter`, block-storage, attachment, and Object Storage)
is the authoritative CAS-backed `ProviderMutationJournal`. It persists a
`ProviderMutationIntent` bound to its scope, action, epoch, idempotency key,
and complete request fingerprint. The journal states are `Prepared`,
`Submitted`, `Unknown`, `Succeeded`, and `Failed`; a known capacity rejection
may return `Submitted` to `Prepared` with an advanced attempt cursor. Adapters
persist `Submitted` before dispatch, reuse the same intent after an uncertain
result, and refuse conflicting operations while an intent is unresolved.

The context-based node-create adapter and the CI-runner lifecycle are separate
current contracts: node create verifies a signed, durably consumed invocation
capability, while CI-runner recovery and termination require durable ownership
evidence. They are not yet represented by the provider mutation journal or the
planned unified authorization record.

The `AuthorizedForProviderCall` record described below is the planned unified
authorization record. Until every concrete adapter consumes that record, its
requirements apply to the controller authorization layer where supported, and
the provider-neutral journal requirements above remain the effective adapter
boundary. This distinction is intentional: neither layer may be treated as a
permission to bypass the other.

The following numbered lifecycle is the target unified contract; the current
adapter state transitions are described above and remain normative until that
migration is complete.

1. A pure controller decision persists an operation as `Prepared`. The record
   includes the exact target or deterministic create identity, expected
   observation and generation, proposed terminal state, permitted
   compensations, required approvals, deadline, preparing authority epoch, and
   operation identity. `Prepared` is durable intent, not provider-call
   authorization.
2. While the operation is `Prepared`, the current fenced writer evaluates a
   fresh provider observation, positive ownership, matching generation,
   approvals, policy, quorum, budget gates, and the unexpired deadline. A
   failed or stale check moves the operation to `Held` and makes no provider
   call.
3. In the planned unified lifecycle, if every gate passes, the writer
   atomically persists `AuthorizedForProviderCall`. That record freezes the
   exact provider action
   and payload digest, target OCID or create identity, desired terminal state,
   provider retry token, allowed compensations, authorizing epoch, policy and
   approval digests, deadline evaluated at authorization, and authorization
   commit sequence and digest.
4. In that planned lifecycle, the durable transition to
   `AuthorizedForProviderCall` is the irreversible commit point. Before it,
   expiry, leadership loss, stale observation, or approval withdrawal can hold
   the operation without a call. After it, those changes may pause an unsent
   dispatch or force reconciliation, but they cannot cancel the committed
   provider step, replace its terminal target, change its payload or request
   identity, or authorize a conflicting operation. Current adapters obtain the
   equivalent call boundary by persisting `Submitted` in their mutation
   journal immediately before dispatch.
5. In the planned unified lifecycle, only an exact
   `AuthorizedForProviderCall` record can produce a `ProviderOperationContext`.
   The regional actuator verifies that record and its digest immediately before
   dispatch. The current context-based node-create adapter instead verifies the
   bound context, signed invocation capability, and durable capability
   consumption; the current provider-neutral adapters verify their mutation
   intent and CAS journal. A successor continues the same committed operation.
6. Before crossing the provider boundary, the actuator durably records the
   dispatch attempt against the authorization commit. It sends the frozen
   operation-bound retry token and records the work-request ID or exact
   resource identity when OCI returns one.
7. A timeout or lost transport response is `OutcomeUnknown`, not failure and
   not permission to create a fresh logical operation.
8. Recovery reads provider truth and the recorded work request, retry token,
   or resource identity. A successor resumes or observes the same authorized
   action and desired terminal state. Renewed authority to execute cannot
   change the committed action, target, payload, retry token, or terminal
   target.
9. A late completion is accepted only when it safely completes the already
   authorized operation. Any other result is quarantined as an inconsistent
   observation and cannot authorize cleanup by itself.
10. Tags help discovery and mismatch detection only. Mutation authority
    requires the matching durable provider record and, for context-based
    operations, the scoped capability and authorization checks described above.
    The planned unified form binds those checks to an
    `AuthorizedForProviderCall` record. IAM propagation is not a leadership
    fence.
11. The actuator persists the provider result and binds it to the authorization
    commit before the controller acknowledges terminal control work.

Once `AuthorizedForProviderCall` commits, leaders converge on the same provider
step and terminal intent. The commit does not guarantee provider success or
permit blind dispatch after authority or deadline checks fail. A hold preserves
the committed target and request identity, and recovery reconciles or resumes
that same operation.

## `ProviderOperationContext` contract

The context binds at least:

- operation ID, kind, cell, compartment, and exact target OCID or deterministic
  create identity;
- authorization commit sequence and record digest;
- authorizing epoch, current executor identity, and execution lease;
- expected provider observation, ownership, and generation;
- desired terminal state, exact action and payload digest, allowed
  compensations, and required approval digests;
- authorization deadline and persisted dispatch-attempt sequence;
- provider retry token plus the work-request ID when known; and
- immutable correlation to the owning admitted candidate and accepted
  desired-state generation.

For context-based operations, the adapter rejects a context whose authorization
state, commit digest, action, payload, target, retry token, or owning operation
differs from the journal; it cannot convert an unauthorized request into an
adapter context. The current provider-neutral OCI adapters perform the
equivalent binding with `ProviderMutationIntent` and reject a malformed,
stale, or conflicting journal transition. Their `Prepared` record is the
durable intent from which the adapter may proceed to `Submitted`; it is not the
controller authorization state described by the planned unified record.

## Safety rules

- Every current OCI mutation adapter consumes an exact `ProviderMutationIntent`
  through an authoritative CAS-backed `ProviderMutationJournal`. Context-based
  adapters consume only typed intents produced by `Authorize`; the planned
  unified form names their shared committed record
  `AuthorizedForProviderCall`. No adapter can invent business intent.
- One logical operation owns a target transition. Leadership changes the
  executor, not the authorized terminal outcome.
- Create retries reuse one deterministic create identity and provider retry
  token.
- Authorization requires fresh observation, exact target identity, matching
  generation, an unexpired deadline, all required approvals, and positive
  ownership.
- Clock anomalies before authorization hold destructive work. An anomaly after
  authorization may hold dispatch, but cannot erase or alter the commit.
- An unknown response is reconciled through read or work-request APIs before
  retry or compensation.
- Discovery results and tags cannot authorize mutation, adoption, cleanup, or
  compensation.
- Regional credentials remain compartment scoped. GRU distributes policy and
  limits but does not hold routine regional mutation credentials.
- An emergency budget may stop new non-safety scale-out. It cannot manufacture
  destructive authority or block safety expansion needed to prevent data loss.
- Compensation is another provider mutation. It requires an allowed target,
  known provider truth, and its own authorization checkpoint.

## Destructive operations

Delete, terminate, detach, and release require every ordinary fence plus a
current owner, retention and drain completion, dependency checks, and a fresh
provider observation. Missing inventory, a stale authority term, an ambiguous
work request, or a conflicting generation makes the operation read-only.

The authorized operation lists every permitted compensation and its exact
target. A controller cannot invent cleanup after an unexpected partial result.

## Failure and resume behavior

| Failure point | Required recovery behavior |
| --- | --- |
| Before `Prepared` persists | No provider call is permitted. Replanning may create a new operation. |
| `Prepared`, before authorization | Re-evaluate every gate. Move to `Held` on stale authority, observation, generation, approval, ownership, quorum, or deadline. |
| Checks pass, before authorization commits | The irreversible boundary has not been crossed. Leadership loss or expiry holds without a call. |
| Authorization committed, before dispatch | Preserve the exact action, target, payload, retry token, and terminal state. A successor resumes the same operation. |
| Dispatch recorded, provider acceptance unknown | Treat the outcome as unknown and reconcile before retrying with the same operation identity. |
| OCI accepted the request, response lost | Read by work request, retry token, or resource identity. Do not infer failure from timeout. |
| Resource created, identity not persisted | Discover only within the exact compartment and create identity, verify ownership and generation, then bind or quarantine. |
| Leadership changes while a work request runs | Observe or resume the same terminal target. Do not issue a conflicting request. |
| Deadline expires after authorization | Stop blind dispatch and retries. Preserve the commit and continue read-only reconciliation. |
| Provider reports a mismatched target or generation | Return `ERR-PROVIDER-OWNERSHIP-MISMATCH`, quarantine the result, and make no further mutation. |
| Scoped credentials are denied | Persist the denial and require scoped recovery. Do not fall back to broader credentials. |

## Required verification

Provider adapter tests cover lost responses, delayed work-request visibility,
controller restart, leadership change, duplicate delivery, stale generation,
unknown resources, capacity errors, and authorized compensation after a
partial result. Tests must prove that an unauthorized controller context
cannot produce a provider intent, that a prepared mutation cannot be replaced
while unresolved, and that authority loss cannot replace a committed operation
with a conflicting one.

Live OCI qualification remains opt-in and requires dedicated non-production
compartments and credentials. It must confirm each OCI service's retry-token,
work-request, ambiguity, and reconciliation behavior before that service is
production qualified.

## Consequences

Provider adapters return typed observations and do not own terminal-state,
retry, compensation, or ownership policy. Controller authorization traces
expose held and rejected decisions; provider mutation journals distinguish
`Prepared`, `Submitted`, `Unknown`, dispatch attempts, and terminal provider
outcomes. The planned unified journal will add an immutable authorization
record. Operator tooling exposes unknown and held outcomes without an unscoped
retry action. Credential scope limits damage, but it does not replace the
logical fence.
