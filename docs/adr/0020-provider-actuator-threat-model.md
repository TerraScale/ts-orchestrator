# ADR 0020: Fence provider mutations with persisted intent

- Status: Accepted safety boundary; tested contracts exist, production
  composition is pending ORCH-6
- Updated: 2026-08-31
- Scope: OCI compute, volumes, attachments, work requests, Object Storage, and
  other external mutations owned by Orchestrator

## Context

An OCI mutation can outlive the controller leadership and HTTP call that
started it. The control plane may crash after its last authority check, lose a
response, time out while OCI continues the request, or observe a delayed work
request after another leader takes over. OCI does not understand a NATS lease
or controller fencing epoch.

An idempotency key prevents some duplicate calls, but it does not prove who
authorized the action, which target and payload were accepted, or whether a
different leader may replace an uncertain operation. Provider safety needs a
fresh authorization decision, an immutable provider request identity, and a
durable same-operation resume path.

This threat model covers crash-stop failure of trusted Orchestrator code and
ordinary provider or network faults. Compromise of an actuator host or its OCI
credentials is outside this boundary.

## Implemented contracts

The repository has three separate, tested provider safety contracts. None is
composed into a production runtime.

### Authorization policy

`ProviderOperationContext` binds the operation, region, compartment,
controller epoch, resource kind, action, exact target, expected generation and
observation, terminal state, approvals, deadline evidence, idempotency key,
permitted compensations, and typed action parameters.

`Authorize` checks bounded and consistent evidence, current regional
authority, scope, epoch, durable ownership, observed generation, deadline,
approvals, prior authorization compatibility, action compatibility, and tag
consistency. Missing or ambiguous evidence returns a held or rejected decision
and no `ProviderIntent`.

`AuthorizeWithOwnership` reloads existing-resource ownership from a
`DurableOwnershipEvidence` store immediately before it calls `Authorize`.
Caller-supplied tags and ownership records cannot establish ownership.

`DurableProviderAuthorization` binds the exact context fingerprint,
operation ID, terminal state, and an irreversible flag.
`CaptureDurableAuthorization` produces that value only after matching call
evidence says the provider accepted the call, its response was lost, or it
completed. The current type has no serializer or durable store.
`NewDurableProviderAuthorization` is an unwired constructor and is not proof
that any durable write occurred.

No production code calls `Authorize`, `AuthorizeWithOwnership`,
`CaptureDurableAuthorization`, or `NewDurableProviderAuthorization`.
`ProviderActuator` is an interface with no production implementation or
caller. These contracts are implemented and tested, but they do not currently
authorize a live provider call.

### Signed create-node boundary

`OciCreateNodeProvider` accepts a `CreateNodeProviderRequest`, not a
`ProviderIntent` through `ProviderActuator`. The request carries a
`ProviderOperationContext`, a signed create-node handoff receipt, and a signed
invocation capability bound to the receipt. Before it calls its client, the
provider validates the request and durably consumes the invocation capability.
A replay cannot consume the same capability again.

This path has no production caller. It does not call `Authorize` or use
`ProviderMutationJournal`. Its one-time capability boundary is tested, but it
is not the production composition of the authorization policy.

### CAS provider mutation journal

The provider-neutral OCI adapters require `ProviderMutationJournal`. Its
CAS-backed implementation stores one `ProviderMutationIntent` per logical
resource scope. The intent binds:

- operation ID, scope, action, and controller epoch;
- provider idempotency key; and
- a SHA-256 fingerprint of every provider-visible immutable request field.

The implemented journal states are:

| State | Meaning |
| --- | --- |
| `MutationPrepared` | The exact intent owns the resource scope. No provider dispatch is recorded. This state does not prove that `Authorize` admitted the request. |
| `MutationSubmitted` | The adapter recorded dispatch before crossing the provider boundary. |
| `MutationUnknown` | OCI may have accepted the call. The same operation must be reconciled; a replacement is forbidden. |
| `MutationSucceeded` | The provider result is persisted and immutable. |
| `MutationFailed` | A provider-proven terminal failure is persisted and immutable. |

The same operation may resume at a newer controller epoch. A different
operation cannot replace an unresolved intent. A capacity attempt that OCI
proved it rejected may move from `MutationSubmitted` back to
`MutationPrepared` with an advanced durable attempt cursor. An unknown
outcome cannot use that transition.

`OCIComputeAdapter`, `OCIBlockStorageAdapter`,
`OCIVolumeAttachmentAdapter`, and `OCIObjectStorageAdapter` prepare the
exact intent, record `MutationSubmitted` before the HTTP mutation, and persist
the result before returning success. `NewCASProviderMutationJournal` and the
concrete adapter constructors have no production caller. Their current call
paths are contract tests.

The CI-runner client has another ownership and lifecycle contract. It is not
composed with `Authorize` or `ProviderMutationJournal`.

## Decision

Keep the implemented contracts and make their boundaries normative. Do not
claim that they form one runtime until ORCH-6 wires and tests the complete call
path.

1. A production controller must call `AuthorizeWithOwnership` with fresh
   regional authority, durable ownership, current provider observation,
   generation, deadline, approvals, and call evidence before any adapter
   request is eligible.
2. A held or rejected decision makes no provider call. Tags remain consistency
   evidence only.
3. The exact authorized context and `ProviderIntent` must bind byte-for-byte
   to the provider request and its `ProviderMutationIntent`. A translation
   mismatch fails closed.
4. For provider-neutral adapters, the irreversible provider-dispatch boundary
   is the durable transition from `MutationPrepared` to
   `MutationSubmitted` for that exact intent. The adapter must not cross the
   network boundary before the transition succeeds.
5. For `OciCreateNodeProvider`, the current irreversible boundary is durable
   consumption of the exact signed invocation capability. The receipt,
   capability, context, and concrete request must remain bound through
   reconciliation.
6. Once either dispatch boundary is crossed, leadership changes the executor,
   not the action, target, payload, idempotency key, permitted compensation, or
   terminal goal. A successor resumes or observes the same operation.
7. A timeout or lost response is an unknown outcome. Recovery reads OCI
   through the recorded work request, retry token, deterministic create
   identity, receipt binding, or exact target. It does not create replacement
   intent.
8. The adapter persists the provider result before the controller acknowledges
   terminal control work. A terminal journal record cannot change.

Deployment-driven provider work cannot use an external candidate as authority
until DEP-3 wires and admits that machine handoff. Other provider work binds to
its accepted desired-state generation and durable operation origin.

Regional actuators use compartment-scoped OCI identities. The GRU global
controller distributes policy and limits but does not hold routine regional
mutation credentials. Credentials never appear in control messages, operation
documents, logs, or test fixtures.

- `MutationPrepared` is a durable adapter intent, not controller
  authorization. Production composition must prove both boundaries.
- `NewDurableProviderAuthorization` cannot substitute for captured and
  durably stored accepted call evidence.
- One logical operation owns a resource transition. A new leader cannot replace
  an unresolved operation.
- Create retries reuse one deterministic create identity and provider
  idempotency key.
- Unknown outcomes require read-only reconciliation before retry,
  compensation, or replacement.
- Tags and discovery results never authorize mutation, adoption, cleanup, or
  compensation.
- Delete, terminate, detach, and release require positive durable ownership,
  matching generation, retention and drain completion, dependency checks,
  required approvals, and a fresh provider observation.
- Compensation is another provider mutation. It requires an allowed exact
  target, known provider truth, and the same authorization and journal gates.
- A budget emergency may stop new non-safety scale-out. It cannot manufacture
  destructive authority or block safety expansion required to prevent data
  loss.
- Regional credentials remain compartment scoped. GRU distributes policy and
  limits but does not hold routine regional mutation credentials.
- Credentials never appear in operation records, messages, logs, or fixtures.

## Failure and resume behavior

| Failure point | Required behavior |
| --- | --- |
| `AuthorizeWithOwnership` holds or rejects | Make no provider request and persist no dispatch. |
| Authorization passes, adapter boundary not crossed | Recheck stale inputs or hold. No external effect is committed. |
| `MutationPrepared`, before `MutationSubmitted` | Preserve the exact intent. Submit only after its authorization binding is revalidated. |
| Invocation capability not consumed | Make no create-node call. |
| `MutationSubmitted` or invocation capability consumed | Preserve the exact request identity. Reconcile or resume that operation only. |
| OCI acceptance is unknown | Persist or retain the unknown state and reconcile. Never replace the operation. |
| Leadership changes while a work request runs | Observe or resume the same operation under current execution authority. |
| Deadline expires before dispatch | Hold with no provider call. |
| Deadline expires after dispatch | Stop blind retries, preserve the exact operation, and reconcile read-only. |
| Provider reports a mismatched target or generation | Quarantine the result and make no further mutation. |
| Scoped credentials are denied | Persist the denial. Never fall back to broader credentials. |
| Terminal result is known | Persist it before acknowledgement. Never rewrite the terminal record. |

## Production composition

ORCH-6 must complete the runtime using the tested contracts already in this
package:

1. invoke `AuthorizeWithOwnership` from the regional control path using a
   durable ownership store and current authority;
2. bind the returned `ProviderIntent` and exact context to each concrete
   adapter request and `ProviderMutationIntent`;
3. persist and reload captured `DurableProviderAuthorization` through the
   control journal for same-operation resume;
4. keep `OciCreateNodeProvider` under its receipt and invocation-capability
   boundary, and add the authorization-policy binding or leave the path
   disabled with a typed refusal;
5. construct the CAS journal and concrete OCI adapters from a production
   command with an authoritative JetStream-backed store;
6. keep CI-runner provider mutations disabled until they use the same
   authorization and outcome-fencing rules; and
7. keep external candidate correlation disabled until DEP-3 supplies the
   admitted machine contract.

Any new persisted state or adapter interface needs its own claimed task and
tests. This ADR does not create one through prose.

## Verification

Tests must prove stale-leader refusal before dispatch, authorization-to-request
binding, same-operation resume after leadership change, single-use create-node
capability consumption, unknown-outcome fencing, capacity cursor recovery,
immutable terminal results, destructive-operation gates, result persistence
before acknowledgement, and the absence of a live adapter bypass.

Live OCI qualification remains opt-in and requires dedicated non-production
compartments and credentials. Each enabled OCI service must prove its retry
token, work-request visibility, ambiguity, reconciliation, and ownership
behavior before production sign-off.

## Consequences

The package contains tested safety contracts, not a production provider
runtime. Keeping that distinction explicit prevents an unwired policy object
or test-only adapter from being mistaken for a live mutation fence. ORCH-6
must compose the existing contracts and keep provider mutations disabled until
the complete path passes its local, simulation, and live qualification gates.
