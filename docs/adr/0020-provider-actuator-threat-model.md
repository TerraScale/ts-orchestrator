# ADR 0020: Provider mutation fencing and same-operation recovery

- Status: Accepted safety boundary; provider qualification remains a gate
- Decision owner: Cloud

## Context

An OCI or Cloudflare mutation can outlive the controller and the request that
started it. A process can crash after its authority check, lose a response, or
receive a delayed work-request result after leadership changes. Provider IAM
does not understand the orchestrator's lease or fencing epoch.

The orchestrator therefore treats every external mutation as a durable,
restart-safe operation. This boundary applies to the declared estate and host
lifecycle; it never carries customer data or authorizes a TerraBase mutation.

## Decision

Use persisted intent plus same-operation resume as the control fence:

1. Persist a `Prepared` operation with its exact target or deterministic create
   key, expected observation, generation, terminal state, deadline, and
   operation identity. `Prepared` is intent, not provider-call authorization.
2. The current fenced writer re-observes the provider, verifies ownership,
   authority, approvals, policy, and deadline, and transitions stale work to
   `Held` without calling the provider.
3. Once every gate passes, atomically persist `AuthorizedForProviderCall` with
   the exact action, target, payload digest, idempotency key, authorizing epoch,
   and evidence digests. This is the irreversible commit point in the control
   model.
4. Only that exact record can create a provider operation context. The
   compartment-scoped actuator verifies it immediately before dispatch and
   records the dispatch attempt before crossing the provider boundary.
5. A timeout or lost response is an unknown outcome. Recovery reads provider
   truth using the same operation and idempotency key, then resumes or
   reconciles that operation; it never creates a replacement operation merely
   because the response was lost.
6. A late completion is accepted only when it completes the already-authorized
   operation. Otherwise it is quarantined as an inconsistent observation and
   cannot authorize compensating destruction by itself.

Once authorization commits, leadership or deadline changes may hold dispatch
or require reconciliation, but cannot replace the action, target, payload,
request key, or terminal intent. This does not claim that a provider call must
succeed or that a deliberate, separately authorized compensation is
impossible.

## Safety rules

- Every mutating adapter call consumes one committed authorization record.
- Exactly one logical operation owns a target transition; leadership changes
  the executor, not the authorized outcome.
- Create retries reuse the same deterministic create identity.
- Unknown responses are reconciled through provider read/work-request APIs
  before retry or compensation.
- Discovery, tags, and provider inventory never authorize adoption, cleanup,
  mutation, or compensation.
- Credentials remain scoped to the Region and compartment whose estate is
  being reconciled; broader credentials are never a retry fallback.
- Journals, logs, traces, metrics, and evidence contain no secret material.

## Required verification

Qualification must inject process loss, leadership loss, deadline changes,
stale observations, duplicate requests, delayed responses, and contradictory
provider observations before and after every authorization and dispatch
checkpoint. It must prove one owned terminal outcome, no duplicate create, no
stale accepted mutation, and no mutation of unowned resources. The D-81
Firecracker suite covers local host and systemd failure behavior; real OCI and
Cloudflare qualification remains required for provider semantics.
