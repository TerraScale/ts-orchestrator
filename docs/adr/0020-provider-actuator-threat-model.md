# ADR 0020: Fence provider mutations with persisted intent

- Status: Accepted
- Updated: 2026-08-30
- Scope: OCI compute, volumes, attachments, work requests, Object Storage, and
  other external mutations owned by Orchestrator

## Context

An OCI operation can continue after the initiating HTTP call times out or the
controller loses leadership. OCI does not understand a NATS lease. Retrying as
a new logical operation could create a duplicate resource or let a stale
controller conflict with its successor.

## Decision

Every provider mutation uses persisted intent and same-operation resume.

1. Before any provider call, the current regional authority writes a prepared
   operation with the exact target or deterministic create identity, desired
   terminal state, ownership facts, permitted compensation, deadline, and
   authority term.
2. The actuator rechecks the current authority, local quorum, operation state,
   positive ownership, expected provider observation, and deadline before the
   call.
3. The provider request uses the operation's deterministic retry token and
   resource name. Retries never create a new logical identity.
4. A timeout or lost response moves the operation to `OutcomeUnknown`. The
   controller observes OCI and its work request until it can prove the
   original operation's outcome.
5. A successor resumes the same operation. It cannot replace it with a fresh
   create, detach, delete, or compensation request.
6. The controller persists the provider result before acknowledging terminal
   control work.

Tags help find resources but never grant authority. Mutation requires a
persisted operation plus positive ownership and matching generation. An
unknown resource remains untouched.

## Destructive operations

Delete, terminate, detach, and release operations require all ordinary fences
plus a current owner, retention and drain completion, dependency checks, and a
fresh provider observation. Missing inventory, a stale term, an ambiguous work
request, or a conflicting generation makes the operation read-only.

Compensation is explicit. The prepared operation lists which compensating
steps are allowed and their targets. A controller cannot invent cleanup after
an unexpected partial result.

## Credentials

Regional actuators use compartment-scoped OCI identities. The GRU global
controller distributes policy and limits but does not hold routine regional
mutation credentials. Credentials never appear in control messages, operation
documents, logs, or test fixtures.

## Required tests

Provider adapters cover lost responses, work-request eventual consistency,
controller restart, leadership change, duplicate delivery, stale generation,
unknown resources, capacity errors, and compensation after partial completion.
Live OCI tests stay opt-in and use a dedicated development scope.

## Consequences

Provider operations take more reconciliation steps, but retries converge on
one owned outcome. A stale controller cannot turn uncertainty into a second
mutation.
