# ADR 0020: Provider actuator crash-stop and irreversible-operation fencing

- Status: Accepted safety boundary; provider qualification pending
- Date: 2026-07-13
- Decision owner: Cloud
- Readiness entry: `20 / provider-actuator-threat-model`

## Context

An OCI mutation can outlive the controller leadership and HTTP call that initiated it. The control plane may crash after its last authority check, lose the response, observe an SDK timeout while the request continues, or receive a delayed work-request completion after another leader takes over. OCI does not understand a NATS lease or controller fencing epoch, and IAM or dynamic-group propagation is not a leader-failover fence ([specification, lines 642-646](../../docs/architecture/orchestrator.md#L642-L646)).

The safety requirement is stronger than avoiding duplicate API calls: every external mutation must have one persisted, authorized terminal intent, and stale actors must be unable to create a conflicting accepted outcome (`INV-004`, `INV-005`, and `INV-006`; [specification, lines 146-148](../../docs/architecture/orchestrator.md#L146-L148)). The provider interface therefore requires a `ProviderOperationContext` for every mutation ([specification, lines 687-702](../../docs/architecture/orchestrator.md#L687-L702)).

This threat model is scoped to crash-stop failure of trusted, signed orchestrator code and ordinary provider/network faults. It does not claim safety against Byzantine execution by a root-compromised actuator host. Compromise prevention, detection, credential revocation, and recovery still require a separately reviewed IAM/host security design.

## Decision

Use **persisted intent plus same-operation resume** as the control fence:

1. A pure controller decision persists an operation as `Prepared`, with exact target/creation key, expected observation and generation, proposed terminal state, permitted compensations, required approvals, deadline, preparing controller epoch, and operation identity. `Prepared` is durable intent, but **is not provider-call authorization**.
2. While `Prepared`, the current fenced writer evaluates fresh provider observation, positive ownership, generation, approvals, policy/quorum/budget gates, and the unexpired deadline. A failed or stale check transitions to `Held` and makes no provider call. The controller may safely abandon or re-plan a never-authorized preparation according to its owning state machine.
3. If every gate passes, the writer atomically persists `AuthorizedForProviderCall`. That record freezes the exact provider action and payload digest, target OCID or create key, desired terminal state, provider idempotency/retry key, allowed compensations, authorizing epoch, evidence/approval digests, deadline evaluated at authorization, and authorization commit sequence/digest.
4. The durable transition to `AuthorizedForProviderCall` is the **irreversible commit point**. Before it, expiry, leadership loss, stale observation, or approval withdrawal may hold the operation without a call. After it, a leadership or deadline change may pause an as-yet-unsent dispatch or force reconciliation/escalation, but cannot cancel the committed provider step, replace its terminal target, change its payload/request key, or authorize a conflicting operation.
5. Only an exact `AuthorizedForProviderCall` record can produce a `ProviderOperationContext`. The compartment-scoped regional actuator verifies that record and its digest immediately before dispatch. If the current executor cannot safely dispatch—for example, it lost leadership before crossing the API boundary—it records a hold/transfer of execution; a successor continues the same committed operation rather than preparing a replacement.
6. Before crossing the provider boundary, the actuator durably records the dispatch attempt against the authorization commit. It supplies the frozen operation-bound OCI retry/idempotency token and captures the work-request identifier or exact provider resource identity when OCI exposes them. The exact OCI SDK/service semantics remain unselected until primary sources and spikes establish them.
7. The adapter persists the returned identity/result. A timeout or transport loss is `outcome unknown`, never `operation failed` and never permission to issue a fresh logical operation.
8. Recovery reads provider truth and the recorded work request/idempotency key. A new leader resumes or re-observes the **same authorized operation and desired terminal state**. Any renewed execution lease or approval to resume dispatch is attached to that operation; it cannot change the authorization commit's action, target, payload, request key, or terminal target.
9. Late completion is accepted only when it completes that already-authorized operation safely. Otherwise it is quarantined as an inconsistent observation and cannot authorize compensating destruction by itself.
10. Tags aid discovery and mismatch detection only. Mutation authority requires the scoped OCI capability and the authoritative `AuthorizedForProviderCall` record; IAM propagation is never treated as a fencing signal.

Once the `AuthorizedForProviderCall` transition commits, the destructive provider step is irrevocable in the control model. “Irrevocable” means the exact action and desired terminal intent cannot be replaced with a conflicting intent merely because leadership changed, the deadline elapsed, or a call timed out. It does not mean the provider call must succeed, that execution may ignore an expired dispatch/leadership gate, that every action lacks a deliberate compensation, or that an operator can never approve a later independent operation after the committed operation reaches a known terminal state. A post-commit hold preserves the committed target and request identity; recovery reconciles or resumes that same operation.

## `ProviderOperationContext` contract

The proposed minimum fields are:

- authoritative operation ID and operation kind;
- `AuthorizedForProviderCall` commit sequence and record digest;
- cell and exact compartment;
- authorizing controller/fencing epoch and current executor identity/lease;
- exact target OCID, or a deterministic idempotent create key before an OCID exists;
- expected provider observation and resource/template/bootstrap generation;
- desired terminal state;
- exact action/payload digest, approval/evidence digests, and permitted compensations;
- absolute deadline evaluated at authorization and persisted dispatch-attempt sequence;
- provider idempotency/retry token and, once known, work-request ID;
- immutable correlation to the owning handoff receipt and accepted desired-state generation.

The adapter must reject a context whose authorization state, commit digest, payload digest, target, request key, or correlation does not match the authoritative journal. A `Prepared` or `Held` operation cannot be converted to an adapter context. This ADR does not freeze serialization, OCI header names, token lifetimes, SDK versions, per-operation compensation policy, or the exact action-specific required fields.

## Safety rules

- Every mutating adapter call consumes an exact committed `AuthorizedForProviderCall` record; an adapter cannot invent business intent or execute a merely `Prepared` operation.
- Exactly one logical operation may own a target transition. A leadership change changes the executor, not the authorized terminal outcome.
- All create retries use the same deterministic create identity. Losing an HTTP response cannot create a second instance ([scale-out rule, lines 706-725](../../docs/architecture/orchestrator.md#L706-L725)).
- The irreversible commit requires fresh observation, exact target identity, generation match, an unexpired deadline, all required approvals, and positive ownership under ADR 0004.
- Wall-clock anomalies before commit hold destructive actions. Local lease validity uses bounded monotonic duration plus authoritative server timestamps ([partition rule, line 589](../../docs/architecture/orchestrator.md#L589)). After commit, anomaly or expiry can hold dispatch but cannot erase or alter the committed authorization; resume/reconciliation stays on the same operation.
- An unknown response is reconciled through read/work-request APIs before retry or compensation.
- A stale leader's late call can only be absent or safely complete the existing operation; it cannot create a second accepted writer or conflicting terminal state.
- Discovery results and tags cannot authorize mutation, adoption, cleanup, or compensation.
- Credentials are regional and compartment scoped. GRU distributes policy and ceilings but does not receive ordinary SFO/FRA mutation authority after handoff ([specification, lines 665-671](../../docs/architecture/orchestrator.md#L665-L671)).
- The global emergency budget may stop new non-safety scale-out but cannot manufacture destructive authority or block safety expansion needed to avoid data loss ([specification, lines 746-754](../../docs/architecture/orchestrator.md#L746-L754)).

## Failure and resume matrix

| Failure point | Required recovery behavior |
|---|---|
| Before `Prepared` persistence | No provider call is permitted. Replanning may create a new operation. |
| `Prepared`, before authorization checks | Resume evaluation; transition to `Held` if authority, observation, generation, approval, ownership, or deadline is stale. No provider call is permitted. |
| Checks passed, before `AuthorizedForProviderCall` commits | The irreversible boundary has not been crossed. Leadership loss or expiry holds without a call; the successor must re-evaluate all gates. |
| `AuthorizedForProviderCall` committed, before dispatch record | The exact action/target/payload/request key/terminal state are irrevocably fixed. A leadership/deadline change may hold dispatch, but cannot authorize a replacement; a successor resumes the same committed operation. |
| Dispatch recorded, before request reaches OCI | Treat provider outcome as potentially unknown if boundary crossing cannot be disproved. Reconcile before reusing the same operation-bound request key. |
| OCI accepted request, response lost | Read by work-request/idempotency/resource identity; never infer failure from timeout. |
| Resource created, ID not persisted | Discover only within the exact compartment and create identity, verify the full operation/generation/ownership tuple, then bind or quarantine. Tags alone are insufficient. |
| Leadership changes while work request runs | New leader observes/resumes the same terminal target; it cannot cancel by issuing a conflicting destructive request. |
| Late old-leader completion | Accept only as safe completion of the same authorized operation; otherwise hold and alert for review. |
| Deadline expires after authorization commit | Deadline stops blind dispatch/retries and may enter a held/escalated state; it does not negate the committed target or an in-flight mutation. Continue read-only reconciliation, and resume only the same operation under its action-specific recovery policy. |
| Provider returns inconsistent target/generation | `ERR-PROVIDER-OWNERSHIP-MISMATCH`; quarantine and make no further mutation. |
| Credential revoked or access denied | Persist denial, make no broader-credential fallback, and require scoped recovery. |

## Rejected unsafe interpretations

### Fencing token in a tag prevents a stale OCI call

Rejected. OCI does not atomically validate the control-plane lease when applying general compute/storage/LB calls. A tag is observation metadata, not a provider-side compare-and-swap fence.

### IAM/dynamic-group propagation fences leadership

Rejected. Propagation is delayed and is not transactionally coupled to regional leadership. Revoking the old identity may reduce exposure, but cannot prove a late call is absent.

### Timeout means the operation failed

Rejected. The provider may have accepted the request. Starting a new logical operation after timeout can duplicate a create or conflict with an in-flight destruction.

### New leader compensates before learning provider truth

Rejected. Compensation is itself a mutation and may race the original request. Only the persisted operation's permitted compensation may run, after reconciliation and its own authorization checkpoint.

### Best-effort target discovery by name or tags

Rejected. Non-unique or mutable metadata cannot bind an irreversible operation to an exact owned resource.

### Epoch change cancels an authorized destructive step

Rejected. The provider cannot enforce that cancellation. Once durably authorized, leaders converge on the same terminal intent so a late call remains safe in the control model.

## Consequences

- Provider adapters return typed observations and never contain ownership, retry, compensation, or terminal-state business rules.
- Journals distinguish `Prepared`, `Held`, and the immutable `AuthorizedForProviderCall` commit from dispatch attempts and provider outcomes.
- Journals retain enough sanitized request/work-request identity to distinguish `not sent`, `unknown`, `in progress`, `succeeded`, `failed`, and `inconsistent` after crashes.
- Journals, errors, logs, traces, metrics, and evidence obey `SEC-NO-SECRET-OUTPUT`; credential material and private keys are never persisted as provider-operation diagnostics.
- Each provider operation needs explicit idempotency, ambiguity, reconciliation, and compensation semantics; a generic retry policy is unsafe.
- Operator tooling must display an unknown/held provider outcome without offering an unscoped “retry anyway.”
- Credential scope is a blast-radius control, not the logical fence. A root-compromised trusted actuator remains outside this ADR's crash-stop guarantee.
- ADR 0004 must establish positive ownership before this actuator can mutate transferred resources.

## Unresolved inputs and evidence

The former readiness map requires exact OCI SDK idempotency/work-request semantics, a compartment-scoped IAM policy, leadership-loss/adapter-race evidence, and an independent security review; it depends on ADRs 1, 4, and 23. Acceptance remains blocked on:

- per-OCI-service retry token support, token scope/retention, work-request lookup, cancellation, timeout, and eventual-consistency behavior from primary documentation and executable spikes;
- the exact per-operation ambiguity and compensation table for compute, boot/block volume, attachment, LB backend, and any later provider mutations;
- exact regional compartment IAM statements, workload identity issuance/rotation/revocation, and denial behavior;
- the controller leadership-loss state model, `Prepared`/`Held`/`AuthorizedForProviderCall` journal schema, and action-specific post-commit dispatch-expiry policy;
- approved regional RPO/RTO, storage SLO, maximum survival window, and cost limits where they control deadlines, safe holds, expansion, and replacement;
- owner decisions governing regional outage mutation policy, storage cleanup, runtime defaults, and provider portability where downstream operations differ;
- independent review of the crash-stop assumption and the residual risk of host or credential compromise.

The removed incomplete read-only OCI inventory granted no mutation authority
and established no resource ownership.

## Required verification before production qualification

- **Review:** primary OCI semantics for every mutating API, exact `ProviderOperationContext`, per-operation ambiguity/compensation matrix, compartment policy, and independent security threat-model review.
- **L0:** exhaustively inject leader loss and deadline/approval/observation changes on both sides of the `AuthorizedForProviderCall` commit, then before and after every dispatch, call, response, work-request, reconciliation, compensation, and completion checkpoint. Explore duplicate, reordered, delayed, and contradictory observations. Prove pre-commit changes make no call, post-commit changes cannot alter the exact terminal target/request identity, one owned terminal outcome, no stale accepted mutation, and no tag-authorized action.
- **L3S:** fake-provider full-region scenarios for lost responses, arbitrarily delayed completions, actuator crash/restart, leadership churn, GRU/WAN loss, duplicate callbacks, stale observations, and operation-journal restore.
- **L4:** targeted disposable OCI A1/IAM/storage/LB tests after the exact-tree credential gate. Delay real work requests across leadership change and prove a new leader resumes the same operation without duplicate creation or conflicting destruction.
- **Security:** demonstrate that an identity cannot mutate another region/compartment or an unlisted resource/action, and that access denial never falls back to broader credentials.

Phase 4 cannot exit until crash/retry and leadership loss at every provider and handoff checkpoint produces exactly one owned terminal outcome and unowned resources remain untouched ([specification, lines 1538-1548](../../docs/architecture/orchestrator.md#L1538-L1548)). No test described here authorizes a cloud instance or API call before the exact-tree pre-deployment gate.

## Traceability

| Kind | Stable/proposed ID | Disposition in this ADR |
|---|---|---|
| Requirement | `REQ-O010` | Provides the regional actuator created by the Pulumi handoff. |
| Requirement | `REQ-O011` | Applies the fence to automatic node and storage mutations. |
| Requirement | `REQ-O023` | Prevents old-estate discovery from becoming adoption or mutation authority. |
| Invariant | `INV-004` | Exactly one fenced writer advances a provider operation. |
| Invariant | `INV-005` | Commands are idempotent, generation/deadline bound, and replay-safe. |
| Invariant | `INV-006` | Stale leaders/agents cannot produce a conflicting accepted mutation. |
| Invariant | `INV-014` | Limits the actuator to concrete resources transferred under ADR 0004. |
| Security rule | `SEC-NO-SECRET-OUTPUT` | Excludes credentials/private keys from operation state and diagnostics. |
| Proposed state machine | `SM-NODE-SCALE-OUT` | Requires request persistence before create and same-operation recovery. |
| Proposed state machine | `SM-NODE-SCALE-IN` | Requires exact-instance, gated destruction with fresh observations. |
| Proposed security rule | `SEC-PROVIDER-MUTATION-AUTHORITY` | Scoped capability plus persisted intent is required; tags never authorize. |
| Proposed error | `ERR-PROVIDER-OWNERSHIP-MISMATCH` | Holds mutation on target/ownership mismatch. |
| Proposed error | `ERR-SCALE-IN-METRICS-STALE` | Holds destructive scale-in on stale evidence. |
| Proposed error | `ERR-CLOCK-SKEW-DESTRUCTIVE-HOLD` | Holds destructive action when wall-clock validity is anomalous. |
| Proposed gate | `REQ-GATE-PHASE4` | Requires leadership-loss and delayed-call proof at every checkpoint. |

The live stable-identifier registry now transcribes the accepted identifiers in
`GOAL.md`. The proposal names in this ADR remain historical and are not frozen
stable identifiers
([current registry](../../src/orchestrator/contracts/stable_identifier_registry.go),
[historical registry note](../guides/phase0-evidence.md#registry-and-retirement)).
