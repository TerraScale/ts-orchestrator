# ADR 0020: Provider actuator crash-stop and irreversible-operation fencing

- Status: Proposed
- Date: 2026-07-13
- Decision owner: Cloud
- Readiness entry: `20 / provider-actuator-threat-model`

## Context

An OCI mutation can outlive the controller leadership and HTTP call that initiated it. The control plane may crash after its last authority check, lose the response, observe an SDK timeout while the request continues, or receive a delayed work-request completion after another leader takes over. OCI does not understand a NATS lease or controller fencing epoch, and IAM or dynamic-group propagation is not a leader-failover fence ([specification, lines 642-646](../../ORCHESTRATOR.md#L642-L646)).

The safety requirement is stronger than avoiding duplicate API calls: every external mutation must have one persisted, authorized terminal intent, and stale actors must be unable to create a conflicting accepted outcome (`INV-004`, `INV-005`, and `INV-006`; [specification, lines 146-148](../../ORCHESTRATOR.md#L146-L148)). The provider interface therefore requires a `ProviderOperationContext` for every mutation ([specification, lines 687-702](../../ORCHESTRATOR.md#L687-L702)).

This threat model is scoped to crash-stop failure of trusted, signed orchestrator code and ordinary provider/network faults. It does not claim safety against Byzantine execution by a root-compromised actuator host. Compromise prevention, detection, credential revocation, and recovery still require a separately reviewed IAM/host security design.

## Proposed decision

Use **persisted intent plus same-operation resume** as the control fence:

1. A pure controller decision creates an authoritative operation with exact target/creation key, expected observation and generation, desired terminal state, permitted compensations, approvals, deadline, controller epoch, and operation identity.
2. The operation and planned provider request are durably recorded before the adapter receives mutation intent.
3. The compartment-scoped regional actuator rechecks current authority immediately before the provider call. A failed check records a typed hold and makes no call.
4. The adapter supplies the operation-bound OCI retry/idempotency token and captures the work-request identifier or exact provider resource identity when OCI exposes them. The exact OCI SDK/service semantics remain unselected until primary sources and spikes establish them.
5. The adapter persists the returned identity/result. A timeout or transport loss is `outcome unknown`, never `operation failed` and never permission to issue a fresh logical operation.
6. Recovery reads provider truth and the recorded work request/idempotency key. A new leader resumes or re-observes the **same operation and desired terminal state**. It cannot supersede a durably authorized destructive step with a conflicting operation.
7. Late completion is accepted only when it completes that already-authorized operation safely. Otherwise it is quarantined as an inconsistent observation and cannot authorize compensating destruction by itself.
8. Tags aid discovery and mismatch detection only. Mutation authority requires the scoped OCI capability and the authoritative persisted operation; IAM propagation is never treated as a fencing signal.

Once a destructive provider step is durably authorized, it is irrevocable in the control model. “Irrevocable” means the desired terminal intent cannot be replaced with a conflicting intent merely because leadership changed or a call timed out. It does not mean the provider call must succeed, that every action lacks a deliberate compensation, or that an operator can never approve a later independent operation after the first reaches a known terminal state.

## `ProviderOperationContext` contract

The proposed minimum fields are:

- authoritative operation ID and operation kind;
- cell and exact compartment;
- controller/fencing epoch;
- exact target OCID, or a deterministic idempotent create key before an OCID exists;
- expected provider observation and resource/template/bootstrap generation;
- desired terminal state;
- explicit approvals and permitted compensations;
- absolute deadline and persisted attempt/request sequence;
- provider idempotency/retry token and, once known, work-request ID;
- immutable correlation to the owning handoff receipt and accepted desired-state generation.

This ADR does not freeze serialization, OCI header names, token lifetimes, SDK versions, per-operation compensation policy, or the exact action-specific required fields.

## Safety rules

- Every mutating adapter call consumes a previously persisted intent; an adapter cannot invent business intent.
- Exactly one logical operation may own a target transition. A leadership change changes the executor, not the authorized terminal outcome.
- All create retries use the same deterministic create identity. Losing an HTTP response cannot create a second VM ([scale-out rule, lines 706-725](../../ORCHESTRATOR.md#L706-L725)).
- Destructive calls require fresh observation, exact target identity, generation match, unexpired authorization, all required approvals, and positive ownership under ADR 0004.
- Wall-clock anomalies hold destructive actions. Local lease validity uses bounded monotonic duration plus authoritative server timestamps; it does not extend or recreate an expired authorization ([partition rule, line 589](../../ORCHESTRATOR.md#L589)).
- An unknown response is reconciled through read/work-request APIs before retry or compensation.
- A stale leader's late call can only be absent or safely complete the existing operation; it cannot create a second accepted writer or conflicting terminal state.
- Discovery results and tags cannot authorize mutation, adoption, cleanup, or compensation.
- Credentials are regional and compartment scoped. GRU distributes policy and ceilings but does not receive ordinary SFO/FRA mutation authority after handoff ([specification, lines 665-671](../../ORCHESTRATOR.md#L665-L671)).
- The global emergency budget may stop new non-safety scale-out but cannot manufacture destructive authority or block safety expansion needed to avoid data loss ([specification, lines 746-754](../../ORCHESTRATOR.md#L746-L754)).

## Failure and resume matrix

| Failure point | Required recovery behavior |
|---|---|
| Before intent persistence | No provider call is permitted. Replanning may create a new operation. |
| After intent, before authority recheck | Resume the same operation; hold if authority/generation/approval is stale. |
| After authority recheck, before request reaches OCI | A stale leader may still race. The new leader reconciles truth before issuing the same operation-bound request. |
| OCI accepted request, response lost | Read by work-request/idempotency/resource identity; never infer failure from timeout. |
| Resource created, ID not persisted | Discover only within the exact compartment and create identity, verify the full operation/generation/ownership tuple, then bind or quarantine. Tags alone are insufficient. |
| Leadership changes while work request runs | New leader observes/resumes the same terminal target; it cannot cancel by issuing a conflicting destructive request. |
| Late old-leader completion | Accept only as safe completion of the same authorized operation; otherwise hold and alert for review. |
| Deadline expires with unknown provider state | Deadline stops blind retries; it does not negate an in-flight provider mutation. Continue read-only reconciliation and enter an explicit held/unknown state. |
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
- Journals retain enough sanitized request/work-request identity to distinguish `not sent`, `unknown`, `in progress`, `succeeded`, `failed`, and `inconsistent` after crashes.
- Journals, errors, logs, traces, metrics, and evidence obey `SEC-NO-SECRET-OUTPUT`; credential material and private keys are never persisted as provider-operation diagnostics.
- Each provider operation needs explicit idempotency, ambiguity, reconciliation, and compensation semantics; a generic retry policy is unsafe.
- Operator tooling must display an unknown/held provider outcome without offering an unscoped “retry anyway.”
- Credential scope is a blast-radius control, not the logical fence. A root-compromised trusted actuator remains outside this ADR's crash-stop guarantee.
- ADR 0004 must establish positive ownership before this actuator can mutate transferred resources.

## Unresolved inputs and evidence

The readiness map requires exact OCI SDK idempotency/work-request semantics, a compartment-scoped IAM policy, leadership-loss/adapter-race evidence, and an independent security review; it depends on ADRs 1, 4, and 23 ([readiness index, lines 239-248](readiness-index.yaml#L239-L248)). Acceptance remains blocked on:

- per-OCI-service retry token support, token scope/retention, work-request lookup, cancellation, timeout, and eventual-consistency behavior from primary documentation and executable spikes;
- the exact per-operation ambiguity and compensation table for compute, boot/block volume, attachment, LB backend, and any later provider mutations;
- exact regional compartment IAM statements, workload identity issuance/rotation/revocation, and denial behavior;
- the controller leadership-loss state model and persisted journal schema;
- approved regional RPO/RTO, storage SLO, maximum survival window, and cost limits where they control deadlines, safe holds, expansion, and replacement;
- owner decisions governing regional outage mutation policy, storage cleanup, runtime defaults, and provider portability where downstream operations differ;
- independent review of the crash-stop assumption and the residual risk of host or credential compromise.

The incomplete read-only OCI audit grants no mutation authority and establishes no resource ownership ([OCI audit, lines 22-40](../audits/oci/phase0-residual-inventory.md#L22-L40)).

## Required verification before acceptance

- **Review:** primary OCI semantics for every mutating API, exact `ProviderOperationContext`, per-operation ambiguity/compensation matrix, compartment policy, and independent security threat-model review.
- **L0:** exhaustively inject leader loss before and after every persistence, authority-check, call, response, work-request, reconciliation, compensation, and completion checkpoint. Explore duplicate, reordered, delayed, and contradictory observations. Prove one owned terminal outcome, no stale accepted mutation, and no tag-authorized action.
- **L3S:** fake-provider full-region scenarios for lost responses, arbitrarily delayed completions, actuator crash/restart, leadership churn, GRU/WAN loss, duplicate callbacks, stale observations, and operation-journal restore.
- **L4:** targeted disposable OCI A1/IAM/storage/LB tests after the exact-tree credential gate. Delay real work requests across leadership change and prove a new leader resumes the same operation without duplicate creation or conflicting destruction.
- **Security:** demonstrate that an identity cannot mutate another region/compartment or an unlisted resource/action, and that access denial never falls back to broader credentials.

Phase 4 cannot exit until crash/retry and leadership loss at every provider and handoff checkpoint produces exactly one owned terminal outcome and unowned resources remain untouched ([specification, lines 1538-1548](../../ORCHESTRATOR.md#L1538-L1548)). No test described here authorizes a VM or cloud call before the exact-tree pre-deployment gate.

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

The registry audit classifies existing requirement/invariant entries as ID-only and proposes the state-machine/security/error/gate IDs; this ADR does not freeze those proposals ([registry audit, lines 30-57](../audits/registry/registry-audit.json#L30-L57); [registry audit, lines 67-98](../audits/registry/registry-audit.json#L67-L98)).
