# Phase 0 cloud ADR draft handoff

- Work package predecessor: `ee72a8f`
- Branch: `docs/phase0-cloud-adrs`
- Scope changed: ADR backlog items 4 and 20 plus this handoff only
- Status of both ADRs: `Proposed`
- Cloud, VM, Pulumi, sibling-repository, or other external mutation: none

## Result

Drafted:

- `docs/adr/0004-pulumi-provider-ownership.md`
- `docs/adr/0020-provider-actuator-threat-model.md`

ADR 0004 preserves the specification's two-owner boundary: Pulumi retains durable foundation and transfers an exact fresh-resource inventory through a signed, crash-resumable handoff before the regional actuator becomes the sole lifecycle owner. It rejects continuous dual reconciliation, historical-resource adoption, tag-based authority, and convention-only handoff.

ADR 0020 scopes provider correctness to trusted-code crash-stop failures and defines persisted intent plus same-operation resume. It records the minimum proposed `ProviderOperationContext`, late-call/timeout/leadership-loss recovery matrix, and why tags, IAM propagation, timeouts, or a new epoch cannot fence an already accepted OCI request.

Both drafts preserve unknown details instead of accepting them. They trace the current requirement/invariant IDs and clearly label state-machine, security, error, and gate identifiers from the registry audit as proposals that are not yet canonical.

## Validation

```text
git diff --check
python3 docs/adr/validate_readiness.py
python3 -m unittest discover -s docs/adr/tests -v
python3 <inline local Markdown anchor resolver>
```

Observed results:

- readiness index validated all 24 ADR backlog entries exactly once;
- all 6 readiness-validator tests passed;
- all 14 exact local source anchors in ADR 0004 resolved to nonblank, in-bounds lines;
- all 12 exact local source anchors in ADR 0020 resolved to nonblank, in-bounds lines;
- no VM, service, container, Pulumi, or OCI command was run.

## Remaining gaps before acceptance

- exact OCI compartment IAM policy and action/resource matrix;
- exact tag namespace and immutability rules;
- primary-source and executable evidence for the chosen Pulumi retain/unmanage transition;
- exact handoff receipt/resource-type/crash-checkpoint model;
- exact OCI SDK retry-token, idempotency, work-request, timeout, cancellation, and eventual-consistency semantics per mutating service;
- controller/adapter leadership-loss model, per-operation ambiguity/compensation table, and independent security review;
- repaired read-only OCI inventory evidence; current discovery is authentication-blocked and proves neither OKE absence nor an empty residual account;
- unresolved owner choices and measurable cost, storage, RPO/RTO, security, and regional-survival targets that control dependent behavior and acceptance evidence.

The drafts grant no deployment or mutation authority. L0, L3S, and L4 evidence described in them remains future acceptance work, and L4 cannot run before the repository's exact-tree pre-deployment gate.
