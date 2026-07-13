# Phase 0 owner decision and SLO packet handoff

- Work package predecessor: `f393dc4`
- Branch starting point observed by this lane: `5322e62`
- Scope changed: `docs/decisions/**` and this handoff only
- Destructive/external actions: none

## Result

The packet preserves all ten owner questions and both options exactly as written in `ORCHESTRATOR.md:89-98`. Every record carries its source line and a SHA-256 over the four exact source cells. `recommended: A` represents the table heading only; all ten `answer` fields are null and validation rejects any checked-in default.

There are 38 explicitly unset records:

- 10 owner decisions and 19 measurable targets required before the affected contract/ADR tranche can freeze;
- 2 Phase 0 planning inputs (team size and desired first-production date), explicitly not promoted to architecture decisions;
- 7 later Phase 0 implementation selections, segregated from owner decisions.

The measurable targets cover maximum three-region pre-user BRL/day cost; per-member IOPS, MiB/s, and p95/p99 read/write milliseconds; regional RPO seconds and RTO minutes; credential-revocation seconds, workload-certificate/renewal-lead hours, break-glass minutes, and critical-remediation hours; orchestrator RSS MiB and post-failure compact utilization percent; hot/immutable audit-retention days; and disconnected regional-survival hours. No value was inferred from a recommendation, provisional threshold, historical bill, current implementation, or agent judgment.

## Downstream impact coverage

Every owner question and input maps to canonical ADR IDs 1–24 and at least one canonical readiness/acceptance gate. Collectively the packet directly impacts ADRs 1–3, 5–12, 14, 16–17, 19, 21, and 24. The segregated later selections additionally cover ADRs 15, 22, and 23. ADRs 4, 13, 18, and 20 have no controlling owner/SLO input in the readiness map and are deliberately not given fabricated dependencies.

Gate mapping covers contract freeze, the Phase 0 exit, and the applicable L0, L0C, L1R, L3S, L4, and L5 evidence layers. An impact is not represented as a passing result.

## Validation and adversarial review

```text
python3 docs/decisions/validate_owner_decision_packet.py
python3 -m unittest discover -s docs/decisions/tests -v
python3 -m json.tool docs/decisions/owner-decision-packet.json
git diff --check
```

The validator derives exact question text and checksums directly from `ORCHESTRATOR.md`, enforces questions 1–10 exactly once, rejects any checked-in answer/value/selection, checks exact units and validation rules, and enforces canonical ADR/gate mappings. Four data fixtures adversarially mutate the valid packet to prove rejection of an accidental recommendation default, omitted question, invalid option, and invalid unit.

## Remaining gaps

- The owner has supplied none of the 10 answers or 21 planning/SLO values in this work package; this lane intentionally cannot reduce that unresolved count.
- The 7 implementation selections still require their own evidence-backed Phase 0 work; this packet only prevents them from being mistaken for owner answers.
- ADR impact mapping is synchronized to the Phase 0 ADR readiness lane but does not accept an ADR or replace its exit evidence.
- The packet validates checked-in unresolved state. A later response-ingestion workflow must validate supplied numeric values, cross-field relations such as p99 not below p95 and immutable retention not below hot retention, record owner provenance, and produce a separate reviewed acceptance record; it must not overwrite this blank template silently.

## Exact compact response

```text
1=_ 2=_ 3=_ 4=_ 5=_ 6=_ 7=_ 8=_ 9=_ 10=_; team-size=_ people; first-production-date=_; maximum-cost=_ BRL/day; storage-iops=_ IOPS; storage-throughput=_ MiB/s; storage-read-p95=_ ms; storage-read-p99=_ ms; storage-write-p95=_ ms; storage-write-p99=_ ms; regional-rpo=_ seconds; regional-rto=_ minutes; security-revocation=_ seconds; certificate-ttl=_ hours; certificate-renewal-lead=_ hours; break-glass-ttl=_ minutes; security-critical-remediation=_ hours; orchestrator-rss=_ MiB; compact-post-failure-utilization=_ percent; audit-hot-retention=_ days; audit-immutable-retention=_ days; regional-survival=_ hours
```

Unknown values should remain `_`; each A/B answer must be an explicit owner choice.
