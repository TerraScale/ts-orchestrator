# Independent registry v2 review of `7deaf74`

Reviewed integration tree: `7deaf74a4d481570e0e45679c0e353c8297ac939`.

This review does **not** freeze any of the 43 proposed IDs. Labels have the following
strict meanings:

- **Confirmed issue**: behavior reproduced from the integrated files or an internal
  contradiction in the current proposal.
- **Recommendation**: a steward change that improves the contract, but whose exact
  form is not forced by the current source.
- **Blocked owner decision**: a semantic choice that the steward must not invent.

## Executive conclusion

The v2 migration is a useful exact-source-anchor baseline, but it is not yet a
traceability contract. The source-range digests correctly detect a change to a
normalized cited slice. They do not validate semantic adequacy, audit/registry
parity, co-reviewers, root schema metadata, or meaningful evidence identities.
All 43 registered entries still have `evidenceState: missing`, so the audit's
`semantic: 43` means “metadata populated,” not “semantically complete” or verified.

The 43 proposed missing IDs are a discovery inventory, not a freeze-ready registry
patch. State-machine and error candidates are mostly sound families after the
clarifications below. Security proposals need explicit refinement relationships to
existing invariants. All 17 gate proposals require a namespace/kind decision and
per-assertion decomposition.

## Confirmed issues

### C1 — `REQ-GATE-*` contradicts the declared `acceptance-gate` kind

All 17 gate findings propose a `REQ-GATE-*` ID with kind `acceptance-gate`. Both the
Python checker and `RepositoryBoundaryTests` infer `REQ` as kind `requirement`.
Adding any proposal exactly as written therefore fails the current validators.

**Action:** before registration, choose one model: (a) keep `REQ-GATE-*` and use
`kind: requirement` plus an explicit gate subtype/relationship, or (b) add a real
`GATE-*` namespace and update the steward-owned schema and both validators. Do not
silently register the current contradictory pair.

### C2 — audit-to-registry semantic parity is not checked

A controlled mutation changed `AUD-ID-001.owner` from Integration to Cloud and its
layers to `[L0]`, while leaving `REQ-O001` unchanged. The checker returned `ACCEPTED`.
The audit can therefore disagree with its canonical registry entry while passing.

**Action:** for every `semantic` finding, compare kind, owner, acceptance layers,
source anchor, statement identity/digest, evidence state, and evidence targets with
the referenced registry entry. Make ordering semantics explicit for layer lists.

### C3 — `coReviewers` is dead, unchecked contract data

All 43 entries contain `coReviewers: []`, but neither validator parses or validates
the field. A controlled `[NOT-A-LANE]` mutation passed. This is especially unsafe
after collapsing `control-plane`, `cloud-storage`, and `delivery-security` aliases
to one exclusive primary lane.

**Action:** add `CoReviewers` to the typed model and Python parser; require unique
canonical lanes, forbid the primary owner, and populate cross-lane reviews. At a
minimum review REQ-O011 (Storage + Cloud/TerraBase), REQ-O015 (Delivery +
Messaging/security), INV-014 (Cloud + Integration), INV-016 (Verification + affected
production lanes), and INV-018 (Messaging/security + Cloud/Runtime/Storage).

### C4 — evidence targets are only nonempty strings with the right count

A controlled replacement of an evidence target with `"x"` passed. The integrated
targets are generic repetitions such as `L0 evidence bound to the exact integration
tree`; no check binds a target to its layer, scenario, artifact, dependency closure,
or digest. Target count is not evidence identity.

**Action:** use structured targets containing at least `layer`, stable scenario or
test ID, artifact/attestation identity, candidate-tree digest, status, and producing
lane. Validate one unique target per declared layer (or explicitly model many-to-one
authority). Keep every current target missing until an artifact exists.

### C5 — root contract metadata is ignored

A controlled mutation to `schemaVersion: 999`, `status: frozen`, and an invalid
`evidenceStateVocabulary` passed. The C# deserializer ignores these fields entirely.

**Action:** validate the exact supported schema version, allowed registry status,
normative source, unresolved-question shape, and evidence vocabulary in both
validators. Freeze must additionally reject unresolved owner questions and missing
evidence.

### C6 — presence is mistaken for semantic quality

Replacing a normative statement with `"x"` passed. A digest binds the cited bytes,
but the checker proves neither that the statement faithfully summarizes those bytes
nor that the range contains the full normative rule. Coordinated source and digest
changes also pass without a separately recorded source-revision identity.

**Action:** add review provenance (reviewer, source commit, decision/ADR) and a
negative fixture for truncated ranges. Treat the slice digest as drift detection,
not proof of semantic completeness. A document/revision digest is recommended for
freeze attestations.

### C7 — `INV-010` and `SEC-NO-SECRET-OUTPUT` duplicate one rule

They cite the same line, use the same SHA-256, owners, layers, and materially
identical normative statements. This creates two evidence identities for one rule
without a refinement or alias relationship.

**Action:** retain one canonical ID and alias the other, or explicitly model the
security item as a test/control refinement of INV-010 with inherited evidence. Do
not require duplicate proof merely because two taxonomies are useful.

### C8 — the migrated README contradicts the migrated data

The current README says all 43 entries are `id-only`, have alias owners, and carry no
semantic fields. The integrated JSON instead reports 43 `semantic`, zero `id-only`,
and zero owner aliases; the registry has populated statements/digests. Its opening
paragraph was updated, but the next paragraph was not.

**Action:** steward-update the canonical audit README to distinguish 43
source-anchored proposals from zero complete/verified contracts. Add README summary
values to review or generation so this drift cannot recur.

### C9 — `ERR-PHASE0-NOTREADY` is not demonstrated as a stable product error

The entry anchors repository planning status at lines 3–4, not an externally visible
runtime rejection, protocol error, or typed client outcome. This conflicts with the
audit's stated error-family selection rule.

**Action:** either reclassify it as a gate/readiness status or cite the contract that
defines a stable error surface, payload, and consumer. Do not freeze it as an error
based only on planning prose.

## Source-digest assessment

**Confirmed:** Python `splitlines()` + `"\n".join(...)` and C# `ReadAllLines` +
`string.Join('\n', ...)` implement the same normalized-slice SHA-256 semantics.
Exact cited text drift is detected; the added negative fixture exercises it.

**Recommendation:** document that line endings and the final newline are excluded,
and that line-number movement is intentionally breaking. Bind a frozen registry to
a source commit/document digest as well as slice hashes. Add tests for an expanded
range, a truncated-but-still-containing range, duplicate source hashes, and
coordinated audit/registry mismatch.

## Review of every proposed missing ID

“Retain” means retain as a proposal after the global schema/evidence fixes; it does
not mean freeze.

| Finding / proposed ID | Classification | Required steward disposition |
|---|---|---|
| AUD-SM-001 / SM-SELF-UPGRADE | Recommendation | Rename `SM-ORCHESTRATOR-SELF-UPGRADE` to disambiguate the actor; retain the full rollback graph. |
| AUD-SM-002 / SM-NATS-MEMBER-REPLACEMENT | Recommendation | Retain, but parameterize/control-vs-product plane and bind ambiguity/quorum holds as named transitions. |
| AUD-SM-003 / SM-PULUMI-OWNERSHIP-HANDOFF | Recommendation | Retain; add INV-014 relationship and remove L5 unless a soak assertion is identified. |
| AUD-SM-004 / SM-NODE-SCALE-OUT | Recommendation | Retain; require provider-fake transition evidence and explicit idempotent retry states. |
| AUD-SM-005 / SM-NODE-SCALE-IN | Recommendation | Retain; link stale-metric, fencing, drain, and ownership holds to typed outcomes. |
| AUD-SM-006 / SM-VOLUME-CREATE-ATTACH | Recommendation | Rename or split: cited graph also formats and mounts. Preserve irreversible-format recovery as an independently evidenced transition. |
| AUD-SM-007 / SM-VOLUME-EXPANSION | Recommendation | Retain; split provider, guest-rescan, filesystem-growth, and verification failure reasons beneath the family. |
| AUD-SM-008 / SM-GITOPS-RECONCILIATION | Recommendation | Retain; identify the durable-acceptance boundary and remove L5 unless a specific soak assertion exists. |
| AUD-SEC-001 / SEC-MTLS-TRUST-BOUNDARIES | Recommendation | Retain as an umbrella security policy; decompose independently failing trust boundaries into evidence targets. |
| AUD-SEC-002 / SEC-NATS-DUAL-AUTHORIZATION | Recommendation | Retain as a refinement of SEC-MTLS-TRUST-BOUNDARIES; prove both mTLS identity and NATS permission denial separately. |
| AUD-SEC-003 / SEC-CLOSED-ROLE-ADMISSION | Recommendation | Link as a narrower control refinement of INV-017 or merge; avoid parallel evidence for the same admission fact. |
| AUD-SEC-004 / SEC-NATS-MONITORING-ISOLATION | Recommendation | Retain; specify bind address, authorization, and exposure assertions separately. |
| AUD-SEC-005 / SEC-PROVIDER-MUTATION-AUTHORITY | Recommendation | Retain; link to INV-006/INV-014 and require Cloud plus security co-review. |
| AUD-SEC-006 / SEC-SURVIVAL-BUNDLE-NO-PLAINTEXT | Recommendation | Retain only as a scoped refinement of INV-010, with inherited no-secret-output evidence and separate offline-root-key assertion. |
| AUD-SEC-007 / SEC-NATIVE-CREDENTIAL-DELIVERY | Recommendation | Rename `SEC-NATIVE-SYSTEMD-CREDENTIAL-DELIVERY` if the source is intentionally native-only; do not imply container coverage. |
| AUD-SEC-008 / SEC-VAULT-STANDARD-CRYPTO | Recommendation | Retain as review/static-analysis policy; L4 does not itself prove absence of custom crypto/parser code, so identify authoritative evidence. |
| AUD-ERR-001 / ERR-NATS-AMBIGUOUS-STORE-HOLD | Recommendation | Retain; define stable payload/retryability and link to the NATS replacement held transition. |
| AUD-ERR-002 / ERR-NATS-QUORUM-DESTRUCTIVE-HOLD | Recommendation | Retain; distinguish peer-count and quorum/currentness facts in the error detail. |
| AUD-ERR-003 / ERR-SNAPSHOT-ANTI-ROLLBACK | Recommendation | Rename to an outcome such as `ERR-SNAPSHOT-ROLLBACK-REFUSED`; define generation/identity fields. |
| AUD-ERR-004 / ERR-COMMAND-ENVELOPE-REJECTED | Recommendation | Keep a family only if stable reason codes separately identify expired, stale, wrong-cell, wrong-identity, and lower-generation failures; otherwise split. |
| AUD-ERR-005 / ERR-CLOCK-SKEW-DESTRUCTIVE-HOLD | Recommendation | Retain; define measured skew input, held operations, retryability, and operator remediation. |
| AUD-ERR-006 / ERR-GRU-HA-RESERVE-EXHAUSTED | Recommendation | Rename to `ERR-GRU-HA-MARGIN-VIOLATION`; the source is a failure-margin invariant, not necessarily resource exhaustion. |
| AUD-ERR-007 / ERR-PROVIDER-OWNERSHIP-MISMATCH | Recommendation | Retain; differentiate unowned, mismatched cell, generation, and handoff states as stable reasons. |
| AUD-ERR-008 / ERR-SCALE-IN-METRICS-STALE | Recommendation | Retain; bind only to scale-in and state the freshness threshold via an owner-resolved parameter. |
| AUD-ERR-009 / ERR-KNOWN-VOLUME-FORMAT-REFUSED | Recommendation | Retain; define recognized-signature evidence and make destructive override impossible rather than merely operator-configurable. |
| AUD-ERR-010 / ERR-VOLUME-EXPANSION-HELD | Recommendation | Retain as a family only with provider/rescan/filesystem/verification reason codes and resumable operation identity. |
| AUD-GATE-001 / REQ-GATE-PHASE0 | Confirmed issue + blocked owner decision | Resolve C1; split each exit assertion. Satisfaction remains blocked by owner questions 1–10 and unresolved measurable targets. |
| AUD-GATE-002 / REQ-GATE-PHASE1 | Confirmed issue | Resolve C1; model as an aggregate depending on the predeployment and evidence-threshold gates, not duplicate evidence. |
| AUD-GATE-003 / REQ-GATE-PHASE2 | Confirmed issue + blocked owner decision | Resolve C1; split identity/NATS assertions. Final topology/credential choices must remain configurable until owners answer. |
| AUD-GATE-004 / REQ-GATE-PHASE3 | Confirmed issue + blocked owner decision | Resolve C1; split native/container lifecycle assertions and retain the owner-selected default as unresolved. |
| AUD-GATE-005 / REQ-GATE-PHASE4 | Confirmed issue + blocked owner decision | Resolve C1; split provider/handoff/leadership assertions; cost/SLO policy remains owner-owned. |
| AUD-GATE-006 / REQ-GATE-PHASE5 | Confirmed issue + blocked owner decision | Resolve C1; split bootstrap, replication, backup, restore, expansion, and fencing assertions; RPO/RTO/storage choices remain unresolved. |
| AUD-GATE-007 / REQ-GATE-PHASE6 | Confirmed issue | Resolve C1; split durable HTTP acceptance from reconciliation/rollback assertions and relate them to SM-GITOPS-RECONCILIATION. |
| AUD-GATE-008 / REQ-GATE-PHASE7 | Confirmed issue + blocked owner decision | Resolve C1; split immutable promotion, trust-zone, interruption, and rollout assertions; signing/release choices remain owner-owned. |
| AUD-GATE-009 / REQ-GATE-PHASE8 | Confirmed issue + blocked owner decision | Resolve C1; split read-only, telemetry, outage, VPN, orphan, and browser assertions; observability targets remain unresolved. |
| AUD-GATE-010 / REQ-GATE-PHASE9 | Confirmed issue + blocked owner decision | Resolve C1; split each qualification threshold; do not freeze omitted SLO/cost/RPO/RTO values. |
| AUD-GATE-011 / REQ-GATE-PRODUCTION-PLATFORM | Confirmed issue + blocked owner decision | Resolve C1; model as a parent gate over independently named platform assertions, with no duplicated child evidence. |
| AUD-GATE-012 / REQ-GATE-PRODUCTION-TERRABASE-STORAGE | Confirmed issue + blocked owner decision | Resolve C1; split backup/restore/failover/expansion assertions and leave RPO/RTO/storage parameters owner-resolved. |
| AUD-GATE-013 / REQ-GATE-PRODUCTION-COMPATIBILITY | Confirmed issue + blocked owner decision | Resolve C1; split promotion, rollback, upgrade, compatibility, and retirement assertions; retain release-policy choices as unresolved. |
| AUD-GATE-014 / REQ-GATE-PREDEPLOYMENT-EVIDENCE | Confirmed issue | Resolve C1; retain as a parent gate whose children are exact pre-VM assertions, not one opaque evidence string. |
| AUD-GATE-015 / REQ-GATE-MINIMUM-EVIDENCE-THRESHOLDS | Confirmed issue | Resolve C1; split each numeric floor and define denominator semantics (declared, applicable, skipped, quarantined). |
| AUD-GATE-016 / REQ-GATE-TEST-LAYER-AUTHORITY | Confirmed issue | Resolve C1; this is authority policy, not one executable test. Represent per-layer authority rules and gate dependencies. |
| AUD-GATE-017 / REQ-GATE-PERFORMANCE-CORRECTNESS | Confirmed issue + blocked owner decision | Resolve C1; split deterministic placement, latency/resource budgets, recovery, and soak criteria; numeric targets remain owner decisions. |

## Steward patch plan

Apply these as small steward-owned commits; no proposal should be frozen merely by
landing the mechanics.

1. **Correct the migration narrative.** Update the canonical README to 43 semantic
   metadata entries, 43 missing proposals, zero verified/complete entries.
2. **Close validator holes.** Validate root metadata, co-reviewers, semantic
   audit/registry parity, structured evidence identities, and freeze preconditions in
   both Python and C#. Add adversarial fixtures for every C2–C6 mutation.
3. **Resolve taxonomy.** Record an ADR choosing `REQ`+gate subtype or a new `GATE`
   namespace. Add `refines`, `aliasOf`, `parentGate`, and `dependsOn` (or equivalent)
   so aggregate gates/security controls do not duplicate invariant evidence.
4. **Deduplicate current registry.** Resolve INV-010 versus SEC-NO-SECRET-OUTPUT and
   reclassify ERR-PHASE0-NOTREADY before adding IDs.
5. **Restore ownership semantics.** Populate and validate cross-lane co-reviewers;
   owner approval is required for the named high-risk entries and each proposed
   cross-domain family.
6. **Register reviewed SM/SEC/ERR candidates as `proposed`.** Apply the table's
   renames/splits/reason-code decisions. Keep `evidenceState: missing`.
7. **Decompose gates.** Introduce independently failing child assertions and a DAG
   for Phase/production aggregates. Do not create one target per bullet by string;
   create stable evidence identities with explicit authority.
8. **Owner-decision checkpoint.** Keep unresolved parameterized values and gate
   satisfaction blocked. Only a subsequent reviewed freeze commit may change status.

## Verification record

- `python3 docs/audits/registry/check_registry_audit.py --negative-fixtures docs/audits/registry/fixtures/negative-cases.json` — PASS (43 registry entries, 86 findings, 10 fixtures).
- `dotnet restore TerraScale.Orchestrator.slnx --locked-mode` — PASS.
- `dotnet build TerraScale.Orchestrator.slnx --no-restore` — PASS, zero warnings.
- `dotnet test TerraScale.Orchestrator.slnx --no-build` — PASS, 4/4 tests.
- Controlled in-memory checker mutations C2–C6 — all incorrectly accepted, as
  recorded above. No canonical files were changed to perform those tests.
