# Direct delivery runbook

Operator procedures for the direct-delivery runtime (the `direct.operation.*` journal, the
`direct.target.*` region state, and the `direct.evidence.*` artifact evidence records on the
regional delivery ledger). Every error code, state, and remediation below is the exact string
the implementation produces; when this document and a receipt disagree, the receipt wins.

The operator status surface is the typed, read-only projection
`DirectDeliveryOperatorStatusProjection.Project(<durable journal record>)`: it reports the
current operation, per-region progress, health, rollback state, and the actionable failure,
and it never carries request text, actor identities, or customer content.

## Receipt anatomy (what to read first)

A `DeliveryReceipt` is the terminal authority for one `operationId`:

- `status`: `succeeded`, `failed`, or `rolled_back`. `rolled_back` means the delivery's own
  mutation failed and the recorded previous artifact was restored and health-verified.
- `rollback.targetArtifactDigest` / `rollback.status`: the recovery anchor (`not_required`,
  `succeeded`, `failed`) and whether it holds.
- `error.code` / `error.remediation`: the stable, bounded failure identity and the operator
  action. Codes are stable strings; remediations are the actionable text quoted below.

Durable per-region truth lives in the journal record's `regions` list (each region's `state`
and `previousArtifactDigest`/`previousManifestDigest`), not only in the receipt: with
heterogeneous per-region previous digests, the receipt's single `targetArtifactDigest` is a
representative anchor, and each region's own recorded previous digest is authoritative for
what that region must restore.

## Failed mutation

Symptoms: receipt `error.code` is `mutation_failed`, or `mutation_race`.

- `mutation_failed` — "The target mutation failed." Remediation: "Inspect the target and
  retry after remediation."
  - If mutation began and a safe previous artifact existed, the coordinator already attempted
    rollback; a receipt of `rolled_back` with `rollback.status = succeeded` means the region
    set is back at its recorded previous digests — nothing is left to restore. That operation
    is terminal: replaying the same `operationId` returns the same receipt, so a redeploy uses
    a new `operationId` once the target fault is fixed.
  - First-ever deployment into a pristine region cannot roll back: the remediation is
    extended with "Region(s) deployed for the first time have no prior artifact to roll back
    to and remain deployed; remediate them or redeploy a fixed artifact (bootstrap
    expectation)." Those regions stay on the new artifact by design.
- `mutation_race` — "A concurrent mutation changed the region between admission and
  mutation." Remediation: "The region was left untouched by this delivery. Inspect the
  concurrent writer, then submit a new delivery request for the digest you actually want
  deployed; the recorded rollback target of this operationId is spent."
  - Do not retry the same `operationId` expecting the race to resolve: the fence deliberately
    refuses to re-mutate a region another writer owns. Submit a fresh request.

Transient boundaries report distinct codes and are safe to wait out or retry in place:
`authorization_unavailable` ("Retry the same operationId after the control plane is
reachable.") and `provenance_unavailable` ("Retry the same operationId after the evidence
source is reachable."). Authentication-class failures are denials, not transients:
`unauthorized_actor` and `provenance_failed`.

## Failed rollback

Symptoms: receipt `status = failed`, `error.code = rollback_failed` — "Automatic rollback did
not complete." Remediation: "Restore the recorded target artifact digest and inspect the
target before retrying."

- The recovery anchor is exact: `rollback.targetArtifactDigest` (and
  `rollback.targetManifestDigest` when present). Restore that digest, per region, from the
  journal record's `regions[].previousArtifactDigest` / `previousManifestDigest` when regions
  differ.
- Retrying the same `operationId` resumes the rollback instead of replaying the terminal
  receipt: durable `rollback_pending` / `rollback_failed` regions are collected and re-driven.
  A completed rollback whose receipt never persisted converges on replay without re-applying.
- Never hand-edit `direct.target.*` values to "fix" a region: rollbacks are fenced against
  the recorded previous digest, and an unrecorded change turns the next delivery into a
  `mutation_race`.

## Stale evidence

Symptoms: `error.code` is `stale_digest` or `provenance_failed` (production), or the delivery
evidence record cannot be found for the requested digest.

- `stale_digest` — "The artifact digest is stale." Remediation: "Publish or select the exact
  current artifact digest."
- `provenance_failed` — "Source and artifact provenance could not be verified." Remediation:
  "Provide matching immutable source, configuration, and artifact evidence."
- Production verifies requests only against durable, signed evidence records
  (`direct.evidence.<sha256(lowercased artifact digest)>`), recorded by the CI artifact
  attestation gate when a trusted-build pipeline attests a published artifact. A digest
  without a durable record is denied — that is the boundary working, not a bug.
- Evidence verification uses the CI **artifact** role's trust root
  (`TS_ORCH_CI_ARTIFACT_TRUST_KEY_FILES`), and native runtime observations use the **runtime**
  role's (`TS_ORCH_CI_RUNTIME_TRUST_KEY_FILES`). The roles are deliberately distinct key
  material: a runtime-observation signature never verifies as an artifact signature. If both
  roles' verifiers reject records that used to verify, check for a key rotation that did not
  update the trust sets — do not merge the trust sets to work around it; startup fails closed
  if a production role lacks its own identity
  (`TS_ORCH_CI_JOB_SIGNING_KEY_FILE`, `TS_ORCH_CI_ARTIFACT_SIGNING_KEY_FILE` +
  `TS_ORCH_CI_ARTIFACT_TRUST_KEY_FILES`, `TS_ORCH_CI_RUNTIME_TRUST_KEY_FILES`).
- A record filed under the wrong digest key is treated as corruption, never as evidence: the
  denial is permanent. Re-publish the artifact so a correctly-bound record is recorded.

## Journal outage

Symptoms: `error.code = journal_unavailable` — "The durable delivery journal is unavailable."
Remediation: "Restore journal health and retry the same operationId; the operation replays
its durable progress."

- Retry the **same** `operationId`: the operation replays its durable per-region progress.
  A new `operationId` for the same request is admitted as a separate operation and re-applies.
- A delivery that was already applied, healthy, and converged is **never** rolled back when
  only the final journal append failed; the replayable receipt keeps the operation resumable.
- Two journal-unavailable shapes carry their own remediations and are not journal-health
  problems:
  - Retention cap overflow ("The durable delivery journal is over its retention cap with
    unprunable records."): "Raise the retention cap or let the bounded-age horizon pass, then
    retry the same operationId; the operation replays its durable progress."
  - Conflicting progress append ("Another writer advanced this operation's durable progress
    (continuity or write-ahead rollback-material conflict); no update was lost. Reconcile the
    region state, then submit a new delivery request.") — the journal refused a contradiction;
    it is healthy.
- A record this build cannot decode ("A durable delivery journal record for this operation
  cannot be read by the current record codec."): "The journal record predates the current
  record codec and cannot be replayed; clear or drain the affected operation before
  continuing." No journal restoration makes those bytes replayable.
- Retention never prunes a record that still owes rollback recovery; if unprunable records
  pin the cap, resolve their rollbacks first (see "Failed rollback").

## Stuck reconciliation

Symptoms: an operation whose journal record stays in `applying` or `rolling_back`, or regions
stuck in `rollback_pending`, with no new receipt; repeated `cancelled`,
`authority_fenced`, or replayable failures.

- `cancelled` — "The delivery operation was cancelled." Remediation: "Retry the same
  operationId once the target is available; the operation replays its durable progress."
- `authority_fenced` — "The delivery authority changed before the mutation completed."
  Remediation: "Sign and submit a new delivery request under the current authority: the fenced
  request's authority generation and writer epoch are bound into the operation fingerprint, so
  retrying the same operationId can never be admitted." Retrying the same ID is a dead end by
  design.
- A stuck `applying` region means a process died between the write-ahead persist and the
  `applied` persist. Its previous digests are durably recorded; replaying the same
  `operationId` resumes from them (a crash-replayed fence over an already-applied region is a
  no-op, not a race).
- A stuck `rollback_pending` region is collected by the next replay of the same
  `operationId`; if replays cannot complete because the target boundary is down, treat it as
  the provider fault in "Failed mutation" and restore the recorded digests manually.
- `operation_conflict` — "The operationId is already bound to a different request."
  Remediation: "Generate a new operationId for a different request." An operation identity is
  one request; it never migrates.
- Commit-status delivery-budget exhaustion — on the final allowed delivery of an event it
  must retry, the CI event consumer logs a single loud error line beginning
  "CI event delivery budget exhausted" that names the subject and the delivery counts and
  states that the Forgejo commit status for the revision was never reported and the event
  will not be redelivered, ending with "Operator action required: inspect the durable CI run
  for this revision and report the commit status manually." The durable CI work is
  unaffected; only the notification is missing. Report the status by hand after inspecting
  the run, and fix the condition that kept the event retrying.

## Drills (in-process)

The following failure drills are exercised by the test suite at in-process fidelity (fakes
and virtual boundaries, no live providers):

| Drill | Coverage |
| --- | --- |
| Restart | terminal-receipt replay, crash between apply and persist, restart mid-rollback (DirectDeliveryTests, DirectDeliveryProductionAdapterTests) |
| Duplicate message | duplicate delivery replays the same receipt without a second mutation |
| Stale metric | stale health is not eligible (EndpointVerificationTests); stale digests and unverified provenance fail closed |
| Expired credential | authentication-class boundary failures report denial codes, not transient ones |
| Provider timeout | timed-out authorization/provenance boundaries report the transient codes |
| Partition | a provider-unreachable later region rolls back earlier regions and journals the typed failure |
| Journal failure | unavailable journal, retention overflow, mid-apply journal loss, journal failure after a healthy deployment |

Regional three-lab and production-provider drills are out of scope for this document; they are
gated by the repository's exact-tree pre-deployment evidence rules.
