# Physical deletion completion source audit

Date: 2026-09-07. Scope: source inspection only; no provider calls, destructive
operations, builds, or runtime qualification were performed for this audit.

Physical deletion completion remains unimplemented. Neither elapsed retention
nor successful backup deletion is evidence that every retained copy is gone.
Do not publish `effects_completed` from either condition.

## Current production chain

- `src/orchestrator/databaseadmission/delete_workflow.go` accepts deletion,
  records per-region access and usage-stop receipts, and reaches
  `cleanup_pending`. `finalizeDeletion` closes the billable lifetime at the
  accepted cutoff. Retained cleanup must not extend that lifetime.
- `src/orchestrator/reaper/reaper.go` runs CDN purge, `DestroyDEK`, and
  `DeleteOwnedData`, in that order, before its local `PhaseDeleted` transition.
  Each operation has durable retry checkpoints. A terminal publication must
  follow successful completion of all required effects, including all members
  and affected branches; the reaper phase alone is not currently connected to
  the admission inventory.
- `cmd/orchestrator/runtime_native_lifecycle.go` dispatches native deletion to
  the admitted member targets and journals their successful responses. It has
  no terminal admission publication caller.
- `../terrabase/crates/terrabase-server/src/production_lifecycle_control.rs`
  validates native deletion intent and retention, invokes provider backup
  deletion, then deliberately returns
  `provider-owned backup deletion complete; local/key cleanup is pending`.
  Its successful backup cleanup is not successful native deletion.
- `src/orchestrator/reaper/admission_key_revocation.go` explicitly excludes
  `AdmissionKeyRevoker` from `KeyAdapter`: revoking known wrapped copies does
  not destroy the wrapping authority for copies in journal history or
  snapshots. Waiting for key leases to expire does not resolve this gap.
- `src/orchestrator/databaseadmission/lifecycle_journal.go` and
  `lifecycle_transport.go` accept only `streams` through generic lifecycle
  publication. Although `databaselifecycle/state.go` models
  `EffectsCompletedAt`, there is no production `effects_completed` producer.
- `src/orchestrator/databaseadmission/placement_current.go` requires explicit
  physical completion before releasing deleted resources from current
  placement. Dashboard cleanup progress must consequently remain pending.

## Dependencies before terminal integration

1. Qualify local data removal and irreversible key cleanup, including retained
   wrappers, all admitted copies, historical placements, backups, and branches.
   The wrapping-authority choice remains unresolved; known-copy revocation
   must not be relabeled crypto-shred.
2. Reconcile retention representation. Automatic admission intentionally leaves
   `retain_until` absent because its eligibility deadline is not physical
   retention. Native deletion currently rejects absent retention as unknown.
   Do not substitute the eligibility deadline or interpret absence as immediate
   destructive authorization without an accepted policy contract.
3. Add an authority-fenced terminal transaction backed by those verified
   effects, using durable operation identity and immutable receipt bytes for
   retries. Preserve the generic publisher's restricted authority. Update
   deletion status and lifecycle inventory together rather than allowing them
   to disagree after a crash.
4. Verify lost responses, restart between physical completion and publication,
   partial member/provider cleanup, retained-copy failures, and retry after a
   closed billing snapshot. In every case, assert that cleanup adds no billed
   writes or storage lifetime and that partial cleanup never reports complete.

This audit supplies no physical-deletion completion or launch evidence.

## Retention producer trace

The missing retention decision also affects owner-requested deletion:
`cmd/orchestrator/runtime_database.go` constructs an empty
`DeletionPolicyDecision` after the owner authorization succeeds.
`runtime_database_delete.go` decodes authorization scope/freshness but has no
retention field. For automatic deletion, `BeginAutomatic` explicitly passes an
absent retention boundary, and the dashboard claim records an eligibility
deadline, not a retention decision. The dashboard lifecycle service's
`retainUntil` is an echo of observed native lifecycle state; feeding it back
would not establish an independent retention policy.

The producer repair therefore needs an approved, versioned retention decision
from the deletion policy authority for both entrypoints. That decision must
distinguish an explicit immediate cleanup disposition from an unknown boundary,
bind the database/subtree and operation, survive replay in the durable claim and
intent, and propagate unchanged through regional stop receipts to native
cleanup. Native cleanup can then enforce that decision. Neither replacing null
with the current clock nor reusing an elapsed billing/idle grace deadline
establishes this authorization. No such retention policy was invented during
this source repair.
