# Durable host plan acknowledgements

`EpochStore.AcknowledgeStorageTransitionPlan` now retains a host-signed receipt
for the existing private plan pin. It validates receiver ownership, the plan and
manifest bindings, the current authority floor, and the plan lifetime. It fsyncs
the private journal before signing the exact pin digest. The signed receipt is
then persisted through file fsync, rename, and directory fsync. A retry verifies
and returns the original signed bytes without accessing a signing key.

`controltransition.VerifyPlanPins` checks the complete distinct-host inventory.
It supports both source/GRU co-hosting and a separate GRU destination, requiring
three or four acknowledgements respectively. Each receipt binds the same owner
plan as its immediate predecessor. The only admitted phase is `plan-pinned`.
See [the contract](../contracts/control-transition-plan.md#host-acknowledgements).

Tests passed for:

- interrupted directory sync after both the plan pin and receipt renames;
- cancellation after receipt rename, with refusal to return success and exact
  recovery of the persisted receipt under a new live context;
- receiver restart and byte-identical replay with no signer;
- replay after actual journal retirement while R1 remains refused;
- exact private-pin digest and original command/epoch provenance;
- wrong host keys, scope, phase, grants, manifest, command, dates and authority;
- complete three-host and four-host acknowledgement sets, plus rejection of
  missing, additional, duplicate, reordered and future receipts;
- preserving correctly signed but conflicting receipt evidence;
- corrupt, writable, symlinked, hard-linked and oversized receipt files; and
- refusal after ordinary destination admission, while retaining historical
  signature verification for audit.

The focused race suite passed for `controltransition` and `nodeauthority`.
Output is retained in `storage-plan-acknowledgements-focused-2026-09-05.txt`.
After the final cancellation and fuzz-fixture changes, `make check` passed
formatting, vet, build, and the full portable race suite. Its output is retained
in `storage-plan-acknowledgements-portable-2026-09-05.txt`.

The initial multi-document fuzz target exercised only six cases in its longer
run. It was replaced with a receipt-only target using a fixed public signed
fixture. The final ten-second run completed 37,360 executions without failure;
output is in `storage-plan-acknowledgements-fuzz-2026-09-05.txt`. The fixture has
no private keys and requires no wall-clock override. This is bounded parser
evidence, not an exhaustive security audit.

These acknowledgements prove agreement with a plan, not broker preparation,
storage readiness, quorum, source shutdown, or the final cut. They are retained
locally and returned to the trusted caller. External publication, receipt reads
independent of the source broker, pre-NATS host composition, and the remaining
phase journal are not wired. No storage or ordinary authority effect is enabled
by this change. The engine membership and guest-readiness blockers remain open.
