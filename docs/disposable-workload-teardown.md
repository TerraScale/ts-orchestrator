# Explicit disposable workload teardown

This procedure removes the current GRU preview's disposable TerraBase workload
through `ts-orchestrator`. It requires an operator to review and authorize the
exact workload inventory. It does not target controller instances, regional
foundation, shared services, or unrelated resources. It is an operator
procedure: the 72-hour cutoff does not itself schedule teardown, while an
accepted marker is reconciled automatically. No live OCI teardown is claimed
here.

## GRU preview cost cutoff

The shared goal caps qualification and preview together at US$200/month. The
current GRU cost plan allows one replacement host and its extra storage to
overlap for at most 72 hours. For this preview, record each paid workload
resource's OCI `time-created` and its `time-created + 72 hours` cutoff in a new
owner-only operations receipt. Start teardown early enough that instance
termination, volume detachment and deletion, and positive OCI readback finish
before each resource's cutoff. Record a fresh inventory after teardown; a
terminated instance alone does not stop volume charges. The 72-hour cap is a
current GRU operations constraint, not a general `ts-orchestrator` resource
lease or an automatic teardown deadline.

The owner-only GRU retention ledger is
`/home/mariogk/.local/share/terrascale-controller-bootstrap-20260927/oci-operator-20260927/workload-retention-ledger-20260928.json`.
Its current SHA-256 is
`fd3bd7da5812bd25e790f84291afcd5f3bfcf31c5b8f3c345a3ea8fd72e2b33b`; it is
currently empty and explicitly does not certify cloud state. Follow its entry
rule to record each created resource's exact OCID, kind, compartment, OCI
creation time, +72-hour UTC cutoff, owner, and fresh deletion readback. Perform
a new OCI inventory and cost admission before each create or resize.

## Authorization and reviewed plan

The controller config's trusted-signer entry for the operator actor must
explicitly set `can_teardown_terrabase: true`. The operator config's actor and
Ed25519 signing key must match that entry. The capability is default-deny and
is required for planning, applying, and reading teardown status. See
[production role configuration](production-role-config.md#operator-inputs) for
the owner-only operator key and config installation.

Generate a read-only plan for the admitted database and partition:

```sh
/ABSOLUTE/PATH/terrascale-orchestrator operator terminal-plan \
  --config /var/lib/terrascale-operator/operator.json \
  --database-id DATABASE_ID \
  --partition-id PARTITION_ID \
  > /ABSOLUTE/PATH/terminal-plan.json
```

Review the plan's cell, database and partition, regional owner, compartment,
fleet and placement generations, placement digest, and every exact target.
For the current GRU preview, the targets are the two admitted TerraBase seats;
each target binds its seat and member identity, create keys, and exact instance,
boot-volume, and data-volume OCIDs. An empty OCID is accepted only where the
controller positively confirms that the corresponding resource was never
created. A fully provisioned two-seat preview therefore has two instance OCIDs
and four volume OCIDs. The plan must match current placement and the durable
OCI journal.
Unknown create outcomes, unsettled OCI operations, foreign resources, or
unresolved enrollment-grant effects hold admission.

The generated template sets these three fields to `false`:

```json
{
  "disposable_workload": false,
  "acknowledge_permanent_data_loss": false,
  "authorize_forced_stop": false
}
```

Only after deciding that this workload and its data are disposable, set all
three fields to `true` in a separate reviewed copy. Preserve every other field
and target exactly. Apply that reviewed file:

```sh
/ABSOLUTE/PATH/terrascale-orchestrator operator terminal-apply \
  --config /var/lib/terrascale-operator/operator.json \
  --intent /ABSOLUTE/PATH/terminal-plan-approved.json
```

The operator CLI signs the exact intent. Its request envelope is valid for five
minutes. Before committing the immutable terminal marker, the controller
rechecks the signed scope, current placement, OCI inventory, and exact target
enrollment grants. It disables each exact existing grant or creates a durable
disabled tombstone for an absent grant, then reads back the fence before
committing the marker. An unresolved older enrollment effect also holds
admission unless its exact durable fence is proven.

A failed `terminal-apply` does not authorize OCI deletion, but it may have
already disabled one or more exact target grants. If the error says grant
fencing or readback held, keep the reviewed file unchanged and retry
`terminal-apply` with that same file and operation ID after the cause is
resolved. The CLI signs a fresh five-minute envelope for the same intent. Do
not make a new plan or manually re-enable a grant to bypass a partial fence.
`terminal-status` only works after a marker exists; before then it returns an
error without a status receipt. Once the marker commits, its envelope expiry no
longer limits teardown.

The marker fences further placement, host-registration, and enrollment
effects for this database and partition. It is durable and irreversible for
that scope. A changed inventory is not a reason to edit the approved file or
broaden its targets. If exact scope validation fails, stop and route the
mismatch to the current resource owner before retrying the same reviewed
intent.

## Reconciliation and completion

The current controller leader resumes accepted teardown markers and retries
reconciliation every five seconds. A restart or leader change does not remove
the accepted marker. For each pinned instance, the OCI worker records the
operation before calling OCI, uses the instance's current ETag for termination,
and waits for `TERMINATED` or not-found. It preserves boot and data volumes
until the instance is terminal and volume attachments are inactive, then
deletes only the pinned volumes with their current ETags. Ambiguous OCI results
are held for readback rather than blindly retried. The runtime verifies the
pre-marker enrollment fence again before reporting overall completion.

Read status without advancing teardown:

```sh
/ABSOLUTE/PATH/terrascale-orchestrator operator terminal-status \
  --config /var/lib/terrascale-operator/operator.json \
  --database-id DATABASE_ID \
  --partition-id PARTITION_ID
```

Status phases mean:

- `pending`: exact resources remain in provider termination or deletion; the
  response lists pending resource IDs.
- `held`: provider readbacks show the pinned OCI resources settled, but the
  controller could not verify the durable enrollment-grant fences. The
  response includes a pending reason. Other provider or inventory read errors
  return a command error without a status receipt.
- `complete`: every pinned instance, boot volume, and data volume is positively
  absent, no active attachment remains, terminal OCI operation results are
  settled, and each pinned enrollment grant is absent or durably disabled and
  read back.

A command error has no authoritative status receipt and must not be treated as
`complete`. If status is `held` or a command errors after marker admission,
preserve the approved plan and marker, keep the cost cutoff visible, and have
the current resource owner resolve the reported inventory or readback
condition. For a pre-marker grant-fencing error, retry only the exact reviewed
intent as described above. Do not run broad compartment cleanup or manually
repeat an ambiguous OCI mutation. Take a fresh OCI inventory after `complete`
and retain it with the per-resource cutoff receipt. No live GRU teardown result
is implied by this procedure.

## Source paths

The real operator caller and signed terminal request are in
[`operator.go`](../internal/app/operator.go) and
[`operator_terminal.go`](../internal/app/operator_terminal.go). The immutable
intent and authority fence are in [`types.go`](../internal/authority/types.go)
and [`log.go`](../internal/authority/log.go). The current leader's resume path
and enrollment grant checks are in
[`controller_terminal.go`](../internal/app/controller_terminal.go) and
[`host_enrollment_revoke.go`](../internal/app/host_enrollment_revoke.go);
operation-bound disabled grants and absent-grant tombstones use
[`grant.go`](../internal/hostenroll/grant.go).
Exact OCI discovery, conditional deletion, and status readback are in
[`terminal.go`](../internal/oci/terminal.go) and
[`terminal_scope.go`](../internal/oci/terminal_scope.go).

Focused regression coverage is in
[`operator_terminal_test.go`](../internal/app/operator_terminal_test.go),
[`operator_terminal_integration_test.go`](../internal/app/operator_terminal_integration_test.go),
[`log_test.go`](../internal/authority/log_test.go),
[`grant_terminal_test.go`](../internal/hostenroll/grant_terminal_test.go),
[`terminal_test.go`](../internal/oci/terminal_test.go), and
[`sdk_test.go`](../internal/oci/sdk_test.go). These source-level tests do not
establish that the current GRU preview has been deployed or torn down.
