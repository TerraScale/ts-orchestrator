# Regional OCI reconciliation

Regional reconciliation is always on at a fixed one-minute cadence. The ordinary
controller calls the concrete `rootoci.Client.ReconcileFoundation` endpoint; it
has no OCI SDK fallback. Root reconciles the signed regional foundation before
reconciling signed amendments. An absent `controller.oci_reconcile` section means
there are no configured amendments; foundation reconciliation still runs.

The retired `enabled`, `interval_seconds`, `tag_mode` and `tag_namespace` fields
are rejected. Ownership always uses the region owner and the existing freeform
`terrascale-managed-by`, `terrascale-owner` and `terrascale-resource-key` tags.
Foreign resources are reported and never adopted or changed.

## Signed amendment authority

Root independently opens the exact accepted controller configuration, current
root chain and current root-signed cell spec. `oci_reconcile.desired` supplies
the installed baseline; a current root-signed `oci_desired` cell-spec section
replaces that baseline. A leaf-signed current spec cannot authorize amendments.
All admitted desired entries enforce their signed specs.

Root uses ordered stream-leader reads. A missing stream, deletion, purge or
missing source after prior history fails closed. An untouched, empty source
stream can represent the installed baseline. The protected journal retains the
accepted spec generation even when there are no desired resources, so a later
pass cannot silently roll back to the baseline.

The ordinary controller supplies no desired payload, provider or cloud target
through IPC. Root derives these values and checks the sealed call, exact runtime
candidate, deployment, own cell, current lease and original deadline. Observing
a lease never promotes it into root mutation authority. Source, drain and
placement facts are reread at mutation fences. Renewed leases or credentials
cannot extend an operation's original effect deadline.

## Managed amendments

| Kind | Desired state | Effect |
|---|---|---|
| `nsg-rules` | Signed `desired.nsg_rules` | Converges rules on an already owned, region-admitted NSG. |
| `security-list-rules` | Signed `desired.security_lists` | Replaces rules under If-Match on an owned security list. |
| `route-table-rules` | Signed `desired.route_tables` | Replaces static routes under If-Match; OCI `LOCAL` routes stay untouched. |
| `bucket-protection` | Signed `desired.buckets` | Observes versioning and marked retention rules; property mutations require CAP admission. |
| `nlb-backends` | Signed `public_nlb` plus observed placement | Converges one owned NLB backend set to RUNNING member hosts. |
| `lb-backends` | Signed `public_lb` plus the TerraBase profile and drain records | Converges one owned L7 backend set while preserving the serving-health guard. |

NSGs, security lists, route tables, buckets and load balancers themselves are
never created or deleted by these amendment reconcilers. Member hosts and data
volumes remain with the journaled regional fleet.

## Protected operations and observations

Amendment desired state and operation history live in `OCIResources` inside the
existing protected own-cell foundation object. They share its unchanged
128 KiB whole-object bound and compare-and-set revision. Each update rereads the
whole record and preserves unrelated foundation, IAM, capacity and original
create history. A conflicting or uncertain conditional write is not retried
blindly.

Before each cloud mutation, root checkpoints its exact method, URL, body,
If-Match, retry token, start and original deadline. Authorization headers are
never stored. Each operation retains at most 128 requests; each body is bounded
at 64 KiB, with the smaller shared whole-object limit still applying. Retries
retain original bytes, token and deadline. An uncertain request prevents a
different mutation until its original outcome is resolved. Revoked desired
authority may still be observed to confirm an original operation; it cannot
start a new effect.

`TS_OCI_OBSERVED` remains an observation store for drift insights. It does not
authorize cloud writes. Seat rollout obtains fresh backend observations through
root IPC on every request. Root checks exact load-balancer identity, ownership
and signed TerraBase membership, with bounded backend and health rows.

## Pruning and protection

Pruning requires current signed removal authority over a prior protected entry.
It first records a tombstone with removal provenance and a not-before time.
NSG and load-balancer cleanup remains fenced and ownership checked; a later
observation confirms removal before the protected entry is purged.

Security-list, route-table and bucket tombstones relinquish management without
changing cloud protection. Locked retention rules are never created, shortened
or deleted. Retention rules outside this reconciler's display-name marker remain
untouched. Existing empty-rule, empty-route and serving-backend safeguards still
apply.

## Open integration requirements

Unsigned legacy `TS_OCI_DESIRED` records are never imported as authority. Their
migration is **OPEN**; discovering legacy desired state stops the amendment pass.

The additive protected-object schema requires final ROOT and security approval.
Bucket property-spend admission requires CAP authority; absent that authority,
property mutations fail closed. Source fixtures do not qualify the full real
root-IPC and OCI-SDK amendment path. That end-to-end qualification remains
**OPEN** until the integrated candidate passes its leased QA run.
