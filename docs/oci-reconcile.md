# Declarative OCI reconcile

`internal/ociresource` reconciles regional OCI resources other than member
hosts and their data volumes, which stay with the journaled `internal/oci`
fleet. It is off unless `controller.oci_reconcile.enabled` is set, and it runs
only on the regional authority leader.

## What it manages today

| Kind | Desired state | Effect |
|---|---|---|
| `nsg-rules` | Records in `TS_OCI_DESIRED` | Adds and removes the NSG's managed security rules. The NSG itself is never created or deleted. |
| `nlb-backends` | Published from placement when `oci_reconcile.public_nlb` is set | Keeps one NLB backend set equal to the RUNNING member hosts. The NLB and backend set are never created or deleted. |

No CLI or API writes `nsg-rules` desired records yet, so the NSG pass has nothing
to do until one does.

## Ownership must exist before enforcement

A resource is managed only when it carries this controller's ownership tags:
the `terrascale-managed-by`, `terrascale-owner` and `terrascale-resource-key`
freeform tags, or the same values in the defined-tag namespace when
`tag_mode` is `defined`. A resource without them is reported as foreign and is
never mutated or deleted. The reconciler does not adopt resources by itself.

`public-api` creates the public NLB without these tags. Before enabling
`public_nlb`, an operator must tag the NLB with the owner (the region
controller owner) and the resource key `<CELL>/nlb-backends/<name>` (with `terrascale-managed-by=ts-orchestrator`). Until then the
NLB is reported as foreign and its backends are left alone.

## Safety

- Every individual mutation re-checks the authority epoch, so a controller
  that loses leadership mid-pass stops.
- Ownership restamps after backend or rule changes re-read the object for a
  fresh ETag and re-check ownership.
- Deletion is two-phase: the desired record is tombstoned first, the managed
  parts are removed after its not-before instant, and the record is purged
  by compare-and-set once a later pass confirms nothing is left. A tombstone
  whose NSG, NLB or backend set no longer exists is purged.
- An exclusive NSG spec removes every rule it did not ask for while
  enforced. Its tombstone removes the rules it managed, including unmarked
  rules that matched the spec, and leaves rules the spec never named.
- NSG specs are limited to OCI's 120 rules per NSG and require canonical
  CIDRs, so a rule is never re-added on every pass.
