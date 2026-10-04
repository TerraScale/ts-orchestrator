# Declarative OCI reconcile

`internal/ociresource` reconciles regional OCI resources other than member
hosts and their data volumes, which stay with the journaled `internal/oci`
fleet. It is off unless `controller.oci_reconcile.enabled` is set, and it runs
only on the regional authority leader.

## What it manages today

| Kind | Desired state | Effect |
|---|---|---|
| `nsg-rules` | `oci_reconcile.desired.nsg_rules`, or records written to `TS_OCI_DESIRED` | Adds and removes the NSG's managed security rules. The NSG itself is never created or deleted. |
| `nlb-backends` | Published from placement when `oci_reconcile.public_nlb` is set | Keeps one NLB backend set equal to the RUNNING member hosts. The NLB and backend set are never created or deleted. |
| `security-list-rules` | `oci_reconcile.desired.security_lists` | Replaces all ingress and egress rules of an owned security list in one If-Match update. |
| `route-table-rules` | `oci_reconcile.desired.route_tables` | Replaces all static route rules of an owned route table in one If-Match update. OCI-generated `LOCAL` rules are neither compared nor sent. |
| `bucket-protection` | `oci_reconcile.desired.buckets` | Sets versioning (Enabled or Suspended) and the bucket's marked retention rules. |

## Desired specs from the controller configuration

`controller.oci_reconcile.desired` lists desired specs by logical name. The
regional leader publishes them into `TS_OCI_DESIRED` at the start of every
pass, writing a new generation only when a spec or policy changes. On a
baked controller this configuration is bound to the signed controller
manifest, so the desired state is as trusted as the rest of the
controller configuration.

```json
"oci_reconcile": {
  "enabled": true,
  "desired": {
    "nsg_rules": {"members": {"policy": "enforce", "spec": {"nsgId": "ocid1.networksecuritygroup...", "rules": [
      {"direction": "INGRESS", "protocol": "6", "peer": "10.0.0.0/16", "portMin": 4222, "portMax": 4222}]}}},
    "security_lists": {"private": {"spec": {"securityListId": "ocid1.securitylist...", "rules": [...]}}},
    "route_tables": {"private": {"spec": {"routeTableId": "ocid1.routetable...", "routes": [
      {"destination": "0.0.0.0/0", "networkEntityId": "ocid1.natgateway..."}]}}},
    "buckets": {"backups": {"policy": "enforce", "spec": {"namespace": "tenancy", "bucket": "backups",
      "retention": [{"name": "daily", "days": 30}]}}}
  }
}
```

- Every entry defaults to the `report` policy: drift is recorded and shown,
  and nothing in OCI changes until the entry says `"policy": "enforce"`.
- An NSG spec may only name an NSG listed in the signed region
  configuration's `network_security_group_ids`.
- The whole configuration is validated before anything is written; one bad
  entry fails controller start rather than publishing half a set.
- `prune` (off by default) tombstones records of these four kinds that the
  configuration no longer lists, `prune_delay_seconds` later (default one
  hour, at most seven days). With prune off, unlisted records, including
  records written by tools, are left alone.

## Kinds that never strip protection

Security lists, route tables and buckets are shared infrastructure, so a
tombstone for these kinds **relinquishes** management: the record is
purged without any cloud write, and the rules, routes, versioning and
retention stay as they were. Other safety rules:

- Security list and route table specs must not leave a direction (or the
  table) empty unless `allowEmpty` is set.
- Bucket specs cannot combine versioning with retention rules (Object
  Storage refuses it). The reconciler removes unwanted managed retention
  rules before switching versioning on, and adds rules last.
- The reconciler never creates a locked retention rule and never changes or
  deletes a locked one: a locked managed rule that differs from the spec
  fails the record and shows as an insight. Retention rules created by
  other tools (without the `terrascale/<name>/` display-name prefix) are
  left alone.

## Decisions and insights

Published desired sets, corrected drift, cloud deletes and released records
are journaled (`oci_desired_published`, `oci_drift_corrected`,
`oci_resource_deleted`, `oci_resource_released`). Every controller with the
reconcile enabled reads `TS_OCI_OBSERVED` for the dashboard's `oci_drift`
insight: a foreign object raises a warning at once; a record that keeps
failing, or stays out of sync for ten minutes, raises a warning under
`enforce` and an info item under `report`. Persistence needs a later pass
that observed the condition again (re-reading one stored observation is
not evidence), and the drift of a pass that just applied a correction is
not counted. Observations older than three hours are treated as unknown
and raise one "observations are stale" info item instead.

Desired publication re-checks the authority epoch before every desired
write and every prune tombstone, so a controller that loses leadership in
the middle of a set stops at once.

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
