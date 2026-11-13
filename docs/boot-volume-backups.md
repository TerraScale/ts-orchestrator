# Boot volume backup policies

On both launch and adoption, `region add` assigns the regional user-defined
`ts-boot-weekly-4` policy to the selected instance's attached boot volume before
continuing with regional identity and routing setup. It creates the policy in
the region's control compartment when absent. The regional storage client lists
and creates policies in that region; policy IDs are never shared across regions.
An existing policy must have exactly one weekly incremental schedule retained
for exactly 28 days and no destination region. New policies schedule Sunday at
00:00 UTC. There are no monthly or yearly schedules.

Repeated runs read the policy and assignment without changing them. Dry runs
perform the lookups and report planned policy creation and assignment without
writing. A new instance in a dry run has no volume yet, so its assignment is
reported with an unknown ID. Duplicate names, invalid schedules and an existing
different assignment cause an error for operator review. The command never
changes another policy or silently replaces an existing assignment.

Assigning a policy does not create an immediate recovery point; the first
backup follows the schedule. Policy presence proves scheduling is configured;
successful backup creation and restore usability require separate verification.

Backup storage is billed by retained incremental GB-month at the Object Storage
list price, without a policy fee or boot volume performance charge. SKU `B91628`
in the [Oracle BRL price list](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?currencyCode=BRL)
is BRL 0.13351035 per retained GB-month at the time of this change, before tax,
allowances and discounts. For the monthly estimate, budget at most five retained
points per volume, each no larger than the volume's used blocks at its snapshot:
`5 × used GB × BRL 0.13351035`. Read current root-filesystem usage with `df` over
read-only SSH; convert bytes to GiB for OCI's storage GB units. Current usage is
an estimate for future points; incremental sharing can lower the bill, while
future disk growth changes it. The capacity ceiling is
`5 × provisioned GB × BRL 0.13351035` per month. Backups left by earlier policies
remain separately billable until their own expiry. Verify retained storage and
billed usage after backups begin. See [Oracle policy schedules](https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/schedulingvolumebackups.htm).

For existing volumes, inventory the instance, its attached boot volume, its
assignment and existing backups in one region before any write. Set `REGION`,
`COMPARTMENT_ID` and `BOOT_VOLUME_ID` from that authenticated inventory. List
user-defined policies in that same region and compartment; use the unique
`ts-boot-weekly-4` policy after reading its schedule back, or create it if absent:

```sh
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv volume-backup-policy list --region "$REGION" --compartment-id "$COMPARTMENT_ID" --all
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv volume-backup-policy create --region "$REGION" --compartment-id "$COMPARTMENT_ID" --display-name ts-boot-weekly-4 --schedules '[{"period":"ONE_WEEK","backupType":"INCREMENTAL","retentionSeconds":2419200,"offsetType":"STRUCTURED","dayOfWeek":"SUNDAY","hourOfDay":0,"timeZone":"UTC"}]'
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv volume-backup-policy get --region "$REGION" --policy-id "$POLICY_ID"
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv boot-volume-backup list --region "$REGION" --compartment-id "$COMPARTMENT_ID" --boot-volume-id "$BOOT_VOLUME_ID" --all
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment --region "$REGION" --asset-id "$BOOT_VOLUME_ID"
```

Stop for ambiguous resources or an unexpected assignment. Replacing an existing
assignment requires an explicit operations task identifying the volume and old
policy. For such a migration, remove only the verified old assignment, create
the new assignment immediately and read it back. If creation fails, restore the
old assignment before stopping. Leave existing backups to expire; never delete
them as part of the policy change. For an unassigned volume, create and verify:

```sh
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv volume-backup-policy-assignment create --region "$REGION" --asset-id "$BOOT_VOLUME_ID" --policy-id "$POLICY_ID"
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment --region "$REGION" --asset-id "$BOOT_VOLUME_ID"
```

The final read must return exactly one assignment with the intended volume and
regional policy IDs. Complete and verify one region before proceeding to the
next. No volume creation, resizing, detaching, deletion or manual backup is
needed for this operation.
