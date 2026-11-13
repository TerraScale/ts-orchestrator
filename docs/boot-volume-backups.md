# Boot volume backup policies

Region founding creates boot volumes. On both launch and adoption, `region add`
assigns the Oracle-defined Silver policy to the selected instance's attached
boot volume before continuing with regional identity and routing setup.
Repeated runs read the assignment without changing it. Dry runs perform the
lookups and report a planned assignment without writing. A new instance in a
dry run has no volume yet, so its assignment is reported with an unknown ID.
An existing different policy causes an error for operator review; it is never
silently replaced.

Silver retains weekly incremental backups for four weeks, monthly incremental
backups for twelve months and annual incremental backups for five years.
Bronze does not meet the weekly recovery requirement. Gold additionally retains
daily incremental backups for seven days. These policies do not copy backups
to another region. Assigning a policy does not create an immediate recovery
point; the first backup follows the Oracle schedule.

Policies have no fixed tier price. Backup storage is billed by retained
incremental GB-month at the Object Storage rate, not by boot volume performance
units. Obtain the current currency-specific rate from the
[Oracle price list](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?currencyCode=BRL),
SKU `B91628`. Provisioned capacity alone cannot establish the cost of daily
backups: changed blocks and long-lived monthly and annual recovery points also
consume storage. Estimate retained bytes and verify billed usage after backups
begin. See [Oracle policy schedules](https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/schedulingvolumebackups.htm).

For an existing boot volume, first read its assignment and the Oracle-defined
policy list. Set `REGION` and `BOOT_VOLUME_ID` from an authenticated instance and
boot-volume inventory; set `POLICY_ID` to the unique Oracle-defined Silver ID.
Stop if the volume already has a different policy or the resource is ambiguous.
The write below changes only the policy assignment. Read it back immediately:

```sh
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment --region "$REGION" --asset-id "$BOOT_VOLUME_ID"
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv volume-backup-policy list --region "$REGION" --all
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv volume-backup-policy-assignment create --region "$REGION" --asset-id "$BOOT_VOLUME_ID" --policy-id "$POLICY_ID"
export PATH="$HOME/.local/bin:$HOME/.local/share/mise/shims:$PATH"; oci bv volume-backup-policy-assignment get-volume-backup-policy-asset-assignment --region "$REGION" --asset-id "$BOOT_VOLUME_ID"
```

The final asset read must return exactly one assignment with the intended volume
and policy IDs. Policy presence proves scheduling is configured; successful
backup creation and restore usability require separate verification. No volume
creation, resizing, detaching, deletion or manual backup is needed to assign a
policy.
