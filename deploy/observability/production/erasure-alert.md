# Pending deletion alert (TS-873)

`TerraBaseErasurePendingDay20` fires when either a shared-history erasure or a
database purge has remained pending for at least 20 days, sustained for 15
minutes. It uses `terrabase_history_erasure_oldest_age_seconds` and
`terrabase_purge_oldest_age_seconds` from TerraBase. An absent metric provides
no evidence that deletion completed.

The rule is in `operational-rules.yml`, already loaded by the production
Prometheus configuration. The existing default Alertmanager route forwards
warning alerts to the email and push relay. No new credentials or routing
permissions are needed. This change does not install or reload production
monitoring, or prove delivery to a recipient.

Inspect the pending holders and erasure phase. A listed offline region keeps
its GC hold and prevents completion. Bring it back; removing the region
requires an explicit user decision. The alert never removes a region or
overrides GC. Backup retention and rewrite failures can also keep a deletion
pending, so the alert does not diagnose the cause.
