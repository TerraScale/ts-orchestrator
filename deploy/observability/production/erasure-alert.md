# Pending deletion alert (TS-873)

`TerraBaseErasurePendingDay20` fires when either a shared-history erasure or a
database purge has remained pending for at least 20 days, or a history erasure
reports a replica-epoch stall. The epoch-stall alert fires within 15 min.
The current rule has no additional hold and fires on the first matching
evaluation. It uses
`terrabase_history_erasure_oldest_age_seconds`,
`terrabase_purge_oldest_age_seconds` and
`terrabase_history_erasure_epoch_stalled` from TerraBase. An absent metric provides
no evidence that deletion completed.

The rule is in `operational-rules.yml`, which the production Prometheus
configuration is configured to load. The authorized read-only check found
this rule was not yet loaded. The existing default Alertmanager route forwards
warning alerts to the email and push relay. No new credentials or routing
permissions are needed. This change does not install or reload production
monitoring, or prove delivery to a recipient.

Inspect the pending holders and erasure phase. A listed offline region keeps
its GC hold and prevents completion. Bring it back; removing the region
requires an explicit user decision. The alert never removes a region or
overrides GC. Backup retention and rewrite failures can also keep a deletion
pending, so the alert does not diagnose the cause.

An epoch-stalled erasure stays stalled. Escalate to engineering (TS-875); there
is no operator re-cut command or roots-only override. Missing old-epoch
coverage is never accepted as completion. Scrape/evaluation intervals, normal
Alertmanager grouping and delivery still apply; immediate rule firing is not
a claim of instantaneous recipient delivery.
