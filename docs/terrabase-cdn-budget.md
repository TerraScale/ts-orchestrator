# TerraBase shape cleanup budget and alerts

F6 grants the TerraBase role access to `terrabase_cdn_budget`: persistent
file storage, history one, no TTL. Revision compare-and-set on
`purge.6cd3f3639e928077593d9b470765efeb` coordinates Cloudflare prefix purges.
The role integration test verifies reads, writes and stale-revision rejection
while preserving denial on unrelated buckets.

This role declaration does not establish an account-wide rate limit. The
production application must share the authority with every CI and benchmark
purge caller. N1 owns the cross-region JetStream topology; until it is live,
the application keeps pending cleanup visible when its budget is unavailable.
The current application spaces grants by 12.5 seconds times the discovered
serving-region count to account for independent cell buckets.

Production alert rules report parked cleanup immediately, oldest due work
over one hour, and inventory saturation lasting five minutes. Promtool tests
cover firing and clearing. Credential/policy repair belongs in OCI Vault;
restarting the service resumes parked inventory.

No credentials, feature switches or application schema changes are added.
No visual change.
