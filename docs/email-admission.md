# Shared email admission

The alert relay reserves its existing durable group/status and rolling-hour
budget before asking ts-auth for one shared non-auth email slot. The 12/hour
local cap and four-hour dedupe remain; ts-auth additionally applies its shared
account budget and ts-alerts limit of 50 attempts per 25 hours.

The relay sends one POST to
`https://auth.terrascale.tech/v1/terrascale/email/admission`, with JSON
`{"attemptId":"<new ULID>"}`. Authorization is Bearer followed by lowercase-hex
HMAC-SHA256: key is the existing Cloudflare token's UTF-8 bytes, data is UTF-8
`terrascale:email-admission:v1:ts-alerts`. No new secret or dashboard identity is
distributed. The derived proof is a secret too; never log it. Auth validates
ULIDs as at most five minutes old and at most one minute in the future.

Only HTTP 200 with `status: admitted` and a future UTC ISO `sendBy` within ten
seconds permits Cloudflare delivery. Auth computes the deadline before its
atomic reservation, so storage and network delay consume the grant lifetime.
The provider request context ends at that deadline. Admission has a five-second
request timeout, bounded response size, no redirects and no retry. Duplicate
attempt IDs return 429; the relay never retries them or refunds ambiguous sends.
Denied, unavailable, malformed or expired admission suppresses email and keeps
push independent. Webhook HTTP 202 also covers suppression, not inbox delivery.

This narrow HTTP integration stays beside the existing provider relay because
no SDK admission operation exists. It grants no tenant data, recipient selection
or sign-in priority. Both sides must use the exact versioned proof domain.

Rollout belongs to the parent/FR1: deploy the auth admission endpoint and shared
sender accounting first, then this orchestrator release and monitoring rules.
Preserve `/var/lib/ts-alerts/email-ledger.json` and its StateDirectory. Until auth
is ready, the new relay suppresses mail while continuing push. No deploy,
restart, provider send or credential change is part of this source change.

`AuthEmailProviderExhausted` pages on new or first-observed
`ts_auth_emails_total{outcome="provider_exhausted"}` events through the existing
relay. Push remains available when email capacity is exhausted. The rule drops
all labels except service and region, and old events clear after five minutes.
