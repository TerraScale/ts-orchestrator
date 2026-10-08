# TS-746 browser login evidence

Host: beta, 2026-10-08. No dashboard tokens or session cookie values are recorded.

## Original failure

Real headless Playwright Chromium and Firefox both submitted the deployed GRU
login form at `http://ts-gru-1.nb.ts.internal:9463/login` with `Origin: null`
and no `Sec-Fetch-Site`. Both received HTTP 403, `cross-site request refused`.
The shared T3 browser reproduced the same failure. A deliberately invalid
placeholder token suffices to reproduce the CSRF rejection before token checking.

## Local verification

A local Go harness mounted the production observability server and dashboard
on a file-backed embedded NATS server. The browsers addressed it by an HTTP
DNS hostname mapped to loopback (`ts746.nb.ts.internal:19463`), reproducing
NetBird's non-secure-context behavior: Fetch Metadata is absent. A second
listener with the original `no-referrer` policy reproduced HTTP 403 and
`Origin: null` in both browsers.

With `Referrer-Policy: same-origin`, both Chromium and Firefox:

- Redirected an unauthenticated `/members` navigation to `/login?next=...`.
- Submitted a matching Origin and received HTTP 303, landing on `/members`.
- Received a persistent `HttpOnly`, `SameSite=Strict` cookie and HTTP 200 on reload.
- Kept HTTP 200 after closing and reopening the browser with its saved cookie jar.
- Kept HTTP 200 after restarting the Go controller and embedded NATS using the same disk store.
- Refused a different-origin form POST to `/logout` with HTTP 403.
- Logged out successfully; a second browser context replaying a copy of the cookie redirected to login.

Go regression tests cover opaque same-origin forms, refusal of cross-site and
same-site forms, mismatching schemes/hosts, redirects on guarded routes,
401 for invalid bearer tokens (even with a valid cookie) and stream requests,
cookie renewal, hashed storage, no KV TTL, broker/controller restart,
logout persistence, A-to-B-to-A token rotation, and storage failures.

The server never expires a session. Cookies request the maximum persistent
lifetime and refresh on authenticated requests. Browser-enforced cookie caps
still apply: Chromium removes a cookie after 400 days without a visit.

## Deployment verification

Pending CI, ts-reviewer approval, merge, and regional rollout.
