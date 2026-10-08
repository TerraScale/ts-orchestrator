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

## Local Go checks

Passed with the repository's documented `umask 022`, every local check at
`nice -n 19`: `make test-fast` for the entire repository, focused authentication
race tests, observability/dashboard race suites, vet of the three changed
packages, formatting, generated templ consistency, and `make release-check`
for static Linux amd64 and arm64 binaries. An initial broader local run under
`umask 077` failed existing exact-mode fixtures; the focused mode check and
full fast suite passed after correcting the shell environment.

## Deployment prerequisites

PR: https://git.terrascale.tech/TerraScale/ts-orchestrator/pulls/330

Read-only checks on 2026-10-08 confirmed:

- `TS_AUTO_DEPLOY_CELLS` is unset, so main CI does not dispatch deployment.
- The current `TS_RELEASE_UPDATE_DELEGATION` allows only GRU, arm64, canary.
- `ts-orch release fleet-status --namespace grxnmoqvrcdv` reports GRU's
  channel run 1570 failed: `release-g5-controllers frozen: rollback deadline exceeded`.
- The authenticated live GRU `/rollouts` page still shows that rollout frozen;
  SFO's current channel run 1609 is complete.

Both regional Vault tokens were fetched to owner-only temporary files without
printing their values. Bearer-authenticated `/topology` returns HTTP 200 in
both regions. Live browser verification of the new login remains pending
review, merge, and a rollout path that respects the existing GRU recovery fences.
No rollout fences, signing grants, or deployment settings were changed.
