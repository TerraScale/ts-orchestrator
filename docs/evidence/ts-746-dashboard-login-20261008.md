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

## Reviewer regression checks

The first ts-reviewer round identified four issues: host dashboard login lacked
its previous local backend, controller attachment did not retry transient
errors, obsolete sessions accumulated at the fixed byte limit, and arbitrary
logout cookies could create purge markers.

The follow-up keeps hosts' process-local login, retries controller attachment
with bounded attempts/backoff, uses CAS-allocated slots to cap each listener
scope at 1,024 live sessions without evicting them, and reclaims retired
generations. Logout verifies the stored hash and purges only that revision;
sequence-bounded marker compaction preserves slots reused concurrently.
New regressions cover unknown-cookie floods leaving KV bytes/count unchanged,
logout/compaction preserving reused slots, simultaneous allocation at capacity
across controllers, reusing a login at capacity, rotation reclaiming all old
records, stale collectors preserving a newer generation, host login/logout,
and attachment retry/cancellation.

The follow-up focused race tests, full-repository fast suite (`umask 022`),
vet, formatting and generated-template checks passed. Chromium and Firefox
also repeated the full local login/browser-reopen/controller-and-broker-restart/
cross-site-logout/copied-cookie-revocation journey with the corrected backend.

## CI run 1671

The dashboard race suite and both release architectures passed. The sole failure
was the existing cellscale drain-recovery test's 200 ms success deadline under
load. Its successful recovery phase now permits five seconds; stale-evidence
refusal phases retain the short deadline. Fifty focused race repeats, the full
cellscale race suite, vet and formatting passed locally at low CPU priority.

## Second reviewer round

The requested absolute/inactivity session cap conflicts with TS-746's explicit
requirement that sessions never expire. The no-TTL design remains deliberate;
logout and token rotation revoke sessions, and the slot limit bounds storage.
Authorization remains uncached to avoid stale grants after revocation.

Session validation now distinguishes storage errors from invalid cookies.
Storage operations share a five-second deadline and preserve earlier request
cancellation. Read outages return HTTP 503 without redirecting or modifying
the cookie; bearer authentication remains independent, and the original
cookie authenticates again when the store recovers. Login no longer runs a
watcher/collection pass; CAS slots enforce capacity, with collection limited
to store attachment and token rotation.

Regressions cover both failed token/session reads, bounded deadlines,
cancellation, cookie preservation/recovery, bearer behavior during an outage,
and login with session enumeration disabled. Focused app/auth race tests,
complete observability/dashboard race suites, full-repository fast tests,
vet, formatting and template generation passed. Chromium and Firefox repeated
login, browser reopen, controller/broker restart, cross-site logout rejection
and copied-cookie revocation successfully.

## CI run 1695

The cluster-health fixture selected route ports, released them, and let NATS
choose its client ports automatically. CI assigned peer2's client listener
the same port as its route listener (`36603`), causing a fatal bind failure.
The fixture now uses the existing `reserveControllerPorts` helper to select
six distinct client/route ports together, and explicitly configures both
listeners. Ten race repetitions of the real three-broker cluster-health
test and distinct-port regression passed, along with vet, formatting and
diff checks. Production code is unchanged by this fixture correction.

## Third reviewer round

Rotation now commits the new token-generation CAS before deleting retired
records. A timed-out metadata update leaves active sessions and KV bytes/count
unchanged. If collection fails after the CAS commits, old sessions remain
revoked and a subsequent attachment retries cleanup.

Uncontended login still allocates directly. After eight occupied-slot
conflicts, one metadata-only snapshot identifies available slots; CAS creates
only those candidates. Purge markers from interrupted logout are reusable.
The near-capacity regression injects 5 ms latency per Create, pits two
controllers against the last slot, verifies exactly one login succeeds, and
limits the pair to at most 20 Create requests instead of a serial 1,024-slot
probe. Rotation/failure/allocation regressions passed ten race repetitions.

Full observability/dashboard race suites, focused app race tests, vet,
formatting and generated-template checks passed. Chromium and Firefox both
repeated login, browser reopening, controller/NATS restart, cross-site logout
rejection, and copied-cookie revocation with this revision.

## Fourth reviewer round

Authentication now checks the leader-backed token generation again after the
session hash matches, within the existing five-second deadline. A rotation
committed between the first generation read and the session-record read cannot
authorize the retired generation, even if its record remains during failed
cleanup. An error on the final generation read fails closed as a storage error.

Both deterministic regressions failed before the fix and passed thirty race
repetitions afterward. Full observability/dashboard race suites, vet,
formatting and generated-template checks passed. Chromium and Firefox repeated
login, browser reopening, controller/NATS restart, cross-site logout rejection,
and copied-cookie revocation successfully.

## Fifth reviewer round

NetBird registration now carries the secret OCID and version from the same
OCI CURRENT bundle response as the token, plus the adopted signed-spec
generation. CAS refuses older Vault versions, conflicting values at one
version, obsolete secret references, and unversioned overwrites before
changing metadata or collecting sessions. A newer spec checkpoint for an
unchanged token preserves the logical session generation. A real Vault
version rotation advances it, including same-value and A-to-B-to-A rotations.
Restoring an old value therefore requires creating a newer Vault version.

Matching-token listeners reconcile to the current logical generation for
authentication, issuance, and logout; retired cookies remain revoked. Failed
listener starts invalidate the token cache so the next check rereads Vault.
The listener regression uses the real five-minute cache: another controller
registers version 2, then an address change restarts the cached version-1
listener. Its stale registration cannot revoke version-2 sessions, and the
next check refreshes Vault and recovers. Vault outages preserve a serving
listener. Authority tests cover signed-reference fencing, checkpoint
preservation, same-value rotations, A-to-B-to-A reconciliation, and logout
from a matching-token stale binding. Missing Vault metadata fails safely.

Ten race repetitions of the authority/rotation/logout regressions and the
app listener-cache regression passed. Full observability and Vault race
suites, repository fast tests, vet, formatting, and generated-template checks
passed. Chromium and Firefox passed login, browser reopen, controller/NATS
restart, cross-site logout rejection, and copied-cookie revocation with the
versioned-token harness. These are local checks; post-deploy regional
verification remains pending.
