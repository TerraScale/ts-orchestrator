# User-only production E2E credential issuance

The parent prepares one approved isolated `deployment-e2e` project with positive
database `e2e_read`, negative database `e2e_negative` containing one document,
and four `production` environment variables first. Preparation creates no key.
Existing `status_canary`, auth/dashboard and the status canary are untouched.
The user executes the command below in a
private interactive terminal after reviewing this helper. Agents must never
execute the real helper or redirect a real password/key to it.

```sh
python3 /home/mariogk/.t3/worktrees/ts-orchestrator/fix/ku-security-deploy/scripts/e2e/issue-production-credential.py < /home/mariogk/.config/terrascale/mailbox-password
```

This is one command, with no manual login/code entry or native key response
transfer. The existing mailbox password file is read only through stdin; the
helper does not open that path itself. Shell redirection contains a path, never
its value. Do not use shell tracing, terminal recording or debugging. Expect
up to about 4 minutes after confirmation if email sign-in is needed; mailbox
checks run every 10 seconds for at most 3 minutes. A cached hosted session
avoids email entirely. Across processes on this host, at most one sign-in
request is permitted per 5 minutes, including failed or ambiguous requests.
Any HTTP 429 records a shared 15-minute cooldown; a new attempt refuses until
it expires. The helper never sleeps for that cooldown or retries a request.
No key exists from this handoff until the user runs and confirms the helper.

## Checks before issuance

1. The shared installer preflight verifies GitHub.com account `MarioGK`, exact
   repository `TerraScale/ts-orchestrator`, environment `production`, custom
   deployment policy allowing only branch `main`, and four native identifiers:
   `E2E_ORGANIZATION_ID`, `E2E_PROJECT_ID`, `E2E_DATABASE`,
   `E2E_UNRELATED_DATABASE`. The two database names must differ within one project.
2. A hidden `/dev/tty` confirmation names the organization, both exact
   same-project database pairs, no negative-database key, and secret destination.
   Password stdin cannot answer this prompt. Missing controlling terminal or unsafe echo control refuses
   before password input or authentication.
3. Load `~/.cache/ts-session/mariogk.cookies` as a MozillaCookieJar first. The
   session directory must be owned by this user with mode 0700; all cache,
   lock and timestamp files must be owned by this user with mode 0600.
   Symlinks, hardlinked files, malformed caches and unsafe permissions refuse.
   Probe `GET https://auth.terrascale.tech/ui/terrascale/device`: 200 proves a
   hosted signed-in form. Only an absent cache, HTTP 401, or HTTP 302 with the
   exact `/ui/terrascale/sign-in` location (relative or the pinned absolute URL)
   allows email sign-in. Other errors, redirects and outages stop without
   sending email. Acquire `~/.cache/ts-session/signin.lock` with `flock`, recheck
   cooldown and reload/probe the cache under the lock before sending anything.
   Keep the lock through email login and atomic private cookie-cache save.
   `last-signin-at` and `cooldown-until` contain numeric epoch seconds shared
   with other host processes; legacy `signin-state.json` is not read or changed.
   When necessary, hosted ts-auth sign-in sends one email code to
   `mariogk@terrascale.tech`.
   TLS IMAP uses `mailserver.purelymail.com:993`, readonly INBOX and header-only
   `BODY.PEEK`. The Date may be up to 2 minutes before the sign-in request
   for clock skew, and at most 5 seconds ahead of the current time. Only that
   Date window, exact parsed recipient and native English or
   Portuguese TerraScale/ts-auth sign-in-code subject match; multiple distinct
   fresh codes refuse. No resend loop runs. The code is redeemed with the same
   cookie jar that requested it. Every session, including a reused cache, approves
   the public ts-cli device client `00000000000000000000000007`, scope
   `openid email`. The helper waits the advertised interval and polls once;
   refresh tokens refuse. Userinfo must return this exact verified email.
4. Native organization metadata must prove owner/admin. One project record
   must identify the approved organization. One public-client token
   exchange requests only `databases:read`; authenticated GETs of both exact
   database records prove their current existence. Missing databases, redirects,
   errors or anonymous responses cannot establish that proof. This helper
   provisions nothing. The target project's native key list must be empty with
   no next page; existing keys refuse. GitHub preflight is rechecked unchanged.
5. One native POST creates `deployment-e2e-read`, exact database,
   `scopes: ["documents:read"]` and a UTC expiry 23 hours ahead. The shared
   validator checks native key/id, organization, project, database, exact scope
   and expiry within 24 hours. The helper also checks the key name. The complete
   native JSON goes directly to the existing protected-stdin `gh secret set`
   implementation for `production/E2E_PROJECT_CREDENTIAL`, once, with stdout and
   stderr suppressed. No key enters argv, environment, chat, a host file or
   another secret store.

TLS certificate/hostname verification stays enabled. Auth and TerraBase HTTPS
origins are fixed, redirects and proxy environment settings are disabled, and
hosted auth cookies never accompany TerraBase requests. Only the hosted cookie
jar persists in the explicitly authorized private cache; it is never printed
or committed. Password, email/device codes and bearer/key values stay in memory
and are never written to disk. The helper looks up `e2e_read`'s ULID and narrows the key by
that id: since terrascale#778, a key narrowed by a database name mints no token.
The credential's `database` is therefore the ULID, while `E2E_DATABASE` keeps the
name, and TerraBase checks that the name resolves to the key's id. The key is restricted to `e2e_read`; acceptance
must prove that reading the existing document in `e2e_negative` fails with that
same key. The helper does not create a second project or a negative-database key.
Core dumps are disabled. On exit, references/cookies are cleared; Python does
not guarantee cryptographic erasure of immutable strings from process memory.

## Failure and cleanup

After validation, only native key id, normalized expiry and approved target are
printed as cleanup metadata. Success says installation completed; it does not
prove production acceptance. A failed installation is ambiguous: the GitHub
write may already have succeeded. The helper stops without retry, replacement
issuance or revocation. Do not rerun it after an issuance/installation failure.
Have the operator inspect native metadata and the exact destination first.
If creation failed before a usable response, no key id may be available; inspect
only the approved project's metadata for `deployment-e2e-read`. Private HTTP
bodies, authentication errors, exception strings and subprocess diagnostics
are never displayed. Cleanup/revocation remains a separate owner action.

The native list exposes unrevoked keys only; empty-list verification is not an
inventory of historical revoked credentials. The list/create pair is not an
atomic server-side transaction: keep this isolated project's key issuance
exclusive to this operator. A concurrent external issuer could race that check.
The workflow still has to validate live key authority and production denials;
metadata checks alone do not prove those results. Preserve existing merge,
security and activation holds.

## Existing native JSON installation

`python3 scripts/e2e/install-production-credential.py` remains supported with
its existing hidden native-JSON paste and exact negative-target confirmation.
It installs an already-created native response and performs no authentication,
issuance or live target-existence checks. Use the new user-only issuance command
to avoid transferring a one-time key response between processes or people.
The earlier manual-paste runbook describes that default mode; this file adds
an automatic user-process issuance mode and does not authorize agent execution.

## Synthetic verification

```sh
nice -n 19 python3 -B scripts/e2e/test_issue_production_credential.py
nice -n 19 python3 -B scripts/e2e/install-production-credential.py --self-test
```

These checks use fake credentials, temporary cookie/state directories, mocked
HTTP/GitHub/mailbox calls and real local pseudo-terminals. They do not read the
host's actual cache/password/state files, log in, contact APIs, issue keys, install
secrets or invoke provisioning. Full suites and production execution are outside
this handoff preparation.
