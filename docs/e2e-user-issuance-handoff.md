# User-only production E2E credential issuance

The parent prepares the approved isolated project/database, existing negative
project/database and four `production` environment variables first. No key is
created during that preparation. The user executes the command below in a
private interactive terminal after reviewing this helper. Agents must never
execute the real helper or redirect a real password/key to it.

```sh
python3 /home/mariogk/.t3/worktrees/ts-orchestrator/fix/ku-security-deploy/scripts/e2e/issue-production-credential.py < /home/mariogk/.config/terrascale/mailbox-password
```

This is one command, with no manual login/code entry or native key response
transfer. The existing mailbox password file is read only through stdin; the
helper does not open that path itself. Shell redirection contains a path, never
its value. Do not use shell tracing, terminal recording or debugging. Expect
about 30–90 seconds after confirmation; mailbox checks stop after 60 seconds.
No key exists from this handoff until the user runs and confirms the helper.

## Checks before issuance

1. The shared installer preflight verifies GitHub.com account `MarioGK`, exact
   repository `TerraScale/ts-orchestrator`, environment `production`, custom
   deployment policy allowing only branch `main`, and four native identifiers:
   `E2E_ORGANIZATION_ID`, `E2E_PROJECT_ID`, `E2E_DATABASE`,
   `E2E_UNRELATED_PROJECT_ID`. The projects must differ.
2. A hidden `/dev/tty` confirmation names the organization, both exact
   project/database pairs and secret destination. Password stdin cannot answer
   this prompt. Missing controlling terminal or unsafe echo control refuses
   before password input or authentication.
3. Hosted ts-auth sign-in sends one email code to `mariogk@terrascale.tech`.
   TLS IMAP uses `mailserver.purelymail.com:993`, readonly INBOX and header-only
   `BODY.PEEK`. Only a fresh Date, exact parsed recipient and native English or
   Portuguese TerraScale/ts-auth sign-in-code subject match; multiple distinct
   fresh codes refuse. No resend loop runs. The signed hosted session approves
   the public ts-cli device client `00000000000000000000000007`, scope
   `openid email`. The helper waits the advertised interval and polls once;
   refresh tokens refuse. Userinfo must return this exact verified email.
4. Native organization metadata must prove owner/admin. Both project records
   must identify the same approved organization. Two public-client token
   exchanges request only `databases:read`; authenticated GETs of both exact
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
hosted auth cookies never accompany TerraBase requests. Password, email/device
codes, signed session and access/key values remain in the user's process.
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

These checks use fake credentials, mocked HTTP/GitHub/mailbox calls and real
local pseudo-terminals. They do not log in, contact APIs, issue keys, install
secrets or invoke provisioning. Full suites and production execution are outside
this handoff preparation.
