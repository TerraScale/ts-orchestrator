# Project/workflow OIDC production proof

Status: implementation only; authenticated production acceptance remains pending.
This supplements `e2e-project-handoff-20261023.md`. Its hidden, user-run native
JSON credential installer remains required and unchanged. No credential, trust,
environment, deployment or production data is created by the runner.

## Contract prepared by the owning thread

| Binding | Exact value |
| --- | --- |
| Public OAuth client | `01M4GHA0E2E000000000000000` |
| Grant type | `urn:terrascale:params:oauth:grant-type:github-actions` |
| Token endpoint | `https://auth.terrascale.tech/terrascale/oauth/token` |
| GitHub assertion issuer | `https://token.actions.githubusercontent.com` |
| Requested GitHub assertion audience | `https://auth.terrascale.tech/terrascale` |
| Repository / owner IDs | `1422428095` / `206395477` |
| Workflow ref | `TerraScale/ts-orchestrator/.github/workflows/e2e.yml@refs/heads/main` |
| Event / ref / environment | `workflow_dispatch` / `refs/heads/main` / `production` |
| GitHub subject | `repo:TerraScale/ts-orchestrator:environment:production` |
| Reusable workflow claim | `job_workflow_ref` must be absent |
| Access-token audience / scope | `https://api.terrascale.tech` / only `documents:read` |

Bind the trust to the existing `E2E_ORGANIZATION_ID`, `E2E_PROJECT_ID`, and
canonical database **name** in `E2E_DATABASE`. Set its non-null UTC grant deadline
to the same `expires_at` as the native credential, within 24 hours of preparation.
The runner uses this existing validated metadata as the deadline; it does not
read administrative trust settings. Auth must issue a JWT expiring within
15 minutes and no later than that grant deadline. Auth must verify GitHub's
signature, exact trust claims, and single-use `jti`. The owning thread verifies
the deployed trust and deadline separately; this implementation does not activate
or configure them.

The owner must separately confirm that `E2E_UNRELATED_PROJECT_ID` is an existing
different project in the same organization with an existing database whose name
is exactly `E2E_DATABASE`. A missing database also returns `404 unknown_database`
and cannot establish isolation. Keep that confirmation with the run evidence.

## Execution and retained evidence

1. Complete the existing user-run hidden JSON credential handoff. Keep the native
   key exchange and all eight native production scenarios in the evidence.
2. After review and deployment by the owning thread, dispatch the existing E2E
   workflow on `main` with target `prod`. Only its `prod` job has `contents: read`
   plus `id-token: write`; the local job cannot request an assertion.
3. Require all five additional scenario results to pass: OIDC exchange and exact
   project/database/audience/scope/lifetime assertions, ts-go own-project read,
   ts-go different-project same-name database denial, scope elevation denial
   (`400 invalid_scope`), and replay denial (`400 invalid_grant`). No green result
   substitutes for a missing, inert, expired or undeployed trust.
4. Retain the report, workflow run/head SHA, native non-secret metadata, exact
   deployed artifact/trust identity, and owner-confirmed negative target. Browser
   sign-in, dashboard sessions and other signed-in behavior remain unproven.

The runner requests GitHub assertions directly through native HTTPS using
`ACTIONS_ID_TOKEN_REQUEST_URL` and a bearer header from
`ACTIONS_ID_TOKEN_REQUEST_TOKEN`. Only HTTPS `*.actions.githubusercontent.com`
`/idtoken` URLs are accepted, without userinfo, ports or fragments; the requested
audience is fixed. Actions and OAuth redirects fail without following them.
Assertions and issued access tokens stay in process memory; they are never put
in output, reports, environment exports or files. Response bodies and transport
errors are suppressed. There is no fallback to native credentials for OIDC.

The scope probe fetches a second assertion and requires different token bytes
and `jti` before requesting `documents:write`, so replay rejection cannot mask a
scope error. The replay probe reuses the assertion from the successful exchange.
Denials require the exact HTTP/OAuth error and no access, refresh or ID token.
The decoded access-token assertions do not verify its signature locally:
TerraBase verifies it on the subsequent real SDK read.

After the approved window, the owning thread handles trust expiry/revocation and
the existing native-key cleanup. This change creates no secrets, keys, paid
capacity or runtime mesh/Swarm settings.
