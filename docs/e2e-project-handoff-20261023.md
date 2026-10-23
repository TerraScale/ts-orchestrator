# Project-only production E2E handoff

Status: implementation prepared; credential approval, user installation and an
authenticated production run are still required. This file supersedes the
production credential/provisioning instructions in `docs/e2e.md`; local contract
tests remain unchanged. Do not use dashboard management credentials, user-id
impersonation, organization-wide keys, `tb_` keys or GitHub organization tokens.

## Approval and destination

MarioGK approved **one** isolated test project, `deployment-e2e`. The lead
provisions two databases inside that same project: `e2e_read` for positive reads
and `e2e_negative` for negative reads. The negative database must contain one
document and have **no key**. The single native credential and OIDC binding both
restrict access to `e2e_read`; no second project or extra key is needed or allowed.
Status canary, auth and dashboard data are outside this fixture scope.

Before environment preparation and credential handoff, record the owner's
confirmation of the organization id, project id and both database names, including
the negative database's current existence and document. A nonexistent database
returns the same `404 unknown_database` as a denied read. Missing either database
or confirmation blocks the proof; the runner never provisions fixtures or reads
customer data.

| Variable | Approved value |
| --- | --- |
| `E2E_ORGANIZATION_ID` | Approved isolated organization id |
| `E2E_PROJECT_ID` | The single approved `deployment-e2e` project id |
| `E2E_DATABASE` | `e2e_read`, the native key and OIDC binding's positive database |
| `E2E_UNRELATED_DATABASE` | `e2e_negative`, a distinct existing database in that same project, with one document and no key |

The only credential destination is GitHub.com, account **MarioGK**, repository
**TerraScale/ts-orchestrator**, environment **production**, secret
**E2E_PROJECT_CREDENTIAL**. No host, OpenBao, OCI Vault or other repository copy
is needed. Missing environment/protections or approved identifiers are blockers;
this helper does not create environments, rules, credentials or grants.
The TS-753 environment-protection approval prerequisite requires
`deployment_branch_policy: {protected_branches: false, custom_branch_policies: true}`
and exactly one deployment policy: name `main`, type `branch`. Tags, wildcard
patterns and additional branches are refused **before** any secret prompt.

## User-run handoff

1. After approval, MarioGK uses ts-auth's native project-key flow at
   `https://auth.terrascale.tech/v1/terrascale/organizations/<org>/projects/<project>/api-keys`.
   Select exactly `scopes: ["documents:read"]`, the approved `database`, and a
   non-null UTC `expires_at` no more than 24 hours ahead. Keep the complete native
   creation response (`api_key` metadata plus `key`) private; no chat, tickets,
   screenshots, command arguments, shell history or diagnostic logs.
2. In a private interactive terminal at the approved checkout's repository root,
   run **one command**: `python3 scripts/e2e/install-production-credential.py`.
   Reconfirm the exact owner-approved existing `<E2E_PROJECT_ID>/e2e_negative` pair
   when prompted. Paste the native response into its hidden terminal prompt;
   both one-line and formatted JSON are supported. Echo stays disabled across
   the whole paste and is restored on completion or interruption; unsafe
   terminals are refused. Finish with Enter (or an empty line to abort
   incomplete JSON).
   The helper verifies the GitHub account/repository/environment, approved
   environment variables, native key/id, exact scope, database and expiry. It
   sends JSON only through protected subprocess stdin to
   `gh secret set --repo TerraScale/ts-orchestrator --env production E2E_PROJECT_CREDENTIAL`;
   subprocess stderr and secret-install stdout are discarded. Never have an
   agent run this command with a real credential.
3. After the reviewed change reaches main and the owner authorizes execution,
   dispatch **TerraScale E2E**, branch `main`, target `prod`. The workflow grants
   `contents: read` and `id-token: write`, consumes the one environment secret
   and serializes production jobs without canceling the running manual check. Installation
   alone is not completion.

The helper validates metadata, not live authority. The runner exchanges the key
**without project/scope narrowing**, asserts native project/database/read-only
JWT claims and a lifetime at most 15 minutes, and requires server denial of
cross-project exchange. An organization key disguised by edited metadata fails.
The negative database must already exist in the **same approved project**.
The helper requires the exact `<E2E_PROJECT_ID>/<E2E_UNRELATED_DATABASE>`
confirmation before hidden secret entry, naming both the positive restriction
and negative fixture. Native canonical database names are required, and empty,
malformed or equal positive/negative names are refused before secret entry.
Neither the restricted runner nor a `404 unknown_database` verifies existence;
without the recorded prerequisite, that denial proves no database isolation.
The cross-project token-exchange probe uses a valid alternate project id solely
as a requested OAuth target; it does not require or read another project.

## Evidence and cleanup

The runner first checks `https://api.terrascale.tech/readyz`,
`https://auth.terrascale.tech/readyz` and issuer discovery at `/terrascale`.
It reads one page of collections for the exact approved project/database using
ts-go and requires `X-TerraBase-Region: gru`. It never creates projects, databases,
collections or documents. The pinned SDK's API-key source still requires the
retired `tsk_` key format. Standard native OAuth HTTP accepts the current native
key response and preserves raw denial responses so a denial containing a token
cannot pass. The SDK is pinned to commit
`6a9d69c9c2aa1cbe88428b80934dd6581a1c84f6` so its data client accepts project JWTs
while preserving the existing local Management-credential contract.
Native auth administration and raw management-denial probes have no SDK method.

All production report scenarios must pass: readiness/discovery, native exchange,
collection read, cross-project exchange (`400 invalid_target`), scope elevation
(`400 invalid_scope`), same-project negative database read
(`404 unknown_database`), auth administration read (`401 unauthorized`) and
TerraBase compatibility management
read (`404 unknown_database`). No write is attempted to prove write denial.
Unexpected successes, redirects, outages and malformed responses fail; they
never count as permission denials or pending features. Reports contain only
source SHA, validated non-secret key metadata, the exact negative organization/
project/database target in the same project and its owner-confirmation
prerequisite, and sanitized
scenario outcomes. The report explicitly states that target existence is not
verified by the runner; retain the owner's prior confirmation with the evidence
before claiming database isolation.
The authenticating data read lets TerraBase verify the JWT signature; decoded
claim assertions in the runner do not replace server signature verification.

Record the workflow run/head SHA, deployed artifact identity from the runtime
owner, approved scope/expiry and sanitized report. On 2026-10-23, main was
`f1eeddaf66029e5c8f0cf9769c9928a60466e8d4`; both public readiness routes returned
200 and discovery named `https://auth.terrascale.tech/terrascale`. These probes
do not establish authenticated acceptance or an exact deployed image.

MarioGK owns rotation and revocation of the **exact project key id** in the
report. After the approved window, revoke it through the native project-key
flow, remove this environment secret and clear any private clipboard/source
copy. Superseded keys need explicit identification before revocation. A revoked
or expired key cannot obtain another token; an already-issued JWT can remain
usable for up to 15 minutes. Owner-authorized cleanup evidence must show key
metadata/revocation outcome and failed subsequent exchange without secret values.
