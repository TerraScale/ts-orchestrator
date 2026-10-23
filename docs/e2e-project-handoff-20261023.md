# Project-only production E2E handoff

Status: implementation prepared; credential approval, user installation and an
authenticated production run are still required. This file supersedes the
production credential/provisioning instructions in `docs/e2e.md`; local contract
tests remain unchanged. Do not use dashboard management credentials, user-id
impersonation, organization-wide keys, `tb_` keys or GitHub organization tokens.

## Approval and destination

MarioGK approves the existing isolated organization, project, database and a
different **existing project in the same organization** for the negative check.
No customer project/data may be chosen. Confirm these non-secret identities
before creating any credential or setting these `production` environment variables:

| Variable | Approved value |
| --- | --- |
| `E2E_ORGANIZATION_ID` | Existing isolated organization id |
| `E2E_PROJECT_ID` | Existing isolated project id |
| `E2E_DATABASE` | Existing database name in that project |
| `E2E_UNRELATED_PROJECT_ID` | Different existing same-organization project id |

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
   Paste the native response into its hidden `getpass` prompt; both one-line and
   formatted JSON are supported, with hidden continuation prompts.
   The helper verifies the GitHub account/repository/environment, approved
   environment variables, native key/id, exact scope, database and expiry. It
   sends JSON only through protected subprocess stdin to
   `gh secret set --repo TerraScale/ts-orchestrator --env production E2E_PROJECT_CREDENTIAL`;
   subprocess stderr and secret-install stdout are discarded. Never have an
   agent run this command with a real credential.
3. After the reviewed change reaches main and the owner authorizes execution,
   dispatch **TerraScale E2E**, branch `main`, target `prod`. The workflow grants
   only `contents: read`, consumes the one environment secret and serializes
   production jobs without canceling the running manual check. Installation
   alone is not completion.

The helper validates metadata, not live authority. The runner exchanges the key
**without project/scope narrowing**, asserts native project/database/read-only
JWT claims and a lifetime at most 15 minutes, and requires server denial of
cross-project exchange. An organization key disguised by edited metadata fails.
The negative project's existence and same-organization membership must be
verified by the owner beforehand; an unknown id alone proves no isolation.

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
(`400 invalid_scope`), unrelated-project read (`404 unknown_database`), auth
administration read (`401 unauthorized`) and TerraBase compatibility management
read (`404 unknown_database`). No write is attempted to prove write denial.
Unexpected successes, redirects, outages and malformed responses fail; they
never count as permission denials or pending features. Reports contain only
source SHA, validated non-secret key metadata and sanitized scenario outcomes.
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
