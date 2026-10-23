# Deployment credential scope audit — 2026-10-23

Status: metadata audit complete; protection changes and credential lifecycle work
remain approval-gated. No credentials, grants, environment settings, production
data, release grace periods or rollback behavior changed during this audit.

## Evidence baseline

Remote main was checked with `git ls-remote origin refs/heads/main`:

| Repository | Main inspected |
| --- | --- |
| TerraScale/ts-orchestrator | `f1eeddaf66029e5c8f0cf9769c9928a60466e8d4` |
| TerraScale/terrascale | `49e32e99ca20c94e581bd080f61f3ca7668e715b` |

The assigned `fix/ku-security-deploy` worktrees initially matched these revisions.
Concurrent parent changes are outside this audit's owned file. Ticket description
and comment were read from the supplied snapshot; quoted historical conclusions
below are distinguished from live observations.

## Nonsecret inventory

| Identity / credential | Consumer and destination | Observed scope, owner and expiry |
| --- | --- | --- |
| GitHub Actions OIDC | ts-orchestrator `ci.yml`, release-push job; no stored deployment secret | `contents: read`, `id-token: write`; push/main-only job. Verifier requires TerraScale owner, main ref, exact workflow, audience `ts-orch`, signed unexpired JWT (one-minute skew). GitHub issues token per job; no fixed expiry value was collected. |
| App release OIDC | terrascale `ci.yml` → `terrabase`, `ts-auth`; ts-dashboard `images-ghcr.yml` → `ts-dashboard`; orchestrator `app-canary.yml` → `app-canary` | Exact main workflow/service mapping in `internal/releasepush/oidc.go`. TerraScale owns repositories; named operational owner is not declared here. Monorepo image job has `contents: read`, `packages: write`, `id-token: write`. |
| Mesh/digest OIDC | orchestrator `multi-region.yml`, `app-digests.yml` | Distinct workflow identities; digest workflow is state-read-only. Mesh workflow has mutation authority; it is not a preview-only cleanup identity. No environment claim is validated. |
| `TS_DEPLOY_OCI_KEY` (historical) | Previously reported in deploy-lag.yml | Current main deploy-lag has no OCI secret reference, only job-scoped GitHub token: contents/actions/checks read, issues write. Orchestrator repo and production environment each have zero secrets. Organization secret visibility is **unknown** (403); absence from repo does not prove OCI-side revocation. |
| `TIGRIS_CI_CREDENTIALS` | terrascale repository secret; `ci.yml` Slow TerraBase job → BuildKit temporary secret file | Created/updated 2026-10-13T21:24:29Z. Repo docs describe Editor-style bucket-scoped CI storage at `ts-terrabase-ci`, TerraScale org, fresh per-run prefixes. Actual key roles, owner and expiry were not verified; secret metadata exposes neither. |
| `TS_DOTNET_DEPLOY_KEY` | terrascale repository secret; shared checkout step for `TerraScale/ts-dotnet` in `ci.yml` | Created/updated 2026-10-11T21:16:44Z. Target repo deploy-key metadata: id `166123566`, title `terrascale CI (read-only)`, `read_only: true`, created 2026-10-11T21:16:42Z, last used 2026-10-21T12:09:40Z. Matching timestamps/title support association, but no secret/public-key comparison was performed. API has no expiry field. |

GitHub metadata calls: `repos/{repo}/actions/secrets`,
`repos/TerraScale/ts-orchestrator/environments/production{,/secrets,/variables}`,
`repos/TerraScale/terrascale/environments`, and `repos/TerraScale/ts-dotnet/keys`
(allowlisted metadata only). Monorepo has no GitHub environments. The organization
secret listing returned 403 requiring org admin/actions-secret access; no access
expansion was attempted.

OCI `iam region list` confirms GRU=`sa-saopaulo-1`, SJC=`us-sanjose-1`,
FRA=`eu-frankfurt-1`. Metadata-only user/API-key inventory found two ACTIVE API
keys under `mariogk@terrascale.tech`, created 2026-09-12 and 2026-10-04; the
`terrascale-smtp` user had no API keys. Neither key can be attributed to the old
GitHub secret without an operator-supplied nonsecret fingerprint. User identity
alone does not establish effective policy scope or expiry; do not revoke either
key based on this audit. No SMTP passwords, private keys or Vault values read.

Tigris `whoami` reports OAuth admin@terrascale.tech but active organization
**Admin Terrascale**, not TerraScale (`flyio_1xglmxrdqv0movy6`). No key inventory
was run against that personal organization and no organization selection changed.
The ticket's 2026-10-22 comment reports all Fly apps absent and six old Fly tokens
revoked on 2026-10-16; this audit did not independently recheck Fly metadata.

## Existing authorized/denied boundary evidence

No duplicate test file is needed: `internal/releasepush/releasepush_test.go`
already exercises the requested boundaries with locally signed synthetic tokens:

| Test | Allow / deny evidence in source |
| --- | --- |
| `TestVerify` | Valid release identity accepted; wrong owner/repository/audience/issuer, expired token, PR event, branch and other workflow rejected. |
| `TestAppValidation` | terrascale CI releases terrabase and ts-auth; ts-dashboard, wrong image owner/service, tags and retired image workflow rejected. App canary identity cannot release orchestrator. |
| `TestAuthPermissions` | Own version request works; unrelated publish and broad/other-run inbox subscriptions yield NATS permission violations. |
| `TestMeshBridge` | Main mesh schedule/dispatch accepted; branch, other repository and release-workflow mesh use rejected. App-digests state read accepted; apply/rm/ping rejected. |

These are source coverage observations, not a new test execution. Current-main
[Go checks run 39906779904](https://github.com/TerraScale/ts-orchestrator/actions/runs/39906779904)
was successful, including `deploy/release-push`; its race jobs were skipped, so
it does not independently prove these individual tests executed on this SHA.
[App release canary 39906780014](https://github.com/TerraScale/ts-orchestrator/actions/runs/39906780014)
was successful. Deployment lag guard run 39907090209 failed; successful release
delivery is not a claim that all deployment checks are green. No live hostile
deployment attempt was performed. There is no production/preview environment
claim boundary to prove: the verifier checks ref/workflow/service, not environment.

## Exact approval proposal (not applied)

1. Approve a **main-only deployment branch policy** on
   `TerraScale/ts-orchestrator` environment `production` (id `24531838776`).
   Current state: `protection_rules: []`, `deployment_branch_policy: null`,
   `can_admins_bypass: true`; zero environment secrets/variables. Proposed PUT
   `/repos/TerraScale/ts-orchestrator/environments/production` body:
   `{"deployment_branch_policy":{"protected_branches":false,"custom_branch_policies":true}}`,
   followed by POST `.../production/deployment-branch-policies` body
   `{"name":"main","type":"branch"}`. No tag policy, reviewers, wait timer,
   new secret, credential, grant or trust activation is included. This is the
   smallest change preserving unattended main monitoring. It blocks non-main
   jobs targeting this environment, not malicious code already on main.
2. Do not imply this protects every release: only jobs declaring the environment
   inherit it. Current main deploy-lag and e2e declare production; release-push
   does not. Parent-owned release serialization/environment changes need their
   own exact diff and approval review. Required-reviewer protection would pause
   every scheduled production job and needs a separate explicit operational
   decision; it is excluded from the minimal proposal.
3. Owner proposal: MarioGK (GitHub user id `8379079`, verified repository admin)
   owns credential inventory and expiry review. Review long-lived credentials
   every 90 days; next review 2027-01-21 if approved 2026-10-23. This is a review
   date, not a claim of enforced expiry. Obtain nonsecret historical OCI
   fingerprint, Tigris key id/role/expiry metadata in the correct org, and org
   secret visibility from an already authorized administrator. Do not create a
   replacement until a distinct approval names scope, expiry and destination.
4. After approval, verify main environment job admission and non-main denial
   using a no-secret/no-mutation workflow. Record resulting run URLs. Only after
   exact old-key attribution, consumer inventory and verified replacement or
   retirement may the operator approve revocation. Rollback before revocation:
   restore the prior environment policy; never restore a known compromised key.
   No replacement/revocation or persistent credential installation is authorized
   by this document.

Remaining acceptance gaps: actual Tigris/legacy OCI scope and expiry, named owner
confirmation, organization-secret visibility, protection approval/application and
post-change admission evidence. Existing release denial tests cover services,
workflows and organizations but do not prove a preview environment boundary.
