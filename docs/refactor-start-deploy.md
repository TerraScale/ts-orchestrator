# Main-to-production inspection

Inspected 2026-10-16 using the checked-out workflow/scripts and read-only GitHub
API calls for `TerraScale/ts-orchestrator`. No deployment or cloud mutation ran.

## Publication boundary

Every main push, including documentation-only changes, starts `ci.yml`. After
verification and retained binary publication, its last step dispatches
`deploy.yml` for that exact source SHA and CI run ID/number. Image input detection
applies only to `image.yml`; it does not suppress fleet deployment.

`deploy.yml` checks main ancestry and CI success/overtaking, then invokes
`scripts/ci/deploy-fleet.sh`. The script fetches retained qualified binaries,
loads the release leaf/delegation from OCI Vault and invokes `release deploy`.
That producer signs, uploads and publishes each discovered serving region.
Existing signature, regional scope, ordering, quorum and rollout health checks
remain, but these paths do not require the refactor's exact-candidate RUNTIME/HA,
workload isolation or stateful qualification evidence.

Therefore a runtime-changing main push can reach production when the configured
credentials and variables exist, without proving those refactor gates. A
source-only documentation push takes the same dispatch path, although it does not
introduce a runtime behavior change. Workflow names are not gate evidence.

## Observed GitHub configuration

Read-only API results:

| Query | Observed result |
| --- | --- |
| Repository metadata | Public; default branch `main`; authenticated account has repository admin access. |
| Repository environments | `total_count: 0`, `environments: []`. |
| Environment `production` | HTTP 404; no reviewer/branch protection was observed. |
| Repository Actions secrets | Empty list; secret values were neither requested nor printed. |
| Repository Actions variables | Empty list; variable values were neither requested nor printed. |
| `deploy.yml` workflow runs | Empty list. |
| Organization Actions secret inventory | HTTP 403: current token lacks `admin:org` scope. |

No production environment protection is established by this inspection. Missing
repository variables and `TS_DEPLOY_OCI_KEY` mean the observed repository setup
cannot complete the scripted deployment as currently configured. Organization
secret inheritance and actual OCI IAM permissions were not established. The
script's comment describing a Vault-read/object-write-only OCI key is intent,
not independently verified credential-scope evidence.

## Required runtime publication proof

Before the first runtime-affecting main publication, require an always-on
qualification admission check before any deployment credential/signature use.
It must consume retained, authenticated evidence for the exact source/artifact
candidate, affected region and runtime/architecture, including RUNTIME/HA and
the workload's applicable safety/isolation gate. A missing or mismatched record
must refuse that region without cancelling independently qualified regions.

Incomplete slices remain qualified on isolated disposable fixtures. Such tests
do not establish live production qualification. Documentation and isolated source
work can proceed; paid provisioning, credential creation and production cutover
remain subject to the existing authorization and scope boundaries.
