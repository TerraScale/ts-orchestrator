# Main-to-production inspection and admission

Inspected 2026-10-16 using the checked-out workflow/scripts and read-only GitHub
API calls for `TerraScale/ts-orchestrator`. No deployment or cloud mutation ran.

## Publication boundary

Every main push, including documentation-only changes, starts `ci.yml`. After
verification and retained binary publication, its last step dispatches
`deploy.yml` for that exact source SHA and CI run ID/number. Image input detection
applies only to `image.yml`; it does not suppress fleet deployment.

The deployment workflow checks main ancestry and CI success/overtaking. Its
credential-free step runs `scripts/ci/deploy-fleet.sh qualify`; a later step with
the deployment credential environment runs `scripts/ci/deploy-fleet.sh deploy`.
QA owns the shared workflow wiring. The two script stages are mandatory phases,
not feature switches; invoking the deployment phase without completed admission
fails before the script reads any OCI credential input.

Admission fetches the exact `ci-SHA-run-ID` release's `qualification.json`, both
Linux binaries, and retained signed regional production records. The real
`release verify-production` command inspects the binary build metadata and
hashes, discovers current serving membership through Atlas, and checks every
region independently. A signed record binds the source revision, binary digest,
qualification-manifest digest, region, production environment,
`swarmkit-containerd` runtime, architecture and `orchestrator` role. It requires
both `runtime-ha` and `workload-safety` evidence with authenticated retained bytes.
The existing public trust root authenticates a root signature or a separate,
explicit qualification delegation. A binary-release delegation cannot authorize
qualification.

Missing, expired, mismatched, tampered or unavailable evidence refuses that
region. A complete region proceeds even when another is refused. No qualified
region means the credential-free step fails. Partial admission retains all
regional JSON results, deploys only qualified regions, and ultimately fails the
fleet result to keep refused regions visible. Both Linux architectures are
required by this admission step; a region cannot silently inherit evidence from
another architecture.

The deployment phase rechecks the admitted records before reading the OCI API
key. `release deploy` also verifies scoped retained evidence before loading its
Vault delegation/signing key and verifies that evidence remains valid for the
rollout deadline before signing. `release apply` independently requires the
matching scoped evidence before production object writes. Existing release
signature, ordering, scope, quorum, health and rollback checks still apply.

## Retained evidence contract

The existing release's immutable asset names are:

| Retained asset | Local verifier path under the candidate directory |
| --- | --- |
| `production-CELL-ARCH.json` | `production/CELL/ARCH/production.json` |
| `production-CELL-ARCH-delegation.json`, when delegated | `production/CELL/ARCH/delegation.json` |
| `production-evidence-SHA256` | `production/objects/SHA256` |

`CELL` is a catalog region such as `GRU`; `ARCH` is `amd64` or `arm64`.
`scripts/ci/fetch-production-evidence.sh TAG CANDIDATE_DIR` retrieves this layout
without loading OCI credentials. It bounds record/object downloads using release
metadata and signed evidence limits. Asset names and unsigned metadata grant no
admission; the verifier authenticates signatures and exact bytes afterwards.

An authorized disposable-target qualifier supplies the signed record, any
explicit qualification delegation, and retained gate logs in that local layout.
After building `dist/ts-orch`, retain the already signed results with:

```sh
bash scripts/ci/retain-production-evidence.sh CANDIDATE_DIR ROOT_PUBLIC_KEY GRU
```

The retention command checks the real verifier for both architectures, compares
the exact retained build manifest, uploads evidence/delegation first and signed
records last, and reads every asset back for byte equality. Existing assets are
never overwritten. It creates no signing key, authority or qualification claim.
The CI build publisher permits these narrowly named additional assets on retries;
its build qualification remains separate from production qualification.

Admission results remain at
`$RUNNER_TEMP/production-$SOURCE_SHA-run-$SOURCE_CI_RUN_ID/production-admission.jsonl`
for workflow artifact retention. Deployment never signs or writes a refused
region. No evidence publisher or live runtime qualification has been executed by
this source change; current candidates without such evidence remain refused.

## Observed GitHub configuration

Read-only API results repeated on 2026-10-16:

| Query | Observed result |
| --- | --- |
| Repository environments | `total_count: 0`, `environments: []`. |
| Repository Actions secrets | `total_count: 0`; names only were requested. |
| Repository Actions variables | `total_count: 0`; names only were requested. |
| `deploy.yml` workflow runs | `total_count: 0`. |
| Organization Actions secret inventory, prior inspection | HTTP 403; current token lacks `admin:org` scope. |

No production environment protection is established by these results. Missing
repository variables and `TS_DEPLOY_OCI_KEY` prevent the observed repository setup
from completing the scripted deployment. Organization inheritance and actual OCI
IAM permissions remain unverified. A script comment describing Vault-read and
object-write scope is intent, not credential-scope evidence. No secret values
were requested or printed.

## Integration evidence and remaining scope

`TestProductionEvidenceReleaseTransport` crosses the retained-release CLI process
and filesystem boundary, then invokes the real candidate/signature verifier. It checks immutable producer uploads/readback, rejects changed retained records,
checks complete GRU admission alongside unavailable oversized SFO evidence and
rejects evidence bytes changed after retrieval. The retained-artifact integration
matrix additionally rejects source/digest/manifest/scope/runtime/architecture/role
mismatches, missing gates, expiry, foreign signers and release-only delegation.
`TestProductionDeployRefusesBeforeSigningCredentials` proves missing qualification
reaches neither Vault signing lookup nor binary/channel writes.

These disposable local scenarios establish admission behavior, not RUNTIME/HA or
workload production readiness. Live regional qualification, actual OCI IAM scope,
production environment protection, credential installation and paid provisioning
remain outside this change. Runtime production exposure still requires the
region's retained RUNTIME/HA and applicable workload safety/isolation evidence.
