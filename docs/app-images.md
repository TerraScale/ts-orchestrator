# Regional app images

The reviewed tenancy namespace lives in `deploy/m1/registry.json`, embedded in
`ts-orch`. Hosts do not query the Artifacts configuration API to discover it.

Fleet service images and deployment records use `<pkg>@sha256:<manifest digest>`.
The digest identifies
the native Linux child manifest, currently arm64 in the fleet, rather than a
multi-platform index. The image bytes and digest are identical in every region.
Each host expands it to
`<oci-region>.ocir.io/<namespace>/<repo-prefix>/<pkg>@sha256:<manifest digest>`.
The embedded registry document contains the `prod` mapping:
namespace `grxnmoqvrcdv` and prefix `terrascale`.
Production uses `sa-saopaulo-1`, `us-sanjose-1` and `eu-frankfurt-1`.
The fleet reference and containerd image
record retain the hostless form; registry requests use the regional form.
containerd parses a pull reference as `host/path`, so the executor pulls the
regional form and the regional resolver names the stored image with the
hostless form after verifying it.
`release wait --service <service> --image <pkg>@sha256:<digest>` compares that
stable fleet identity with running tasks.

Hosts discover a release from their regional
`<registry>/<namespace>/<repo-prefix>/<pkg>:release`. That tag selects a digest;
it never authorizes one. A signed GET to `/20180419/docker/token` requests
`service=<registry>` and `scope=repository:<namespace>/<repo-prefix>/<pkg>:pull`.
The OCI instance-principal signer signs the method, request target, host and
date. An absent signed Date yields an anonymous token at OCIR, so the host
always supplies Date before signing. The response contains `token`,
`access_token`, `scope` and `expires_in` with no `issued_at`; expiry is measured
from the token request. The returned token stays in memory, scoped to that repository, and is
refreshed before its expiry. Signed token requests cannot redirect. Pull
credentials are bound to the regional registry.

The selected manifest must carry both SLSA build provenance and a release
selection with predicate type
`https://terrascale.tech/attestations/release-selection/v1`, naming the service
and source revision. Both are standard OCI 1.1 referrers with artifact type
`application/vnd.dev.sigstore.bundle.v0.3+json`, subject equal to the selected
manifest digest, and one JSON bundle layer with the same media type. OCIR
returns 404 for the referrers API. Producers maintain the OCI fallback index
tag `sha256-<manifest hex digest>` in the same repository. `remote.Referrers`
reads that tag; registries supporting the API also work.

App-canary CI builds once, copies the identical arm64 child manifest to all
three production repositories, and attaches the same build,
selection and SBOM bundles using ORAS 1.3.6. Selection is a cosign v3.0.2
attestation over the exact raw manifest bytes, whose SHA-256 is the image
digest. Its subject filename does not change the digest or workflow identity.
CI verifies the published build provenance before moving each single-platform
`:release` tag, and waits for the production rollout using the package-only
reference. The region order is ts-orch's, not CI's: the app release leader
reads its own region's `:release` tag and, once it selects a new digest,
releases it to each target in the catalog order gru, fra, sjc. Dispatch and
reconciliation of a signed multi-region release require the order from
every manager in each target's SwarmKit receiver inventory. Each later region needs the earlier targets'
fresh serving and bake evidence for the same generation. A service with one
target still releases to that region.
CI therefore moves every region's tag before it waits; a release that moves
one region's tag and waits for that region alone stalls whenever the leader
runs in another region. Login uses the local `ocir-login` action and GitHub OIDC exchange.

Verification uses the embedded Sigstore trust root, certificate identity of
the producing GitHub Actions workflow on `refs/heads/main`, source revision,
transparency evidence and manifest digest. It does not contact GitHub,
Fulcio or Rekor. Release selection supplies the signed run and attempt used
by deployment ordering. TerraBase selections require the approved manual
workflow dispatch. Executors verify the bundles again before a newly pulled
OCIR image can run.

## Staged migration

The first migration build retains GHCR pulls for already deployed GHCR service
documents and rollback state, using the existing Vault token path. New
discovery reads only regional OCIR `:release` tags. Once images and both
bundles have been published in all three registries, each service's next
signed release changes its document to the hostless OCIR reference. Only a
signed release of the same service may perform that repository change.
Services continue serving through the existing regional bake and rollback
protocol.

Task comparisons treat a legacy `ghcr.io/terrascale/<pkg>@sha256:<digest>`
and `<pkg>@sha256:<digest>` as the same image identity. Changing only that
reference updates the service document without replacing its running tasks.
New tasks use the updated service template; a different package or digest
still requires replacement. Runtime evidence retains each task's actual
reference while checking its canonical package and digest.

A second PR removes GHCR resolution, the old dashboard package handoff and
Vault token paths after no live fleet document, retained deployment floor or
rollback image requires GHCR. GHCR pull-token secrets are then removed, one
region at a time, with a metadata read before deletion and a serving-state
check after each region.
Reports list names and verification outcomes, never credential values.

## Local proof

The `e2e-m1 / ocir` lane runs an HTTPS registry and a token endpoint that
cryptographically verifies OCI request signatures. It resolves `:release`,
pulls an app layer, verifies build and selection bundles offline through both
the referrers API and fallback tag, checks the token is reused in memory, and
refuses unsigned images and tampered images carrying copied bundles. Its
transport permits requests only to the selected regional registry. The lane
requires a signed Date, uses the production token response shape, and checks
that production regions expand the same package digest into their regional
repositories. Empty namespace or repository-prefix declarations fail the lane.
