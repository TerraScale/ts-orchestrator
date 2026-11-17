# Regional app images

The reviewed tenancy namespace lives in `deploy/m1/registry.json`, embedded in
`ts-orch`. Hosts do not query the Artifacts configuration API to discover it.

Fleet service images and deployment records use
`<namespace>/terrascale/<pkg>@sha256:<manifest digest>`. The digest identifies
the native Linux child manifest, currently arm64 in the fleet, rather than a
multi-platform index. The image bytes and digest are identical in every region.
Each host prepends its own registry: `gru.ocir.io`, `sjc.ocir.io` or
`fra.ocir.io`. Staging uses San Jose. The fleet reference and containerd image
record retain the hostless form; registry requests use the regional form.
`release wait --service <service> --image <hostless reference>` compares that
stable fleet identity with running tasks.

Hosts discover a release from their regional
`<registry>/<namespace>/terrascale/<pkg>:release`. That tag selects a digest;
it never authorizes one. A signed GET to `/20180419/docker/token` requests
`service=<registry>` and `scope=repository:<namespace>/terrascale/<pkg>:pull`.
The OCI instance-principal signer signs the method, request target, host and
date. The returned token stays in memory, scoped to that repository, and is
refreshed before its expiry. Signed token requests cannot redirect. Pull
credentials are bound to the regional registry.

The selected manifest must carry both SLSA build provenance and a release
selection with predicate type
`https://terrascale.tech/attestations/release-selection/v1`, naming the service
and source revision. Both are standard OCI 1.1 referrers with artifact type
`application/vnd.dev.sigstore.bundle.v0.3+json`, subject equal to the selected
manifest digest, and one JSON bundle layer. A registry without the referrers API
uses the OCI fallback index tag `sha256-<manifest hex digest>` in the same
repository. `remote.Referrers` reads either representation.

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

A second PR removes GHCR resolution, the old dashboard package handoff and
Vault token paths after no live fleet document, retained deployment floor or
rollback image requires GHCR. GHCR pull-token secrets are then removed, one
region at a time, with a metadata read before deletion and a serving-state
check after each region. The staging secret is `stg-1-ghcr-pull-token`.
Reports list names and verification outcomes, never credential values.

## Local proof

The `e2e-m1 / ocir` lane runs an HTTPS registry and a token endpoint that
cryptographically verifies OCI request signatures. It resolves `:release`,
pulls an app layer, verifies build and selection bundles offline through both
the referrers API and fallback tag, checks the token is reused in memory, and
refuses unsigned images and tampered images carrying copied bundles. Its
transport permits requests only to the selected regional registry. The lane
also refuses an unset embedded fleet namespace.
