# Oracle Container Registry (OCIR)

Orchestrator releases (C40) and app images (C42) live in OCIR, not on GitHub.
Hosts read them with their instance principal; GitHub Actions pushes them by
exchanging its OIDC token for a short-lived OCI session token. GitHub keeps
code, pull requests and CI only. Built on 2026-11-17 (C41).

## Repositories

Tenancy object-storage namespace: `grxnmoqvrcdv`. Hosts take it from the fleet
document and never call `GetContainerConfiguration`.

Every repository is private, mutable, and lives in its region's control
compartment with the freeform ownership tags the reconciler uses:
`terrascale-managed-by=ts-orchestrator`, `terrascale-owner=terrascale` and
`terrascale-resource-key=<cell>/container-repository/<name>`.

| Region | OCI region | Compartment | Repository prefix |
|---|---|---|---|
| sjc | `us-sanjose-1` | `sjc-1-control` | `us-sanjose-1.ocir.io/grxnmoqvrcdv/terrascale/` |
| fra | `eu-frankfurt-1` | `fra-1-control` | `eu-frankfurt-1.ocir.io/grxnmoqvrcdv/terrascale/` |
| gru | `sa-saopaulo-1` | `gru-1-control` | `sa-saopaulo-1.ocir.io/grxnmoqvrcdv/terrascale/` |

Each prefix holds five repositories:

| Name | Content |
|---|---|
| `orchestrator-release` | Orchestrator binaries and their Sigstore bundles as OCI artifacts, and the signed channel document |
| `terrabase` | TerraBase image |
| `ts-auth` | ts-auth image |
| `terrascale-dashboard` | Dashboard image |
| `app-canary` | App canary image |

The sjc release repository is
`us-sanjose-1.ocir.io/grxnmoqvrcdv/terrascale/orchestrator-release`.
A repository name is unique per namespace and region.

## Host read

Policy `ts-orch-hosts-ocir` in compartment `TerraScale`
(`ocid1.policy.oc1..aaaaaaaatvxxcmeiepkkkchtw74ot54o2e3p5hw6ey6dyvav3y5jtdvdcepq`):

```text
Allow dynamic-group ts-orch-hosts to read repos in compartment sjc-1-control
Allow dynamic-group ts-orch-hosts to read repos in compartment fra-1-control
Allow dynamic-group ts-orch-hosts to read repos in compartment gru-1-control
```

`read repos` lists, reads and pulls; it cannot push or delete. No host has a
registry credential on disk.

A host gets a registry token with an instance-principal-signed
`GET https://<region>.ocir.io/20180419/docker/token`. The signed headers are
`date (request-target) host`, so the request must carry a `Date` header: the Go
SDK's `RequestSigner.Sign` does not add one, and without it OCIR answers 200
with an anonymous token that private repositories refuse with 403. On OCI
images the metadata service answers only root.

The reply is `application/json` with exactly these fields:

| Field | Value |
|---|---|
| `token` | Bearer token for `https://<region>.ocir.io/v2/...` |
| `access_token` | String |
| `scope` | `""` |
| `expires_in` | `3600` (one hour; there is no `issued_at`) |

Blob GETs, including 64 MiB layers, are answered 200 by `<region>.ocir.io`
itself, with no redirect to another host.

OCIR does not implement the OCI 1.1 referrers API:
`GET /v2/<repo>/referrers/<digest>` answers 404 `NOT_FOUND`, with or without
`artifactType`. It accepts a manifest with a `subject` (201) but returns no
`OCI-Subject` header. It accepts the fallback tag `sha256-<hex>` holding an OCI
image index of the referrers, so Sigstore bundles
(`application/vnd.dev.sigstore.bundle.v0.3+json`) are published and found
through that tag.

## CI write

GitHub Actions pushes without an OCI user key or auth token:

1. The job (`permissions: id-token: write`) asks GitHub for an OIDC token with
   audience `terrascale-ocir`.
2. It makes an RSA key pair that lives only in the job and exchanges the token
   at the identity domain's `/oauth2/v1/token` (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
   `requested_token_type=urn:oci:token-type:oci-upst`, `subject_token_type=jwt`,
   `public_key=<the public key, DER, base64>`) for a user principal session
   token (UPST) of service user `ts-ci-ocir`.
3. It signs `GET https://<region>.ocir.io/20180419/docker/token` with that key
   and `keyId="ST$<UPST>"`, and runs `docker login <region>.ocir.io -u BEARER_TOKEN`.

The composite action `.github/actions/ocir-login` does all three:

```yaml
permissions:
  contents: read
  id-token: write
steps:
  - uses: TerraScale/ts-orchestrator/.github/actions/ocir-login@main
    with:
      regions: us-sanjose-1 eu-frankfurt-1 sa-saopaulo-1
      domain-url: ${{ vars.OCI_IDENTITY_DOMAIN_URL }}
      client-id: ${{ vars.OCI_TOKEN_EXCHANGE_CLIENT_ID }}
      client-secret: ${{ secrets.OCI_TOKEN_EXCHANGE_CLIENT_SECRET }}
  - run: docker push us-sanjose-1.ocir.io/${{ vars.OCIR_NAMESPACE }}/terrascale/<name>:<tag>
```

Repository settings on `TerraScale/ts-orchestrator` and `TerraScale/terrascale`:

| Name | Kind | Value |
|---|---|---|
| `OCIR_NAMESPACE` | variable | `grxnmoqvrcdv` |
| `OCI_IDENTITY_DOMAIN_URL` | variable | The `Default` identity domain URL |
| `OCI_TOKEN_EXCHANGE_CLIENT_ID` | variable | Client ID of app `ts-ci-ocir-exchange` |
| `OCI_TOKEN_EXCHANGE_CLIENT_SECRET` | secret | Client secret of app `ts-ci-ocir-exchange` |

Identity domain `Default` objects:

| Object | Name | Setting |
|---|---|---|
| Group | `ts-ci-ocir` | Only member `ts-ci-ocir` |
| User | `ts-ci-ocir` | Service user; API keys, auth tokens, console password, customer secret keys, DB, SMTP and OAuth client credentials disabled |
| Confidential app | `ts-ci-ocir-exchange` | Grant `client_credentials` only, no app roles or scopes; authenticates the exchange call |
| Identity propagation trust | `github-actions-ocir` | Type JWT, issuer `https://token.actions.githubusercontent.com`, keys from its `/.well-known/jwks`, `aud` must be `terrascale-ocir`, only client `ts-ci-ocir-exchange`, impersonates `ts-ci-ocir` for the rules below |

Trust rules (both repositories use GitHub's immutable subject form):

```text
sub eq repo:TerraScale@206395477/ts-orchestrator@1422428095:ref:refs/heads/main
sub eq repo:TerraScale@206395477/terrascale@1414527764:ref:refs/heads/main
```

Policy `ts-ci-ocir` in compartment `TerraScale`
(`ocid1.policy.oc1..aaaaaaaa4ukzjj3v2gxm6zw3islz57tfyetfzbib6oixrnkkbrffltaz6sca`):

```text
Allow group 'Default'/'ts-ci-ocir' to manage repos in compartment sjc-1-control
Allow group 'Default'/'ts-ci-ocir' to manage repos in compartment fra-1-control
Allow group 'Default'/'ts-ci-ocir' to manage repos in compartment gru-1-control
```

The identity domain authenticates the token-exchange call only with a
confidential client, so the client secret exists. On its own it grants nothing:
the app has no roles or scopes, and the exchange also needs a GitHub OIDC token
for `main` of one of the two repositories with audience `terrascale-ocir`.
Rotate it with the app's "Generate new secret" action and
`gh secret set OCI_TOKEN_EXCHANGE_CLIENT_SECRET --repo <repo>` from stdin.

## Retention

Keep the last 20 orchestrator releases and every digest a fleet document still
references, in every region. OCIR has no keep-the-last-N retention policy, and
the referenced-digest rule needs the fleet documents, so the release pipeline
prunes (C40): after a successful publish it lists `orchestrator-release`, keeps
the 20 newest releases plus every digest any committed fleet document names, and
deletes the rest. App images follow the same rule in their release pipeline
(C42). Untagged manifests are deleted with their release.

## Cost

OCIR storage is billed as Object Storage, about USD 0.0255 per GB-month at
list price. An orchestrator release is two Linux binaries (amd64 about 100 MB,
arm64 about 92 MB) plus small bundles and the channel document, about 0.2 GB
uncompressed. 20 releases in three repositories (sjc, fra, gru) are about
12 GB. App images with shared layers add an expected 10 to 20 GB across the
three regions. Expected total: 22 to 32 GB, under USD 1 a month. Pulls inside a
region are free. Nothing else is billed: no new compute, network or capacity.

## Proof (2026-11-17)

- Host read, instance principal, from `ts-sjc-1`, `ts-fra-1` and `ts-gru-1`:
  docker token 200 (`expires_in` 3600), `GET /v2/grxnmoqvrcdv/terrascale/orchestrator-release/tags/list`
  and `.../terrascale/terrabase/tags/list` 200, a 64 MiB layer blob GET 200
  from `<region>.ocir.io` with a matching digest, no `~/.oci` or `/root/.oci`.
- CI write: workflow run
  https://github.com/TerraScale/ts-orchestrator/actions/runs/44125693531 on
  branch `cos/20eaa46e-C41-ocir-infra` (a temporary trust rule for that branch,
  removed afterwards) exchanged its OIDC token, logged in and pushed
  `terrascale/c41-scratch:ci-44125693531`. The scratch repositories were
  deleted afterwards.
