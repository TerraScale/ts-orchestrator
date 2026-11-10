# Read-only production verification (TS-520)

```sh
umask 022
nice -n 19 make build
dist/ts-orch verify --live --region gru --cell gru --terrabase-url https://gru.api.terrascale.tech > verification.md
dist/ts-orch verify --live --region sjc --cell sjc --terrabase-url https://sjc.api.terrascale.tech > verification-sjc.md
dist/ts-orch verify --live --region fra --cell fra --terrabase-url https://fra.api.terrascale.tech > verification-fra.md
```

The live run is explicitly opt-in (`--live` or `TS_VERIFY_LIVE=1`). It prints
a timestamped Markdown result table and exits nonzero for any FAIL or UNKNOWN.
PASS means the individual observation met its contract; UNKNOWN means the
acceptance claim lacks evidence, not that the service passed. Default targets
are production `gru`, `gru.api.terrascale.tech`, `auth.terrascale.tech`,
`dash.terrascale.tech` and `status.terrascale.tech` (observed 2026-11-04:
TerraBase `/healthz` bodies and `X-TerraBase-Region` headers report `gru`,
`sjc` and `fra`; a region value with a `-1` suffix fails the header check).
Every HTTP request has a
10-second deadline, uses GET and refuses redirects. Responses are limited to
1 MiB; reports omit bodies, cookies, tokens and user records.

Use `ts-orch verify --help` for URL, region, cell and timeout overrides.
The controller manifest cell is `gru` (`--cell` / `TS_VERIFY_CELL`). TerraBase
regions in production are the short names `gru`, `sjc` and `fra`; the flag
default is still the legacy `gru-1`, so always pass `--region <gru|sjc|fra>`
(or set `E2E_REGION`) for a passing header check. The command
uses TS-512's `E2E_TERRABASE_URL`, `E2E_AUTH_URL`, `E2E_DASHBOARD_URL`,
`E2E_STATUS_URL` and `E2E_REGION` conventions and its bounded, non-redirecting
HTTP probe approach.
TS-471's live write/restart E2E remains separately authorized work.

| Acceptance item | Evidence required / present limits |
| --- | --- |
| Orchestrator deployed and working | `/healthz`, `/readyz`, current `/v1/snapshot` with schema, controller role, `gru` cell identity and build version. Supply an existing controller observability origin in `TS_VERIFY_ORCHESTRATOR_URL` and its existing token in `TS_VERIFY_ORCHESTRATOR_TOKEN`. No URL/token means UNKNOWN. Private HTTP needs an already available loopback tunnel; remote origins require HTTPS. No tunnel, login or token is created by the verifier. |
| Orchestrator deployed healthy TerraBase | `/healthz` verifies `status=ok`, version, body region and `X-TerraBase-Region`. It does not prove orchestrator deployment or storage readiness. The combined claim stays UNKNOWN until current signed host deployment and passive readiness evidence are available (TS-484/485/524). |
| ts-auth persists in TerraBase | `/healthz` proves versioned liveness only. Durable state/active backend remain UNKNOWN pending passive store evidence (TS-489/525). |
| Dashboard persists in TerraBase | `/health/live` and `/health/ready` report `status`, `region` and (readiness) dependency names, but no `version` field, so the verifier's versioned-health contract FAILs; treat this as a documented contract gap, not a dashboard outage. Persistence remains UNKNOWN pending passive backend and existing-record evidence (TS-472/492/526). |
| TerraBase authenticates Management/user calls through ts-auth | Discovery must name the configured ts-auth issuer; JWKS must use the same origin and a reviewed `/.well-known/jwks`, `/.well-known/jwks.json` or `/connect/jwks` route. The platform issuer is `https://auth.terrascale.tech/terrascale`; its discovery and JWKS answer 200. The root-path discovery `https://auth.terrascale.tech/.well-known/openid-configuration` also answers, but its `jwks_uri` points at the root JWKS route, which currently answers HTTP 500 (OpenIddict serves JWKS only under a tenant slug), so the verifier's OIDC row FAILs until that is fixed or discovery stops advertising the root route. Retrieval alone cannot prove TerraBase validates JWTs. All Management GETs are skipped because `ListOrganizationsAsync` calls `EnsureCatalogAsync`, which initializes/migrates catalog documents. JWT acceptance remains UNKNOWN pending a guaranteed passive authenticated route (TS-519/527); no valid, absent or invalid credential probe can reach this handler through the verifier. Existing JWT/service credentials are never sent. |

## Readiness endpoints with write side effects

Source inspection found that TerraBase's `/readyz` calls
`SqliteStorageEngine.IsReadyAsync`, which creates/deletes a `.ready.*.probe`
file. ts-auth's `/readyz` calls `TerraBaseStorageHealth.CheckAsync`, which
creates, reads and conditionally deletes a synthetic health document. The
verifier deliberately never requests either endpoint. GET alone does not
guarantee passive behavior. Management reads can also initialize/migrate the
catalog through `EngineManagementService.ReadAsync` / `EnsureCatalogAsync`.
The verifier never calls those routes, even with absent/invalid credentials:
an authentication bypass could otherwise allow a write. New gaps TS-524 and
TS-525 cover read-only readiness observations; TS-526 covers dashboard store
evidence; TS-527 covers passive JWT acceptance evidence. No gap fixes or live
deployment actions are part of TS-520.

The status site's `/api/v1/status` is a supporting observation, not evidence
of any deployment, authentication or persistence claim. Its reported overall
status and generation timestamp are included separately. PASS on the Status
API response means the API answered with its schema, even during an outage;
it does not qualify any component. Similarly, retrieving a nonempty JWKS
alone does not establish usable signing keys or successful authentication.

## Pinned-versus-running audit (2026-11-04)

The pin for every mesh service is the `app-digests` branch's
`deploy/m1/app-digests.json` (written by `app-digests.yml` from
`ts.release.mesh.state`; nightly and after App release canary runs, so
it can lag the hosts by hours); the
`deploy/m1/services/*.json` images in this repository are only the
first-application specs and do not track releases. The ts-orch pin is
this repository's `main`: the `ci.yml` `release-push` job pushes every
published build to all `deploy/m1/regions.json` regions and retains the
per-region JSONL result (`release-push-<sha>-<run>` artifact, state
`installed` plus `serving_ms`).

Auditing what a region actually runs needs no write path:

- The region's ts-orch revision: `ts.release.version` on the pinned 4222
  release listener answers `{"version": "<vcs.revision>"}`; `ts-orch
  release push` reads exactly this to prove serving. A read of it needs
  a GitHub OIDC token minted by a qualifying workflow (`id-token:
  write`), so an operator without a CI job cannot poll it from a laptop;
  treat the newest `release-push` artifact as the pinned evidence.
- The dashboard revision: `GET https://dash.terrascale.tech/readyz`
  returns `X-TerraScale-Revision` (the image's `SourceRevisionId`),
  checked per release by the monorepo's
  `scripts/dashboard/verify-live.py` directly against the origin.
- TerraBase, ts-auth and MCP expose only `version` strings on `/healthz`
  (`0.1.0`, `0.1.0-alpha.ttd.3`), not image digests; per-region running
  digests for them are not exposed by any read-only command today
  (`ts-orch inspect digests --region <r>` is the proposed gap filler;
  the mesh's `ts.svc.state` carries each region's desired image but its
  loopback listener and the CI-only `ts.release.mesh.state` both sit
  behind credentials an operator does not hold).

Measured 2026-11-04 23:28Z and re-checked 23:58Z (no change between
rounds): all three regions reported TerraBase `0.1.0` with matching
`X-TerraBase-Region`/`X-TerraBase-Machine`, controllers answered
`/healthz` and `/readyz` on 9463 over NetBird, the dashboard served
`X-TerraScale-Revision` equal to the newest released qualified main
commit, and the newest ts-orch push had reached every region within
~11 s of serving. Atlas discovery (`atlas.terrascale.tech`) answered
NXDOMAIN during the audit, so `ts-orch release fleet-status` could not
enumerate regions then; discovery now reads each cell's head-bucket release
status instead (Nov 2026).

## Offline checks

```sh
umask 022
nice -n 19 make lint build
```

The first
production result and gap mapping are retained in the TS-520 PR body.
