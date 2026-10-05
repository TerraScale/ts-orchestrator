# Read-only production verification (TS-520)

```sh
umask 022
nice -n 19 make build
dist/ts-orch verify --live > verification.md
```

The live run is explicitly opt-in (`--live` or `TS_VERIFY_LIVE=1`). It prints
a timestamped Markdown result table and exits nonzero for any FAIL or UNKNOWN.
PASS means the individual observation met its contract; UNKNOWN means the
acceptance claim lacks evidence, not that the service passed. Default targets
are production `gru-1`, `gru.api.terrascale.tech`, `auth.terrascale.tech`,
`dash.terrascale.tech` and `status.terrascale.tech`. Every HTTP request has a
10-second deadline, uses GET and refuses redirects. Responses are limited to
1 MiB; reports omit bodies, cookies, tokens and user records.

Use `ts-orch verify --help` for URL, region, cell and timeout overrides.
The controller manifest cell is `gru` (`--cell` / `TS_VERIFY_CELL`), distinct
from TerraBase's `gru-1` region. The command
uses TS-512's `E2E_TERRABASE_URL`, `E2E_AUTH_URL`, `E2E_DASHBOARD_URL`,
`E2E_STATUS_URL` and `E2E_REGION` conventions and its bounded, non-redirecting
HTTP probe approach. The independent `e2e/` module cannot be imported by the
single-binary operational CLI. Its full production scenario runner creates
projects/documents and must **not** be called for this read-only verification.
TS-471's live write/restart E2E remains separately authorized work.

| Acceptance item | Evidence required / present limits |
| --- | --- |
| Orchestrator deployed and working | `/healthz`, `/readyz`, current `/v1/snapshot` with schema, controller role, `gru` cell identity and build version. Supply an existing controller observability origin in `TS_VERIFY_ORCHESTRATOR_URL` and its existing token in `TS_VERIFY_ORCHESTRATOR_TOKEN`. No URL/token means UNKNOWN. Private HTTP needs an already available loopback tunnel; remote origins require HTTPS. No tunnel, login or token is created by the verifier. |
| Orchestrator deployed healthy TerraBase | `/healthz` verifies `status=ok`, version, body region and `X-TerraBase-Region`. It does not prove orchestrator deployment or storage readiness. The combined claim stays UNKNOWN until current signed host deployment and passive readiness evidence are available (TS-484/485/524). |
| ts-auth persists in TerraBase | `/healthz` proves versioned liveness only. Durable state/active backend remain UNKNOWN pending passive store evidence (TS-489/525). |
| Dashboard persists in TerraBase | `/health/live` and `/health/ready` prove versioned process/store-presence observations. A non-nil memory store also passes readiness; persistence remains UNKNOWN pending passive backend and existing-record evidence (TS-472/492/526). |
| TerraBase authenticates Management/user calls through ts-auth | Discovery must name the configured ts-auth issuer; JWKS must use the same origin and a reviewed `/.well-known/jwks`, `/.well-known/jwks.json` or `/connect/jwks` route. Retrieval alone cannot prove TerraBase validates JWTs. All Management GETs are skipped because `ListOrganizationsAsync` calls `EnsureCatalogAsync`, which initializes/migrates catalog documents. JWT acceptance remains UNKNOWN pending a guaranteed passive authenticated route (TS-519/527); no valid, absent or invalid credential probe can reach this handler through the verifier. Existing JWT/service credentials are never sent. |

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

## Offline checks

```sh
umask 022
nice -n 19 mise exec -- go test -race ./internal/liveverify ./internal/cli
nice -n 19 make verify shellcheck fixturetest-check build
```

Tests use `httptest`, including malicious discovery URLs that would reach
writing readiness/Management routes if accepted. They never run the live
verifier implicitly or contact production. The first
production result and gap mapping are retained in the TS-520 PR body.
