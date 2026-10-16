# Cross-project E2E (TS-512)

GitHub migration status (2026-10-16): `TerraScale/terrabase`,
`TerraScale/ts-auth` and `TerraScale/ts-libs` are not available through the
current GitHub account (API returns 404). Fresh qualified service inputs and
full E2E runs remain blocked until those repositories, pinned commits and
release assets are available on GitHub. Commands below describe the target
GitHub flow; they do not establish a successful deployment. Historical
Forgejo evidence and signed records remain historical and must not be relabeled.

For read-only production observations, use
[`ts-orch verify --live` (TS-520)](live-verification.md). It reports missing
deployment/persistence evidence as UNKNOWN and does not run the mutating
production scenarios below.

The independent `e2e/` Go module runs one scenario registry against local or
production endpoints. It never imports the orchestrator module, changes cloud
resources, or uses fake TerraBase responses. Management and document operations
use `terrascale.tech/sdk/v1`; HTTP is limited to readiness/status probes and local
admin key bootstrap, which the SDK does not expose.

## Run locally

Linux amd64, Go 1.27.1, the .NET 10 SDK, Git, Node/npm and network access are
required. The first run downloads pinned source and artifacts and builds auth
and dashboard; allow 10–20 minutes. Subsequent runs still rebuild the pinned services; allow 5–10 minutes.
The suite owns temporary data, certificates, credentials and child processes.

```sh
cd e2e
# Set TERRABASE_TOKEN and E2E_GITHUB_TOKEN in your environment if GitHub
# requires read credentials. These are read-only artifact/source credentials.
nice -n 19 go test -race ./...
nice -n 19 go vet ./...
nice -n 19 go build ./...
E2E_TARGET=local nice -n 19 go run .
```

`E2E_TARGET` defaults to `local`. `E2E_REPORT` defaults to `report.json` in the
current directory. The JSON includes each scenario's components, tickets,
status (`pass`, `pending`, `fail`), detail and duration. The readable summary
prints `PENDING(ticket)` for unshipped features. Only failures cause exit 1;
pending work is never counted as passed. Artifact corruption, missing tools,
build errors and unexpected runtime errors are failures, not pending features.

## Current coverage and release gaps

The shipped Management and document APIs create an organization, project and
database, bootstrap a scoped `tb_` key, and exercise document create, read, put,
patch, delete, list, query, transaction commit and rollback. Successful document
responses must carry the expected `X-TerraBase-Region`. The client `/readyz`
route shipped in terrabase#16/TS-483 and must return 200; a missing route or
unready server fails the suite.
Local TerraBase runs with TLS, a dashboard credential file and
`TERRABASE_REGION=local-1`. SDK calls resolve the endpoint through a
`StaticResolver`; no SDK client default hardcodes a production region.

| Scenario | Missing feature reported as pending |
| --- | --- |
| Shape read | TS-481: the pinned SDK lacks a shape method and its TerraBase OpenAPI lacks this route |
| Auth signup, code + PKCE, tokens, userinfo | TS-489, TS-490, TS-491 |
| Dashboard sign-in, Management API provisioning and restart persistence | TS-472, TS-492 |
| Atlas discovery, session pin and wrong-pin 421 | TS-496 |
| Ouroboros: both services' durable state in `terrascale` | TS-472, TS-489, TS-492 |

The pinned dashboard refuses live configuration because it only wires a seeded
demo store. The suite builds and launches its real executable with live
configuration and records that known rejection; it never enables demo mode.
The auth pin wires an unavailable storage health probe: the suite contacts its
real readiness endpoint and reports the known 503 as pending. An unexpected
response or connection failure still fails. Local status-page coverage is
explicitly pending TS-512 because ts-status is not an artifact in this local
stack; production checks its configured status URL.

These results do not claim the pending cross-project journeys already work.
Bump the producer pins and implement the pending scenarios as their features
ship. A pending result is an outstanding acceptance item, not qualification for
production release.

## Production (TS-471)

Production execution belongs to TS-470 after COS relays user approval. This
change prepares the runner and manual workflow; development verification does
not execute production mutations. Configure a dedicated organization named
**`terrascale-e2e`** and a user who owns it. The runner checks that organization
through Management before creating anything. It creates uniquely named projects
and removes its databases and projects in reverse order, including after errors,
with independent cleanup deadlines. It never deletes the shared organization or
its pre-provisioned key. Cleanup failures fail the run.

Required environment:

```sh
export E2E_TARGET=prod
export E2E_MANAGEMENT_CREDENTIAL=… # dashboard service credential
export E2E_USER_ID=…               # dedicated authenticated test user id
export E2E_ORGANIZATION_ID=…       # terrascale-e2e organization id
export E2E_API_KEY=…               # existing org-scoped tb_ read/write key
export E2E_DASHBOARD_URL=https://…
# After TS-470 approval:
nice -n 19 go run .
```

Optional static overrides: `E2E_TERRABASE_URL` (default
`https://gru.api.terrascale.tech`), `E2E_AUTH_URL` (default
`https://gru.auth.terrascale.tech`), `E2E_STATUS_URL` (default
`https://status.terrascale.tech`), and `E2E_REGION` (default `gru-1`). These
are harness settings passed to the resolver. Production endpoints require HTTPS
origins and redirects are refused. No secret values are written intentionally
into the report. Production key issuance is explicitly `PENDING(TS-481)` until
a public SDK/key-management contract ships. The suite uses the dedicated
existing org key rather than opening the admin listener remotely. Failed cleanup identifies the failed SDK resource operation;
inspect the dedicated organization before retrying if a request outcome was lost.

## CI

`.github/workflows/e2e.yml` runs the local target for PRs touching `e2e/`,
nightly at 03:00 UTC, and manual dispatch with `target=local` (default).
A separate job runs production only on manual dispatch with `target=prod`.
Both retain the JSON report even on failure. CI uses normal CPU priority.
Artifact/source access uses existing read credentials; production credentials
come from repository secrets. No secret or infrastructure changes are made by
this suite. Fork PRs without read credentials fail clearly if artifacts are not
publicly accessible.

## Add a scenario

1. Add one entry to `scenarios()` in `e2e/scenarios.go`, tagging components and tickets.
2. Use ts-go for supported application APIs; assert returned state, not just HTTP success.
3. Register cleanup immediately after each successful creation, using fresh bounded contexts.
4. Return `pending{ticket, reason}` only for a documented feature missing from the pinned producer.
5. Add the smallest runnable regression check, then run the module checks and local suite.

Keep probes and bootstrap distinct from application operations. An unsupported
feature must have its own report entry so shipped checks still run. Never turn a
missing credential, corrupt artifact, timeout or assertion failure into pending.

## Bump pins

`e2e/pins.json` records artifact versions/checksums and source commits, including
auth's ts-dotnet/ts-libs dependencies. Select a published real TerraBase release,
verify its `.sha256` against the artifact, update the matching version and digest,
and run local E2E. The current main prerelease is
`ci-27611cb984ccaaf8b37faea9a34a192a2e45b76a-run-16211`. Source pins are
complete commit hashes, never moving branches.
Switch auth from pinned source to the TS-488 release artifact once available.

The SDK is pinned in `e2e/go.mod` to the merged `main` commit
`f8f51d8a46c695734c502536dad5e31b968b994f`, pseudo-version
`v0.0.0-20261009173424-f8f51d8a46c6`. It uses the current
`/documents/by-key?id=…` point route and exposes project-key revocation,
which cleanup requires before project deletion. The local backend starts with
`--management-credential-file` and a 256 MiB memory budget. Service-credential
Management requests use its loopback admin listener. Its vanity path is not published, so a
GitHub replacement fetches that same commit. Update both version references
and run `go mod tidy` when bumping. Replace the pseudo-version with the release
tag once the SDK release is published. Review newly shipped features and replace
their pending entry with a real assertion in the same change; rerun local E2E
before committing.

`E2E_CACHE` selects the artifact and bare-source cache (default
`~/.cache/terrascale/e2e`). `E2E_TERRABASE_BINARY` accepts a previously downloaded
artifact only when its SHA-256 matches the pin; the installer copies it into
its owned cache and sets executable permissions without changing the original.
Cached source inputs use Git commit identities, and every run builds a fresh
checkout. Corrupt artifacts fail rather than being overwritten silently.
On machines with a tool wrapper that intercepts `dotnet`, put the actual .NET
SDK's `dotnet` on `PATH`: its pinned `global.json` allows installed 10.0.x patch
updates. The suite does not relax producer toolchain requirements.
