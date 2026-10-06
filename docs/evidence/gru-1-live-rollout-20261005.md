# TS-550 gru-1 live rollout, 2026-10-05

Live run from mariogk-dev under the standing non-destructive gru-1
authorization. The operator reached the controllers' NATS (4222) with
`operator --nats-forward` over local forwards: 127.0.0.1:14222 and :14223
were an existing OpenSSH forward through `ts-ops` left from TS-470 (to
`10.251.0.12` and `.13`), and :14224 a NetBird SSH forward on the TS-547
automation peer (`ts-orch netbird ssh -- -L 127.0.0.1:14224:10.251.0.13:4222
root@gru-1-ctl-1.nb.ts.internal`). Member checks used NetBird SSH. No secret,
token or device code appears here.

## Step 1: TerraBase main to gru-1

Release `ci-b9d16432d0d7260c1711d55d3187b14ce130de90-run-13722` (TerraBase
`main` `b9d1643`, TS-473; it includes TS-519, TS-535, TS-539, TS-464 and
TS-521). `terrabase-linux-arm64` SHA-256
`7da6542c242429e127975d4286d40c6ec4c666fbef6b655e48b96fdfb7025704`,
`sha256sum -c` OK. Operator CLI: the cell's qualified
`terrascale-orchestrator` `555876d8`; profile: the signed
`terrabase-gru-1-profile.json`.

```text
$ sudo terrascale-orchestrator operator terrabase-release --config /var/lib/terrascale-operator/operator.json \
    --nats-forward 10.251.0.11:4222=127.0.0.1:14222 --nats-forward 10.251.0.12:4222=127.0.0.1:14223 \
    --nats-forward 10.251.0.13:4222=127.0.0.1:14224 --binary terrabase-linux-arm64 --sha256 terrabase-linux-arm64.sha256 \
    --source-checkout terrabase --commit b9d16432d0d7260c1711d55d3187b14ce130de90 --environment canary \
    --profile terrabase-gru-1-profile.json --wait 10m
{"step":"artifact","digest":"7da6542c…7025704","previous":"9a2f9b5b…82563a1"}
{"step":"deploy","digest":"7da6542c…7025704","generation":5}
{"step":"ready","digest":"7da6542c…7025704","members":2}
exit=0   # 2026-10-05T22:21:48Z
```

The command switches every member at once (per-member rolling waits for
replication); it gates on readiness and would have rolled back to `9a2f9b5b…`.

`operator hosts`, 2026-10-05T22:24Z:

```text
gru-1-db-1  terrabase  running  7da6542c242429e1  generation 5
gru-1-db-2  terrabase  running  7da6542c242429e1  generation 5
```

Each member on its own host (NetBird SSH, `curl -k https://127.0.0.1:9465`):

```text
== gru-1-db-1
healthz 200 {"status":"ok","version":"0.1.0","region":"gru-1"}
readyz 200 {"status":"ready","version":"0.1.0","region":"gru-1"}
root 302 -> /scalar/      openapi 200      scalar 200
== gru-1-db-2
healthz 200 {"status":"ok","version":"0.1.0","region":"gru-1"}
readyz 200 {"status":"ready","version":"0.1.0","region":"gru-1"}
root 302 -> /scalar/      openapi 200      scalar 200
```

Public, through Cloudflare and the `gru-1-api` load balancer (backend
`gru-1-db-1`), 2026-10-05T22:22Z:

```text
200 https://gru.api.terrascale.tech/openapi/v1.json   openapi 3.2.0, "TerraBase API" 0.1.0, 53 paths
200 https://gru.api.terrascale.tech/scalar/
200 https://gru.api.terrascale.tech/healthz, /readyz
302 https://gru.api.terrascale.tech/?q                -> scalar/   (origin)
302 https://gru.api.terrascale.tech/                  -> https://gru.api.terrascale.tech/docs   (ts-atlas Worker)
401 https://gru.api.terrascale.tech/v1/management/organizations   {"error":{"code":"invalid_key"}}
200 https://api.terrascale.tech/openapi/v1.json       (through ts-atlas)
```

The bare root never reaches TerraBase: ts-atlas has the exact route
`https://gru.api.terrascale.tech/` (`wrangler.toml`) and answers it itself.
The deployed Worker redirects to `/docs`; ts-atlas `main` redirects to
`/v1/docs`; TerraBase serves neither (404).

## Blocker for steps 2 to 6, 2026-10-05T23:00Z

The gru-1 controllers cannot take any change to their signed config or binary
while they run:

| Need | Where it lives | Why it cannot change in place |
|---|---|---|
| `TERRABASE_MANAGEMENT_CREDENTIAL_FILE` (phase A, `import-org`) and `TERRABASE_AUTH_ISSUER`/`_AUDIENCE` (ts-auth JWTs) | signed `controller.workloads.terrabase` | The planner refuses a release whose profile digest differs from it; the host passes only that env (`internal/host/terrabase.go:305`). |
| Release and host-registration grant for role `ts-auth` | signed `controller.trusted_signers` (`mariogk`: `terrabase`, `canary`) | `authorizeArtifact`/`authorizeIntent` and `verifyAndRegister` read only it. |
| TS-546 service sets and #176 (which would carry both) | controller binary | The controllers run the image binary `555876d8`. Two separate pins stop a binary-only self-update. (1) On every `run`, restart admission requires the running binary to equal the image receipt's binary (`internal/bootstrapstart/admission.go:677-678`, `binary.go:24-38`, via `internal/app/bootstrap_controller.go`), so a self-updated controller refuses to start and the watchdog rolls it back. (2) The signed config has no `self_update_proof_file`, so no activation is ever confirmed (`internal/selfupdate/decisions.go:70`). Adding the proof file alone fixes nothing while (1) holds. TS-552 fixes (1); TS-553 fixes (2) in the image. |
| NATS/TLS credentials for a host agent on the controllers (ts-auth replicas) | controller enrollment endpoint | Only TerraBase members (`<cell>-db-<n>` in `TERRABASE_PEERS`) and managed placement hosts can enroll. `operator host-register` issues no credential. |

The TerraBase main release was not affected: it used the signed profile
unchanged. Nothing was changed while investigating.

## TerraBase backend set stays `gru-1-db-1` only

The `gru-1-api` backend set `terrabase` lists only `10.251.0.21:9465`, from
the plan's `public_api.terrabase_members: ["gru-1-db-1"]` (TS-486). That is
still correct after this rollout, so `gru-1-db-2` was not added:

- The signed profile has no `TERRABASE_PEER_ADDRESSES`, so the members send no
  changes to each other.
- Even with it, TerraBase `main` replicates only client database documents:
  "Management catalog and API-key data remain local … peer replication does
  not create or rename organizations, projects or their registered databases"
  (`terrabase/docs/replication.md`).
- TS-529 phase A creates the `terrascale` organization, both projects and both
  API keys on `gru-1-db-1` only. Behind a two-member backend set, about half of
  the ts-auth and dashboard requests would reach `gru-1-db-2` and fail with an
  unknown key or project.

`gru-1-db-2` joins `public_api.terrabase_members` (then `ts-orch oci-region
public-api apply`) once `TERRABASE_PEER_ADDRESSES` is in the profile and the
catalog and keys exist on every member.

## Controller rebuild: what blocks it, 2026-10-06

Checked against `main` `b64277df` (TS-546, #176, #177 merged) and the TS-470
attempt state. Read-only; nothing changed on gru-1.

| # | Finding | Evidence |
|---|---|---|
| F | **The cell expires 2026-10-12T16:58:11Z.** The controller CA (`CN=TerraScale gru controller CA`), controller certificates, host TLS issuer and NATS JWT chain all come from material issued 2026-10-05T17:07Z with `validity_days` 7. Material is capped at 30 days and has no rotation path. Host TLS certificates renew every 48 h but cannot outlive the CA. | `openssl x509 -enddate` of the db hosts' bundle `ca_pem`; `bootstrapmaterial/material.go:46,340` |
| A | A new controller image conflicts with the db hosts' image pin. Controllers require `oci-region.json` `image_id` to equal their own image, and static db enrollment requires the db boot image to equal that same `image_id`. | `app/managed_image.go:200-203`, `oci/sdk.go:175-181` |
| B | The same deployment ID cannot be founded twice: ledger objects are create-only and only attempt 1 is admitted. A new deployment ID cannot reuse the material record, which binds its deployment ID. | `bootstrap/ledger_head.go:237`, `attempt/attempt.go:865-871`, `bootstrap/cli/render_controller_config.go:175` |
| C | The attempt imports the image under the fixed name `gru-1-arm64` and refuses an existing image of that name with other contents. | `attempt/attempt.go:623-625`, `ociregion/imageimport/import.go:546` |
| D | After the relaunch, db hosts cannot re-enroll on their own: `host-setup` sends a renewal, and the controller refuses a renewal without a grant (409), with no fallback to enrollment. TerraBase stops when its host session lapses (30 s). | `app/host_enrollment_static.go:79-83`, `app/host_setup.go:128-134`, `host/agent.go:657-666` |
| E | The cell cannot reach `gru.api` or `gru.auth`: no internet route. ts-auth needs TerraBase at `https://gru.api.terrascale.tech`, and TerraBase fetches ts-auth's keys from `https://gru.auth.terrascale.tech/terrascale`. | `curl` from gru-1-ctl-1 and gru-1-db-1 (no connection); `docs/region-bootstrap.md:356` |

F means the db hosts cannot stay untouched past 2026-10-12. Their launch
metadata pins the current CA, response key and cell account, so after that
date they need either new controller material (an updated enrollment bundle
or a relaunch) or a material rotation feature.
