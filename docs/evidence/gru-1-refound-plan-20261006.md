# TS-550 gru-1 re-found plan, 2026-10-06

**Approved by the user (via COS), not yet executed.** gru-1 is re-founded once
on the new self-updating image: `gru-1-ctl-1..3` and `gru-1-db-1..2` are
terminated (boot volumes included) and relaunched under a new deployment ID
with fresh material. Expect about one hour of `gru.api` downtime. ts-ops,
ts-forgejo, the `gru-1-api` load balancer, DNS, buckets and unrelated Vault
secrets are not touched.

## Why a re-found

The [rollout evidence](gru-1-live-rollout-20261005.md#controller-rebuild-what-blocks-it-2026-10-06)
lists the blockers. Summary:

- The current material expires **2026-10-12T16:58:11Z** for every server, and
  nothing rotates it. Fresh material lasts 30 days, the maximum
  (`bootstrapmaterial.MaxValidity`). In-place controller material rotation is
  still open; TS-558 (#185) rotates root keys, not this material.
- The same deployment cannot be founded twice. The ledger records of
  `ts-470-gru-rebuild-2` are retained (35-day retention rule); #179 lets the new
  deployment found beside them.
- Fresh material and a new image break the db hosts' enrollment: their
  launch metadata pins the old CA, response key and cell account, and their
  boot image must equal `oci-region.json` `image_id`. They are relaunched
  too. gru-1 has no data volumes: TerraBase writes to the boot disk, and
  `gru-1-db-1` holds only an empty `_system.db` (132 KB, no tenants).

## Inputs

On mariogk-dev, in `~/.local/state/ts550-refound/` (0700):

| Input | Value |
|---|---|
| `attempt.template.json` | TS-470's attempt with `deployment_id` `ts-550-gru-refound-3`, `prefix` `gru-1`, `validity_days` 30, a new workdir, and the TS-470 trust keys (root and release leaf, also in Vault as `gru-1-trust-*`). `orchestrator.source_revision` is `main` with #190, and its `ci.yml` run. |
| `base_plan` | [TS-486 public-edge bound plan](gru-1-public-edge-20261005/bound-plan.json) |
| `operator_grant` | `{"actor":"mariogk",…,"roles":["terrabase","ts-auth"],"environments":["canary"],"can_register_hosts":true,"can_roll_out_orchestrator":true}` |
| `terrabase_profile` | the TS-470 base profile (region, ports, `TERRABASE_PEERS`) |
| `kv_snapshot` | `{"enabled":true,"region":"sa-saopaulo-1","namespace":"grxnmoqvrcdv","bucket":"gru-1-head","prefix":"kv-snapshot/v1","interval_seconds":30}` (#190) |
| `terrabase` | `ci-b9d16432d0d7260c1711d55d3187b14ce130de90-run-13722` |

Only boot-time settings go into the signed controller configs. The cell spec
(TS-556) carries the rest as generation 1, root-signed because each item
widens authority:

- `terrabase`: the committed profile's additions,
  `TERRABASE_MANAGEMENT_CREDENTIAL_FILE`, `TERRABASE_AUTH_ISSUER`
  `https://gru.auth.terrascale.tech/terrascale` and `TERRABASE_AUTH_AUDIENCE`
  `https://gru.api.terrascale.tech`.
- `ts-auth`: the committed profile with its six Vault secret refs (TS-554)
  and the committed service (2 stateless replicas, `canary`).
- Host grants for `gru-1-ctl-1..3` (`10.251.0.11-13`, role `ts-auth`).

The ts-auth profile must not set `TS_AUTH_LISTEN`. The host agent starts every
replica with `TS_AUTH_LISTEN=http://0.0.0.0:8080`, the port the load balancer's
`ts-auth` backend set checks on `10.251.0.11-13`.

`controller.rollouts.executor` stays off: production controllers refuse it
until the root step agent ships (`internal/app/rollout_control.go:80`).

Created ahead of the re-found (names and OCIDs only):

| Secret | Compartment | OCID |
|---|---|---|
| `gru-1-ts-auth-master-key` | `gru-1-control` | `…cghg6ut6xoobvrq` |
| `gru-1-ts-auth-audit-signing-key` | `gru-1-control` | `…qnm2x4z7rf6qghq` |
| `gru-1-ts-auth-operator-key` | `gru-1-control` | `…xgfkzwv5d6rq` |
| `gru-1-ts-auth-dashboard-client-secret` | `gru-1-control` | `…a7r5xwesuqxafxa` |
| `gru-1-terrabase-management-credential` | `TerraScale` | `…knz6e3jd7jua` |

## Steps

`A` is `ts-orch oci-region attempt --config ~/.local/state/ts550-refound/attempt.json`.
NATS is reached with `--nats-forward 10.251.0.1N:4222=127.0.0.1:1422M` over the
OpenSSH forward through `ts-ops` (`14221`-`14223` to `gru-1-ctl-1..3`).

| # | Step | Kind |
|---|---|---|
| 0 | Fill the template. `$A plan`: inventory, phase-2 plan and cost against the $200 ceiling. | read-only |
| 1 | `$A material`: fresh material and its Vault secrets under the new deployment's names; the controller IAM policy gains the `kv-snapshot/v1/*` grant. | OCI create, policy update |
| 2 | `$A release`: verify the orchestrator release against the root. | local |
| 3 | Rename `gru-1-arm64` (`…oq455rr5lhfa`) to `gru-1-arm64-555876d8`, then `$A image` imports the new `gru-1-arm64`. | OCI update, create |
| 4 | `$A sign`: controller configs and founder plan. | local |
| 5 | **Terminate `gru-1-ctl-1..3` and `gru-1-db-1..2`**, `--preserve-boot-volume false`. | **destructive** |
| 6 | `$A launch`, `$A complete`, `$A continuity`, `$A operator`: three healthy controllers, JetStream meta size 3. | OCI create |
| 7 | Root-signed cell spec generation 1 (above): `ts-orch diff`, `release sign-spec --root`, `ts-orch apply`. | signed spec |
| 8 | `$A members`: both db hosts on the new image; they enroll. Write the management credential to `/etc/terrascale-orchestrator/terrabase-management-credential` (`root:terrascale-workload` 0640) on each. | OCI create, file |
| 9 | `operator terrabase-release` of `b9d16432` with the extended profile. `ts-orch oci-region public-api apply --member-ca <new CA>` updates the `terrabase` backend set's CA. Verify `gru.api`. | in place, LB update |
| 10 | Verify the KV snapshot objects under `gru-1-head/kv-snapshot/v1/gru/`. | read-only |
| 11 | Self-update round trip on one controller with a leaf-signed later `main` build: the watchdog confirms, a restart passes admission (TS-552), then roll back to the image build. | in place |
| 12 | Delete the old image `…oq455rr5lhfa` once all five servers boot the new one. | **destructive** (approved) |
| 13 | TS-550 steps 2 to 6. | |

## Still open

- **Egress.** The private subnet has no internet route. ts-auth calls
  `https://gru.api.terrascale.tech`, and TerraBase fetches ts-auth's keys from
  `https://gru.auth.terrascale.tech/terrascale`. Neither is reachable from the
  cell (checked from gru-1-ctl-1 and gru-1-db-1). Proposed: an opt-in NAT
  gateway route with security-list egress limited to Cloudflare's IPv4
  ranges on TCP 443. That needs a plan-code change and approval.
- **`/` to `/scalar/` on `gru.api`.** The ts-atlas Worker's exact route
  `https://gru.api.terrascale.tech/` answers the bare root. That needs a
  ts-atlas deploy or a route change, and neither is authorized.
- **NetBird.** The relaunched servers enroll under the same names. Pruning
  the stale `gru-1-*` peers is a deletion and is listed for approval.
