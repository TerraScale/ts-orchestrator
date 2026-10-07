# TS-651 role NATS identity on gru-1, 2026-10-07

Every gru-1 TerraBase member (`gru-1-ctl-1..3`) holds its own NATS identity
from ts-orch and reaches its lease bucket with it. Delivered live under the
ticket's pre-approval, each cell change coordinated with TS-632. No secret,
seed or key appears here: keys are public NKeys, files are named by path.

## Outcome (verified 14:05Z to 14:18Z)

| Check, on each of ctl-1, ctl-2, ctl-3 | Result |
|---|---|
| Host agent and controller binary | `8a3b738b…` (main `712215a3`, includes #277) |
| `/srv/ts-managed/roles`, `…/roles/terrabase` | `root:terrascale-workload 0750` |
| `nats.creds`, `nats.key`, `nats.pem`, `nats-ca.pem` | `terrascale-workload` `0600`; readable by uid 2000, not by `nobody` |
| Client certificate | `CN=terrabase.gru-1-ctl-N`, URI `spiffe://hosts.gru.terrascale.internal/roles/terrabase/gru-1-ctl-N`, 48 h (ctl-1 to 2026-10-09T14:05:52Z) |
| User JWT | name `terrabase@gru-1-ctl-N`, issuer role signer `AA7I262SSTF4BDME3BLGV3RT33ZDC24XRG5H7U5MQ5QTEBJUJDKUXH3A`, tags `role:terrabase`, `kv:terrabase_backup_leases` |
| Member environment | `TERRABASE_NATS_{URL,CREDENTIALS_FILE,CERTIFICATE,PRIVATE_KEY,CA}` set at its start |
| Bucket `terrabase_backup_leases` (created by the leader) | memory, R3, max age 15 s, direct get |
| As uid 2000, with the member's own files, TLS-first to its controller's 4222 | create, update, get, delete pass (revisions 7, 10, 13) |
| Same user binds `TS_HOST_STATE` / publishes `ts.orch.v1.gru.placement.apply` | refused: permissions violation, both |
| TerraBase pid before and after the probe | unchanged (ctl-1 1280, ctl-3 1403, ctl-2 1111) |

The probe was a throwaway nats.go client (not committed) dialing TLS first,
as `natscell/tls_dialer.go` does.

## Steps

1. **Spec generation 4** (root-signed, sha256 `be39a98f…509e`): `mariogk`
   gets `can_rotate_broker_account`; `ci-release`, services, host grants and
   `release_fence` are unchanged. Planned 3 → 4 with only that signer.
2. **Role claim**: `ts-orch bootstrap role-claim` from the re-found 6
   material (cell account `ADEJPP2WN4X3GIEBHPV7BN7BATK4DGYTVUGMA4EHDXUE2MGM3FEDONNY`;
   the durable claim before was sequence 3, sha256 `c8e9b7fd…e201`, equal to
   the material's `cell.jwt`). Output sha256 `5cb311f9…a542`.
3. **Claim apply**, about 13:05Z, in TS-632's window: `operator
   broker-claim-apply --expected-sequence 3` returned `fenced` (every broker
   acked), durable sequence 139096. The operator's own grant check used a
   copy of `operator.json` with the new capability
   (`/root/ts651/operator-claim.json` on mariogk-dev); the installed one is
   unchanged. After it, every host renewed its session and every role kept
   `running`.
4. **Rollout gen 2** = main `712215a3` (CI run 1492 green; arm64 `8a3b738b`),
   `rollout publish` at 13:41:50Z. Controllers b, c, a promoted by about 13:58Z.
5. **Host agents**: a host agent on a controller VM shares the controller's
   release root and runs it from its next restart, so the rollout left them
   on 9debb9b7 (`dfc2ff7a`). `ts-orch node reboot` moved each, leader last:

   | Node | Act | Done |
   |---|---|---|
   | gru-1-ctl-1 | 14:04:39Z | 14:07:10Z |
   | gru-1-ctl-3 | 14:10:31Z | 14:12:52Z |
   | gru-1-ctl-2 (leader, epoch 14) | 14:15:04Z | 14:17:04Z; ctl-3 leads at epoch 15 |

   The first live reboot of the leader resumed on the new leader.

## Availability

`gru.api` and `gru.auth` `/readyz`, every 2 s:

| Window | OK | Failed |
|---|---|---|
| Rollout, 13:41 to 13:58Z | 850 | 0 |
| Reboots, 14:02:50 to 14:17Z | 838 | 2 |

The two failures are `gru.auth` 503 at 14:04:44Z and 14:06:00Z. ctl-1 is
TerraBase's catalog primary: while it restarted, the other members' catalog
streams reconnected and ts-auth's readiness briefly failed on nodes still in
rotation. That is a ts-auth/TerraBase coupling, recorded by TS-632, not a
fence gap. `gru.api` had none.

## Findings

- **The client port is TLS first.** ts-orch's broker bridge completes mutual
  TLS before any NATS byte, then says `tls_required=false`. TerraBase used
  NATS.Net `TlsMode.Require` and would never have connected; terrabase #60
  switches it to `TlsMode.Implicit` (TS-633). Documented in
  `docs/terrabase-runtime-contract.md`.
- **Direct get may lag right after a write.** One probe read a key it had
  just written as missing from an R3 follower; the next read found it.
  TerraBase's lease CAS retries every 5 s.
- **Main CI is flaky under load.** #277's own push run 1489 failed
  `TestReleaseChannelRollsCIReleasesOutRegionByRegion` (103 s on CI, 26 s
  locally with race); run 1482 before it failed three other integration
  tests. The next main build passed.

## Not yet live

- **Secret files.** `gru-1-terrabase-backup-secret-key` and
  `gru-1-terrabase-backup-kms-private-key` exist in the Vault. They reach the
  members once the terrabase profile names them as
  `TERRABASE_BACKUP_SECRET_KEY_FILE` and
  `TERRABASE_BACKUP_KMS_PRIVATE_KEY_FILE`, together with the rest of the
  `backup-*` settings (TerraBase refuses a partial set). That is TS-633's
  rollout slice; check the two files on each member after its release.
- **sfo-1.** Same code; its cell account needs its own `role-claim` and
  apply.
