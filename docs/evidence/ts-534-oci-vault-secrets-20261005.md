# TS-534 OpenBao to OCI Vault migration, 2026-10-05

TerraScale's secrets moved from OpenBao to the gru-1 OCI Vault
(`ocid1.vault.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr7ebplea4ua3memgthsupcfn3crg6d56vipsw7o2butchdrx3urmq`,
master key `…hmfu2ia`). Naming, compartments and commands are in
[secrets](../secrets.md). This record holds names, OCIDs and results only; no
value was printed, logged or written here.

Tool: `ts-orch` built from `41724d50` (`make release-linux`), run as
`ts-orch vault put`, which stores a value once and then reads the current
version back and fails unless it equals the input.

## Secrets

Each was created once (`created: true`), then a second identical run
returned `created: false` and passed the byte-for-byte readback. All are
`ACTIVE`.

| Secret | Compartment | Source | OCID |
| --- | --- | --- | --- |
| `gru-1-trust-root-private-key` | `TerraScale` | mariogk-dev `~/.local/state/ts470-gru-1-phase2/trust/gru-1-root.private.pem` | `…ph5z7eydjldin3bipgwqxoq3foh5cye2ytii5bcyhslq` |
| `gru-1-trust-root-public-key` | `TerraScale` | same directory, `gru-1-root.public.pem` | `…5lwau23l6vcb6nx7e2v6gcb6m4aqvvlalxjgothshtca` |
| `gru-1-trust-release-leaf-private-key` | `TerraScale` | same directory, `gru-1-release-leaf.private.pem` | `…n4gngzr4smkzdwnniqmeulhpibxug7mdtzfxa2xwnyea` |
| `gru-1-trust-release-leaf-public-key` | `TerraScale` | same directory, `gru-1-release-leaf.public.pem` | `…aatot2tu3dphfx45cpuoqw5j7crmyj5dpl6y4ten33bwa` |
| `gru-1-netbird-datastore-encryption-key` | `ts-ops` | OpenBao `external/ts-forgejo-oci/static/netbird` v1 `NETBIRD_DATASTORE_ENCRYPTION_KEY` | `…mtvozh55kwjwpydqcjm6ropkuujmctebz4ekx5okf6oa` |
| `gru-1-netbird-relay-auth-secret` | `ts-ops` | same entry, `NETBIRD_RELAY_AUTH_SECRET` | `…lb6mz4hwvmiudubrrqgdragpr57eku7szwj7sn6u3rba` |
| `gru-1-netbird-session-cookie-encryption-key` | `ts-ops` | same entry, `NETBIRD_SESSION_COOKIE_ENCRYPTION_KEY` | `…5b3xnl5qn5eyufh4f4evmpakw24e3jo4rdnt62vbpzta` |
| `gru-1-netbird-owner-email` | `TerraScale` | OpenBao `infra/netbird/owner` v3 `NETBIRD_OWNER_EMAIL` | `…vl7cd4tow7qst5cna2fs4tscp7dpji7b4wdyvtfwov4a` |
| `gru-1-netbird-owner-password` | `TerraScale` | same entry, `NETBIRD_OWNER_PASSWORD` | `…5xxxl6zumnop2gjiyxokufpcraufgf5iqxg2rnuyxbyq` |
| `gru-1-netbird-automation-user-id` | `TerraScale` | OpenBao `infra/netbird/automation` v2 `NETBIRD_AUTOMATION_USER_ID` | `…iehl4sfnm2xikudgj4rcu2sa57vtd6tsenkoak2wff6a` |
| `gru-1-netbird-automation-pat` | `TerraScale` | same entry, `NETBIRD_AUTOMATION_PAT` | `…dohae2kwzjpghy5bgt2hddmiup5baghkksdpcucsfdca` |
| `gru-1-netbird-automation-pat-id` | `TerraScale` | same entry, `NETBIRD_AUTOMATION_PAT_ID` | `…qyoto7t4i3hlfopggtfwfzwuxipa5mlxhwkkpmxrnfzq` |
| `gru-1-netbird-automation-pat-expires` | `TerraScale` | same entry, `NETBIRD_AUTOMATION_PAT_EXPIRES` | `…sp7tcknvkz33kedikrudfansizfzacxe7u5kxevvfopq` |
| `gru-1-cloudflare-dns-edit-token` | `TerraScale` | OpenBao `infra/cloudflare/terrascale-dns-edit` v1 `CF_API_TOKEN` | `…xiyp5342ukvyfr442rg36bad224topnlredmjepwvo3q` |

OCIDs are `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa` followed by
the suffix shown. OpenBao values were piped from `bao kv get` (read-only
identity) through `jq` into `put` on stdin; they never touched a disk. The
trust key files were read in place on mariogk-dev and left unchanged;
TS-470 keeps signing from them.

## IAM

| Resource | Name | OCID |
| --- | --- | --- |
| Dynamic group | `ts-ops`: `ALL {instance.id = 'ocid1.instance.oc1.sa-saopaulo-1.antxeljrppuhpdqc53olclenle4v5cjyionsslnbelqojmund72yjdppmuna'}` | `ocid1.dynamicgroup.oc1..aaaaaaaa6l7yuyjg7krdpnp3rzhz2zvpuvs563qmqvx5mhqjsliqeld6mb3a` |
| Policy, compartment `ts-ops` | `ts-ops-netbird-manager-secrets`: three `read secret-bundles` statements, one per NetBird manager secret above, by `target.secret.id` | `ocid1.policy.oc1..aaaaaaaaweeu3s6bjp7pynylsnvyql6n4fxnll5cuesvq4jyyavi52haatba` |

Before this change no policy granted any dynamic group secret access in
`TerraScale` or `ts-ops`; the only dynamic-group secret grants are the gru-1
ones in `gru-1-control`.

## Consumers

| Consumer | Check | Result |
| --- | --- | --- |
| NetBird manager on ts-ops | `ts-orch vault render` as root with ts-ops's instance principal into `/root/ts534/config.yaml` | The 3 secrets read; non-comment lines identical to the running `/etc/netbird/config.yaml` (only the stale OpenBao comment header differed) |
| | Rendered again to `/etc/netbird/config.yaml` | `root:root 600`, equal to the check copy; `netbird-server` and `netbird-dashboard` active, `GET /api/instance` 200. No restart: the effective configuration is unchanged. The check copy was shredded and the temporary binary removed |
| `ts-orch netbird inventory` | `--pat-file` holding `gru-1-netbird-automation-pat` read from Vault | Succeeded: 9 peers |
| `ts-orch oci-region public-api`, `dns` | `CF_API_TOKEN` from `gru-1-cloudflare-dns-edit-token`, `GET /client/v4/user/tokens/verify` | `success: true`, `status: active` |
| NetBird owner login | Byte-for-byte readback against OpenBao | Equal |
| Trust keys | Byte-for-byte readback against the files | Equal |

The ts-ops OpenBao materializer (`forgejo-openbao-materializer.timer`) was
already disabled and has no NetBird target, so nothing else writes the file.
`ts-orch` is not yet installed persistently on ts-ops; `install.sh` needs the
released binary at `/usr/local/bin/ts-orch` for the next deploy.

## Not changed

No OpenBao entry was written or deleted. `infra/netbird/servers-gru` was not
read. The OpenBao entries that did not move are listed in
[secrets](../secrets.md#retired-openbao-entries).
