# GRU teardown dry run and confirmed DNS cleanup, 2026-10-04

Confirmation package for TS-470, collected read-only before the COS-relayed
decision below. No backup is requested. This evidence is committed with the
rebuild plan at the user's request. Rebuild creates need a separate exact
plan and COS-relayed user confirmation.

## COS-relayed decision and approved DNS deletion

The user approved the teardown plan on 2026-10-04, retaining the scheduled
purges, and explicitly directed **no OCI `--apply` now**. COS will request
the same apply after 2026-10-11 to delete the empty old compartment. No OCI
apply or live create was executed. OpenBao deletion was **not approved**;
`secret/homelab/infra/netbird/servers-gru`, including both versions, stays
unchanged and must not be overwritten by the rebuild.

The separately approved Cloudflare cleanup completed at
**2026-10-04T21:15:54Z**. Before deleting, the exact record readback matched
ID `cc03b04d0ab60d267c8a7ae98ca8cee1`, type `A`, name
`gru.api.terrascale.tech`, content `150.230.93.187`.

```sh
cf dns records delete cc03b04d0ab60d267c8a7ae98ca8cee1 -z terrascale.tech --force
```

The delete response was `{"id":"cc03b04d0ab60d267c8a7ae98ca8cee1"}`.
An exact-name DNS record list after deletion returned **`[]`**. The protected
DKIM CNAMEs were read back afterward and remain:
`terrascale-gru-20260708._domainkey.terrascale.tech`
(`8d2a3e188ca53d7b2396bf3b4e985bdb`) and
`terrascale-gru._domainkey.terrascale.tech`
(`d759cea514daadb3a73de465f3772347`). Forgejo, the NetBird manager,
ts-infra Email Delivery and other DNS records were not changed.

## Source and real dry run

- Fetched `origin/main`: `e8ea4844370334a483f687b26d2a5c4c5520b06b`, the
  merged #152 revision, including #148, #147 and #151.
- Built `/tmp/ts470-main-ts-orch` from that clean committed source at
  `nice -n 19`, with `umask 022` and `-trimpath -buildvcs=true`.
- Binary SHA-256:
  `2a0d608e8776bc95870f108850725132cbd074e5ef32302d47b5bce7764c5c89`.
- Reviewed OCI plan: `docs/evidence/gru-teardown-20261004-plan.json`;
  SHA-256 `fa18e2cbe197a0eb0b5bafa8445806443fb0e19eabf9d1a3e1acb5dab0d8a12c`.
- OCI profile: `DEFAULT`; cell region and observed ready tenancy home
  region: `sa-saopaulo-1`. Region subscriptions were read live.

Executed **without `--apply`**, from the repository root:

```sh
/tmp/ts470-main-ts-orch oci-region teardown --plan docs/evidence/gru-teardown-20261004-plan.json
```

Started `2026-10-04T20:54:14Z`; finished `2026-10-04T20:56:33Z`:
**139 seconds (2 minutes 19 seconds)**, exit 0, empty stderr.

```text
incomplete: gone 0, absent 0, pending 505, delete 0, held 1, keep 9
```

The full live output matches the merged evidence byte for byte, SHA-256
`c67c0e5822a67112f00db20ff8faed52b889652e1e62cb6ab5b6fbc69beb0b49`.
Each remaining vault content passed the live identity/ownership checks;
no unknown or shared key/secret blocked the dry run. The fresh inventory
also used direct OCI list/get calls, Cloudflare record reads, NetBird
inventory and OpenBao key/metadata reads. No secret values are included.

## Approved OCI command, deferred until COS asks after 2026-10-11

Working directory:
`/home/mariogk/.t3/worktrees/ts-orchestrator/cos-hold-ts-470-gru-rebuild`.
The OCI command is limited to the reviewed 506-resource JSON plan:

```sh
/tmp/ts470-main-ts-orch oci-region teardown --plan docs/evidence/gru-teardown-20261004-plan.json --apply
```

**Today this would skip all 505 pending resources and hold the compartment;
it would make zero OCI deletion calls.** The purges were scheduled during
the previous operator reset and continue independently of this command.
It cannot accelerate or reschedule them. After the contents are gone, a
fresh dry run of the same reviewed plan can make the control compartment
eligible; the same confirmed apply command is idempotent across those reruns.
An exit of 0 while resources are pending does not mean teardown is complete.

The OCI command does not perform the separately approved DNS cleanup:

```sh
cf dns records delete cc03b04d0ab60d267c8a7ae98ca8cee1 -z terrascale.tech --force
```

The DNS action above is completed and verified. Both GRU-named email DKIM
records remain. OpenBao deletion is not approved: retain `servers-gru`,
`automation`, `owner` and all other entries. No NetBird deletion is proposed:
there are no GRU peers, groups, networks or zones left to delete.

## Ordered scope and category counts

Empty categories have no name/OCID to approve. The OCI execution order for
remaining resources is secrets, keys, vault, then compartment. Non-OCI
cleanup is listed separately after the OCI command. Short OCIDs below mean
the last 12 characters; the complete identities are included in the full
tables and raw live diff later in this file. All 506 OCI short IDs are unique.

| Order/category | Cell-owned count | Names / short identities | Current disposition |
|---|---:|---|---|
| Instances | 0 | — | No instances in the root, TerraScale parent or control compartment |
| Boot volumes | 0 | — | None; ts-ops boot volume is protected |
| Block volumes | 0 | — | None; Forgejo data volume is protected |
| VNICs | 0 | — | No cell instance/VNIC attachments; only the ts-ops attachment remains |
| NSGs / subnets / route tables / security lists | 0 each | — | No cell VCN remains; the only VCN is ts-ops |
| Internet / service / NAT / local-peering gateways; DRGs | 0 each | — | No cell VCN or DRG remains; ts-ops IGW is protected |
| Load balancers / network load balancers | 0 each | — | Direct lists empty in every active compartment |
| Buckets | 0 | — | Only `ts-forgejo` and `ts-forgejo-backup` remain, protected |
| 1. Vault secrets | 502 | `terrascale-gru-netbird-setup-key` (`…lqs4z6zsrdta`); `ts-preview-gru-20260926-terrabase-live-s3` (`…oypsdgng5oiq`); 500 exact `ts-canary-sa-saopaulo-1-ts-preview-gru-*` entries in the full table | Already pending purge `2026-10-05T01:45:58Z` |
| 2. Vault keys | 2 | `terrascale-control-key-gru` (`…csd4t3lddj5q`); `RSA wrapping key` (`…odykru3fxgsa`) | Already pending purge `2026-10-11T01:48:37Z` |
| 3. Vaults | 1 | `terrascale-control-vault-gru` (`…cyr2it3qs5oq`) | Already pending purge `2026-10-11T01:48:37Z` |
| 4. Compartments | 1 | `terrascale-control` (`…mqkbjc5nvria`) | ACTIVE, held while the 505 contents remain |
| 5. DNS records | 1 Cloudflare A at collection; 0 OCI | `gru.api.terrascale.tech`, record ID `cc03b04d0ab60d267c8a7ae98ca8cee1` | Approved deletion completed; exact-name list now empty |
| NetBird peers | 0 | — | Only shared/operator peers remain |
| OpenBao enrollment reference (retained) | 1 path, 2 versions | `secret/homelab/infra/netbird/servers-gru` | Deletion not approved; unchanged |

The old `terrascale-network`, `terrascale-workload` and
`terrascale-production-gru-forge` compartments were positively observed
`DELETED`; they are not additional deletion targets. Direct resource lists
cover the root, TerraScale parent, active control compartment and ts-ops;
the latter is protected throughout. Network objects requiring a VCN cannot
survive the removal of the cell VCN. Fresh ts-ops lists show no LPG, NAT
gateway, service gateway or DRG; its route tables contain only the shared
internet route and an empty default table.

**Approved cleanup scope: 506 OCI identities (apply deferred) and one
Cloudflare record (deletion completed).** The OpenBao path and both versions
are retained. Only the 506 OCI identities belong to the `ts-orch` apply command.

## Everything that stays

- The `TerraScale` parent compartment and the tenancy itself; tenancy-wide
  IAM users, groups, policies, tag namespaces/defaults and other platform
  resources outside the reviewed cell allowlist. `Tenant Admin Policy`
  and `ts-forgejo-object-storage` remain.
- The whole `ts-ops` compartment, running `ts-ops` instance at
  `10.250.10.155` / `163.176.73.79`, Forgejo and the NetBird manager/routing
  peer. This includes the boot volume, `ts-forgejo-data` block volume,
  VNIC/public IP, VCN `10.250.0.0/16`, subnet, NSG/rules, route tables,
  internet gateway, security list, DNS zones/view/resolver, and buckets
  `ts-forgejo` and `ts-forgejo-backup`, including all their objects.
- Shared ts-infra Email Delivery: domain `terrascale.tech`, DKIM
  `terrascale-tech-dkim`, sender `noreply@terrascale.tech`, and the two
  Cloudflare CNAMEs `terrascale-gru-20260708._domainkey.terrascale.tech`
  (`8d2a3e188ca53d7b2396bf3b4e985bdb`) and
  `terrascale-gru._domainkey.terrascale.tech`
  (`d759cea514daadb3a73de465f3772347`).
- Shared NetBird peers `beta`, `delta`, `mariogk-laptop`, `ts-ops`; groups
  `All`, `operators`, `ts-ops-gateway`; policies
  `operators-to-ts-ops-forgejo`, `operators-to-ts-ops-ping`; all seven
  non-GRU setup-key entries and the manager's store/configuration.
- All other Cloudflare records/zones and all OpenBao paths, specifically the
  NetBird `servers-gru`, `automation` and `owner` entries. There are no GRU NetBird
  peers or GRU DNS zones to remove.

Full reviewed keep identities and the fresh shared-resource inventory
are included below. The shared private DNS zones are
`public.tsforgejo.oraclevcn.com` and `250.10.in-addr.arpa`.

## Estimated duration and irreversible effects

- One OCI inspection/apply sweep: budget **2–5 minutes**; this dry run took
  **139 seconds**. Current apply would perform zero OCI deletions. The
  approved DNS cleanup completed; OpenBao cleanup is excluded.
- The 502 secrets are already scheduled for
  **2026-10-05 01:45:58 UTC** (2026-10-04 22:45:58 São Paulo), about
  **4 hours 49 minutes after the observed dry run**. Their values and
  versions are unrecoverable after the purge. The command's scheduling
  interval for a newly eligible secret is 25 hours; it skips pending ones.
- Both keys and the vault are already scheduled for
  **2026-10-11 01:48:37 UTC** (2026-10-10 22:48:37 São Paulo), about
  **6 days 5 hours after the observed dry run**. The command schedules newly
  eligible keys/vaults at 7 days plus 1 hour, and never changes an existing
  pending date. OCI permits cancellation while pending; **after purge the
  cryptographic keys and vault contents cannot be recovered**, and data
  encrypted under those keys cannot be decrypted without another valid key.
- Complete teardown and reuse of the control compartment name cannot happen
  before that vault purge. After OCI positively reports the contents gone,
  allow another **2–5 minute sweep** and budget **10–30 minutes** for the
  asynchronous compartment deletion/readback; OCI may take longer. A
  deleted compartment cannot recover the purged resources. No forced purge
  or bypass of the deletion window is proposed.
- Cloudflare record deletion removes the old API DNS record immediately;
  caches follow their TTL. It can be recreated, with a new record identity.
  OpenBao deletion is not approved; its two versions remain unchanged.
  No backups are planned for the approved OCI wipe.

The compute, disks, bucket objects and cell network already removed during
the previous reset are not new deletion actions in this package. No OCI,
NetBird or OpenBao mutation has been executed. The sole live mutation in
this confirmation follow-up is the approved Cloudflare record deletion above.

## Full ordered OCI deletion identities

All names and full OCIDs below are verbatim from the reviewed plan whose
individual live reads and vault contents passed the real dry run.

### vault-secret: 502

| # | Name | Short OCID | Full OCID | Action |
|---|---|---|---|---|
| 1 | `terrascale-gru-netbird-setup-key` | `…lqs4z6zsrdta` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah36eekkgznp466jwk24f4zcoxpjtjvznlqs4z6zsrdta` | pending |
| 2 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-a-controller-a-creds` | `…urbs4brnyema` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavwx6blcbn7q2gcajt6xgupnwzgqpoyyrurbs4brnyema` | pending |
| 3 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-a-controller-a-response-key` | `…3i6qrrj6o6qa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqablebr775v5q5ukwyzv4vwxt5ouyk4c6e3i6qrrj6o6qa` | pending |
| 4 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-a-controller-a-tls-cert-pem` | `…fluo4n3ote4q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaful5s246qujvepmyosgt3tainjazlcekfluo4n3ote4q` | pending |
| 5 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-a-controller-a-tls-key-pem` | `…t5y4kgftokyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacaiax6vmccdikkjfgnspnpjqlfx3wkrht5y4kgftokyq` | pending |
| 6 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-b-controller-b-creds` | `…dffm5zfmuxpa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaepjdgx7tu54wyynkw6a43ffutt5fhjftdffm5zfmuxpa` | pending |
| 7 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-b-controller-b-response-key` | `…zyymrugclzla` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahww3kvof6bdqip5upa4ct6nxuvxhjpnszyymrugclzla` | pending |
| 8 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-b-controller-b-tls-cert-pem` | `…x6oxumoekvja` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqat4z5oqcfnvnyxr2l6vnqb6iihs77irgyx6oxumoekvja` | pending |
| 9 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-b-controller-b-tls-key-pem` | `…vjvctw44rhlq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasclrdbiy3r2by52fu7p7tlul4yzowiuhvjvctw44rhlq` | pending |
| 10 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-c-controller-c-creds` | `…vi44sfii5ana` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagozwawj5sv3x3h4dvabofg34yqrnzhzrvi44sfii5ana` | pending |
| 11 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-c-controller-c-response-key` | `…w4ff7cb6vada` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanidoqxbtka3tw3wq4oc3o3nu67x7ualuw4ff7cb6vada` | pending |
| 12 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-c-controller-c-tls-cert-pem` | `…4d3shatnlala` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakl23su7zvhk2grv4ayda7vbknsy4j5jb4d3shatnlala` | pending |
| 13 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-c-controller-c-tls-key-pem` | `…2w74ezk7gflq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarjugquzp6pqxc6dr3jt5dmzert2htjae2w74ezk7gflq` | pending |
| 14 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-host-issuer-shared-host-nats-issuer-seed` | `…jwbpffssqxta` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagxmj5ucszfwwqr4xrja53vuuzuqooss3jwbpffssqxta` | pending |
| 15 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-host-issuer-shared-host-tls-issuer-cert-pem` | `…abaxooyaia2q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7s6hds2flihhfygabhsxvnog42c3oyqhabaxooyaia2q` | pending |
| 16 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-host-issuer-shared-host-tls-issuer-key-pem` | `…w6vnbclr7xuq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7pudw7xybjakrsfpw3xxyn2zpwlbxsctw6vnbclr7xuq` | pending |
| 17 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-ca-pem` | `…33rb5ndclvka` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafepumie6an67k6xjcqhaw64wx2dn7y2o33rb5ndclvka` | pending |
| 18 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-cell-jwt` | `…hhzel5dqezwa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaawkylrpoh6yjqc6ufbbacl2mwrgbtk6ohhzel5dqezwa` | pending |
| 19 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-operator-jwt` | `…g2wmxyaiyu5a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafinezv6dhkm5bjdnjqxrsiribl2lwaq5g2wmxyaiyu5a` | pending |
| 20 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-route-password` | `…7yj2fb5w2dwq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa52ydbi7rewbd7vbe7h7mba4n4e3tnygh7yj2fb5w2dwq` | pending |
| 21 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-system-creds` | `…ardoqxjhyw6a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaahzirr2xihr5p6l7acg4ggolbufervwyardoqxjhyw6a` | pending |
| 22 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-system-jwt` | `…ujsqfpfq3aga` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaejzbaxm2ytrc4wtusbv2r2eu62v7bmq3ujsqfpfq3aga` | pending |
| 23 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-ticket-key` | `…xa6vi436hmuq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaa2ohbvvdk6ctc4uxxtb6dmvcxcyufigdxa6vi436hmuq` | pending |
| 24 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-ticket-pub` | `…6jrvndknpwjq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqap3go3ywh6zafdojn2gf5tm7of3ys5uhb6jrvndknpwjq` | pending |
| 25 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-seed-founder-controller-a-founder-peer-key` | `…3hxra5eldy7a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalqsg6mlkbn2dgdvguuyffxwvsvulcdp73hxra5eldy7a` | pending |
| 26 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-seed-ledger-signer-controller-a-founder-ledger-key` | `…wqs4solz5cdq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqao24c4mvpeofqzzyme5jgxqvcizhjnt2dwqs4solz5cdq` | pending |
| 27 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-a-controller-a-creds` | `…6h5dcba6bfiq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaujng3x2gyjq37r3ddyruchiwkrwnnzae6h5dcba6bfiq` | pending |
| 28 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-a-controller-a-response-key` | `…qv6oa7hzniyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6hx2nffqlretjauew4xxhyndz5b76d37qv6oa7hzniyq` | pending |
| 29 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-a-controller-a-tls-cert-pem` | `…v53u5gg2ulka` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqak3zb4tsyx2zlkcgasw6gs665psmlbvrmv53u5gg2ulka` | pending |
| 30 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-a-controller-a-tls-key-pem` | `…63i7xieztvta` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadpgwj5hjzeuqkutctns6pbqv5vfqenfz63i7xieztvta` | pending |
| 31 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-b-controller-b-creds` | `…vl4pru5jjqkq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxq6ncu727ajzlso7l3djxyci2hfcpmcivl4pru5jjqkq` | pending |
| 32 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-b-controller-b-response-key` | `…bry65ks355gq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxj2mks3d4yutoqnmwbzfndfy43zm64dybry65ks355gq` | pending |
| 33 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-b-controller-b-tls-cert-pem` | `…2o3quzve3ymq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqav2aqyrckzc7nesmbq6zuzb2puf4u3tcn2o3quzve3ymq` | pending |
| 34 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-b-controller-b-tls-key-pem` | `…ezpwipir74ja` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaesdk44xuw3vbtookpaibua2yeuvm5qnmezpwipir74ja` | pending |
| 35 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-c-controller-c-creds` | `…vhipajqi55wq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqau4ggxppwvd6ilgb4rg4tkoy2kshvrsavvhipajqi55wq` | pending |
| 36 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-c-controller-c-response-key` | `…62fay3ijww3a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqak3vhtkyz3fhcmf4gfadjt5i3dcihuf2562fay3ijww3a` | pending |
| 37 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-c-controller-c-tls-cert-pem` | `…xxrtfncl42gq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanhhntaiubserxbu3xh5fyneaz5x2osaaxxrtfncl42gq` | pending |
| 38 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-c-controller-c-tls-key-pem` | `…nofj2h4phxsq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5f3znme6qqka7yznkwshdesv5o25yeounofj2h4phxsq` | pending |
| 39 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-host-issuer-shared-host-nats-issuer-seed` | `…zx5yuevxkjza` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafsegtfjccatx6bli3kbu34yek72gr7zbzx5yuevxkjza` | pending |
| 40 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-host-issuer-shared-host-tls-issuer-cert-pem` | `…izainc67aida` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7jwcozwuzpqbrgpktl77j233qoorn6nnizainc67aida` | pending |
| 41 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-host-issuer-shared-host-tls-issuer-key-pem` | `…r4fvp2ekkbvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaen2odvux6n52nq7nmhklxnllucnjcfalr4fvp2ekkbvq` | pending |
| 42 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-ca-pem` | `…f65ks5yr35sa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayqchefeigwuq232utybar63n2vdsxw6yf65ks5yr35sa` | pending |
| 43 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-cell-jwt` | `…yttq2x3yalma` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaof2fx544v35mvz3kutbd5subckyunhx3yttq2x3yalma` | pending |
| 44 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-operator-jwt` | `…eu3hzlfuc5na` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalg2vwjr77vfefaf6p4nvp6h6zcinrq4xeu3hzlfuc5na` | pending |
| 45 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-route-password` | `…ks5sityfml3a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafabtcke4nv7trsaizihnq3w344jskoywks5sityfml3a` | pending |
| 46 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-system-creds` | `…zax74g7kw45a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaomplcxe7aldml5zau52rchtcmoulsjy5zax74g7kw45a` | pending |
| 47 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-system-jwt` | `…oghh3j5mqbua` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6dftjirnhw2chddjxszej4nh2i2e2mlwoghh3j5mqbua` | pending |
| 48 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-ticket-key` | `…ndcfuuybgomq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazox6724qlp7vaevchpj4i7aic7kihw5nndcfuuybgomq` | pending |
| 49 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-ticket-pub` | `…inxe6y3mupmq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazj3x5zqr7d2au4jrtg2nvy3zwfcibmbvinxe6y3mupmq` | pending |
| 50 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-seed-founder-controller-a-founder-peer-key` | `…ejkcl63aajra` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaymj4pt7z27yeblq43uxr5wmgmt6sonfdejkcl63aajra` | pending |
| 51 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-seed-ledger-signer-controller-a-founder-ledger-key` | `…raijt7xj7npq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqateufef2aocgq26pe65rvco5wggnz3puoraijt7xj7npq` | pending |
| 52 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-a-controller-a-creds` | `…2lx4icloc6aq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasdimglwpmnvzgm3whbuffjg2tj3b2ooj2lx4icloc6aq` | pending |
| 53 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-a-controller-a-response-key` | `…i6gadxnrmthq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa73i47dii5mznyuttkxx2gumy2pvzrxv3i6gadxnrmthq` | pending |
| 54 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-a-controller-a-tls-cert-pem` | `…ojs77mcmuvna` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaq5fncwh5m36uu3zxpciqfluprc5vylxoojs77mcmuvna` | pending |
| 55 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-a-controller-a-tls-key-pem` | `…3rhvwcs3hzka` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqal3o2szoclycxulgeqpuzr4o3qh6vj5ox3rhvwcs3hzka` | pending |
| 56 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-b-controller-b-creds` | `…ubekzqtyufda` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqak42wfyrotu2dz2iwsmwrgreqyfjl7qp4ubekzqtyufda` | pending |
| 57 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-b-controller-b-response-key` | `…6lv2e5tfi4ea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarhfzscmrf6plt4hyux4pwgi7phg6z6k46lv2e5tfi4ea` | pending |
| 58 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-b-controller-b-tls-cert-pem` | `…zgq3napandxq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakf4m6oauxl5odezku45acrtfgfsaeiy4zgq3napandxq` | pending |
| 59 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-b-controller-b-tls-key-pem` | `…6mizseqsbhta` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapddiqr2xmpvmqwtxcwidwwh3hf6ogacf6mizseqsbhta` | pending |
| 60 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-c-controller-c-creds` | `…bivfqyff3xwq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanox5klaodqjyquqypsihby57tb2znfmtbivfqyff3xwq` | pending |
| 61 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-c-controller-c-response-key` | `…7bj3k5ejsdua` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazhbuhvzm2hki2jcxl2ymvh6ie7vxi73q7bj3k5ejsdua` | pending |
| 62 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-c-controller-c-tls-cert-pem` | `…4rynfup2qhpa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa363uhwoy3xgdpvjdnrcx3hdflhqtvwfj4rynfup2qhpa` | pending |
| 63 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-c-controller-c-tls-key-pem` | `…m5bbmvvbcyra` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawcgtro2y2mrfgfsqnjygrnjjnavy6abom5bbmvvbcyra` | pending |
| 64 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-host-issuer-shared-host-nats-issuer-seed` | `…yehl7da4lzsa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqav7qhzhfu7kgd6sikadg2fiyuyo2gugjmyehl7da4lzsa` | pending |
| 65 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-host-issuer-shared-host-tls-issuer-cert-pem` | `…l4jfn4vmrzla` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanhsbprnwqdhtbd6j7cede6fpyq64ediel4jfn4vmrzla` | pending |
| 66 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-host-issuer-shared-host-tls-issuer-key-pem` | `…5ndrew4nlyza` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2jukd7talzz3vlsmmmhunethw4dakzsl5ndrew4nlyza` | pending |
| 67 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-ca-pem` | `…nyczaicawflq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6wh62djx7f2cc6lhpu45flenshbe5srynyczaicawflq` | pending |
| 68 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-cell-jwt` | `…qlw7yiuzth3a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaup5ftkc6mey6howkq25ijg33bwgoxonbqlw7yiuzth3a` | pending |
| 69 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-operator-jwt` | `…enpucb5hznjq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqam4wm5cgz5ney5zx3j7vjhtuqm47fxp3yenpucb5hznjq` | pending |
| 70 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-route-password` | `…b5xphtzahtuq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawhupgs5p2f2h5a77s6vbctcvpitthrrqb5xphtzahtuq` | pending |
| 71 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-system-creds` | `…edbxh537srlq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa544bvrz6tzsscbpvtkli4aeaqpbwwt67edbxh537srlq` | pending |
| 72 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-system-jwt` | `…w4lw3pcbclbq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaiscvxsjqxscnppqelmkdgkwoebfvr2wbw4lw3pcbclbq` | pending |
| 73 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-ticket-key` | `…kbkzigcqkugq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqqfjmxiwfmxy2qmqk4mjr7unftvtcce7kbkzigcqkugq` | pending |
| 74 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-ticket-pub` | `…cgp3uug4xqzq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqargky7so667j6rgm4e4sucdm7fxwvghibcgp3uug4xqzq` | pending |
| 75 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-seed-founder-controller-a-founder-peer-key` | `…jgkmy6y2tzza` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaci3ccqvpapt5j6xhfqqpmjzns32uvuo7jgkmy6y2tzza` | pending |
| 76 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-seed-ledger-signer-controller-a-founder-ledger-key` | `…4me3vaivtp4q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqauu2dhclzehyyvgxor5rwr5ljhntanfrc4me3vaivtp4q` | pending |
| 77 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-a-controller-a-creds` | `…tbn3h34smj4q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2acwbvmshkrz2wyml5c4vsicf3ybh764tbn3h34smj4q` | pending |
| 78 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-a-controller-a-response-key` | `…awi6naeubnka` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqau7sbhi6b3w5u4si3nvxzpahexqxfot2yawi6naeubnka` | pending |
| 79 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-a-controller-a-tls-cert-pem` | `…36rqncampddq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalfdybw5vxtfbcewoie227mncizbwm7b536rqncampddq` | pending |
| 80 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-a-controller-a-tls-key-pem` | `…yvisudk4nzdq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadfzkjdrxqnkb34g4ohgbfszj3padbdv2yvisudk4nzdq` | pending |
| 81 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-b-controller-b-creds` | `…yac2auubn5vq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarjfk5aeg666iuypmkadfmtj6codggvllyac2auubn5vq` | pending |
| 82 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-b-controller-b-response-key` | `…hh4fdz7as34a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7qtsadesfqmze35rptqhfjt2uuke6rl2hh4fdz7as34a` | pending |
| 83 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-b-controller-b-tls-cert-pem` | `…5zulxdbbnciq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3zfxm7ltgw6weih3is76g2zmmsw5dcml5zulxdbbnciq` | pending |
| 84 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-b-controller-b-tls-key-pem` | `…2ui4wfhqizhq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoqp6vebsc5jdy6wr6jfczjlqx2f442fv2ui4wfhqizhq` | pending |
| 85 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-c-controller-c-creds` | `…4p4y56orqz3q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabhuilw3jgp3sqngzmjh6ky2akoj3otqu4p4y56orqz3q` | pending |
| 86 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-c-controller-c-response-key` | `…c4zt73l7dl4q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasogdjryfptw3xlvjfgk7dggns7yr44acc4zt73l7dl4q` | pending |
| 87 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-c-controller-c-tls-cert-pem` | `…b7sb7zucohka` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaytyn5dtzdveyq2kq575z5rsnvljdldzdb7sb7zucohka` | pending |
| 88 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-c-controller-c-tls-key-pem` | `…ltoihh7b73bq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxyjraryee2boupvvsi2r7m22yca7z7grltoihh7b73bq` | pending |
| 89 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-host-issuer-shared-host-nats-issuer-seed` | `…dtho543rcagq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakrpzqaq3lpa3wkm4fpry5ntizl2ov4x6dtho543rcagq` | pending |
| 90 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-host-issuer-shared-host-tls-issuer-cert-pem` | `…u3ohyruq7irq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaw62ln7si5ddfu6veigcx4eeyr6sz46rcu3ohyruq7irq` | pending |
| 91 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-host-issuer-shared-host-tls-issuer-key-pem` | `…7oa3bnpnf2sq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasjdbedc5uno3l3g33dpl6lypxhoxnv6g7oa3bnpnf2sq` | pending |
| 92 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-ca-pem` | `…ljoc5rbboaea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakand5nv7tpxyouc5ckphyvoxwlez2ojpljoc5rbboaea` | pending |
| 93 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-cell-jwt` | `…qithvrsopy4a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2c2xzg35gxqyv7bhkaoahtt7agqf6ahwqithvrsopy4a` | pending |
| 94 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-operator-jwt` | `…ltzyr4byqs2q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaawbncfxbvpz4bpy7qx6t2wnsrinefkvpltzyr4byqs2q` | pending |
| 95 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-route-password` | `…oephv76kj54a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadu7j3k67gjf7ejc5d6bkymwqjjc27voroephv76kj54a` | pending |
| 96 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-system-creds` | `…scb3o2qohbzq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavhxd23kstldg3gof2xzskgh6gkrv4lddscb3o2qohbzq` | pending |
| 97 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-system-jwt` | `…b37i6v4ah7nq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqao7zo7kybapnmzsqpwswafmbdhidtkev3b37i6v4ah7nq` | pending |
| 98 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-ticket-key` | `…qyrixkciyrxa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaazom6tmmki6wt7dlfmliio7pno3iaaepqyrixkciyrxa` | pending |
| 99 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-ticket-pub` | `…xhpnluia63rq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabgnav2boj623nx54faetg6naz7ox5wvwxhpnluia63rq` | pending |
| 100 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-seed-founder-controller-a-founder-peer-key` | `…wc4uwhmp36va` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4zydpyomualxjntwis5akcjmc3bckh5uwc4uwhmp36va` | pending |
| 101 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-seed-ledger-signer-controller-a-founder-ledger-key` | `…q3ve57nvgu5a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamknmgelxqnuamd4aq2zzyzljebljut2mq3ve57nvgu5a` | pending |
| 102 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-a-controller-a-creds` | `…baqolakqd5sq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacsux4fygcf6656pgyjt5epj2mdh2dzxnbaqolakqd5sq` | pending |
| 103 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-a-controller-a-response-key` | `…imgbxxw7oxrq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxmgmuirgbugzvpzjpfuawmd46uraas52imgbxxw7oxrq` | pending |
| 104 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-a-controller-a-tls-cert-pem` | `…pbzliexwtm3q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqav4dahzfs7f7oskiiqdqqgjlqgwpywfeupbzliexwtm3q` | pending |
| 105 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-a-controller-a-tls-key-pem` | `…ukefdfeqahvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalpf6ynruqszh2ijq45vyalyuxi2pk4g3ukefdfeqahvq` | pending |
| 106 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-b-controller-b-creds` | `…u7adsh7ftora` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5m4a6rer6to4n5naxe2lv6osyv2wprg5u7adsh7ftora` | pending |
| 107 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-b-controller-b-response-key` | `…k3mpcu6qnw5a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqancieijjhdsgzb7s5fhpo7uizazkzlytkk3mpcu6qnw5a` | pending |
| 108 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-b-controller-b-tls-cert-pem` | `…jury6fbyomwa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah57uq5f2sha2div3ri5yva2ag6pkeshtjury6fbyomwa` | pending |
| 109 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-b-controller-b-tls-key-pem` | `…qtrzs3xs2vmq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagraryk5usw7zdii2zodfbckl6jfc4iy6qtrzs3xs2vmq` | pending |
| 110 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-c-controller-c-creds` | `…4nnggvmxgqyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarbziqmha7xspdge22ier2ze2ua2qee5m4nnggvmxgqyq` | pending |
| 111 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-c-controller-c-response-key` | `…xmkgpii3y5mq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5dahpugl6ixm6xxtjs226wlh72kttfmfxmkgpii3y5mq` | pending |
| 112 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-c-controller-c-tls-cert-pem` | `…nb2zmlzs2fga` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabtupz6v55satqjdlezz5n54zf5udjzolnb2zmlzs2fga` | pending |
| 113 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-c-controller-c-tls-key-pem` | `…7tkaad3kqyiq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaf6pyvfwqcaq6wtp2hqek7k5szqasodqv7tkaad3kqyiq` | pending |
| 114 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-host-issuer-shared-host-nats-issuer-seed` | `…uwbgbclrdxda` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6kokqpijke435cnur25a7yvo44xgbkjiuwbgbclrdxda` | pending |
| 115 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-host-issuer-shared-host-tls-issuer-cert-pem` | `…vvfd26hyjmiq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaweuzjscyn5pe2sj367oiu7xx2xi5hpptvvfd26hyjmiq` | pending |
| 116 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-host-issuer-shared-host-tls-issuer-key-pem` | `…w5o6v3kollyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapeew55k633y3eqa7p3fzv6rmqm5b7ne5w5o6v3kollyq` | pending |
| 117 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-ca-pem` | `…jmziq4e7fboq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6ck3q2f56iuom4kfthqod4iddygycoc5jmziq4e7fboq` | pending |
| 118 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-cell-jwt` | `…nwqkaf6vmqwa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa66mkzngr74ntnpgvxcryyyn7crzykggqnwqkaf6vmqwa` | pending |
| 119 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-operator-jwt` | `…ejtt3esy6b2q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafnb57n7vs37bcnrpa2i3ftcbzzso3b64ejtt3esy6b2q` | pending |
| 120 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-route-password` | `…nebpvsblhtdq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqauzgo4hssfybvrfjdlxwxlpzlzlr2vkksnebpvsblhtdq` | pending |
| 121 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-system-creds` | `…4bkcahfgt4da` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3qv57ps2zkpzniktf4rduf4xinhsxbl74bkcahfgt4da` | pending |
| 122 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-system-jwt` | `…z2rjxoyiazbq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadtm24ejn5jufwad7zodbr5hqmkrmfzelz2rjxoyiazbq` | pending |
| 123 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-ticket-key` | `…7tsopg3gf6na` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanbg5zgswdzfvejdoqamdn62qaonv3xsk7tsopg3gf6na` | pending |
| 124 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-ticket-pub` | `…bcjqjokpj4ja` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatkn6w5ohwhmqfcik2eennw55j5qb4rpsbcjqjokpj4ja` | pending |
| 125 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-seed-founder-controller-a-founder-peer-key` | `…myipypmketsa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafztc5wfsi3zzoz2u5qlnatsxcpxov6pvmyipypmketsa` | pending |
| 126 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-seed-ledger-signer-controller-a-founder-ledger-key` | `…ldfnohnias4a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalxsansvawffpwdfauxrglaefnst4s4qfldfnohnias4a` | pending |
| 127 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-a-controller-a-creds` | `…jgclfk5kexia` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajdwmd6pnzatjlv7ltgh3zkzecbggv2gnjgclfk5kexia` | pending |
| 128 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-a-controller-a-response-key` | `…6xypxo2b7ikq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayyhfgoc2mhtmb4muubwi2cgy6mt23zgs6xypxo2b7ikq` | pending |
| 129 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-a-controller-a-tls-cert-pem` | `…46x3t5k4indq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakbokwwhaogg5ow7j2cx5vcmsdme4a23y46x3t5k4indq` | pending |
| 130 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-a-controller-a-tls-key-pem` | `…wu6j7w5vmifa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqac4vbptqbb4ncr5h7ymwmgctzm6m3rjrtwu6j7w5vmifa` | pending |
| 131 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-b-controller-b-creds` | `…zu5uhwrlpkaq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarflqwkfcg55lz77f4nuaiazagh7uq4hdzu5uhwrlpkaq` | pending |
| 132 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-b-controller-b-response-key` | `…3tc43w5epu4a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatqrlgqrzw6mywf5lsbt4vj73hg7xmk4r3tc43w5epu4a` | pending |
| 133 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-b-controller-b-tls-cert-pem` | `…vxmshfxqm4sq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanhg2uyttuineh4523awux7irikiqtlwlvxmshfxqm4sq` | pending |
| 134 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-b-controller-b-tls-key-pem` | `…5cpvhykofqea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa246jvztma22q4maushlmadvcsg6kylnz5cpvhykofqea` | pending |
| 135 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-c-controller-c-creds` | `…mmecfhyodflq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2amp5g46twspjrdx6pcvfv3wlwurz2opmmecfhyodflq` | pending |
| 136 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-c-controller-c-response-key` | `…udrmox65orva` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagg2txfbgchcbqgo2cqgysuxjxetage56udrmox65orva` | pending |
| 137 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-c-controller-c-tls-cert-pem` | `…aimymkyvk7ia` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacce2r4a3q7vmdywhs6b53274d5mxdeucaimymkyvk7ia` | pending |
| 138 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-c-controller-c-tls-key-pem` | `…avf6mfijrrcq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqack3ncbpwl4wd4tujsofqepvom6doi5m7avf6mfijrrcq` | pending |
| 139 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-host-issuer-shared-host-nats-issuer-seed` | `…gs6xdrusipia` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah7kbddhldkdpf6utmmdkbk4jhjuuhmlxgs6xdrusipia` | pending |
| 140 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-host-issuer-shared-host-tls-issuer-cert-pem` | `…wjwmkrmehn6q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahdee452onmrdr2tq7xpxydu7v4rv23bvwjwmkrmehn6q` | pending |
| 141 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-host-issuer-shared-host-tls-issuer-key-pem` | `…go4scs3gpc5q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazbek2ujfohuh4lllflnbbdvzcgb5ztkugo4scs3gpc5q` | pending |
| 142 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-ca-pem` | `…53kndnsnohia` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahf7gelggzhtu6yebfdo2ll4ybvlc3xe553kndnsnohia` | pending |
| 143 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-cell-jwt` | `…sm3exgzobnqa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3p63itchyyf3rimlc2qldxcbo3wbosxtsm3exgzobnqa` | pending |
| 144 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-operator-jwt` | `…pi4pmiqwemma` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahsvhzruwyz5sbp3xdkvvakvlhxdn4ku7pi4pmiqwemma` | pending |
| 145 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-route-password` | `…vz35zbu2sdca` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7kmkrb5bjhpn5kux6cubw7vgqgi54zurvz35zbu2sdca` | pending |
| 146 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-system-creds` | `…72zgyaz4vh5q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarpuqemf32ns3uqo2ej62753l2unc4odx72zgyaz4vh5q` | pending |
| 147 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-system-jwt` | `…rrvoikyjun7q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanfbq3mzzl3yam3zthtwx4arimqo2svmhrrvoikyjun7q` | pending |
| 148 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-ticket-key` | `…ica2sluu67ra` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqankap7t4sr57wccwx6iik3yzl3r47cdhbica2sluu67ra` | pending |
| 149 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-ticket-pub` | `…i5udcyj5kdha` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqax55b6xy3ov75zeuntfajgi4azd2y62dwi5udcyj5kdha` | pending |
| 150 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-seed-founder-controller-a-founder-peer-key` | `…qvivvffs63xq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasmhw5frqbn7btijdk7bkibh6rn6gzymlqvivvffs63xq` | pending |
| 151 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-seed-ledger-signer-controller-a-founder-ledger-key` | `…427qrsvstppq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajacxoidhjses7257n7cxsxl33syafbpj427qrsvstppq` | pending |
| 152 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-a-controller-a-creds` | `…elpmzt3iqfta` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakezw3z73x7dnrw6l6d2gvyyenipn2qknelpmzt3iqfta` | pending |
| 153 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-a-controller-a-response-key` | `…upwd2zh62bva` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxir5prrxdupiyi25e6d2rin4gjd2jr4aupwd2zh62bva` | pending |
| 154 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-a-controller-a-tls-cert-pem` | `…rn5jlwelh6lq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadxq7pzvwlrk2bv2qwflmkyuxlxdiz75irn5jlwelh6lq` | pending |
| 155 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-a-controller-a-tls-key-pem` | `…s7vknik4gjsq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqauiircsw6egbm3sz7w2btayzc6z76lke6s7vknik4gjsq` | pending |
| 156 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-b-controller-b-creds` | `…cxdtnfwozbvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabudiv4xge7wy6v76lapa57eip6u4tmydcxdtnfwozbvq` | pending |
| 157 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-b-controller-b-response-key` | `…gbjszuwkkeuq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqax7lpcvmt2th7qxvpki3zay4hmj475jgggbjszuwkkeuq` | pending |
| 158 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-b-controller-b-tls-cert-pem` | `…6ue4tcd5vdta` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah5teeeurxqualuwwymhfsbfrlivzgfyr6ue4tcd5vdta` | pending |
| 159 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-b-controller-b-tls-key-pem` | `…lo4om44ysp7a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaw63ktfjqcbjdekqwsmt3n4uomcufwtqflo4om44ysp7a` | pending |
| 160 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-c-controller-c-creds` | `…5kz5awcthnuq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadeccgxrygjgiw4n7jlzbxrw42opkgdd25kz5awcthnuq` | pending |
| 161 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-c-controller-c-response-key` | `…s2oj2zy5psrq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqap3p4f3ng3ytat7shp3jzxyyszn7jqovvs2oj2zy5psrq` | pending |
| 162 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-c-controller-c-tls-cert-pem` | `…qjx7ids3grxq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagme2k3k4k4mcdsjcmcimccp6i7qidy23qjx7ids3grxq` | pending |
| 163 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-c-controller-c-tls-key-pem` | `…falrlxzr7rmq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaigpmuzfoljehmxfz2kepbzei6pgoojy7falrlxzr7rmq` | pending |
| 164 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-host-issuer-shared-host-nats-issuer-seed` | `…prrg4vr7zroq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa45oy5mejjirscn53rzaxadd2qtai6jj3prrg4vr7zroq` | pending |
| 165 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-host-issuer-shared-host-tls-issuer-cert-pem` | `…h6oxyh7x4zwa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2ujjwl3xlhq7pdonq2glq2bkzol5fbcwh6oxyh7x4zwa` | pending |
| 166 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-host-issuer-shared-host-tls-issuer-key-pem` | `…b5fwgdagqdxq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaj4wuljpfplg65hzxho4ieqiyhfcwcfwbb5fwgdagqdxq` | pending |
| 167 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-ca-pem` | `…fg3xsfd7keeq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarygjhswjttcv43gs2iqoygz4hs2n5b6yfg3xsfd7keeq` | pending |
| 168 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-cell-jwt` | `…vjzooyxf4xfq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2q7dxksxsqmos34nfo6z4evzwpwai2rovjzooyxf4xfq` | pending |
| 169 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-operator-jwt` | `…2y4fcngrnfsq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad77erhpob2peyjyvfark6g2imbdy3ely2y4fcngrnfsq` | pending |
| 170 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-route-password` | `…ag2vsipjleha` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3l6hugqbe6g6b2rc4pvarsi6tujiw7tvag2vsipjleha` | pending |
| 171 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-system-creds` | `…agrotl3drznq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqac5oul3q3dnzzosqw3imnq27ugwvs6n4wagrotl3drznq` | pending |
| 172 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-system-jwt` | `…eruiefqt3mha` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqai6ae4tcrforwazvn6mcrcpxecdphkeyceruiefqt3mha` | pending |
| 173 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-ticket-key` | `…4zpx62yqjlvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazrwrl43r2uoowf2caa6vw2lt2pjpeggw4zpx62yqjlvq` | pending |
| 174 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-ticket-pub` | `…jbuhjpeoliwq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamxgqcpgtii234yxkxxjlxrchkiempn4wjbuhjpeoliwq` | pending |
| 175 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-seed-founder-controller-a-founder-peer-key` | `…c64ri4rixqua` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahvxferthyk5usrqxsrirry365jotuc7jc64ri4rixqua` | pending |
| 176 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-seed-ledger-signer-controller-a-founder-ledger-key` | `…nltzsuxjqb6a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa33ngadswivdwkayrdffb6vnxhkcx6txbnltzsuxjqb6a` | pending |
| 177 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-a-controller-a-creds` | `…w5222bz247ea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaskew63a47xav7xxo4xxby772zz4by6d3w5222bz247ea` | pending |
| 178 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-a-controller-a-response-key` | `…wjuk3nrsy4hq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2imhzifz5mg6ojcw3yhirctxb2ox3uicwjuk3nrsy4hq` | pending |
| 179 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-a-controller-a-tls-cert-pem` | `…zcw3xkanslsq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7sr3fz7jpkw2s4fisg2rtfoxntotk5d4zcw3xkanslsq` | pending |
| 180 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-a-controller-a-tls-key-pem` | `…qysym5kufkga` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqal3nez7schyklrnxwljmtkv4rxvreoswfqysym5kufkga` | pending |
| 181 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-b-controller-b-creds` | `…wso2pxyif6iq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaeqdcgc3ybk5z6nhprnhwpadeps47oczywso2pxyif6iq` | pending |
| 182 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-b-controller-b-response-key` | `…rcsrbqyknkhq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad2vva77fu5dcnltvrzbqyfhpdadntgkorcsrbqyknkhq` | pending |
| 183 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-b-controller-b-tls-cert-pem` | `…3lv45yrgtjha` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqac3efbn5bgwlvmhq2ygr4f6bbapelqb6j3lv45yrgtjha` | pending |
| 184 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-b-controller-b-tls-key-pem` | `…waqiqtyma3gq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaowss6tr6wnyecihv4h3gs27rcmtushscwaqiqtyma3gq` | pending |
| 185 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-c-controller-c-creds` | `…u7c476hlwp6a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaif2ajtjtdlomijmtn2ius3xo5766ghkku7c476hlwp6a` | pending |
| 186 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-c-controller-c-response-key` | `…khs6j3zsenza` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarrh3d5tqyib2crteedycj2nny5hbgvkukhs6j3zsenza` | pending |
| 187 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-c-controller-c-tls-cert-pem` | `…dgsvcsh6qacq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaac4vwxndu4gsagsskexdmvw57zurnva6dgsvcsh6qacq` | pending |
| 188 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-c-controller-c-tls-key-pem` | `…da2dcugp2efq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamtznn3f64vnqfwojaff3i6qr2w5fbussda2dcugp2efq` | pending |
| 189 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-host-issuer-shared-host-nats-issuer-seed` | `…aqcy22m6obvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqap5ot437ioioyxnrtx2z6drggqbqhgeqdaqcy22m6obvq` | pending |
| 190 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-host-issuer-shared-host-tls-issuer-cert-pem` | `…c2nigitwdala` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavc6rchrdqsmhdfrc72hkqbkfue3cld7ec2nigitwdala` | pending |
| 191 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-host-issuer-shared-host-tls-issuer-key-pem` | `…i6wko6jm67xq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapnn3vzjcido7bvltycuv23mjgab47sxoi6wko6jm67xq` | pending |
| 192 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-ca-pem` | `…iubncwlfjukq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7g5ggadpwaczn3xtjx6xueaqmfd235taiubncwlfjukq` | pending |
| 193 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-cell-jwt` | `…czklkiktt4va` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaefevyqu6dzyl3lpi6rmia5luruzrqrziczklkiktt4va` | pending |
| 194 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-operator-jwt` | `…4ccxkedzcaea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4m42lph4xx35cjnghubdlgej5yylvl2v4ccxkedzcaea` | pending |
| 195 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-route-password` | `…v3iobv3xehza` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqax3hyrzap4qaxhxm3h5i2j2ro5ewudqpzv3iobv3xehza` | pending |
| 196 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-system-creds` | `…drqbjvtfc2ia` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4m3s4kqw2yuexbavgj4ta3g7odfyftwrdrqbjvtfc2ia` | pending |
| 197 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-system-jwt` | `…l2ju36j3ogsa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2nu3xf42guzobjoqs2qmy3hr2xytdjavl2ju36j3ogsa` | pending |
| 198 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-ticket-key` | `…k6mqp34byj5q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqmz6ots43nyqkbm5v7msfcd4jbzfqap5k6mqp34byj5q` | pending |
| 199 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-ticket-pub` | `…75usr2kfppnq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaooqa6jhrze47w2neydp373igejgj7m3b75usr2kfppnq` | pending |
| 200 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-seed-founder-controller-a-founder-peer-key` | `…skvf5p47oyaq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4gzq4kgmvf2flgxu45jaqxsi6o5kxovqskvf5p47oyaq` | pending |
| 201 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-seed-ledger-signer-controller-a-founder-ledger-key` | `…bkzx2hpm7dnq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqab2ge3m3svza5ckuhc65ptdn2qvkx6ivhbkzx2hpm7dnq` | pending |
| 202 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-a-controller-a-creds` | `…zd3h7ejgcgsq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqc5ej4blced54247yxhgf64hg7bi7rb5zd3h7ejgcgsq` | pending |
| 203 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-a-controller-a-response-key` | `…g7sxxolcbsva` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanbzeshwzvafi36u4544qf36ebqphctqsg7sxxolcbsva` | pending |
| 204 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-a-controller-a-tls-cert-pem` | `…d6a3jcgyufoq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabpjogjjjm72nplicmv7fnda6ikbwly3yd6a3jcgyufoq` | pending |
| 205 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-a-controller-a-tls-key-pem` | `…kkoxtt6voe6q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaiigbbyg4ddpa4juqyi6otgbz5qnoqlfzkkoxtt6voe6q` | pending |
| 206 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-b-controller-b-creds` | `…g45lwvr2pmoq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajrmkaei5cwlrx4peyvatftn3o2meh7j5g45lwvr2pmoq` | pending |
| 207 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-b-controller-b-response-key` | `…ot4ebfb3oqyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqau5dr3labnunqvnsd3ogodgibfyi46e5eot4ebfb3oqyq` | pending |
| 208 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-b-controller-b-tls-cert-pem` | `…54x7bh4xnsha` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7nvzevjzvyroi5ggslvya7gywxwb22gb54x7bh4xnsha` | pending |
| 209 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-b-controller-b-tls-key-pem` | `…psj74tx3trca` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavvws52ngfqo44neg5n5o7woav7aooolxpsj74tx3trca` | pending |
| 210 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-c-controller-c-creds` | `…5eto53ap7fjq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapfpcxd4cganpr2hxxblvz7psqhvcirle5eto53ap7fjq` | pending |
| 211 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-c-controller-c-response-key` | `…pzqch46dohra` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajk5cufoqidtcyt3mylybuhhztzpulkfcpzqch46dohra` | pending |
| 212 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-c-controller-c-tls-cert-pem` | `…gqzit3c6kvtq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazpss2rsjqut3qwndiyyibobc77xpt7d2gqzit3c6kvtq` | pending |
| 213 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-c-controller-c-tls-key-pem` | `…besnnplqzoja` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa33jvw4mgeyylv6e2plr2oed6af53n32xbesnnplqzoja` | pending |
| 214 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-host-issuer-shared-host-nats-issuer-seed` | `…cdnqkssc57mq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafr2onlqsq33o2qbfcji4kdqpboeb4pffcdnqkssc57mq` | pending |
| 215 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-host-issuer-shared-host-tls-issuer-cert-pem` | `…bmoa3mahqj6a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqan2accg5k3ydv7jvhri5igguuakatbnelbmoa3mahqj6a` | pending |
| 216 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-host-issuer-shared-host-tls-issuer-key-pem` | `…fydrkoplhwrq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaibrz66x3lpcc5ehiyvio346u7zugtgoufydrkoplhwrq` | pending |
| 217 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-ca-pem` | `…ukongauwhtrq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxe4do7yirs6ou626rhg7errwxs33i4axukongauwhtrq` | pending |
| 218 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-cell-jwt` | `…lov4vvp2rlzq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqao7pzvqgpdqtumhyekrsrec4cznf5ebtulov4vvp2rlzq` | pending |
| 219 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-operator-jwt` | `…f2dubkinnh2a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqai5pr7vo2rjyuflumq6hfez5txfb5y4ksf2dubkinnh2a` | pending |
| 220 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-route-password` | `…3jxfm7sn4uja` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoolvjq3ourtgzuxjzvdunzkf7qjnfxdy3jxfm7sn4uja` | pending |
| 221 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-system-creds` | `…lbskpeieqwdq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakswlgagso44s7ha2qskjzqadmml75fcclbskpeieqwdq` | pending |
| 222 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-system-jwt` | `…7tabluefo6gq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxsqpugzrtgfuilzvserdwfade6qmm57p7tabluefo6gq` | pending |
| 223 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-ticket-key` | `…5kp4ivjflo2a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqap4zuk5sy33vttublazypzxjatgpj5cyq5kp4ivjflo2a` | pending |
| 224 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-ticket-pub` | `…s36pmkxq3muq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanmhtvztl2tjmhzvj4aec3mzfvkxxnztqs36pmkxq3muq` | pending |
| 225 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-seed-founder-controller-a-founder-peer-key` | `…36egscmcdqyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4bothekzri55rdw2huxscaenxu6x3osu36egscmcdqyq` | pending |
| 226 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-seed-ledger-signer-controller-a-founder-ledger-key` | `…gyhu4i5poula` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqat3i5vdr3xqqi26427ghqklz7oztb73yngyhu4i5poula` | pending |
| 227 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-a-controller-a-creds` | `…7djazujd47qq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqampmbsjilpj3a5scpyqy2zpej5pc3ba537djazujd47qq` | pending |
| 228 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-a-controller-a-response-key` | `…nqbtbkvziynq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacujnd3oq2vcdvfc3nughxjykqpfcroh4nqbtbkvziynq` | pending |
| 229 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-a-controller-a-tls-cert-pem` | `…a7ad2ldskpvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadde762rgiugrb5ra44dn3vvgrhm52xdza7ad2ldskpvq` | pending |
| 230 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-a-controller-a-tls-key-pem` | `…msjuygfvtwda` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2yy3mecpkdtcynui5igojiolrqwgpcalmsjuygfvtwda` | pending |
| 231 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-b-controller-b-creds` | `…xu62v2vp5mnq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqxoqgwvzexvoumwqy2kg3azyobkomoxyxu62v2vp5mnq` | pending |
| 232 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-b-controller-b-response-key` | `…yye26zrhe6pq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavs3i6d4l3fk32bhmzsixxtv6a6tqqfstyye26zrhe6pq` | pending |
| 233 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-b-controller-b-tls-cert-pem` | `…tkqkkdthj7pa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatujtwwcwwivgk2dt3s7zefmphfdtuuavtkqkkdthj7pa` | pending |
| 234 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-b-controller-b-tls-key-pem` | `…dm2xag6mp6kq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawrs4ztjgi53xrk45hmw5mdzbh4rssr33dm2xag6mp6kq` | pending |
| 235 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-c-controller-c-creds` | `…sfvoeojkn3vq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6zlltofn65666ltttwwzepfrqx3dklhjsfvoeojkn3vq` | pending |
| 236 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-c-controller-c-response-key` | `…ojilhshschya` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayf3da6n4csrrnk7es3yz4wrkkeqqjrm3ojilhshschya` | pending |
| 237 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-c-controller-c-tls-cert-pem` | `…5bdzgo53n76a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasb4prm6ylkoxyegmkbnrtsojdvkfas7l5bdzgo53n76a` | pending |
| 238 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-c-controller-c-tls-key-pem` | `…jwjo4wbr7aaa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqairkzyubmx3fub46zzflr6hqoete3liagjwjo4wbr7aaa` | pending |
| 239 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-host-issuer-shared-host-nats-issuer-seed` | `…hrl54yzwwpuq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavd737no2ybsakthx3lcmqivoszpd66wjhrl54yzwwpuq` | pending |
| 240 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-host-issuer-shared-host-tls-issuer-cert-pem` | `…gojjyndtuo4q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahnvk2wlktbyrssehu2mssno3w4r7vfl4gojjyndtuo4q` | pending |
| 241 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-host-issuer-shared-host-tls-issuer-key-pem` | `…bn2kqcq6clua` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaysprzxuoc7qhii7qwespmqddjtsyr4oubn2kqcq6clua` | pending |
| 242 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-ca-pem` | `…a5w45qgwi4qa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabi6nas4ysqtijptxklcjhsjdy5yfq2bta5w45qgwi4qa` | pending |
| 243 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-cell-jwt` | `…iz7vcn3onh3a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacgbbcabtxumq75s2j7c5kf5fkpcj6vwwiz7vcn3onh3a` | pending |
| 244 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-operator-jwt` | `…h4w46fjf2elq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaq5kix5rwu5zb4fdmwfnd7g6jrazttcrbh4w46fjf2elq` | pending |
| 245 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-route-password` | `…bqjinjf4xqma` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabw5cnzzhuwkuekymyuwsirxcrqlczn7bbqjinjf4xqma` | pending |
| 246 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-system-creds` | `…q2pr7uh6fwqa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3t7j5koaiqhslbmrkgwarbgcc3x3iyvmq2pr7uh6fwqa` | pending |
| 247 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-system-jwt` | `…vwwjw63rre6a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahdcmmwzmivvvhjzs3zkb5dkwedwh4dkgvwwjw63rre6a` | pending |
| 248 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-ticket-key` | `…a7ij4sg4satq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagafwuz6kdoeagtxb6ooincyury2hwkdba7ij4sg4satq` | pending |
| 249 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-ticket-pub` | `…b45gidegvwuq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaaqk52vdw7vbuyy7pbkom65nvxiavvl7fb45gidegvwuq` | pending |
| 250 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-seed-founder-controller-a-founder-peer-key` | `…chsrh72z5spq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqae5zbomnet5m3ktczudcteo26fnklqmbuchsrh72z5spq` | pending |
| 251 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-seed-ledger-signer-controller-a-founder-ledger-key` | `…wurrgszojoja` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqai2ofs4ksfthjem6mqh4xrjfuketjcqsiwurrgszojoja` | pending |
| 252 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-a-controller-a-creds` | `…crhhqsoccbra` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazftpxjp6z5zdbcidshpuoe5grxtngfxicrhhqsoccbra` | pending |
| 253 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-a-controller-a-response-key` | `…rhe5yikjykvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqam5k63q7d7synuxnki3orwvqc5jf5uenlrhe5yikjykvq` | pending |
| 254 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-a-controller-a-tls-cert-pem` | `…5eym5lus6fiq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaawt3fktgfk2fany5n4z7k2d4bwje46hf5eym5lus6fiq` | pending |
| 255 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-a-controller-a-tls-key-pem` | `…zzkde4e4iaha` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatgipswzmjoyikejvfadwphyfgwk6vx3uzzkde4e4iaha` | pending |
| 256 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-b-controller-b-creds` | `…jtwryuiboohq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafpodbjozahksz3zjngqircvgfe7twhkqjtwryuiboohq` | pending |
| 257 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-b-controller-b-response-key` | `…73u6ci3jpsdq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaud62nz25pzy3l73epmcivelj6iidphgh73u6ci3jpsdq` | pending |
| 258 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-b-controller-b-tls-cert-pem` | `…7fc7oxtuquia` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamtufpooxa73bojzwfsspful5tcq37dov7fc7oxtuquia` | pending |
| 259 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-b-controller-b-tls-key-pem` | `…lqfkgltwwcha` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqxi37fqqv7zox6t3h75sv54tbfzn2durlqfkgltwwcha` | pending |
| 260 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-c-controller-c-creds` | `…y3lyotiqh7xa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawva36x2kxowqdhqvzuk5jaxhf3mpq4rvy3lyotiqh7xa` | pending |
| 261 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-c-controller-c-response-key` | `…wzzyp63wjv4a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasn6rntdql4fbgwabf2e6lx7ssrjukiezwzzyp63wjv4a` | pending |
| 262 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-c-controller-c-tls-cert-pem` | `…3rapbwcu7nza` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacfch2wzncdt5ta7hldevvt6rmbbh2k5r3rapbwcu7nza` | pending |
| 263 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-c-controller-c-tls-key-pem` | `…hbjsq7ee3a4q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah5xx6ot7vndg6kdwxb5v5jmipl2tyicqhbjsq7ee3a4q` | pending |
| 264 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-host-issuer-shared-host-nats-issuer-seed` | `…6opxsgpbzzja` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqauqhmnhccfgidfafqcvnkt34jfolue46v6opxsgpbzzja` | pending |
| 265 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-host-issuer-shared-host-tls-issuer-cert-pem` | `…ulngg6t5l5ma` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayubwl5srhkjmt45rpxec2dhbhs5asbndulngg6t5l5ma` | pending |
| 266 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-host-issuer-shared-host-tls-issuer-key-pem` | `…mxxsqowheqba` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4j32nhd2p4q3syzkkw2ouphlzjkw72q6mxxsqowheqba` | pending |
| 267 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-ca-pem` | `…drxdis2te2ka` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad2pvwghd5anhhdkhlo5pw5vqo75fyfvfdrxdis2te2ka` | pending |
| 268 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-cell-jwt` | `…zlzd5a4m7hpq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3t57he3qtwco6im45rclfs56lx66gcpzzlzd5a4m7hpq` | pending |
| 269 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-operator-jwt` | `…5gormnabyrya` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavzz6vbefk6qyrh3gdgozukglben4xzdt5gormnabyrya` | pending |
| 270 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-route-password` | `…t5n74kyhvq5a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaiz33ee5cvhg5fnmpqgpe3ut3urjq2cbzt5n74kyhvq5a` | pending |
| 271 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-system-creds` | `…y7wgnng2liuq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxjbaojh6r6efk5z74tm64jickkgdpulvy7wgnng2liuq` | pending |
| 272 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-system-jwt` | `…j5rueazlwpsq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqhuxcoqdbkqjfq2dyic4mqjatyxxydh6j5rueazlwpsq` | pending |
| 273 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-ticket-key` | `…n5c52kc4xoea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatwq64wumdromzwzl2njk47mg5uf3bzufn5c52kc4xoea` | pending |
| 274 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-ticket-pub` | `…jqqsbz77l6yq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayy4p7ttlmxx2o5qfogbjphtw3k3nvibujqqsbz77l6yq` | pending |
| 275 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-seed-founder-controller-a-founder-peer-key` | `…cno2z2za4cda` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatmnqtvzu7uzwo5huey6e33zv6amd6rtjcno2z2za4cda` | pending |
| 276 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-seed-ledger-signer-controller-a-founder-ledger-key` | `…oniy6v4r5bvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawzuhlmndkzuq24ycqkbmlguyll7rwciqoniy6v4r5bvq` | pending |
| 277 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-a-controller-a-creds` | `…6ult6mqrhnda` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaavsry6rwb4lrhva5d2ujhhyknbr4kkai6ult6mqrhnda` | pending |
| 278 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-a-controller-a-response-key` | `…rvxporv4llwq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqar5j7jpgmoaaucxawvve4yxciqakvy3dyrvxporv4llwq` | pending |
| 279 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-a-controller-a-tls-cert-pem` | `…qujw66wnbthq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqak7nrlu7x2czonzyurtq34sr6twg3pr3wqujw66wnbthq` | pending |
| 280 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-a-controller-a-tls-key-pem` | `…p3dk3t2xffnq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah53i4ffb5v7uscdbyrzhfdbmjifofom5p3dk3t2xffnq` | pending |
| 281 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-b-controller-b-creds` | `…whm5wc25fola` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaf5loqgxyirc2hlwa7cbdxr7aqcd3rhilwhm5wc25fola` | pending |
| 282 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-b-controller-b-response-key` | `…jvnqhn73adza` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawgtvsell2wtnqlburibcxfizwweygzozjvnqhn73adza` | pending |
| 283 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-b-controller-b-tls-cert-pem` | `…innkpzycpzoa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasniaqhjs3d3ylmulwnrqqinxixw72phminnkpzycpzoa` | pending |
| 284 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-b-controller-b-tls-key-pem` | `…og4om27z6t5a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakervb265lqexmvbzmnldmyiylbuduepkog4om27z6t5a` | pending |
| 285 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-c-controller-c-creds` | `…oyvqu2qfk5aa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaydmtkv52kd5gqtlrjm3bdp6ff647pe2boyvqu2qfk5aa` | pending |
| 286 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-c-controller-c-response-key` | `…lgk2unlszocq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4nb4yqnmus2hnjf3ixunm6md6tzbxro7lgk2unlszocq` | pending |
| 287 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-c-controller-c-tls-cert-pem` | `…663p35lmikea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafaengg3j3iqp44ebstozggf65jo5rk5g663p35lmikea` | pending |
| 288 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-c-controller-c-tls-key-pem` | `…5kb4onyazisa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6n3mavjz4ti63c5ft5do3rg6nonje6sz5kb4onyazisa` | pending |
| 289 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-host-issuer-shared-host-nats-issuer-seed` | `…6dlbwb5wxopa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahpjd52ie5muwzjccushuwpqrlbtnh7rx6dlbwb5wxopa` | pending |
| 290 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-host-issuer-shared-host-tls-issuer-cert-pem` | `…doqkilexiuyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamxf3hkarufbkvap2yzp3zp725zpokdmjdoqkilexiuyq` | pending |
| 291 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-host-issuer-shared-host-tls-issuer-key-pem` | `…s5edurfn3boa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajgvfrct7veye5aufee2n3xxs73he46u5s5edurfn3boa` | pending |
| 292 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-ca-pem` | `…3lkanpp4fiza` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadicte7bkkamui2tnka37sm55jpg55bcw3lkanpp4fiza` | pending |
| 293 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-cell-jwt` | `…ibanl7tjx6ea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaiddm7itjk3lh4gfaofy4qelo3y3ludouibanl7tjx6ea` | pending |
| 294 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-operator-jwt` | `…cmvfbked6e4q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaet7yuqnyrs7kq4ajw3w44ycajpfo4oylcmvfbked6e4q` | pending |
| 295 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-route-password` | `…bmrbeaolcaja` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatm4wfudv43az234jra7m7pogif4k37gabmrbeaolcaja` | pending |
| 296 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-system-creds` | `…sg2q6sxlr4ua` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayi5trbw5mnyz66efvziw3flazor6eyklsg2q6sxlr4ua` | pending |
| 297 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-system-jwt` | `…jdf6yqlq7gfa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalajqex6aiwlbijfelgt3yqo7i7mlsc4yjdf6yqlq7gfa` | pending |
| 298 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-ticket-key` | `…fyykaveodija` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqactz4gigfyweveizgfvx2wetf3ox5yflhfyykaveodija` | pending |
| 299 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-ticket-pub` | `…cgtv4fbc4ieq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoecmt5xrzsygshy7nbyqyd5opsr6jvkkcgtv4fbc4ieq` | pending |
| 300 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-seed-founder-controller-a-founder-peer-key` | `…sbxkfzht2yaq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah63wendnh4z7xx2q42f6uulou2kk2ny6sbxkfzht2yaq` | pending |
| 301 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-seed-ledger-signer-controller-a-founder-ledger-key` | `…f6qfpcwvslhq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaep2h5a2e2gl77lppm6oxwdfc2ymn7ws3f6qfpcwvslhq` | pending |
| 302 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-a-controller-a-creds` | `…smu5aubi7wba` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawlvygrwuegtzf7feoo35wwcqg7oyvgmnsmu5aubi7wba` | pending |
| 303 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-a-controller-a-response-key` | `…j6h24z4gjpxa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaol3dk33h3iwilqnqhwscxrbn6u7kqkmuj6h24z4gjpxa` | pending |
| 304 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-a-controller-a-tls-cert-pem` | `…zglikrr6aufa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaa7fogsjybufyeo5uh66n7t4bo5d2oezozglikrr6aufa` | pending |
| 305 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-a-controller-a-tls-key-pem` | `…3q6qsffatzkq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalyzimzkw3xztyqrhxg2mddokktzgjfo63q6qsffatzkq` | pending |
| 306 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-b-controller-b-creds` | `…f53blukvxdea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazsaxwe7i34oieqs2rxdiljugvf44avnyf53blukvxdea` | pending |
| 307 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-b-controller-b-response-key` | `…rt5fzwywg4la` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxjf3jyv3pzb5fuiqce3iklgbvyl6s7drrt5fzwywg4la` | pending |
| 308 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-b-controller-b-tls-cert-pem` | `…6fr43sw2uziq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapaylz4fqjxqs5eh4rmutcgzloyi3id7d6fr43sw2uziq` | pending |
| 309 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-b-controller-b-tls-key-pem` | `…ej36adu2vofa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqata6mnnybcuein3ttr4kps45cspiw5ti2ej36adu2vofa` | pending |
| 310 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-c-controller-c-creds` | `…s55ftoav5rma` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5rbixybzpf6zopgb5cfrdagkgnmnutm7s55ftoav5rma` | pending |
| 311 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-c-controller-c-response-key` | `…6xv3amsjs3qq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayrguomfqszq5vk3cxrddmqksvwwbva366xv3amsjs3qq` | pending |
| 312 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-c-controller-c-tls-cert-pem` | `…qpnvnupu4mgq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxl5rtoefi5dcudzi4oexltkkgtkgdjbaqpnvnupu4mgq` | pending |
| 313 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-c-controller-c-tls-key-pem` | `…35tfpqu6ojgq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa23ekhqk2iizapzj6wxkz4uarqohch4fn35tfpqu6ojgq` | pending |
| 314 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-host-issuer-shared-host-nats-issuer-seed` | `…gzqroz3vivzq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqan4hht6otwl7ew37onycuxv6vuitizkmzgzqroz3vivzq` | pending |
| 315 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-host-issuer-shared-host-tls-issuer-cert-pem` | `…wppek3mqr4ya` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqat6w6p6ynyyx4uy4kpwcmhdyct2mncbzpwppek3mqr4ya` | pending |
| 316 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-host-issuer-shared-host-tls-issuer-key-pem` | `…nf2mqoffnkla` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaw455hhlt3trhiceg5g6hvqd7nxymrupfnf2mqoffnkla` | pending |
| 317 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-ca-pem` | `…iaa543bmw7hq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad5nwxucqwf5zfy4vfefyto5ryfmkglnuiaa543bmw7hq` | pending |
| 318 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-cell-jwt` | `…yr66hh5qwnsq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafsqtdx5l66uaw7dsdm5zf47ap6sez6ocyr66hh5qwnsq` | pending |
| 319 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-operator-jwt` | `…fnhtmir3zwfq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqay4pg7c7s6ovm3gdqifebilcvj7vajqzgfnhtmir3zwfq` | pending |
| 320 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-route-password` | `…r6vn5my67h7q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3d6woy6kye3vd57aiply6duqg6zp6ep5r6vn5my67h7q` | pending |
| 321 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-system-creds` | `…6fernbeogtuq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa47vq24qxsm4qaohfqbhdmacfcngjpuml6fernbeogtuq` | pending |
| 322 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-system-jwt` | `…kt25v2ciiaya` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqans5tnu2kvpqp6yn2g5eszrg6hs7sxv5zkt25v2ciiaya` | pending |
| 323 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-ticket-key` | `…267aqtm7t5iq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxwsgto7inqxbcpmp372wnuc4wkllplwe267aqtm7t5iq` | pending |
| 324 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-ticket-pub` | `…2dhmd76fs4yq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4za7c4muoxu6e35w4pun44zw6stbc7ib2dhmd76fs4yq` | pending |
| 325 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-seed-founder-controller-a-founder-peer-key` | `…matrfdot2k4q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadv3r6czjhp753htkptvt7l26wwqucsv5matrfdot2k4q` | pending |
| 326 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-seed-ledger-signer-controller-a-founder-ledger-key` | `…nqjapfbzjctq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa33lnr2svacl53z75zh6sofpupu4qw4j3nqjapfbzjctq` | pending |
| 327 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-a-controller-a-creds` | `…u3osre5nxjma` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaz5arhkrcenwqncyuseanhaniu6r5dbznu3osre5nxjma` | pending |
| 328 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-a-controller-a-response-key` | `…dallv2whgxlq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacaijy73svvh5qyy7iiraebatb3zopcdhdallv2whgxlq` | pending |
| 329 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-a-controller-a-tls-cert-pem` | `…22g6bcxegywq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazvgw76c2i32oxb3pp4gsltmbpyf65nnv22g6bcxegywq` | pending |
| 330 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-a-controller-a-tls-key-pem` | `…qpbm6hi3lxaa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatkdr4hlkva3cjveh7cpuqtjbfs72uqxxqpbm6hi3lxaa` | pending |
| 331 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-b-controller-b-creds` | `…a3xabl3n6p2a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaovdockzrwiov5kcn6g2jl273ehfgvuk5a3xabl3n6p2a` | pending |
| 332 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-b-controller-b-response-key` | `…2igjqskhhqda` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayvgrmkrxs4fjqy6mv2d2g5hmccxdwcim2igjqskhhqda` | pending |
| 333 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-b-controller-b-tls-cert-pem` | `…x5yv2az6zkka` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3jsflkfficocti4bmnhsktjjji62nmlzx5yv2az6zkka` | pending |
| 334 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-b-controller-b-tls-key-pem` | `…h2nz3fbz442a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarec3i255pyyv2ocxgtsjoaoc763b4z6xh2nz3fbz442a` | pending |
| 335 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-c-controller-c-creds` | `…rc5xuqfepwca` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqar4kxbj6hobjrwml7eudwymnhjotiig66rc5xuqfepwca` | pending |
| 336 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-c-controller-c-response-key` | `…jwg4rli3alyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaivmin3vjuettysllpm3c4lcqqsxpzlkijwg4rli3alyq` | pending |
| 337 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-c-controller-c-tls-cert-pem` | `…tgv62znbknta` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayomuerfspfhtron72wd45iytxchosxzqtgv62znbknta` | pending |
| 338 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-c-controller-c-tls-key-pem` | `…ul3cehts2pnq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3cfebl4btcxzxuutddvbpfu4n44qg37zul3cehts2pnq` | pending |
| 339 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-host-issuer-shared-host-nats-issuer-seed` | `…q7ec6m4vb32q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakdwq2vy3lmg5wdvesv6txerbua3365d4q7ec6m4vb32q` | pending |
| 340 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-host-issuer-shared-host-tls-issuer-cert-pem` | `…n5qrdpzgkwnq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarpjke73ifgz65tu4ljzyfgrxtf3ducarn5qrdpzgkwnq` | pending |
| 341 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-host-issuer-shared-host-tls-issuer-key-pem` | `…yqjt3pk5ppha` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatg6fo7tfymkweccqulz7u2ugz4ujuwhnyqjt3pk5ppha` | pending |
| 342 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-ca-pem` | `…hv5f4gn6iaiq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazhqzqpxgmzjreskgprtqno55bxpsmzjvhv5f4gn6iaiq` | pending |
| 343 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-cell-jwt` | `…fsy2bjb6fdiq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaw3fpeijayrbjqdmpvatc6rgshd7aye2xfsy2bjb6fdiq` | pending |
| 344 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-operator-jwt` | `…2k3ivwlsazzq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4qpnjytm7ifiyistmxgwtyrraify7m5c2k3ivwlsazzq` | pending |
| 345 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-route-password` | `…a4sfog52n3aq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavajfp43n5maxya7x53t4iccp5kszbggta4sfog52n3aq` | pending |
| 346 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-system-creds` | `…ys3phcbf62pq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajs3vrlx2m7rkcmmaerewwbw3filwma7nys3phcbf62pq` | pending |
| 347 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-system-jwt` | `…osqbumdg4uca` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaa3u34rbvd6jzl73y5ulrwxu3mobwxzbbosqbumdg4uca` | pending |
| 348 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-ticket-key` | `…hz7ktz3s5emq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabl5r6xwxdoumfdm5gbeio5tpfho4mogshz7ktz3s5emq` | pending |
| 349 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-ticket-pub` | `…wx5ylzytug3a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqnxb3hh34wqqwk3qenw6vdwhznmegj4fwx5ylzytug3a` | pending |
| 350 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-seed-founder-controller-a-founder-peer-key` | `…bd4wm42gvcwa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxwlxdagc32ur2obxpfffdon74xtyqb54bd4wm42gvcwa` | pending |
| 351 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-seed-ledger-signer-controller-a-founder-ledger-key` | `…mgriatpsr2sq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqao6ycmncao5wgfe3l23zyqmslglcvmxovmgriatpsr2sq` | pending |
| 352 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-a-controller-a-creds` | `…k645vxmsnw6a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakswvaec6ysit5s53s7pwok6h5yitjt7uk645vxmsnw6a` | pending |
| 353 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-a-controller-a-response-key` | `…rdttuqxaraya` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafjaksxrlyxdpo7njv4pgd2kkuicsd4ssrdttuqxaraya` | pending |
| 354 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-a-controller-a-tls-cert-pem` | `…dkv6qk53r2uq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqay6xxg5qdcqjt4yugasc4wqjemj6qfmyvdkv6qk53r2uq` | pending |
| 355 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-a-controller-a-tls-key-pem` | `…puf4g7ko2gyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaumfprxjns6t7duiwk7mtiffd2eonzdvqpuf4g7ko2gyq` | pending |
| 356 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-b-controller-b-creds` | `…etfwz7774yla` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqansfprnn524nsiesqmcnkxzssqx2dnho2etfwz7774yla` | pending |
| 357 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-b-controller-b-response-key` | `…c27abaullhyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3d4fxqrvvabllnoqy4h62d4qwdmzlwoic27abaullhyq` | pending |
| 358 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-b-controller-b-tls-cert-pem` | `…6wxpmkfasgxq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaogo42nogeaq3r5nfivbnhahtzni5n5u56wxpmkfasgxq` | pending |
| 359 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-b-controller-b-tls-key-pem` | `…bnupfyfw5fsa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakzfh3u2anr75fsrmcjj4wia5atujgwklbnupfyfw5fsa` | pending |
| 360 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-c-controller-c-creds` | `…75vtp4vajava` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoukx44diu5ncsjelxn6phoc7l72az6in75vtp4vajava` | pending |
| 361 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-c-controller-c-response-key` | `…asx26rrcy2ta` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3pd2sbcs7c2uutv5cux6bemaimcyjarnasx26rrcy2ta` | pending |
| 362 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-c-controller-c-tls-cert-pem` | `…5abg2qwn673q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqax7cxpxnjrsnb4a6wbdtxi4lou2dqwtrz5abg2qwn673q` | pending |
| 363 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-c-controller-c-tls-key-pem` | `…zzlpoan6lnrq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabvooqryaiibdxbwootlsoac5ifi4fc6czzlpoan6lnrq` | pending |
| 364 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-host-issuer-shared-host-nats-issuer-seed` | `…sx5hst7bmyma` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarvd2x2tnjlqsxb7gdqd7ialxevzyqnsosx5hst7bmyma` | pending |
| 365 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-host-issuer-shared-host-tls-issuer-cert-pem` | `…zr2phw65b5tq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqbbkgavge3rfgy4wbdop7yldyc4leldkzr2phw65b5tq` | pending |
| 366 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-host-issuer-shared-host-tls-issuer-key-pem` | `…fqkhwyjt7ixa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarmybejewg5mthcj3fksldcgznjtwmgkxfqkhwyjt7ixa` | pending |
| 367 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-ca-pem` | `…zzb5cfnjyraa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatuommre46qc7udgzr4auxnxgusftjhvqzzb5cfnjyraa` | pending |
| 368 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-cell-jwt` | `…4fgygu4ip4dq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqay7yu6tu5p24mnfrjbsf6fas6bjhewp754fgygu4ip4dq` | pending |
| 369 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-operator-jwt` | `…v5zfzmr4mocq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapmxbqtnppf6takm2d5klt7qpmkdj62ejv5zfzmr4mocq` | pending |
| 370 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-route-password` | `…mshygjsnslla` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaokoujj6pq6xbxsmws2rszyxdh5pnkts7mshygjsnslla` | pending |
| 371 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-system-creds` | `…p6fuxlkezm6a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqand47oaowc5lv34lw4rv2z6md2haqajerp6fuxlkezm6a` | pending |
| 372 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-system-jwt` | `…qedkj4yljfwa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqac4cvcgaw6psgtvaynozbi6zjacoujnlyqedkj4yljfwa` | pending |
| 373 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-ticket-key` | `…6oearrivmqga` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaes5p4dmx4edxef3xbgetpufk3d4jjhbq6oearrivmqga` | pending |
| 374 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-ticket-pub` | `…euzxsgskxtvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaur3umefhwz7fqek7mlzjnr2yj6nhkvr3euzxsgskxtvq` | pending |
| 375 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-seed-founder-controller-a-founder-peer-key` | `…uqejuawpasvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalrfbvek65yzk4i27nyq2qzjkp5m4sh5euqejuawpasvq` | pending |
| 376 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-seed-ledger-signer-controller-a-founder-ledger-key` | `…6oira7skxyxa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahpebhai34dzylcsa7jbonchpr37hfyci6oira7skxyxa` | pending |
| 377 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-a-controller-a-creds` | `…hxmm6gwhlnca` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7hatu2v5zoelqrvr62vczon6shlxafiyhxmm6gwhlnca` | pending |
| 378 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-a-controller-a-response-key` | `…tvdgn22vfifa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqjzrvgwn4i33ihc43njkg6u2o6z3kqhrtvdgn22vfifa` | pending |
| 379 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-a-controller-a-tls-cert-pem` | `…enr3ugp2au4a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqhch5eixluow76jp4gzycm7lb62enifwenr3ugp2au4a` | pending |
| 380 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-a-controller-a-tls-key-pem` | `…txdscjrcmtoa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajprq4vjg7rtzrg5ggq2lbsw6z4ne2b3dtxdscjrcmtoa` | pending |
| 381 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-b-controller-b-creds` | `…6tqrqqrwl2vq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapcf4cq4ovj5icemhylfyoi4cpksyw3uc6tqrqqrwl2vq` | pending |
| 382 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-b-controller-b-response-key` | `…rlrm2m3dcspq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5w75i6v57kesvhffdi45lrucmqh2l2vprlrm2m3dcspq` | pending |
| 383 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-b-controller-b-tls-cert-pem` | `…tiifdgogscsq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaggsqmuyj6izb243q27jdflxwoh7rt5vjtiifdgogscsq` | pending |
| 384 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-b-controller-b-tls-key-pem` | `…r3xophrjxtbq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqfh2pddpg623j3hvkpmmimik33pcmsqer3xophrjxtbq` | pending |
| 385 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-c-controller-c-creds` | `…mzvigoffp4sq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaplwbqh4y2yx4ev33m4ei3uf24runai5wmzvigoffp4sq` | pending |
| 386 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-c-controller-c-response-key` | `…neimtqefqbca` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqautmaklxs2c7clhsxxkrvlnksetkr4l5qneimtqefqbca` | pending |
| 387 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-c-controller-c-tls-cert-pem` | `…wu77f5sch2wa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5l75wungkqranccivokowg64ayiiqqhnwu77f5sch2wa` | pending |
| 388 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-c-controller-c-tls-key-pem` | `…4kzezmgcdi7q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaibopmjd3a66rb5qdhonzuwxuyriakcr74kzezmgcdi7q` | pending |
| 389 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-host-issuer-shared-host-nats-issuer-seed` | `…2glfcb5aevoq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajg63ovuahhxtlrgrm57lln7tzidtpsp42glfcb5aevoq` | pending |
| 390 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-host-issuer-shared-host-tls-issuer-cert-pem` | `…xsutr4d5y6rq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayacuwjgxvcr2i24lr3tsvmdb6ivgepuzxsutr4d5y6rq` | pending |
| 391 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-host-issuer-shared-host-tls-issuer-key-pem` | `…spd6cssf7irq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafbok2zh74ewps5ewpvxocbzxo3tcxfaospd6cssf7irq` | pending |
| 392 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-ca-pem` | `…nsotb5k5dsea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayvvyvfj4ykzldkmksljak7i2xiclm63wnsotb5k5dsea` | pending |
| 393 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-cell-jwt` | `…ekxjxzmmsdaa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavnfbr4i23n4gsjekwi4i5klnrdgkwkn4ekxjxzmmsdaa` | pending |
| 394 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-operator-jwt` | `…tjxqbk64ty6a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoleueyefckumnhmyc3g5uw3zn5rmszogtjxqbk64ty6a` | pending |
| 395 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-route-password` | `…knr5wbvlfnva` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakgion6p5d4nrli5odxyfmqpet346tg66knr5wbvlfnva` | pending |
| 396 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-system-creds` | `…vejn5a36dieq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4ij4yxliirghzunyuo3xkexla22k77fjvejn5a36dieq` | pending |
| 397 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-system-jwt` | `…qk5xvea2kd7q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa74igyfys2lvh7lhpwm2v2meorqnehfv5qk5xvea2kd7q` | pending |
| 398 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-ticket-key` | `…5wqruemnrkda` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarzcxq5rse3ehu5jyfiedlz36s2iul32v5wqruemnrkda` | pending |
| 399 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-ticket-pub` | `…ocwr2laoeedq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapwlm5ozi2zithyoj2l3p4vtp7dakvq2uocwr2laoeedq` | pending |
| 400 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-seed-founder-controller-a-founder-peer-key` | `…z3xxftva4geq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa52eob5duh7wt7qfogyl4mktqrn4pyrzrz3xxftva4geq` | pending |
| 401 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-seed-ledger-signer-controller-a-founder-ledger-key` | `…q5raem2yk25a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqbunvvo2lragpquhut544edgyx56gufoq5raem2yk25a` | pending |
| 402 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-a-controller-a-creds` | `…xugyzefsmbsa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxpjg2jugag6k6egz5v2z45lzktirtmq5xugyzefsmbsa` | pending |
| 403 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-a-controller-a-response-key` | `…avdpjnxbwn7a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5xl2vos5qx25ibnlcpsfasohddxxbglhavdpjnxbwn7a` | pending |
| 404 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-a-controller-a-tls-cert-pem` | `…svctd4dsht3q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalhfs4kmhpamixfzvuzjfsujbdxqjb6ptsvctd4dsht3q` | pending |
| 405 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-a-controller-a-tls-key-pem` | `…ponme74b5p7a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakwfcz3iyrodsoi322ijeihm7t7iyd7jyponme74b5p7a` | pending |
| 406 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-b-controller-b-creds` | `…vkxu5akjp3kq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasggioqo64x7nbgz3ldsuvf7qw7iviuq4vkxu5akjp3kq` | pending |
| 407 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-b-controller-b-response-key` | `…qcg4wuegr2qa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagl2a57owkc5f2ra5ftyd3byoepwom2t4qcg4wuegr2qa` | pending |
| 408 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-b-controller-b-tls-cert-pem` | `…43x6pdohqpkq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4pratlz5kfxqittk7e3ppbvty3amvdbu43x6pdohqpkq` | pending |
| 409 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-b-controller-b-tls-key-pem` | `…2e25rvvufpiq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazhl3eyehti23hoakskmiuqhlokeb2alu2e25rvvufpiq` | pending |
| 410 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-c-controller-c-creds` | `…hvngd5b2trla` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafcnniylx5qkugelqpl2rv3ghjmrtgj2zhvngd5b2trla` | pending |
| 411 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-c-controller-c-response-key` | `…ed26uwcflqbq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacz3i43qrsvhyvna5yapllztkrz5va5s4ed26uwcflqbq` | pending |
| 412 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-c-controller-c-tls-cert-pem` | `…mrpg7zlwgyya` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqai6pgmroufqmanfedcwcddbenodwvwatpmrpg7zlwgyya` | pending |
| 413 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-c-controller-c-tls-key-pem` | `…waial3rwphxq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabf6dhne3oizivombwwr5sp2wfgptdkn2waial3rwphxq` | pending |
| 414 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-host-issuer-shared-host-nats-issuer-seed` | `…ojsye4ghwlxa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaogf4z53bgkqbvedwosdmi4ybn6otfhr7ojsye4ghwlxa` | pending |
| 415 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-host-issuer-shared-host-tls-issuer-cert-pem` | `…3w4s3m4sbyla` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5lc2sclodwltxaxrvnbs4fctmc36jho23w4s3m4sbyla` | pending |
| 416 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-host-issuer-shared-host-tls-issuer-key-pem` | `…vurr4po2n3mq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasf5k5sk3ft63sohfn7ibbztyqeme2azevurr4po2n3mq` | pending |
| 417 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-ca-pem` | `…3ziqpjauspzq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqay6yowcljhlimh5byasiqrzhzlakbyp7s3ziqpjauspzq` | pending |
| 418 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-cell-jwt` | `…oi5gqcnnfhma` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakcklawgigdljkninpe2fms5rjuyxxoj7oi5gqcnnfhma` | pending |
| 419 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-operator-jwt` | `…uhxbzfs4wrgq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazbmgnoweuczmj3efustykxiydbtnas5uuhxbzfs4wrgq` | pending |
| 420 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-route-password` | `…j6shkylzgrqa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoehejaqkybu45rzmfepkrumjze5og3rrj6shkylzgrqa` | pending |
| 421 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-system-creds` | `…bmx2pfpzt7xa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajzgeouan5gynvsuhoe4cjix63p54gu3wbmx2pfpzt7xa` | pending |
| 422 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-system-jwt` | `…v3krhw4ameqq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarmaeddbz2g356iwguquumtua3nh3qgfjv3krhw4ameqq` | pending |
| 423 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-ticket-key` | `…to5ajcsu455a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajw4aqzt6uhqg2746v3n2lh6v6sdncqgcto5ajcsu455a` | pending |
| 424 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-ticket-pub` | `…mgxkzun7cobq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacm4shtwrzt6sercxcoytu7qfpzkokk7nmgxkzun7cobq` | pending |
| 425 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-seed-founder-controller-a-founder-peer-key` | `…lcrcwm6aprya` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasw77vee5hbiqv5egdwll6agqrzxwe62plcrcwm6aprya` | pending |
| 426 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-seed-ledger-signer-controller-a-founder-ledger-key` | `…3yqc2mf7qmyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqax7qxqz72cql5w5a5fj2eujhmrmonbrg43yqc2mf7qmyq` | pending |
| 427 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-a-controller-a-creds` | `…ygsqaw65z46q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2vcer3kzfogsigp26x2e3llikzu4thrhygsqaw65z46q` | pending |
| 428 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-a-controller-a-response-key` | `…zlnbdysxikka` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa25fnoe2zwzl5wz7kasxly6uujx2bo32ezlnbdysxikka` | pending |
| 429 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-a-controller-a-tls-cert-pem` | `…cumpl4vzjipq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah564g57xmloc4nk4wvppummi3d7467secumpl4vzjipq` | pending |
| 430 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-a-controller-a-tls-key-pem` | `…ygd6qadtlsgq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasfuony2jb3tmkw6kcyjculx23oawvua5ygd6qadtlsgq` | pending |
| 431 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-b-controller-b-creds` | `…bnooqqwen6zq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaan6obhpe4eguicj7wz56wgws2ngoo5ljbnooqqwen6zq` | pending |
| 432 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-b-controller-b-response-key` | `…wt2p2izgzqpa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5dexwxfsy7q4u7eo75x2jq2xyy2ptxwpwt2p2izgzqpa` | pending |
| 433 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-b-controller-b-tls-cert-pem` | `…avqcbarwwx4q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqac6naqspmlx4cdzm53mewobsxdvepynllavqcbarwwx4q` | pending |
| 434 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-b-controller-b-tls-key-pem` | `…7krqucfj3koa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqxhg4tk2zyge5l7t4epttxjpl7geb7uu7krqucfj3koa` | pending |
| 435 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-c-controller-c-creds` | `…6htuubnoq2mq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3v2nqqvzzuplh3vfcqxktlfsvlkuckgo6htuubnoq2mq` | pending |
| 436 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-c-controller-c-response-key` | `…7j6vesjyivwa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2jqpsqexrh2275ejuffzx43472gd3jqk7j6vesjyivwa` | pending |
| 437 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-c-controller-c-tls-cert-pem` | `…tkidux3z5ffa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahgqkocd5tgdk34qnxluff55le6ao3ji6tkidux3z5ffa` | pending |
| 438 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-c-controller-c-tls-key-pem` | `…duerbkienj3a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavk2az274lfqaj3urjm33g5cauv6swrhaduerbkienj3a` | pending |
| 439 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-host-issuer-shared-host-nats-issuer-seed` | `…j655ypi7fsia` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6gplpbw4axapuuzjgmzzrici42g3zm54j655ypi7fsia` | pending |
| 440 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-host-issuer-shared-host-tls-issuer-cert-pem` | `…42gleef2hmra` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa52aoooxs55tk7dd6cw4iomurhjlvapuo42gleef2hmra` | pending |
| 441 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-host-issuer-shared-host-tls-issuer-key-pem` | `…53ojo6zlgswq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7iapqeubfeleuqxqkjx6c26x6f6azfcl53ojo6zlgswq` | pending |
| 442 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-ca-pem` | `…7uf2kste4roq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawqmoeppygfw3cwg3i4iskmnmvw6skryk7uf2kste4roq` | pending |
| 443 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-cell-jwt` | `…467hyjxtvlfa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasal33uxclyzsilqwyw4ieveno7dozfis467hyjxtvlfa` | pending |
| 444 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-operator-jwt` | `…cvswier76rdq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2rjkmbf2uwfzjxy2lwwfzhk2tgvowdsicvswier76rdq` | pending |
| 445 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-route-password` | `…cp5wfpsbqo6a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqal3niomjiv3edw2brxvkujsvruaqzjc4xcp5wfpsbqo6a` | pending |
| 446 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-system-creds` | `…yll4tau3qvuq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa44ajrqgqen42hh4sekrpt4o3w5445yg3yll4tau3qvuq` | pending |
| 447 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-system-jwt` | `…sxhnyiyjjiyq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4d4icw7yhougyt2u6pbc6kw2zclpe2ydsxhnyiyjjiyq` | pending |
| 448 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-ticket-key` | `…563ltkfoboja` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6du3ztuy4kcwdhfpc3lfkt4lwmdz4uhw563ltkfoboja` | pending |
| 449 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-ticket-pub` | `…mqf5b6wflsoq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqunvs4gtbdwkn724wr43fo2fkyuusbjimqf5b6wflsoq` | pending |
| 450 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-seed-founder-controller-a-founder-peer-key` | `…tynwxg7ytfra` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaq75tjduanwtibndw655fpyiumlthgblktynwxg7ytfra` | pending |
| 451 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-seed-ledger-signer-controller-a-founder-ledger-key` | `…xmcm4ypy2r2q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5tm6t6mlwk75by3cyaksmmtpumvyg35qxmcm4ypy2r2q` | pending |
| 452 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-a-controller-a-creds` | `…twkqbaqa7kna` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqae2dohwb567q2cgvkh3usvaxgkakstvh4twkqbaqa7kna` | pending |
| 453 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-a-controller-a-response-key` | `…go5vhaqnkilq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaubb5zldtf44dfsny7k24zwvogoaq6trbgo5vhaqnkilq` | pending |
| 454 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-a-controller-a-tls-cert-pem` | `…uguftdsts34a` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahcjsrs4liojf66gmbwwvuavlonkbyxd5uguftdsts34a` | pending |
| 455 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-a-controller-a-tls-key-pem` | `…vo2ps2nbmecq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqairr3khyddhbv45ftkxtwcoduaawhgwsyvo2ps2nbmecq` | pending |
| 456 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-b-controller-b-creds` | `…4lkwbm2uebba` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagmylhxidc6xwuwj3tzol37ldu2tyycxv4lkwbm2uebba` | pending |
| 457 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-b-controller-b-response-key` | `…fare7qrmgp3q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahfmnbfh2ed7ucablau3pv5mroz4zgyvhfare7qrmgp3q` | pending |
| 458 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-b-controller-b-tls-cert-pem` | `…jjbrmgvsgcja` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawyknakzs54oz3kkcrv5pesdyk4yz67rnjjbrmgvsgcja` | pending |
| 459 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-b-controller-b-tls-key-pem` | `…j2ad4ehu7oea` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5wehhri6ldjf3dnzl674rsbpmomvx6zkj2ad4ehu7oea` | pending |
| 460 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-c-controller-c-creds` | `…q64ngt3e3wwq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa532jurt7wkvg2za2dbc4qarz7xrziy5yq64ngt3e3wwq` | pending |
| 461 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-c-controller-c-response-key` | `…ptlcdnmn6wha` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajubvqe4venh4l6qlecqntimee3d2o5i4ptlcdnmn6wha` | pending |
| 462 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-c-controller-c-tls-cert-pem` | `…5qubsq6hc2lq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqang6mobqnvfxkaet5it77uzyc7o5y2z2w5qubsq6hc2lq` | pending |
| 463 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-c-controller-c-tls-key-pem` | `…wmo7azgtxala` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarbnkt6wzfxfwpvfcndqvnhxqhg4ggd7pwmo7azgtxala` | pending |
| 464 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-host-issuer-shared-host-nats-issuer-seed` | `…vaexnlggqhba` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqae6kq5m5oixoodwjt2ke7ms2g4iptddjxvaexnlggqhba` | pending |
| 465 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-host-issuer-shared-host-tls-issuer-cert-pem` | `…3ulstkowxnzq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaogvknpap7t2wyindvvgou7ujw3uxsrtx3ulstkowxnzq` | pending |
| 466 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-host-issuer-shared-host-tls-issuer-key-pem` | `…qsiq45xp2wsq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxuon6qwrxeeuxnv2hk347bafj776vaxiqsiq45xp2wsq` | pending |
| 467 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-ca-pem` | `…rqvrff5p2zia` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaedx47ldcujedianoei5yqzgi3d4x5a52rqvrff5p2zia` | pending |
| 468 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-cell-jwt` | `…mjvase5cnvla` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqams6uupt3vu5v6ryobl7nhlgsyvgdtjgrmjvase5cnvla` | pending |
| 469 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-operator-jwt` | `…qe4ufdfp4bpa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaju5mfqzeeeqdcihs4tu2bnt7u2bsrfgcqe4ufdfp4bpa` | pending |
| 470 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-route-password` | `…z54hqfw3kc7q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamqiri724himvnakloxqgkcqhhxczmrtvz54hqfw3kc7q` | pending |
| 471 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-system-creds` | `…3ld33z6bhgaa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavviygjqav6j2hxmcsco2rqjgniv5r3c53ld33z6bhgaa` | pending |
| 472 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-system-jwt` | `…pazgd5oix45q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqav33cdociknkr53b7m2ghk4o3o2hxgdfepazgd5oix45q` | pending |
| 473 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-ticket-key` | `…r3me72nihqmq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7kgphw2sfxgp2r6t2e7jhm5xxu6eiz7mr3me72nihqmq` | pending |
| 474 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-ticket-pub` | `…jexfol4cx2ya` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabkrydbyhdew3f2b5ajjsp3b7oyqessdsjexfol4cx2ya` | pending |
| 475 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-seed-founder-controller-a-founder-peer-key` | `…uirssg4g33ha` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5qmjrfvpx2f4g3m3euoihem4ihgfetaluirssg4g33ha` | pending |
| 476 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-seed-ledger-signer-controller-a-founder-ledger-key` | `…fri4fdagkuia` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5wu2r6c7egskdk2xz3acroy7coseasymfri4fdagkuia` | pending |
| 477 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-a-controller-a-creds` | `…ts43gpcu4dkq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavulnrnsfofbm4lfaqo7iukafdiufarwcts43gpcu4dkq` | pending |
| 478 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-a-controller-a-response-key` | `…sbzj6y2od3ya` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagnk3cficxev4j4bqtfe5vnzxdb3xnhuhsbzj6y2od3ya` | pending |
| 479 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-a-controller-a-tls-cert-pem` | `…djic7hklyysa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavdkxpi54vyjcp2fblbi5s4nnqqqe4h3mdjic7hklyysa` | pending |
| 480 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-a-controller-a-tls-key-pem` | `…s74vlhk7uida` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavqyzkeddd2cuvbi2obft6mmz5uec5h6ds74vlhk7uida` | pending |
| 481 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-b-controller-b-creds` | `…ytwf63detara` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakvazixculrf34by2sax67oby6c4gwt2rytwf63detara` | pending |
| 482 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-b-controller-b-response-key` | `…yj7jfhfqlkkq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4melc5vlcfjydum3fmi7ghn3qxcmbkleyj7jfhfqlkkq` | pending |
| 483 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-b-controller-b-tls-cert-pem` | `…7dy6jikxw3ua` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatv3b7vihhulaomdwrjr4x6c2k7wwibrg7dy6jikxw3ua` | pending |
| 484 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-b-controller-b-tls-key-pem` | `…3ajvobwk3fta` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoy7trs4s3h7fftazgomglvpjnrzrs7jg3ajvobwk3fta` | pending |
| 485 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-c-controller-c-creds` | `…65ay7xmy5zaa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalf2wxswf5bdp7wtqr4jkwxrng6yo76y665ay7xmy5zaa` | pending |
| 486 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-c-controller-c-response-key` | `…uxeelwckp3vq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavwkcz5m3nv67wiat3sbirzqsirpcbvyguxeelwckp3vq` | pending |
| 487 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-c-controller-c-tls-cert-pem` | `…fgg3fgkxr6vq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamdyw6mvbqg6vcj33unrfn6op4r4xf5npfgg3fgkxr6vq` | pending |
| 488 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-c-controller-c-tls-key-pem` | `…vc7qqk3wn77q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqani7wupstkqru6aurivssh2m5x6g3dugivc7qqk3wn77q` | pending |
| 489 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-host-issuer-shared-host-nats-issuer-seed` | `…qvhzottnnrta` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamvf7do24d5dplshnfc463p3uv6gztl7hqvhzottnnrta` | pending |
| 490 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-host-issuer-shared-host-tls-issuer-cert-pem` | `…3uevw2ykbzvq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanzx4rqjz6vp5qzyxch6x35f5hkudaoy33uevw2ykbzvq` | pending |
| 491 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-host-issuer-shared-host-tls-issuer-key-pem` | `…c5f2hmqpga2q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakrr43qbiplaeqgd2go62rkwzckakhq4jc5f2hmqpga2q` | pending |
| 492 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-ca-pem` | `…trvlcc5anfhq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaf32qrmkunyx3owjwzydf2bglwcana4wptrvlcc5anfhq` | pending |
| 493 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-cell-jwt` | `…e5op4dasaaqa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarzuig5m4ekv7jczf3gxfst2kqyebuih6e5op4dasaaqa` | pending |
| 494 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-operator-jwt` | `…elib7t3qlqqa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqiwwmxqvv3misjzvepwsarjdo73qeawielib7t3qlqqa` | pending |
| 495 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-route-password` | `…nfwtbnrzhwia` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa364wx67jweg7l24wu4akgmibw6egjchrnfwtbnrzhwia` | pending |
| 496 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-system-creds` | `…onk3o7bmltqa` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad5gmkxhzt2zva5zsdq7kru2zrde6pnpvonk3o7bmltqa` | pending |
| 497 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-system-jwt` | `…yiwl4podg26q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqainz6daarvrej62dp2vzjj4vzkuo3pb3tyiwl4podg26q` | pending |
| 498 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-ticket-key` | `…go3oeucsdpda` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadngfb63yyvaxxh7we5sronc44tjjtprzgo3oeucsdpda` | pending |
| 499 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-ticket-pub` | `…ki3jewooxz6q` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6pqdey74rvqvglvyzdnvbpbqucz2yisuki3jewooxz6q` | pending |
| 500 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-seed-founder-controller-a-founder-peer-key` | `…mlwrxytnp4rq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadcuf7dek6ghn6wnrcc7rlhdgezbznu4rmlwrxytnp4rq` | pending |
| 501 | `ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-seed-ledger-signer-controller-a-founder-ledger-key` | `…emu5zmpjutsq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad6ffofruis2lzg2ufg35e6s6tjywlzuremu5zmpjutsq` | pending |
| 502 | `ts-preview-gru-20260926-terrabase-live-s3` | `…oypsdgng5oiq` | `ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqan6fsxu5pqhii6jftzpck7wrycogwoh4ioypsdgng5oiq` | pending |

### kms-key: 2

| # | Name | Short OCID | Full OCID | Action |
|---|---|---|---|---|
| 1 | `terrascale-control-key-gru` | `…csd4t3lddj5q` | `ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrnnobtfquqr72nookj62d552db3dmth4l2iopbxspcsd4t3lddj5q` | pending |
| 2 | `RSA wrapping key` | `…odykru3fxgsa` | `ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrshpju5q3tb37rqwcd5majo6d3crygsn2qkg3qgvpodykru3fxgsa` | pending |

### kms-vault: 1

| # | Name | Short OCID | Full OCID | Action |
|---|---|---|---|---|
| 1 | `terrascale-control-vault-gru` | `…cyr2it3qs5oq` | `ocid1.vault.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrrjahmb7sqvwq2hlh3sa75a6qbrp44mcdg4kuof7vcyr2it3qs5oq` | pending |

### compartment: 1

| # | Name | Short OCID | Full OCID | Action |
|---|---|---|---|---|
| 1 | `terrascale-control` | `…mqkbjc5nvria` | `ocid1.compartment.oc1..aaaaaaaaifvroeyjgu4l5h5gy4qzv7t6yfbcbd3fwwqxmzbamqkbjc5nvria` | held |

## Reviewed OCI keep identities: 9

| Type | Name | Short OCID | Full OCID | Why it stays |
|---|---|---|---|---|
| compartment | `TerraScale` | `…oa42ozvk7cna` | `ocid1.compartment.oc1..aaaaaaaangcm4a4gp4epa2jec7mizqkomvgjnymdrxecimlroa42ozvk7cna` | tenancy-wide parent of every regional cell; the rebuild plan parent_compartment_id |
| compartment | `ts-ops` | `…ytdgc6anlkca` | `ocid1.compartment.oc1..aaaaaaaazb4rfjdb3bfi2rdlle3smjfhcvuf5rq57qk3q3cyytdgc6anlkca` | shared: Forgejo and NetBird manager, with every resource inside it |
| instance | `ts-ops` | `…d72yjdppmuna` | `ocid1.instance.oc1.sa-saopaulo-1.antxeljrppuhpdqc53olclenle4v5cjyionsslnbelqojmund72yjdppmuna` | shared: Forgejo and NetBird manager, 10.250.10.155 |
| vcn | `ts-ops-vcn` | `…3j25pxobnr2a` | `ocid1.vcn.oc1.sa-saopaulo-1.amaaaaaappuhpdqacrdeeo2nt2raxsm5vs4wuevdt6nygxt33j25pxobnr2a` | shared: ts-ops network 10.250.0.0/16 |
| email-domain | `terrascale.tech` | `…4c2hxs7cynnq` | `ocid1.emaildomain.oc1.sa-saopaulo-1.amaaaaaappuhpdqag3fj4is2ojjloo27y3qk5tmqn4oc6zoz4c2hxs7cynnq` | shared: ts-infra Email Delivery |
| email-dkim | `terrascale-tech-dkim` | `…65eggqiaq5ea` | `ocid1.emaildkim.oc1.sa-saopaulo-1.amaaaaaappuhpdqaixwfllnm5bwdfkslodprj2f4mlgvx2pz65eggqiaq5ea` | shared: ts-infra Email Delivery |
| email-sender | `noreply@terrascale.tech` | `…bmyckngh4wya` | `ocid1.emailsender.oc1.sa-saopaulo-1.amaaaaaappuhpdqasgdychesw7ccssfsunifti2m6cs3tavcbmyckngh4wya` | shared: ts-infra Email Delivery |
| policy | `ts-forgejo-object-storage` | `…4hqp7wqdkr3a` | `ocid1.policy.oc1..aaaaaaaamagtqy5wiqbbl3yighnpqh42idawqdaswdyctpqa4hqp7wqdkr3a` | shared: Forgejo storage grant (root compartment) |
| policy | `Tenant Admin Policy` | `…a36sbv6co2sa` | `ocid1.policy.oc1..aaaaaaaa4xwb5ijqop5f3zjvcaub6v57cz3fry7vdm7ywaxca36sbv6co2sa` | tenancy-wide |

## Fresh protected ts-ops resource identities

| Type | Name | Full identity |
|---|---|---|
| instances | `ts-ops` | `ocid1.instance.oc1.sa-saopaulo-1.antxeljrppuhpdqc53olclenle4v5cjyionsslnbelqojmund72yjdppmuna` |
| block-volumes | `ts-forgejo-data` | `ocid1.volume.oc1.sa-saopaulo-1.abtxeljrftl5rmofsk5lpo43o2aaud4byu7rg2tvonqoh3i7t76hcx23pkna` |
| boot-volumes | `ts-ops (Boot Volume)` | `ocid1.bootvolume.oc1.sa-saopaulo-1.abtxeljrjnf4m3cln7mhnd6yjfr3ju3sak3mkntjgkqp2sp5ick7c72griva` |
| vcns | `ts-ops-vcn` | `ocid1.vcn.oc1.sa-saopaulo-1.amaaaaaappuhpdqacrdeeo2nt2raxsm5vs4wuevdt6nygxt33j25pxobnr2a` |
| subnets | `ts-ops-public` | `ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaalmgzqpofr7t2wjomaaqz2ou4v23ymulkec2zdgpyekxhtm3r4dpa` |
| nsgs | `ts-ops-nsg` | `ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaabtl6qvnet4njhx322ouuk7s6dyclt4iyhecwpwpxti6hwtaeqmrq` |
| route-tables | `ts-ops-public-rt` | `ocid1.routetable.oc1.sa-saopaulo-1.aaaaaaaaikzkrgryjmv2lok7zplayqp4xaqwsj6h5liaaqaes7wdtgmik3ba` |
| route-tables | `Default Route Table for ts-ops-vcn` | `ocid1.routetable.oc1.sa-saopaulo-1.aaaaaaaalsdrlwer74meox7bffk35qor4dgdzg7snzqaw6m5ldgmef6psk7q` |
| internet-gateways | `ts-ops-igw` | `ocid1.internetgateway.oc1.sa-saopaulo-1.aaaaaaaaubi6okhp3hff5uojvcszg36r4jkay6zctgyejzfmr44tkyeauona` |
| security-lists | `Default Security List for ts-ops-vcn` | `ocid1.securitylist.oc1.sa-saopaulo-1.aaaaaaaazxjyfzp2qpjvhmpblthrlaajav6tpxhsbwlrxlc7dvfxoeq7ugsa` |
| buckets | `ts-forgejo` | `namespace=grxnmoqvrcdv/bucket=ts-forgejo` |
| buckets | `ts-forgejo-backup` | `namespace=grxnmoqvrcdv/bucket=ts-forgejo-backup` |
| private-dns-zones | `public.tsforgejo.oraclevcn.com` | `ocid1.dns-zone.oc1.sa-saopaulo-1.aaaaaaaare7k5a5anxkuinbycwmh2mfdabb3sm3yodhhrx75xz46pl2nz7mq` |
| private-dns-zones | `250.10.in-addr.arpa` | `ocid1.dns-zone.oc1.sa-saopaulo-1.aaaaaaaau7srcinvddqhm5ppemkuajq7yffhkepn4vjsaqlmgjso626bb6jq` |
| ops-vnic.json | `ts-ops` | `ocid1.vnic.oc1.sa-saopaulo-1.abtxeljro7re4bsi2baknkl3iw5duxcxlayxd6ibfzl737okbfebhqw46ewq` |

## Fresh Cloudflare records: separate delete and keep decisions

| Action | Type | Name | Record ID | Content |
|---|---|---|---|---|
| approved deletion completed | A | `gru.api.terrascale.tech` | `cc03b04d0ab60d267c8a7ae98ca8cee1` | `150.230.93.187` at collection; absent after deletion |
| keep | CNAME | `terrascale-gru-20260708._domainkey.terrascale.tech` | `8d2a3e188ca53d7b2396bf3b4e985bdb` | `terrascale-gru-20260708.terrascale.tech.dkim.gru1.oracleemaildelivery.com` |
| keep | CNAME | `terrascale-gru._domainkey.terrascale.tech` | `d759cea514daadb3a73de465f3772347` | `terrascale-gru.terrascale.tech.dkim.gru1.oracleemaildelivery.com` |

## Fresh NetBird inventory: all entries stay

```json
{
  "account": {
    "network_range": "10.200.0.0/16",
    "dns_domain": "nb.ts.internal"
  },
  "dns": {
    "disabled_management_groups": []
  },
  "groups": [
    {
      "name": "All",
      "peers": 4,
      "resources": 0
    },
    {
      "name": "operators",
      "peers": 3,
      "resources": 0
    },
    {
      "name": "ts-ops-gateway",
      "peers": 1,
      "resources": 0
    }
  ],
  "peers": [
    {
      "name": "beta",
      "dns_label": "beta.nb.ts.internal",
      "ip": "10.200.186.149",
      "connection_ip": "179.124.206.245",
      "connected": true,
      "last_seen": "2026-10-03T23:20:38Z",
      "version": "v0.71.4",
      "groups": [
        "All",
        "operators"
      ]
    },
    {
      "name": "delta",
      "dns_label": "delta.nb.ts.internal",
      "ip": "10.200.87.10",
      "connection_ip": "179.124.206.245",
      "connected": true,
      "last_seen": "2026-10-04T12:09:23Z",
      "version": "v0.71.4",
      "groups": [
        "All",
        "operators"
      ]
    },
    {
      "name": "mariogk-laptop",
      "dns_label": "mariogk-laptop.nb.ts.internal",
      "ip": "10.200.72.78",
      "connection_ip": "179.124.206.245",
      "connected": false,
      "last_seen": "2026-10-04T18:50:06Z",
      "version": "0.79.0",
      "groups": [
        "All",
        "operators"
      ]
    },
    {
      "name": "ts-ops",
      "dns_label": "ts-ops.nb.ts.internal",
      "ip": "10.200.106.253",
      "connection_ip": "163.176.73.79",
      "connected": true,
      "last_seen": "2026-10-03T06:30:33Z",
      "version": "0.79.0",
      "groups": [
        "All",
        "ts-ops-gateway"
      ]
    }
  ],
  "policies": [
    {
      "name": "operators-to-ts-ops-forgejo",
      "description": "Operators → ts-ops: Git SSH 22, HTTPS 443, admin SSH 2022",
      "enabled": true,
      "rules": [
        {
          "name": "operators-to-ts-ops-forgejo",
          "enabled": true,
          "action": "accept",
          "bidirectional": false,
          "protocol": "tcp",
          "ports": [
            "22",
            "443",
            "2022"
          ],
          "sources": [
            "operators"
          ],
          "destinations": [
            "ts-ops-gateway"
          ]
        }
      ]
    },
    {
      "name": "operators-to-ts-ops-ping",
      "description": "Operators → ts-ops: ICMP ping",
      "enabled": true,
      "rules": [
        {
          "name": "operators-to-ts-ops-ping",
          "enabled": true,
          "action": "accept",
          "bidirectional": false,
          "protocol": "icmp",
          "ports": [],
          "sources": [
            "operators"
          ],
          "destinations": [
            "ts-ops-gateway"
          ]
        }
      ]
    }
  ],
  "networks": [],
  "zones": [],
  "setup_keys": [
    {
      "name": "ts-forgejo-gateway",
      "type": "one-off",
      "state": "expired",
      "valid": false,
      "revoked": true,
      "ephemeral": false,
      "used_times": 1,
      "expires": "2026-10-01T17:14:37.702047765Z",
      "auto_groups": [
        "ts-ops-gateway"
      ]
    },
    {
      "name": "netbird-routing-verification-20260930",
      "type": "one-off",
      "state": "expired",
      "valid": false,
      "revoked": true,
      "ephemeral": true,
      "used_times": 1,
      "expires": "2026-10-01T18:22:54.055615219Z",
      "auto_groups": [
        "operators"
      ]
    },
    {
      "name": "beta",
      "type": "one-off",
      "state": "overused",
      "valid": false,
      "revoked": false,
      "ephemeral": false,
      "used_times": 1,
      "expires": "2026-10-10T02:45:59.588763314Z",
      "auto_groups": [
        "operators"
      ]
    },
    {
      "name": "delta",
      "type": "one-off",
      "state": "overused",
      "valid": false,
      "revoked": false,
      "ephemeral": false,
      "used_times": 1,
      "expires": "2026-10-10T02:46:00.505230413Z",
      "auto_groups": [
        "operators"
      ]
    },
    {
      "name": "beta-fctest",
      "type": "one-off",
      "state": "expired",
      "valid": false,
      "revoked": false,
      "ephemeral": false,
      "used_times": 1,
      "expires": "2026-10-04T03:00:47.962732637Z",
      "auto_groups": [
        "operators"
      ]
    },
    {
      "name": "beta-fctest2",
      "type": "one-off",
      "state": "expired",
      "valid": false,
      "revoked": false,
      "ephemeral": false,
      "used_times": 1,
      "expires": "2026-10-04T03:30:05.95034426Z",
      "auto_groups": [
        "operators"
      ]
    },
    {
      "name": "beta",
      "type": "one-off",
      "state": "expired",
      "valid": false,
      "revoked": false,
      "ephemeral": false,
      "used_times": 1,
      "expires": "2026-10-04T19:53:27.498922111Z",
      "auto_groups": [
        "operators"
      ]
    }
  ]
}
```

## Fresh OpenBao GRU metadata: retained, deletion not approved

The following contains metadata only, without either retained secret value.

```json
{
  "current_version": 2,
  "oldest_version": 0,
  "created_time": "2026-09-30T17:14:55.502806296Z",
  "updated_time": "2026-09-30T17:20:01.692597004Z",
  "versions": {
    "1": {
      "created_time": "2026-09-30T17:14:55.502806296Z",
      "deletion_time": "",
      "destroyed": false
    },
    "2": {
      "created_time": "2026-09-30T17:20:01.692597004Z",
      "deletion_time": "",
      "destroyed": false
    }
  }
}

```

## Fresh OCI category counts

Each service list completed with exit 0. Empty CLI output for an empty list is recorded as zero; DNS zeroes also use the returned opc-total-items=0.

```text
instances-root.json	0
instances-parent.json	0
instances-control.json	0
instances-ops.json	1
block-volumes-root.json	0
block-volumes-parent.json	0
block-volumes-control.json	0
block-volumes-ops.json	1
boot-volumes-root.json	0
boot-volumes-parent.json	0
boot-volumes-control.json	0
boot-volumes-ops.json	1
vnics-root.json	0
vnics-parent.json	0
vnics-control.json	0
vnics-ops.json	1
vcns-root.json	0
vcns-parent.json	0
vcns-control.json	0
vcns-ops.json	1
drgs-root.json	0
drgs-parent.json	0
drgs-control.json	0
drgs-ops.json	0
load-balancers-root.json	0
load-balancers-parent.json	0
load-balancers-control.json	0
load-balancers-ops.json	0
network-load-balancers-root.json	0
network-load-balancers-parent.json	0
network-load-balancers-control.json	0
network-load-balancers-ops.json	0
buckets-root.json	0
buckets-parent.json	0
buckets-control.json	0
buckets-ops.json	2
private-dns-zones-root.json	0
private-dns-zones-parent.json	0
private-dns-zones-control.json	0
private-dns-zones-ops.json	2
public-dns-zones-root.json	0
public-dns-zones-parent.json	0
public-dns-zones-control.json	0
public-dns-zones-ops.json	0

```

## Live region subscriptions

```json
[
  {
    "is-home-region": false,
    "region-key": "FRA",
    "region-name": "eu-frankfurt-1",
    "status": "READY"
  },
  {
    "is-home-region": true,
    "region-key": "GRU",
    "region-name": "sa-saopaulo-1",
    "status": "READY"
  },
  {
    "is-home-region": false,
    "region-key": "SJC",
    "region-name": "us-sanjose-1",
    "status": "READY"
  }
]

```

## Full real OCI dry-run output

```text
teardown GRU sa-saopaulo-1 (dry run)
pending  vault-secret terrascale-gru-netbird-setup-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah36eekkgznp466jwk24f4zcoxpjtjvznlqs4z6zsrdta purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavwx6blcbn7q2gcajt6xgupnwzgqpoyyrurbs4brnyema purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqablebr775v5q5ukwyzv4vwxt5ouyk4c6e3i6qrrj6o6qa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaful5s246qujvepmyosgt3tainjazlcekfluo4n3ote4q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacaiax6vmccdikkjfgnspnpjqlfx3wkrht5y4kgftokyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaepjdgx7tu54wyynkw6a43ffutt5fhjftdffm5zfmuxpa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahww3kvof6bdqip5upa4ct6nxuvxhjpnszyymrugclzla purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqat4z5oqcfnvnyxr2l6vnqb6iihs77irgyx6oxumoekvja purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasclrdbiy3r2by52fu7p7tlul4yzowiuhvjvctw44rhlq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagozwawj5sv3x3h4dvabofg34yqrnzhzrvi44sfii5ana purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanidoqxbtka3tw3wq4oc3o3nu67x7ualuw4ff7cb6vada purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakl23su7zvhk2grv4ayda7vbknsy4j5jb4d3shatnlala purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarjugquzp6pqxc6dr3jt5dmzert2htjae2w74ezk7gflq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagxmj5ucszfwwqr4xrja53vuuzuqooss3jwbpffssqxta purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7s6hds2flihhfygabhsxvnog42c3oyqhabaxooyaia2q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7pudw7xybjakrsfpw3xxyn2zpwlbxsctw6vnbclr7xuq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafepumie6an67k6xjcqhaw64wx2dn7y2o33rb5ndclvka purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaawkylrpoh6yjqc6ufbbacl2mwrgbtk6ohhzel5dqezwa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafinezv6dhkm5bjdnjqxrsiribl2lwaq5g2wmxyaiyu5a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa52ydbi7rewbd7vbe7h7mba4n4e3tnygh7yj2fb5w2dwq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaahzirr2xihr5p6l7acg4ggolbufervwyardoqxjhyw6a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaejzbaxm2ytrc4wtusbv2r2eu62v7bmq3ujsqfpfq3aga purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaa2ohbvvdk6ctc4uxxtb6dmvcxcyufigdxa6vi436hmuq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqap3go3ywh6zafdojn2gf5tm7of3ys5uhb6jrvndknpwjq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalqsg6mlkbn2dgdvguuyffxwvsvulcdp73hxra5eldy7a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260926-2fa80a5cdb2e5414-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqao24c4mvpeofqzzyme5jgxqvcizhjnt2dwqs4solz5cdq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaujng3x2gyjq37r3ddyruchiwkrwnnzae6h5dcba6bfiq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6hx2nffqlretjauew4xxhyndz5b76d37qv6oa7hzniyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqak3zb4tsyx2zlkcgasw6gs665psmlbvrmv53u5gg2ulka purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadpgwj5hjzeuqkutctns6pbqv5vfqenfz63i7xieztvta purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxq6ncu727ajzlso7l3djxyci2hfcpmcivl4pru5jjqkq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxj2mks3d4yutoqnmwbzfndfy43zm64dybry65ks355gq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqav2aqyrckzc7nesmbq6zuzb2puf4u3tcn2o3quzve3ymq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaesdk44xuw3vbtookpaibua2yeuvm5qnmezpwipir74ja purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqau4ggxppwvd6ilgb4rg4tkoy2kshvrsavvhipajqi55wq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqak3vhtkyz3fhcmf4gfadjt5i3dcihuf2562fay3ijww3a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanhhntaiubserxbu3xh5fyneaz5x2osaaxxrtfncl42gq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5f3znme6qqka7yznkwshdesv5o25yeounofj2h4phxsq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafsegtfjccatx6bli3kbu34yek72gr7zbzx5yuevxkjza purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7jwcozwuzpqbrgpktl77j233qoorn6nnizainc67aida purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaen2odvux6n52nq7nmhklxnllucnjcfalr4fvp2ekkbvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayqchefeigwuq232utybar63n2vdsxw6yf65ks5yr35sa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaof2fx544v35mvz3kutbd5subckyunhx3yttq2x3yalma purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalg2vwjr77vfefaf6p4nvp6h6zcinrq4xeu3hzlfuc5na purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafabtcke4nv7trsaizihnq3w344jskoywks5sityfml3a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaomplcxe7aldml5zau52rchtcmoulsjy5zax74g7kw45a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6dftjirnhw2chddjxszej4nh2i2e2mlwoghh3j5mqbua purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazox6724qlp7vaevchpj4i7aic7kihw5nndcfuuybgomq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazj3x5zqr7d2au4jrtg2nvy3zwfcibmbvinxe6y3mupmq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaymj4pt7z27yeblq43uxr5wmgmt6sonfdejkcl63aajra purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r2-286f6daf1cb73b1f-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqateufef2aocgq26pe65rvco5wggnz3puoraijt7xj7npq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasdimglwpmnvzgm3whbuffjg2tj3b2ooj2lx4icloc6aq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa73i47dii5mznyuttkxx2gumy2pvzrxv3i6gadxnrmthq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaq5fncwh5m36uu3zxpciqfluprc5vylxoojs77mcmuvna purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqal3o2szoclycxulgeqpuzr4o3qh6vj5ox3rhvwcs3hzka purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqak42wfyrotu2dz2iwsmwrgreqyfjl7qp4ubekzqtyufda purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarhfzscmrf6plt4hyux4pwgi7phg6z6k46lv2e5tfi4ea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakf4m6oauxl5odezku45acrtfgfsaeiy4zgq3napandxq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapddiqr2xmpvmqwtxcwidwwh3hf6ogacf6mizseqsbhta purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanox5klaodqjyquqypsihby57tb2znfmtbivfqyff3xwq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazhbuhvzm2hki2jcxl2ymvh6ie7vxi73q7bj3k5ejsdua purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa363uhwoy3xgdpvjdnrcx3hdflhqtvwfj4rynfup2qhpa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawcgtro2y2mrfgfsqnjygrnjjnavy6abom5bbmvvbcyra purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqav7qhzhfu7kgd6sikadg2fiyuyo2gugjmyehl7da4lzsa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanhsbprnwqdhtbd6j7cede6fpyq64ediel4jfn4vmrzla purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2jukd7talzz3vlsmmmhunethw4dakzsl5ndrew4nlyza purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6wh62djx7f2cc6lhpu45flenshbe5srynyczaicawflq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaup5ftkc6mey6howkq25ijg33bwgoxonbqlw7yiuzth3a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqam4wm5cgz5ney5zx3j7vjhtuqm47fxp3yenpucb5hznjq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawhupgs5p2f2h5a77s6vbctcvpitthrrqb5xphtzahtuq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa544bvrz6tzsscbpvtkli4aeaqpbwwt67edbxh537srlq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaiscvxsjqxscnppqelmkdgkwoebfvr2wbw4lw3pcbclbq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqqfjmxiwfmxy2qmqk4mjr7unftvtcce7kbkzigcqkugq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqargky7so667j6rgm4e4sucdm7fxwvghibcgp3uug4xqzq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaci3ccqvpapt5j6xhfqqpmjzns32uvuo7jgkmy6y2tzza purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260928-r3-b08ace500be7ddda-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqauu2dhclzehyyvgxor5rwr5ljhntanfrc4me3vaivtp4q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2acwbvmshkrz2wyml5c4vsicf3ybh764tbn3h34smj4q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqau7sbhi6b3w5u4si3nvxzpahexqxfot2yawi6naeubnka purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalfdybw5vxtfbcewoie227mncizbwm7b536rqncampddq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadfzkjdrxqnkb34g4ohgbfszj3padbdv2yvisudk4nzdq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarjfk5aeg666iuypmkadfmtj6codggvllyac2auubn5vq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7qtsadesfqmze35rptqhfjt2uuke6rl2hh4fdz7as34a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3zfxm7ltgw6weih3is76g2zmmsw5dcml5zulxdbbnciq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoqp6vebsc5jdy6wr6jfczjlqx2f442fv2ui4wfhqizhq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabhuilw3jgp3sqngzmjh6ky2akoj3otqu4p4y56orqz3q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasogdjryfptw3xlvjfgk7dggns7yr44acc4zt73l7dl4q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaytyn5dtzdveyq2kq575z5rsnvljdldzdb7sb7zucohka purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxyjraryee2boupvvsi2r7m22yca7z7grltoihh7b73bq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakrpzqaq3lpa3wkm4fpry5ntizl2ov4x6dtho543rcagq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaw62ln7si5ddfu6veigcx4eeyr6sz46rcu3ohyruq7irq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasjdbedc5uno3l3g33dpl6lypxhoxnv6g7oa3bnpnf2sq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakand5nv7tpxyouc5ckphyvoxwlez2ojpljoc5rbboaea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2c2xzg35gxqyv7bhkaoahtt7agqf6ahwqithvrsopy4a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaawbncfxbvpz4bpy7qx6t2wnsrinefkvpltzyr4byqs2q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadu7j3k67gjf7ejc5d6bkymwqjjc27voroephv76kj54a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavhxd23kstldg3gof2xzskgh6gkrv4lddscb3o2qohbzq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqao7zo7kybapnmzsqpwswafmbdhidtkev3b37i6v4ah7nq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaazom6tmmki6wt7dlfmliio7pno3iaaepqyrixkciyrxa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabgnav2boj623nx54faetg6naz7ox5wvwxhpnluia63rq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4zydpyomualxjntwis5akcjmc3bckh5uwc4uwhmp36va purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r4-0a1db9cdf9eab688-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamknmgelxqnuamd4aq2zzyzljebljut2mq3ve57nvgu5a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacsux4fygcf6656pgyjt5epj2mdh2dzxnbaqolakqd5sq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxmgmuirgbugzvpzjpfuawmd46uraas52imgbxxw7oxrq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqav4dahzfs7f7oskiiqdqqgjlqgwpywfeupbzliexwtm3q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalpf6ynruqszh2ijq45vyalyuxi2pk4g3ukefdfeqahvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5m4a6rer6to4n5naxe2lv6osyv2wprg5u7adsh7ftora purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqancieijjhdsgzb7s5fhpo7uizazkzlytkk3mpcu6qnw5a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah57uq5f2sha2div3ri5yva2ag6pkeshtjury6fbyomwa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagraryk5usw7zdii2zodfbckl6jfc4iy6qtrzs3xs2vmq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarbziqmha7xspdge22ier2ze2ua2qee5m4nnggvmxgqyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5dahpugl6ixm6xxtjs226wlh72kttfmfxmkgpii3y5mq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabtupz6v55satqjdlezz5n54zf5udjzolnb2zmlzs2fga purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaf6pyvfwqcaq6wtp2hqek7k5szqasodqv7tkaad3kqyiq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6kokqpijke435cnur25a7yvo44xgbkjiuwbgbclrdxda purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaweuzjscyn5pe2sj367oiu7xx2xi5hpptvvfd26hyjmiq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapeew55k633y3eqa7p3fzv6rmqm5b7ne5w5o6v3kollyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6ck3q2f56iuom4kfthqod4iddygycoc5jmziq4e7fboq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa66mkzngr74ntnpgvxcryyyn7crzykggqnwqkaf6vmqwa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafnb57n7vs37bcnrpa2i3ftcbzzso3b64ejtt3esy6b2q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqauzgo4hssfybvrfjdlxwxlpzlzlr2vkksnebpvsblhtdq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3qv57ps2zkpzniktf4rduf4xinhsxbl74bkcahfgt4da purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadtm24ejn5jufwad7zodbr5hqmkrmfzelz2rjxoyiazbq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanbg5zgswdzfvejdoqamdn62qaonv3xsk7tsopg3gf6na purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatkn6w5ohwhmqfcik2eennw55j5qb4rpsbcjqjokpj4ja purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafztc5wfsi3zzoz2u5qlnatsxcpxov6pvmyipypmketsa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r5-9a014c9626e057e4-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalxsansvawffpwdfauxrglaefnst4s4qfldfnohnias4a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajdwmd6pnzatjlv7ltgh3zkzecbggv2gnjgclfk5kexia purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayyhfgoc2mhtmb4muubwi2cgy6mt23zgs6xypxo2b7ikq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakbokwwhaogg5ow7j2cx5vcmsdme4a23y46x3t5k4indq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqac4vbptqbb4ncr5h7ymwmgctzm6m3rjrtwu6j7w5vmifa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarflqwkfcg55lz77f4nuaiazagh7uq4hdzu5uhwrlpkaq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatqrlgqrzw6mywf5lsbt4vj73hg7xmk4r3tc43w5epu4a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanhg2uyttuineh4523awux7irikiqtlwlvxmshfxqm4sq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa246jvztma22q4maushlmadvcsg6kylnz5cpvhykofqea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2amp5g46twspjrdx6pcvfv3wlwurz2opmmecfhyodflq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagg2txfbgchcbqgo2cqgysuxjxetage56udrmox65orva purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacce2r4a3q7vmdywhs6b53274d5mxdeucaimymkyvk7ia purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqack3ncbpwl4wd4tujsofqepvom6doi5m7avf6mfijrrcq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah7kbddhldkdpf6utmmdkbk4jhjuuhmlxgs6xdrusipia purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahdee452onmrdr2tq7xpxydu7v4rv23bvwjwmkrmehn6q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazbek2ujfohuh4lllflnbbdvzcgb5ztkugo4scs3gpc5q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahf7gelggzhtu6yebfdo2ll4ybvlc3xe553kndnsnohia purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3p63itchyyf3rimlc2qldxcbo3wbosxtsm3exgzobnqa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahsvhzruwyz5sbp3xdkvvakvlhxdn4ku7pi4pmiqwemma purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7kmkrb5bjhpn5kux6cubw7vgqgi54zurvz35zbu2sdca purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarpuqemf32ns3uqo2ej62753l2unc4odx72zgyaz4vh5q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanfbq3mzzl3yam3zthtwx4arimqo2svmhrrvoikyjun7q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqankap7t4sr57wccwx6iik3yzl3r47cdhbica2sluu67ra purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqax55b6xy3ov75zeuntfajgi4azd2y62dwi5udcyj5kdha purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasmhw5frqbn7btijdk7bkibh6rn6gzymlqvivvffs63xq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r6-7d7eee87f16d877b-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajacxoidhjses7257n7cxsxl33syafbpj427qrsvstppq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakezw3z73x7dnrw6l6d2gvyyenipn2qknelpmzt3iqfta purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxir5prrxdupiyi25e6d2rin4gjd2jr4aupwd2zh62bva purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadxq7pzvwlrk2bv2qwflmkyuxlxdiz75irn5jlwelh6lq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqauiircsw6egbm3sz7w2btayzc6z76lke6s7vknik4gjsq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabudiv4xge7wy6v76lapa57eip6u4tmydcxdtnfwozbvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqax7lpcvmt2th7qxvpki3zay4hmj475jgggbjszuwkkeuq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah5teeeurxqualuwwymhfsbfrlivzgfyr6ue4tcd5vdta purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaw63ktfjqcbjdekqwsmt3n4uomcufwtqflo4om44ysp7a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadeccgxrygjgiw4n7jlzbxrw42opkgdd25kz5awcthnuq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqap3p4f3ng3ytat7shp3jzxyyszn7jqovvs2oj2zy5psrq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagme2k3k4k4mcdsjcmcimccp6i7qidy23qjx7ids3grxq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaigpmuzfoljehmxfz2kepbzei6pgoojy7falrlxzr7rmq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa45oy5mejjirscn53rzaxadd2qtai6jj3prrg4vr7zroq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2ujjwl3xlhq7pdonq2glq2bkzol5fbcwh6oxyh7x4zwa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaj4wuljpfplg65hzxho4ieqiyhfcwcfwbb5fwgdagqdxq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarygjhswjttcv43gs2iqoygz4hs2n5b6yfg3xsfd7keeq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2q7dxksxsqmos34nfo6z4evzwpwai2rovjzooyxf4xfq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad77erhpob2peyjyvfark6g2imbdy3ely2y4fcngrnfsq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3l6hugqbe6g6b2rc4pvarsi6tujiw7tvag2vsipjleha purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqac5oul3q3dnzzosqw3imnq27ugwvs6n4wagrotl3drznq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqai6ae4tcrforwazvn6mcrcpxecdphkeyceruiefqt3mha purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazrwrl43r2uoowf2caa6vw2lt2pjpeggw4zpx62yqjlvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamxgqcpgtii234yxkxxjlxrchkiempn4wjbuhjpeoliwq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahvxferthyk5usrqxsrirry365jotuc7jc64ri4rixqua purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260929-r9-7627350b1360bf68-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa33ngadswivdwkayrdffb6vnxhkcx6txbnltzsuxjqb6a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaskew63a47xav7xxo4xxby772zz4by6d3w5222bz247ea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2imhzifz5mg6ojcw3yhirctxb2ox3uicwjuk3nrsy4hq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7sr3fz7jpkw2s4fisg2rtfoxntotk5d4zcw3xkanslsq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqal3nez7schyklrnxwljmtkv4rxvreoswfqysym5kufkga purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaeqdcgc3ybk5z6nhprnhwpadeps47oczywso2pxyif6iq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad2vva77fu5dcnltvrzbqyfhpdadntgkorcsrbqyknkhq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqac3efbn5bgwlvmhq2ygr4f6bbapelqb6j3lv45yrgtjha purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaowss6tr6wnyecihv4h3gs27rcmtushscwaqiqtyma3gq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaif2ajtjtdlomijmtn2ius3xo5766ghkku7c476hlwp6a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarrh3d5tqyib2crteedycj2nny5hbgvkukhs6j3zsenza purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaac4vwxndu4gsagsskexdmvw57zurnva6dgsvcsh6qacq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamtznn3f64vnqfwojaff3i6qr2w5fbussda2dcugp2efq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqap5ot437ioioyxnrtx2z6drggqbqhgeqdaqcy22m6obvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavc6rchrdqsmhdfrc72hkqbkfue3cld7ec2nigitwdala purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapnn3vzjcido7bvltycuv23mjgab47sxoi6wko6jm67xq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7g5ggadpwaczn3xtjx6xueaqmfd235taiubncwlfjukq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaefevyqu6dzyl3lpi6rmia5luruzrqrziczklkiktt4va purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4m42lph4xx35cjnghubdlgej5yylvl2v4ccxkedzcaea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqax3hyrzap4qaxhxm3h5i2j2ro5ewudqpzv3iobv3xehza purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4m3s4kqw2yuexbavgj4ta3g7odfyftwrdrqbjvtfc2ia purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2nu3xf42guzobjoqs2qmy3hr2xytdjavl2ju36j3ogsa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqmz6ots43nyqkbm5v7msfcd4jbzfqap5k6mqp34byj5q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaooqa6jhrze47w2neydp373igejgj7m3b75usr2kfppnq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4gzq4kgmvf2flgxu45jaqxsi6o5kxovqskvf5p47oyaq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r10-71fcdf59eefc46b6-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqab2ge3m3svza5ckuhc65ptdn2qvkx6ivhbkzx2hpm7dnq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqc5ej4blced54247yxhgf64hg7bi7rb5zd3h7ejgcgsq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanbzeshwzvafi36u4544qf36ebqphctqsg7sxxolcbsva purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabpjogjjjm72nplicmv7fnda6ikbwly3yd6a3jcgyufoq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaiigbbyg4ddpa4juqyi6otgbz5qnoqlfzkkoxtt6voe6q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajrmkaei5cwlrx4peyvatftn3o2meh7j5g45lwvr2pmoq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqau5dr3labnunqvnsd3ogodgibfyi46e5eot4ebfb3oqyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7nvzevjzvyroi5ggslvya7gywxwb22gb54x7bh4xnsha purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavvws52ngfqo44neg5n5o7woav7aooolxpsj74tx3trca purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapfpcxd4cganpr2hxxblvz7psqhvcirle5eto53ap7fjq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajk5cufoqidtcyt3mylybuhhztzpulkfcpzqch46dohra purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazpss2rsjqut3qwndiyyibobc77xpt7d2gqzit3c6kvtq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa33jvw4mgeyylv6e2plr2oed6af53n32xbesnnplqzoja purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafr2onlqsq33o2qbfcji4kdqpboeb4pffcdnqkssc57mq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqan2accg5k3ydv7jvhri5igguuakatbnelbmoa3mahqj6a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaibrz66x3lpcc5ehiyvio346u7zugtgoufydrkoplhwrq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxe4do7yirs6ou626rhg7errwxs33i4axukongauwhtrq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqao7pzvqgpdqtumhyekrsrec4cznf5ebtulov4vvp2rlzq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqai5pr7vo2rjyuflumq6hfez5txfb5y4ksf2dubkinnh2a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoolvjq3ourtgzuxjzvdunzkf7qjnfxdy3jxfm7sn4uja purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakswlgagso44s7ha2qskjzqadmml75fcclbskpeieqwdq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxsqpugzrtgfuilzvserdwfade6qmm57p7tabluefo6gq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqap4zuk5sy33vttublazypzxjatgpj5cyq5kp4ivjflo2a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanmhtvztl2tjmhzvj4aec3mzfvkxxnztqs36pmkxq3muq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4bothekzri55rdw2huxscaenxu6x3osu36egscmcdqyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r11-f1f64302fbe987c4-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqat3i5vdr3xqqi26427ghqklz7oztb73yngyhu4i5poula purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqampmbsjilpj3a5scpyqy2zpej5pc3ba537djazujd47qq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacujnd3oq2vcdvfc3nughxjykqpfcroh4nqbtbkvziynq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadde762rgiugrb5ra44dn3vvgrhm52xdza7ad2ldskpvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2yy3mecpkdtcynui5igojiolrqwgpcalmsjuygfvtwda purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqxoqgwvzexvoumwqy2kg3azyobkomoxyxu62v2vp5mnq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavs3i6d4l3fk32bhmzsixxtv6a6tqqfstyye26zrhe6pq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatujtwwcwwivgk2dt3s7zefmphfdtuuavtkqkkdthj7pa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawrs4ztjgi53xrk45hmw5mdzbh4rssr33dm2xag6mp6kq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6zlltofn65666ltttwwzepfrqx3dklhjsfvoeojkn3vq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayf3da6n4csrrnk7es3yz4wrkkeqqjrm3ojilhshschya purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasb4prm6ylkoxyegmkbnrtsojdvkfas7l5bdzgo53n76a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqairkzyubmx3fub46zzflr6hqoete3liagjwjo4wbr7aaa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavd737no2ybsakthx3lcmqivoszpd66wjhrl54yzwwpuq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahnvk2wlktbyrssehu2mssno3w4r7vfl4gojjyndtuo4q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaysprzxuoc7qhii7qwespmqddjtsyr4oubn2kqcq6clua purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabi6nas4ysqtijptxklcjhsjdy5yfq2bta5w45qgwi4qa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacgbbcabtxumq75s2j7c5kf5fkpcj6vwwiz7vcn3onh3a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaq5kix5rwu5zb4fdmwfnd7g6jrazttcrbh4w46fjf2elq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabw5cnzzhuwkuekymyuwsirxcrqlczn7bbqjinjf4xqma purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3t7j5koaiqhslbmrkgwarbgcc3x3iyvmq2pr7uh6fwqa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahdcmmwzmivvvhjzs3zkb5dkwedwh4dkgvwwjw63rre6a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagafwuz6kdoeagtxb6ooincyury2hwkdba7ij4sg4satq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaaqk52vdw7vbuyy7pbkom65nvxiavvl7fb45gidegvwuq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqae5zbomnet5m3ktczudcteo26fnklqmbuchsrh72z5spq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r12-1f15e6a6c863a115-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqai2ofs4ksfthjem6mqh4xrjfuketjcqsiwurrgszojoja purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazftpxjp6z5zdbcidshpuoe5grxtngfxicrhhqsoccbra purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqam5k63q7d7synuxnki3orwvqc5jf5uenlrhe5yikjykvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaawt3fktgfk2fany5n4z7k2d4bwje46hf5eym5lus6fiq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatgipswzmjoyikejvfadwphyfgwk6vx3uzzkde4e4iaha purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafpodbjozahksz3zjngqircvgfe7twhkqjtwryuiboohq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaud62nz25pzy3l73epmcivelj6iidphgh73u6ci3jpsdq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamtufpooxa73bojzwfsspful5tcq37dov7fc7oxtuquia purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqxi37fqqv7zox6t3h75sv54tbfzn2durlqfkgltwwcha purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawva36x2kxowqdhqvzuk5jaxhf3mpq4rvy3lyotiqh7xa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasn6rntdql4fbgwabf2e6lx7ssrjukiezwzzyp63wjv4a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacfch2wzncdt5ta7hldevvt6rmbbh2k5r3rapbwcu7nza purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah5xx6ot7vndg6kdwxb5v5jmipl2tyicqhbjsq7ee3a4q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqauqhmnhccfgidfafqcvnkt34jfolue46v6opxsgpbzzja purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayubwl5srhkjmt45rpxec2dhbhs5asbndulngg6t5l5ma purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4j32nhd2p4q3syzkkw2ouphlzjkw72q6mxxsqowheqba purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad2pvwghd5anhhdkhlo5pw5vqo75fyfvfdrxdis2te2ka purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3t57he3qtwco6im45rclfs56lx66gcpzzlzd5a4m7hpq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavzz6vbefk6qyrh3gdgozukglben4xzdt5gormnabyrya purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaiz33ee5cvhg5fnmpqgpe3ut3urjq2cbzt5n74kyhvq5a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxjbaojh6r6efk5z74tm64jickkgdpulvy7wgnng2liuq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqhuxcoqdbkqjfq2dyic4mqjatyxxydh6j5rueazlwpsq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatwq64wumdromzwzl2njk47mg5uf3bzufn5c52kc4xoea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayy4p7ttlmxx2o5qfogbjphtw3k3nvibujqqsbz77l6yq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatmnqtvzu7uzwo5huey6e33zv6amd6rtjcno2z2za4cda purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r13-e752c63fff05f13a-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawzuhlmndkzuq24ycqkbmlguyll7rwciqoniy6v4r5bvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaavsry6rwb4lrhva5d2ujhhyknbr4kkai6ult6mqrhnda purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqar5j7jpgmoaaucxawvve4yxciqakvy3dyrvxporv4llwq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqak7nrlu7x2czonzyurtq34sr6twg3pr3wqujw66wnbthq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah53i4ffb5v7uscdbyrzhfdbmjifofom5p3dk3t2xffnq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaf5loqgxyirc2hlwa7cbdxr7aqcd3rhilwhm5wc25fola purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawgtvsell2wtnqlburibcxfizwweygzozjvnqhn73adza purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasniaqhjs3d3ylmulwnrqqinxixw72phminnkpzycpzoa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakervb265lqexmvbzmnldmyiylbuduepkog4om27z6t5a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaydmtkv52kd5gqtlrjm3bdp6ff647pe2boyvqu2qfk5aa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4nb4yqnmus2hnjf3ixunm6md6tzbxro7lgk2unlszocq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafaengg3j3iqp44ebstozggf65jo5rk5g663p35lmikea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6n3mavjz4ti63c5ft5do3rg6nonje6sz5kb4onyazisa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahpjd52ie5muwzjccushuwpqrlbtnh7rx6dlbwb5wxopa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamxf3hkarufbkvap2yzp3zp725zpokdmjdoqkilexiuyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajgvfrct7veye5aufee2n3xxs73he46u5s5edurfn3boa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadicte7bkkamui2tnka37sm55jpg55bcw3lkanpp4fiza purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaiddm7itjk3lh4gfaofy4qelo3y3ludouibanl7tjx6ea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaet7yuqnyrs7kq4ajw3w44ycajpfo4oylcmvfbked6e4q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatm4wfudv43az234jra7m7pogif4k37gabmrbeaolcaja purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayi5trbw5mnyz66efvziw3flazor6eyklsg2q6sxlr4ua purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalajqex6aiwlbijfelgt3yqo7i7mlsc4yjdf6yqlq7gfa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqactz4gigfyweveizgfvx2wetf3ox5yflhfyykaveodija purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoecmt5xrzsygshy7nbyqyd5opsr6jvkkcgtv4fbc4ieq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah63wendnh4z7xx2q42f6uulou2kk2ny6sbxkfzht2yaq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r14-c8ad81e11476c6ec-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaep2h5a2e2gl77lppm6oxwdfc2ymn7ws3f6qfpcwvslhq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawlvygrwuegtzf7feoo35wwcqg7oyvgmnsmu5aubi7wba purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaol3dk33h3iwilqnqhwscxrbn6u7kqkmuj6h24z4gjpxa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaa7fogsjybufyeo5uh66n7t4bo5d2oezozglikrr6aufa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalyzimzkw3xztyqrhxg2mddokktzgjfo63q6qsffatzkq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazsaxwe7i34oieqs2rxdiljugvf44avnyf53blukvxdea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxjf3jyv3pzb5fuiqce3iklgbvyl6s7drrt5fzwywg4la purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapaylz4fqjxqs5eh4rmutcgzloyi3id7d6fr43sw2uziq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqata6mnnybcuein3ttr4kps45cspiw5ti2ej36adu2vofa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5rbixybzpf6zopgb5cfrdagkgnmnutm7s55ftoav5rma purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayrguomfqszq5vk3cxrddmqksvwwbva366xv3amsjs3qq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxl5rtoefi5dcudzi4oexltkkgtkgdjbaqpnvnupu4mgq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa23ekhqk2iizapzj6wxkz4uarqohch4fn35tfpqu6ojgq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqan4hht6otwl7ew37onycuxv6vuitizkmzgzqroz3vivzq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqat6w6p6ynyyx4uy4kpwcmhdyct2mncbzpwppek3mqr4ya purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaw455hhlt3trhiceg5g6hvqd7nxymrupfnf2mqoffnkla purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad5nwxucqwf5zfy4vfefyto5ryfmkglnuiaa543bmw7hq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafsqtdx5l66uaw7dsdm5zf47ap6sez6ocyr66hh5qwnsq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqay4pg7c7s6ovm3gdqifebilcvj7vajqzgfnhtmir3zwfq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3d6woy6kye3vd57aiply6duqg6zp6ep5r6vn5my67h7q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa47vq24qxsm4qaohfqbhdmacfcngjpuml6fernbeogtuq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqans5tnu2kvpqp6yn2g5eszrg6hs7sxv5zkt25v2ciiaya purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxwsgto7inqxbcpmp372wnuc4wkllplwe267aqtm7t5iq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4za7c4muoxu6e35w4pun44zw6stbc7ib2dhmd76fs4yq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadv3r6czjhp753htkptvt7l26wwqucsv5matrfdot2k4q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r15-eda7f74c44f4755b-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa33lnr2svacl53z75zh6sofpupu4qw4j3nqjapfbzjctq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaz5arhkrcenwqncyuseanhaniu6r5dbznu3osre5nxjma purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacaijy73svvh5qyy7iiraebatb3zopcdhdallv2whgxlq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazvgw76c2i32oxb3pp4gsltmbpyf65nnv22g6bcxegywq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatkdr4hlkva3cjveh7cpuqtjbfs72uqxxqpbm6hi3lxaa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaovdockzrwiov5kcn6g2jl273ehfgvuk5a3xabl3n6p2a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayvgrmkrxs4fjqy6mv2d2g5hmccxdwcim2igjqskhhqda purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3jsflkfficocti4bmnhsktjjji62nmlzx5yv2az6zkka purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarec3i255pyyv2ocxgtsjoaoc763b4z6xh2nz3fbz442a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqar4kxbj6hobjrwml7eudwymnhjotiig66rc5xuqfepwca purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaivmin3vjuettysllpm3c4lcqqsxpzlkijwg4rli3alyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayomuerfspfhtron72wd45iytxchosxzqtgv62znbknta purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3cfebl4btcxzxuutddvbpfu4n44qg37zul3cehts2pnq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakdwq2vy3lmg5wdvesv6txerbua3365d4q7ec6m4vb32q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarpjke73ifgz65tu4ljzyfgrxtf3ducarn5qrdpzgkwnq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatg6fo7tfymkweccqulz7u2ugz4ujuwhnyqjt3pk5ppha purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazhqzqpxgmzjreskgprtqno55bxpsmzjvhv5f4gn6iaiq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaw3fpeijayrbjqdmpvatc6rgshd7aye2xfsy2bjb6fdiq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4qpnjytm7ifiyistmxgwtyrraify7m5c2k3ivwlsazzq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavajfp43n5maxya7x53t4iccp5kszbggta4sfog52n3aq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajs3vrlx2m7rkcmmaerewwbw3filwma7nys3phcbf62pq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaa3u34rbvd6jzl73y5ulrwxu3mobwxzbbosqbumdg4uca purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabl5r6xwxdoumfdm5gbeio5tpfho4mogshz7ktz3s5emq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqnxb3hh34wqqwk3qenw6vdwhznmegj4fwx5ylzytug3a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxwlxdagc32ur2obxpfffdon74xtyqb54bd4wm42gvcwa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r16-f7327c33bb8cc850-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqao6ycmncao5wgfe3l23zyqmslglcvmxovmgriatpsr2sq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakswvaec6ysit5s53s7pwok6h5yitjt7uk645vxmsnw6a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafjaksxrlyxdpo7njv4pgd2kkuicsd4ssrdttuqxaraya purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqay6xxg5qdcqjt4yugasc4wqjemj6qfmyvdkv6qk53r2uq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaumfprxjns6t7duiwk7mtiffd2eonzdvqpuf4g7ko2gyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqansfprnn524nsiesqmcnkxzssqx2dnho2etfwz7774yla purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3d4fxqrvvabllnoqy4h62d4qwdmzlwoic27abaullhyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaogo42nogeaq3r5nfivbnhahtzni5n5u56wxpmkfasgxq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakzfh3u2anr75fsrmcjj4wia5atujgwklbnupfyfw5fsa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoukx44diu5ncsjelxn6phoc7l72az6in75vtp4vajava purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3pd2sbcs7c2uutv5cux6bemaimcyjarnasx26rrcy2ta purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqax7cxpxnjrsnb4a6wbdtxi4lou2dqwtrz5abg2qwn673q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabvooqryaiibdxbwootlsoac5ifi4fc6czzlpoan6lnrq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarvd2x2tnjlqsxb7gdqd7ialxevzyqnsosx5hst7bmyma purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqbbkgavge3rfgy4wbdop7yldyc4leldkzr2phw65b5tq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarmybejewg5mthcj3fksldcgznjtwmgkxfqkhwyjt7ixa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatuommre46qc7udgzr4auxnxgusftjhvqzzb5cfnjyraa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqay7yu6tu5p24mnfrjbsf6fas6bjhewp754fgygu4ip4dq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapmxbqtnppf6takm2d5klt7qpmkdj62ejv5zfzmr4mocq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaokoujj6pq6xbxsmws2rszyxdh5pnkts7mshygjsnslla purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqand47oaowc5lv34lw4rv2z6md2haqajerp6fuxlkezm6a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqac4cvcgaw6psgtvaynozbi6zjacoujnlyqedkj4yljfwa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaes5p4dmx4edxef3xbgetpufk3d4jjhbq6oearrivmqga purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaur3umefhwz7fqek7mlzjnr2yj6nhkvr3euzxsgskxtvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalrfbvek65yzk4i27nyq2qzjkp5m4sh5euqejuawpasvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r17-6fb6798c297d71bc-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahpebhai34dzylcsa7jbonchpr37hfyci6oira7skxyxa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7hatu2v5zoelqrvr62vczon6shlxafiyhxmm6gwhlnca purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqjzrvgwn4i33ihc43njkg6u2o6z3kqhrtvdgn22vfifa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqhch5eixluow76jp4gzycm7lb62enifwenr3ugp2au4a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajprq4vjg7rtzrg5ggq2lbsw6z4ne2b3dtxdscjrcmtoa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapcf4cq4ovj5icemhylfyoi4cpksyw3uc6tqrqqrwl2vq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5w75i6v57kesvhffdi45lrucmqh2l2vprlrm2m3dcspq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaggsqmuyj6izb243q27jdflxwoh7rt5vjtiifdgogscsq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqfh2pddpg623j3hvkpmmimik33pcmsqer3xophrjxtbq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaplwbqh4y2yx4ev33m4ei3uf24runai5wmzvigoffp4sq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqautmaklxs2c7clhsxxkrvlnksetkr4l5qneimtqefqbca purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5l75wungkqranccivokowg64ayiiqqhnwu77f5sch2wa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaibopmjd3a66rb5qdhonzuwxuyriakcr74kzezmgcdi7q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajg63ovuahhxtlrgrm57lln7tzidtpsp42glfcb5aevoq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayacuwjgxvcr2i24lr3tsvmdb6ivgepuzxsutr4d5y6rq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafbok2zh74ewps5ewpvxocbzxo3tcxfaospd6cssf7irq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqayvvyvfj4ykzldkmksljak7i2xiclm63wnsotb5k5dsea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavnfbr4i23n4gsjekwi4i5klnrdgkwkn4ekxjxzmmsdaa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoleueyefckumnhmyc3g5uw3zn5rmszogtjxqbk64ty6a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakgion6p5d4nrli5odxyfmqpet346tg66knr5wbvlfnva purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4ij4yxliirghzunyuo3xkexla22k77fjvejn5a36dieq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa74igyfys2lvh7lhpwm2v2meorqnehfv5qk5xvea2kd7q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarzcxq5rse3ehu5jyfiedlz36s2iul32v5wqruemnrkda purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqapwlm5ozi2zithyoj2l3p4vtp7dakvq2uocwr2laoeedq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa52eob5duh7wt7qfogyl4mktqrn4pyrzrz3xxftva4geq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r18-87c8cbab3cdb91d0-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqbunvvo2lragpquhut544edgyx56gufoq5raem2yk25a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxpjg2jugag6k6egz5v2z45lzktirtmq5xugyzefsmbsa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5xl2vos5qx25ibnlcpsfasohddxxbglhavdpjnxbwn7a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalhfs4kmhpamixfzvuzjfsujbdxqjb6ptsvctd4dsht3q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakwfcz3iyrodsoi322ijeihm7t7iyd7jyponme74b5p7a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasggioqo64x7nbgz3ldsuvf7qw7iviuq4vkxu5akjp3kq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagl2a57owkc5f2ra5ftyd3byoepwom2t4qcg4wuegr2qa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4pratlz5kfxqittk7e3ppbvty3amvdbu43x6pdohqpkq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazhl3eyehti23hoakskmiuqhlokeb2alu2e25rvvufpiq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqafcnniylx5qkugelqpl2rv3ghjmrtgj2zhvngd5b2trla purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacz3i43qrsvhyvna5yapllztkrz5va5s4ed26uwcflqbq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqai6pgmroufqmanfedcwcddbenodwvwatpmrpg7zlwgyya purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabf6dhne3oizivombwwr5sp2wfgptdkn2waial3rwphxq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaogf4z53bgkqbvedwosdmi4ybn6otfhr7ojsye4ghwlxa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5lc2sclodwltxaxrvnbs4fctmc36jho23w4s3m4sbyla purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasf5k5sk3ft63sohfn7ibbztyqeme2azevurr4po2n3mq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqay6yowcljhlimh5byasiqrzhzlakbyp7s3ziqpjauspzq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakcklawgigdljkninpe2fms5rjuyxxoj7oi5gqcnnfhma purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqazbmgnoweuczmj3efustykxiydbtnas5uuhxbzfs4wrgq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoehejaqkybu45rzmfepkrumjze5og3rrj6shkylzgrqa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajzgeouan5gynvsuhoe4cjix63p54gu3wbmx2pfpzt7xa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarmaeddbz2g356iwguquumtua3nh3qgfjv3krhw4ameqq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajw4aqzt6uhqg2746v3n2lh6v6sdncqgcto5ajcsu455a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqacm4shtwrzt6sercxcoytu7qfpzkokk7nmgxkzun7cobq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasw77vee5hbiqv5egdwll6agqrzxwe62plcrcwm6aprya purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r19-13a1ac8ab9e55778-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqax7qxqz72cql5w5a5fj2eujhmrmonbrg43yqc2mf7qmyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2vcer3kzfogsigp26x2e3llikzu4thrhygsqaw65z46q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa25fnoe2zwzl5wz7kasxly6uujx2bo32ezlnbdysxikka purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqah564g57xmloc4nk4wvppummi3d7467secumpl4vzjipq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasfuony2jb3tmkw6kcyjculx23oawvua5ygd6qadtlsgq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaan6obhpe4eguicj7wz56wgws2ngoo5ljbnooqqwen6zq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5dexwxfsy7q4u7eo75x2jq2xyy2ptxwpwt2p2izgzqpa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqac6naqspmlx4cdzm53mewobsxdvepynllavqcbarwwx4q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqxhg4tk2zyge5l7t4epttxjpl7geb7uu7krqucfj3koa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa3v2nqqvzzuplh3vfcqxktlfsvlkuckgo6htuubnoq2mq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2jqpsqexrh2275ejuffzx43472gd3jqk7j6vesjyivwa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahgqkocd5tgdk34qnxluff55le6ao3ji6tkidux3z5ffa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavk2az274lfqaj3urjm33g5cauv6swrhaduerbkienj3a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6gplpbw4axapuuzjgmzzrici42g3zm54j655ypi7fsia purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa52aoooxs55tk7dd6cw4iomurhjlvapuo42gleef2hmra purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7iapqeubfeleuqxqkjx6c26x6f6azfcl53ojo6zlgswq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawqmoeppygfw3cwg3i4iskmnmvw6skryk7uf2kste4roq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqasal33uxclyzsilqwyw4ieveno7dozfis467hyjxtvlfa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa2rjkmbf2uwfzjxy2lwwfzhk2tgvowdsicvswier76rdq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqal3niomjiv3edw2brxvkujsvruaqzjc4xcp5wfpsbqo6a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa44ajrqgqen42hh4sekrpt4o3w5445yg3yll4tau3qvuq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4d4icw7yhougyt2u6pbc6kw2zclpe2ydsxhnyiyjjiyq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6du3ztuy4kcwdhfpc3lfkt4lwmdz4uhw563ltkfoboja purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqunvs4gtbdwkn724wr43fo2fkyuusbjimqf5b6wflsoq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaq75tjduanwtibndw655fpyiumlthgblktynwxg7ytfra purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r20-52708a74f3f93339-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5tm6t6mlwk75by3cyaksmmtpumvyg35qxmcm4ypy2r2q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqae2dohwb567q2cgvkh3usvaxgkakstvh4twkqbaqa7kna purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaubb5zldtf44dfsny7k24zwvogoaq6trbgo5vhaqnkilq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahcjsrs4liojf66gmbwwvuavlonkbyxd5uguftdsts34a purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqairr3khyddhbv45ftkxtwcoduaawhgwsyvo2ps2nbmecq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagmylhxidc6xwuwj3tzol37ldu2tyycxv4lkwbm2uebba purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqahfmnbfh2ed7ucablau3pv5mroz4zgyvhfare7qrmgp3q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqawyknakzs54oz3kkcrv5pesdyk4yz67rnjjbrmgvsgcja purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5wehhri6ldjf3dnzl674rsbpmomvx6zkj2ad4ehu7oea purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa532jurt7wkvg2za2dbc4qarz7xrziy5yq64ngt3e3wwq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqajubvqe4venh4l6qlecqntimee3d2o5i4ptlcdnmn6wha purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqang6mobqnvfxkaet5it77uzyc7o5y2z2w5qubsq6hc2lq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarbnkt6wzfxfwpvfcndqvnhxqhg4ggd7pwmo7azgtxala purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqae6kq5m5oixoodwjt2ke7ms2g4iptddjxvaexnlggqhba purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaogvknpap7t2wyindvvgou7ujw3uxsrtx3ulstkowxnzq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaxuon6qwrxeeuxnv2hk347bafj776vaxiqsiq45xp2wsq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaedx47ldcujedianoei5yqzgi3d4x5a52rqvrff5p2zia purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqams6uupt3vu5v6ryobl7nhlgsyvgdtjgrmjvase5cnvla purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaju5mfqzeeeqdcihs4tu2bnt7u2bsrfgcqe4ufdfp4bpa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamqiri724himvnakloxqgkcqhhxczmrtvz54hqfw3kc7q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavviygjqav6j2hxmcsco2rqjgniv5r3c53ld33z6bhgaa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqav33cdociknkr53b7m2ghk4o3o2hxgdfepazgd5oix45q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa7kgphw2sfxgp2r6t2e7jhm5xxu6eiz7mr3me72nihqmq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqabkrydbyhdew3f2b5ajjsp3b7oyqessdsjexfol4cx2ya purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5qmjrfvpx2f4g3m3euoihem4ihgfetaluirssg4g33ha purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20260930-r21-434286b2f5825d7e-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa5wu2r6c7egskdk2xz3acroy7coseasymfri4fdagkuia purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-a-controller-a-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavulnrnsfofbm4lfaqo7iukafdiufarwcts43gpcu4dkq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-a-controller-a-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqagnk3cficxev4j4bqtfe5vnzxdb3xnhuhsbzj6y2od3ya purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-a-controller-a-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavdkxpi54vyjcp2fblbi5s4nnqqqe4h3mdjic7hklyysa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-a-controller-a-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavqyzkeddd2cuvbi2obft6mmz5uec5h6ds74vlhk7uida purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-b-controller-b-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakvazixculrf34by2sax67oby6c4gwt2rytwf63detara purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-b-controller-b-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa4melc5vlcfjydum3fmi7ghn3qxcmbkleyj7jfhfqlkkq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-b-controller-b-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqatv3b7vihhulaomdwrjr4x6c2k7wwibrg7dy6jikxw3ua purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-b-controller-b-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaoy7trs4s3h7fftazgomglvpjnrzrs7jg3ajvobwk3fta purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-c-controller-c-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqalf2wxswf5bdp7wtqr4jkwxrng6yo76y665ay7xmy5zaa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-c-controller-c-response-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqavwkcz5m3nv67wiat3sbirzqsirpcbvyguxeelwckp3vq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-c-controller-c-tls-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamdyw6mvbqg6vcj33unrfn6op4r4xf5npfgg3fgkxr6vq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-controller-controller-c-controller-c-tls-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqani7wupstkqru6aurivssh2m5x6g3dugivc7qqk3wn77q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-host-issuer-shared-host-nats-issuer-seed ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqamvf7do24d5dplshnfc463p3uv6gztl7hqvhzottnnrta purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-host-issuer-shared-host-tls-issuer-cert-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqanzx4rqjz6vp5qzyxch6x35f5hkudaoy33uevw2ykbzvq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-host-issuer-shared-host-tls-issuer-key-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqakrr43qbiplaeqgd2go62rkwzckakhq4jc5f2hmqpga2q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-ca-pem ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaf32qrmkunyx3owjwzydf2bglwcana4wptrvlcc5anfhq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-cell-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqarzuig5m4ekv7jczf3gxfst2kqyebuih6e5op4dasaaqa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-operator-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqiwwmxqvv3misjzvepwsarjdo73qeawielib7t3qlqqa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-route-password ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa364wx67jweg7l24wu4akgmibw6egjchrnfwtbnrzhwia purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-system-creds ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad5gmkxhzt2zva5zsdq7kru2zrde6pnpvonk3o7bmltqa purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-system-jwt ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqainz6daarvrej62dp2vzjj4vzkuo3pb3tyiwl4podg26q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-ticket-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadngfb63yyvaxxh7we5sronc44tjjtprzgo3oeucsdpda purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-regional-shared-shared-ticket-pub ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa6pqdey74rvqvglvyzdnvbpbqucz2yisuki3jewooxz6q purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-seed-founder-controller-a-founder-peer-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqadcuf7dek6ghn6wnrcc7rlhdgezbznu4rmlwrxytnp4rq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-canary-sa-saopaulo-1-ts-preview-gru-20261001-r22-55e2194d3c66eff4-seed-ledger-signer-controller-a-founder-ledger-key ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqad6ffofruis2lzg2ufg35e6s6tjywlzuremu5zmpjutsq purge 2026-10-05T01:45:58Z
pending  vault-secret ts-preview-gru-20260926-terrabase-live-s3 ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqan6fsxu5pqhii6jftzpck7wrycogwoh4ioypsdgng5oiq purge 2026-10-05T01:45:58Z
pending  kms-key      terrascale-control-key-gru ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrnnobtfquqr72nookj62d552db3dmth4l2iopbxspcsd4t3lddj5q purge 2026-10-11T01:48:37Z
pending  kms-key      RSA wrapping key ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrshpju5q3tb37rqwcd5majo6d3crygsn2qkg3qgvpodykru3fxgsa purge 2026-10-11T01:48:37Z
pending  kms-vault    terrascale-control-vault-gru ocid1.vault.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrrjahmb7sqvwq2hlh3sa75a6qbrp44mcdg4kuof7vcyr2it3qs5oq purge 2026-10-11T01:48:37Z
held     compartment  terrascale-control ocid1.compartment.oc1..aaaaaaaaifvroeyjgu4l5h5gy4qzv7t6yfbcbd3fwwqxmzbamqkbjc5nvria waits for 505 resources inside it to be gone
keep     compartment  TerraScale ocid1.compartment.oc1..aaaaaaaangcm4a4gp4epa2jec7mizqkomvgjnymdrxecimlroa42ozvk7cna tenancy-wide parent of every regional cell; the rebuild plan parent_compartment_id
keep     compartment  ts-ops ocid1.compartment.oc1..aaaaaaaazb4rfjdb3bfi2rdlle3smjfhcvuf5rq57qk3q3cyytdgc6anlkca shared: Forgejo and NetBird manager, with every resource inside it
keep     instance     ts-ops ocid1.instance.oc1.sa-saopaulo-1.antxeljrppuhpdqc53olclenle4v5cjyionsslnbelqojmund72yjdppmuna shared: Forgejo and NetBird manager, 10.250.10.155
keep     vcn          ts-ops-vcn ocid1.vcn.oc1.sa-saopaulo-1.amaaaaaappuhpdqacrdeeo2nt2raxsm5vs4wuevdt6nygxt33j25pxobnr2a shared: ts-ops network 10.250.0.0/16
keep     email-domain terrascale.tech ocid1.emaildomain.oc1.sa-saopaulo-1.amaaaaaappuhpdqag3fj4is2ojjloo27y3qk5tmqn4oc6zoz4c2hxs7cynnq shared: ts-infra Email Delivery
keep     email-dkim   terrascale-tech-dkim ocid1.emaildkim.oc1.sa-saopaulo-1.amaaaaaappuhpdqaixwfllnm5bwdfkslodprj2f4mlgvx2pz65eggqiaq5ea shared: ts-infra Email Delivery
keep     email-sender noreply@terrascale.tech ocid1.emailsender.oc1.sa-saopaulo-1.amaaaaaappuhpdqasgdychesw7ccssfsunifti2m6cs3tavcbmyckngh4wya shared: ts-infra Email Delivery
keep     policy       ts-forgejo-object-storage ocid1.policy.oc1..aaaaaaaamagtqy5wiqbbl3yighnpqh42idawqdaswdyctpqa4hqp7wqdkr3a shared: Forgejo storage grant (root compartment)
keep     policy       Tenant Admin Policy ocid1.policy.oc1..aaaaaaaa4xwb5ijqop5f3zjvcaub6v57cz3fry7vdm7ywaxca36sbv6co2sa tenancy-wide
incomplete: gone 0, absent 0, pending 505, delete 0, held 1, keep 9

```

Package generated locally at 2026-10-04T21:06:44Z

At the original 21:06:44Z collection, no apply command had run, no live
resource had changed and this package was local only. The COS-relayed
decision and approved DNS deletion at 21:15:54Z are recorded at the top;
this updated evidence is included in the rebuild PR at the user's request.
