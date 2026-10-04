# GRU cell teardown inventory, 2026-10-04

TS-470. Read-only inventory of the old GRU cell (`sa-saopaulo-1`, private
subnet `10.251.0.0/25`) before its rebuild as `gru-1`. Taken 2026-10-04
18:40–19:15 UTC with the operator's OCI `DEFAULT` profile, the NetBird
automation PAT, and Cloudflare read access. No resource was changed.

The operator testing reset of 2026-10-03 (commits `d30f4266`, `89e31605`)
already removed most of the cell. Only resources waiting out OCI's deletion
window, their compartment, and one Cloudflare record remain.

## Sources

| Source | Call |
|---|---|
| OCI, all regions | `oci search resource structured-search` (all live states) in `sa-saopaulo-1`, `eu-frankfurt-1`, `us-sanjose-1` |
| OCI, direct lists | instances, block and boot volumes and their backups, VCNs, DRGs, LBs, NLBs, buckets, custom images, vaults, policies in the root, `TerraScale` and `terrascale-control` compartments; `iam compartment list --compartment-id-in-subtree`; `iam dynamic-group list`; `vault secret list` |
| ts-ops network | VCN, subnets, route tables, LPGs, DRGs, NSG rules, security lists, VNICs |
| NetBird | `ts-orch netbird inventory` |
| Cloudflare | `cf dns records list -z terrascale.tech --name-contains gru` |
| OpenBao | key names (no values) under `secret/homelab/infra/netbird` |

The resource search index is stale: it still lists the deleted
`terrascale-network`/`terrascale-workload` compartments and four deleted
policies as `ACTIVE`. Direct reads were used as the authority.

## Cell-owned, still present

| Kind | Name | OCID | State |
|---|---|---|---|
| compartment | `terrascale-control` | `ocid1.compartment.oc1..aaaaaaaaifvroeyjgu4l5h5gy4qzv7t6yfbcbd3fwwqxmzbamqkbjc5nvria` | `ACTIVE` |
| kms-vault | `terrascale-control-vault-gru` | `ocid1.vault.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrrjahmb7sqvwq2hlh3sa75a6qbrp44mcdg4kuof7vcyr2it3qs5oq` | `PENDING_DELETION`, purge 2026-10-11T01:48:37Z |
| kms-key | `terrascale-control-key-gru` | `ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrnnobtfquqr72nookj62d552db3dmth4l2iopbxspcsd4t3lddj5q` | `PENDING_DELETION`, purge 2026-10-11T01:48:37Z |
| kms-key | `RSA wrapping key` | `ocid1.key.oc1.sa-saopaulo-1.ffvlrlvkaaaw6.abtxeljrshpju5q3tb37rqwcd5majo6d3crygsn2qkg3qgvpodykru3fxgsa` | `PENDING_DELETION`, purge 2026-10-11T01:48:37Z |
| vault-secret × 502 | `terrascale-gru-netbird-setup-key`, `ts-preview-gru-20260926-terrabase-live-s3`, 500 × `ts-canary-sa-saopaulo-1-ts-preview-gru-*` | every OCID in the [plan](gru-teardown-20261004-plan.json) | `PENDING_DELETION`, purge 2026-10-05T01:45:58Z |
| Cloudflare DNS A | `gru.api.terrascale.tech` → `150.230.93.187` (proxied) | record `cc03b04d0ab60d267c8a7ae98ca8cee1` | points at the deleted public NLB; the IP is no longer in the tenancy |
| OpenBao KV | `secret/homelab/infra/netbird/servers-gru` | — | stale group and setup-key IDs; replaced by the operator in NetBird fresh-cell enrollment step 3 |

OCI refuses to delete a compartment that still holds a resource, so
`terrascale-control` can go only after the vault purge on 2026-10-11.

## Cell-owned, verified absent

| Kind | Evidence |
|---|---|
| compartments `terrascale-network` (`…w2igbgmgiwm7uq7awu4arpipym7y5xsw65zwlobf4xfyedykvw2q`), `terrascale-workload` (`…s46bwgh6tamohp43vvtw3xmtcwfal34tmwk3zzx3tbxtepbnq5ma`), `terrascale-production-gru-forge` (`…zrkefswryx3mwyygi27thlya4kmmcptct7mbuagvnpqjxvyls4ea`) | `DELETED`, renamed with OCI's deletion suffix |
| instances, boot and block volumes, volume backups, custom images | none in root, `TerraScale` or `terrascale-control` |
| VCN `10.251.0.0/24`, subnets, NSGs, route tables, service/internet/local peering gateways, DRGs | no VCN outside ts-ops; ts-ops has no LPG, DRG, route or rule toward `10.251.0.0/24` |
| network load balancer, load balancer | none |
| foundation buckets `ts-preview-gru-20260926-{ledger,head,backup,material}` | no bucket outside ts-ops |
| policies `terrascale-orchestrator-least-privilege`, `terrascale-control-objectstorage-key`, `terrascale-control-objectstorage-lifecycle`, `terrascale-workload-live-s3-secret` | `iam policy get`: not found |
| dynamic groups `terrascale-orchestrator`, `terrascale-workload-hosts` | `iam dynamic-group list`: empty |
| NetBird GRU server peers, `gru-servers` group, GRU policies, `gru-cell` network, `gru.ts.internal` zone, GRU setup key | inventory: 4 peers (beta, delta, mariogk-laptop, ts-ops), groups All/operators/ts-ops-gateway, no networks, no zones, no GRU setup key |
| other regions | `eu-frankfurt-1` and `us-sanjose-1` hold only tenancy-wide IAM |
| local operator state `~/.local/share/terrascale-*` | absent |

## Shared, stays

| Kind | Name | OCID | Why |
|---|---|---|---|
| compartment | `TerraScale` | `ocid1.compartment.oc1..aaaaaaaangcm4a4gp4epa2jec7mizqkomvgjnymdrxecimlroa42ozvk7cna` | parent of every regional cell; the rebuild plan's `parent_compartment_id` |
| compartment | `ts-ops` and everything in it | `ocid1.compartment.oc1..aaaaaaaazb4rfjdb3bfi2rdlle3smjfhcvuf5rq57qk3q3cyytdgc6anlkca` | Forgejo and NetBird manager |
| instance | `ts-ops` (10.250.10.155, public 163.176.73.79) | `ocid1.instance.oc1.sa-saopaulo-1.antxeljrppuhpdqc53olclenle4v5cjyionsslnbelqojmund72yjdppmuna` | Forgejo and NetBird manager |
| VCN | `ts-ops-vcn` 10.250.0.0/16, with its subnet, IGW, NSG, route tables, security list, DNS zones/view/resolver, public IP, boot and data volumes, buckets `ts-forgejo` and `ts-forgejo-backup` | `ocid1.vcn.oc1.sa-saopaulo-1.amaaaaaappuhpdqacrdeeo2nt2raxsm5vs4wuevdt6nygxt33j25pxobnr2a` | ts-ops |
| Email Delivery | domain `terrascale.tech`, DKIM `terrascale-tech-dkim`, sender `noreply@terrascale.tech`; Cloudflare DKIM CNAMEs `terrascale-gru*._domainkey` | see the [plan](gru-teardown-20261004-plan.json) `keep` list | ts-infra |
| IAM | `Tenant Admin Policy`, `ts-forgejo-object-storage`, Forgejo users and groups, tag namespace and defaults | root compartment | tenancy-wide or Forgejo |
| NetBird | manager, `ts-ops` routing peer, operator peers, `operators-to-ts-ops-*` policies | — | ts-ops |

## Repository references to the old cell

`deploy/oci-region/plan.json` (GRU plan: owner and bucket names
`ts-preview-gru-20260926*`, slots `controller-a..c`/`member-a..b`,
`10.251.0.*` addresses), `scripts/oci-preview/plan.json`,
`deploy/oci-region/testdata/preview-contracts.json`,
`deploy/netbird/{README.md,config.example.json,manager/enrollment-verification.json}`,
`deploy/image/inputs/netbird-gru.json`, `internal/netbird/manager/desired.go`,
`internal/ociregion/publicapi/public.go` (default public subnet),
`docs/region-bootstrap.md`, `docs/terrabase-deployment.md`,
`docs/continuous-delivery.md`, and historical evidence under `docs/evidence`.
The rebuild updates the plan and runbook to static names (TS-466); historical
evidence stays as recorded. ts-infra mentions GRU only as its manually
operated foundation and its Email Delivery region. ts-status probes
`https://gru.api.terrascale.tech` (`data-api-oci-gru`) and the GRU vantage.

## Teardown plan and dry run

[`gru-teardown-20261004-plan.json`](gru-teardown-20261004-plan.json) lists
the 506 OCI resources to delete and the 9 reviewed shared resources that stay.
`ts-orch oci-region teardown --plan docs/evidence/gru-teardown-20261004-plan.json`
printed [`gru-teardown-20261004-dry-run.txt`](gru-teardown-20261004-dry-run.txt):

```text
incomplete: gone 0, absent 0, pending 505, delete 0, held 1, keep 9
```

All 505 vault, key and secret deletions are already accepted by OCI; the
command only waits for them. `terrascale-control` is held until they are gone.

Read-only refresh at 2026-10-04 20:42 UTC on branch
`cos-hold/ts-470-gru-rebuild-2`, based on `325764c3` (TS-466 and TS-467
merged), reproduced the full dry run byte for byte (SHA-256
`c67c0e5822a67112f00db20ff8faed52b889652e1e62cb6ab5b6fbc69beb0b49`).
The vault's live key and secret metadata matched the cell-owned inventory;
no unknown or shared content was found. `iam region-subscription list`
identified `sa-saopaulo-1` as the ready home region; Frankfurt and San Jose
were ready non-home subscriptions. No resource was changed.

The plan records each resource's compartment (the parent for compartments).
The command checks names and compartment IDs before printing the complete
diff, including shared resources, and only then can `--apply` mutate OCI.
It rejects a kept resource whose vault or compartment is deleted, and refuses
to schedule a vault unless every remaining key and secret has a verified
name, compartment and vault binding in the live list matching the reviewed
cell-owned inventory. This check includes every tenancy compartment and
already-pending vaults, and fails if a list cannot be read. Unexpected contents
are printed as `blocked` in the dry run; no mutation is permitted. The contents
are listed and checked again immediately before scheduling a vault deletion.
Identity requests use the ready region subscription marked `isHomeRegion`;
KMS clients stay in the cell's region. Parents wait for planned child
compartments to finish deletion.
An OCI `NotAuthorizedOrNotFound` response is reported as unverified `absent`,
never complete unless its compartment is positively observed `DELETED`.

## Rebuild constraint

TS-466 keeps the plan's compartment names `terrascale-control`,
`terrascale-network` and `terrascale-workload`. Sibling compartment names are
unique, so a rebuild with those names cannot create its control compartment
until the old one is deleted, after 2026-10-11T01:48:37Z.
