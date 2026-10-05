# gru-1 rebuild plan, 2026-10-04

**Current authority:** COS relayed approval for phase 1 (now
[complete](gru-1-phase1-completion-20261004.md)) and phase 2 in gated stages.
The user's 2026-10-04 edge change approves an OCI flexible **L7 Load Balancer
`gru-1-api`**, a **Cloudflare Origin CA certificate**, and **PROXIED** records
for `gru.api.terrascale.tech` and `auth.terrascale.tech`. `gru-1-gw-1`, Caddy,
Let's Encrypt and the NLB are removed from phase 2. Use TS-486's commands
once merged, with fresh cost admission below USD 200/month and clean
preceding-stage readbacks. Deletes and terminations still need the user.

The original proposal below was prepared for TS-470 on branch
`cos-hold/ts-470-gru-rebuild-2`, based on main
`e8ea4844370334a483f687b26d2a5c4c5520b06b`. TS-466 (#148), TS-467 (#147),
and TS-468 (#146) were merged. Its phase-1 lists and pre-create observations
remain the reviewed historical basis; the phase-2 targets below reflect the
subsequent approvals and edge change.
This proposal reuses their Go CLI paths; it does not introduce a second
provisioner. [The confirmed teardown evidence](gru-teardown-dryrun-20261004.md)
records the approved Cloudflare deletion and the retained shared resources.

## Decisions and scope

1. Keep old secret purges at `2026-10-05T01:45:58Z` and key/vault purges at
   `2026-10-11T01:48:37Z`. Do not run OCI teardown apply now. After
   2026-10-11, wait for COS's request, inspect the same reviewed teardown
   plan, and apply only that old plan. New compartments and resources must
   never be added to its allowlist.
2. Create the new foundation beneath the existing TerraScale parent as
   `gru-1-control`, `gru-1-network`, and `gru-1-workload`. Each starts with
   new OCIDs; no old cell resource is adopted. Names are independent of
   release, date and rebuild attempt. Keep the attempt in ownership tags.
3. Preserve ts-ops, Forgejo, the NetBird manager/routing peer, shared disks,
   buckets, public access, tenancy-wide IAM, and ts-infra Email Delivery.
   NetBird's supported private enrollment requires **new shared-side LPG and
   additive route/NSG changes**, itemized below for explicit approval.
4. Leave `secret/homelab/infra/netbird/servers-gru` unchanged, including both
   retained versions. Generate a fresh setup key into a new owner-only local
   file and fresh OCI secret. Never overwrite or delete the OpenBao entry.
5. Use C# `operator terrabase-release` after the separate image, enrollment,
   host-configuration and asset gates pass. Process liveness is measurable;
   replication/readiness acceptance remains open for TerraBase TS-464/469.

## Phase 1: exact foundation and NetBird create list for approval

These are the only live creates requested at the first gate. All are in
`sa-saopaulo-1`; IAM writes use the tenancy's subscribed home region.
Compartment parent is the plan's recorded TerraScale OCID (`…vk7cna`).
Public API resources, images, controller material and compute are held for
later confirmation. Dependencies are ordered from top to bottom.

| Type/count | Exact names | Shape, size or configuration | Estimated USD/month |
|---|---|---|---:|
| Compartments ×3 | `gru-1-control`, `gru-1-network`, `gru-1-workload` | New children of TerraScale, distinct from old pending compartment | 0 |
| VCN ×1 | `gru-1-vcn` | `10.251.0.0/24`, network compartment | 0 |
| Service gateway ×1 | `gru-1-service-gateway` | Only `all-gru-services-in-oracle-services-network`, exact service OCID in plan | 0 |
| LPGs ×2 | `gru-1-netbird-lpg`; `ts-ops-gru-1-lpg` | New LPG in cell VCN; new LPG in existing ts-ops VCN; pair them, no LPG route table | 0 |
| Private route table ×1 | `gru-1-private-routes` | Oracle services → SG; `10.250.10.155/32` → cell LPG | 0 |
| Private security list ×1 | `gru-1-private-security` | No ingress; exact cell/services/NTP/manager egress from plan | 0 |
| Private subnet ×1 | `gru-1-private` | Regional `10.251.0.0/25`; prohibit public VNIC IPs | 0 |
| NSGs ×2 | `gru-1-controllers-nsg`, `gru-1-databases-nsg` | Exact plan rules; member peer 9443, client 9465, controller 4222/6222/8443, scoped SSH | 0 |
| Vault ×1 | `gru-1-vault` | OCI `DEFAULT` vault in control compartment | 0 (standard vault) |
| KMS key ×1 | `gru-1-key` | AES-256, HSM protection, one key version | 0 within first 20 HSM versions allowance |
| Private Standard buckets ×4 | `gru-1-ledger`, `gru-1-head`, `gru-1-backup`, `gru-1-material` | All encrypted by new key; head/material versioning enabled, ledger/backup disabled | Usage, 20 GiB growth/staging reserve = 0.51 before allowances |
| Retention rules ×2 | `ledger-retention`, `backup-retention` | One in respective bucket; 35 days, no irreversible rule lock | 0 separately |
| Dynamic groups ×2 | `gru-1-controllers`, `gru-1-hosts` | Match only new control/workload compartment respectively | 0 |
| IAM policies ×4 | `gru-1-controller-policy`, `gru-1-objectstorage-key`, `gru-1-netbird-enrollment`, `gru-1-netbird-admin-pat` | Controller scopes from native plan helper; object storage delegation to exact key; setup-key read for both groups; PAT read only for controllers | 0 |
| Vault secrets ×2 | `gru-1-netbird-setup-key`, `gru-1-netbird-admin-pat` | Fresh setup key; approved automation PAT mirror for controller reconciliation, never log values; exact-secret IAM grants | 0 separately |
| NetBird group ×1 | `gru-servers` | Only new cell server peers | 0 incremental self-hosted cost |
| NetBird network/resource/router ×1 each | `gru-cell`; `gru-cell-private-subnet`; `gru-cell/ts-ops` | `10.251.0.0/25`, router existing peer ts-ops, masquerade, metric 100 | 0 |
| NetBird policies ×2 | `operators-to-gru-cell-ops-ports`, `operators-to-gru-servers-ssh` | Operators → subnet TCP 22/4222/9465; operators → server group NetBird SSH | 0 |
| NetBird zone ×1 | `gru-cell` | Domain `gru.ts.internal`, operators distribution, TTL 300 | 0 |
| NetBird DNS A records ×10 | Exact rows below | Private static addresses, TTL 300 | 0 |
| NetBird setup key ×1 | `gru-servers` | Reusable, unlimited, never expires; auto-group only gru-servers, as TS-468 implements | 0 |

VCN creation also generates its default route table, default security list,
DHCP options, DNS resolver and default private view; subnet DNS registration
creates Oracle-owned private forward/reverse zones. Use VCN DNS label `gru1`
and private subnet label `private` (`private.gru1.oraclevcn.com`). Capture all
generated identities in the foundation inventory, with no separate resource
charge. Configure/rename the new default route table and security list to
the planned private names before attaching the subnet rather than creating
redundant tables/lists. Keep the DHCP options on OCI's VCN resolver. These
are newly generated cell children, never the shared ts-ops defaults.

| NetBird DNS name | A record contents |
|---|---|
| `ctl-1.gru.ts.internal`, `ctl-2.gru.ts.internal`, `ctl-3.gru.ts.internal` | Respectively `10.251.0.11`, `.12`, `.13` |
| `db-1.gru.ts.internal`, `db-2.gru.ts.internal` | Respectively `10.251.0.21`, `.22` |
| `nats.gru.ts.internal` | Three records: `10.251.0.11`, `.12`, `.13` |
| `terrabase.gru.ts.internal` | Two records: `10.251.0.21`, `.22` |

Required updates, also requiring explicit approval with the foundation:

| Existing target | Exact additive change | Preservation and verification |
|---|---|---|
| `ts-ops-public-rt` (`…wdtgmik3ba`) | `10.251.0.0/25` → new `ts-ops-gru-1-lpg` | Save table/ETag; preserve every other rule, especially default IGW route; update with `--if-match`; read back |
| `ts-ops-nsg` (`…i6hwtaeqmrq`) | Stateful ingress from `10.251.0.0/25`: TCP 443 and UDP 3478 | Preserve public and owner rules, public IP, source/destination checks and services; read back |
| NetBird DNS settings | Add `gru-servers` to `disabled_management_groups` | Retain existing settings and shared policies/peers; no other account changes in observed sync diff |

The read-only `netbird sync` on main produced **18 changes**: 17 creates
above (excluding the later setup key) and the DNS settings update. It
reported only the expected missing setup-key warning. Shared ts-ops policies
were already converged. Setup-key planning requires the newly created group,
so that call follows confirmed sync and readback. No NetBird apply was run.
Full dry-run output SHA-256:
`42c701e52f8de600dc1d0ef39785021b782548dfc3310fce96b65dc2c2baf73d`.

```text
plan: create group gru-servers
plan: create network gru-cell
plan: create network resource gru-cell-private-subnet (10.251.0.0/25)
plan: create network router gru-cell/ts-ops
plan: create policy operators-to-gru-cell-ops-ports
plan: create policy operators-to-gru-servers-ssh
plan: update dns settings disabled_management_groups (gru-servers)
plan: create dns zone gru-cell (gru.ts.internal)
plan: create dns record ctl-1.gru.ts.internal A 10.251.0.11
plan: create dns record ctl-2.gru.ts.internal A 10.251.0.12
plan: create dns record ctl-3.gru.ts.internal A 10.251.0.13
plan: create dns record db-1.gru.ts.internal A 10.251.0.21
plan: create dns record db-2.gru.ts.internal A 10.251.0.22
plan: create dns record nats.gru.ts.internal A 10.251.0.11
plan: create dns record nats.gru.ts.internal A 10.251.0.12
plan: create dns record nats.gru.ts.internal A 10.251.0.13
plan: create dns record terrabase.gru.ts.internal A 10.251.0.21
plan: create dns record terrabase.gru.ts.internal A 10.251.0.22
warning: expected one unrevoked setup key named gru-servers, found 0
18 changes planned; rerun with --apply to apply them
```

## Phase 2: approved targets, gated on merged commands and qualified inputs

| Type/count | Static target names | Shape/size | Monthly USD before free allowances |
|---|---|---|---:|
| Qualified custom ARM64 image ×1 | `gru-1-arm64` | Maximum 10 GiB OCI billable storage; pin final QCOW2/receipt/source/kernel digests first | ≤0.255 |
| Controllers ×3 | `gru-1-ctl-1`, `gru-1-ctl-2`, `gru-1-ctl-3` | Each A1 Flex, 1 OCPU, 6 GiB, 50 GiB boot; private `.11/.12/.13`; FD 1/2/3 | Compute 13.68 + boot 2.125 each |
| C# database hosts ×2 | `gru-1-db-1`, `gru-1-db-2` | Each A1 Flex, 1 OCPU, 6 GiB, 50 GiB boot + 50 GiB data; private `.21/.22`; FD 1/2 | Compute 13.68 + disks 4.25 each |
| Boot volumes ×5; data volumes ×2 | Boot attached to each static host; data `gru-1-db-1-data`, `gru-1-db-2-data` | 350 GiB total, 10 VPUs/GiB; included in host rows | 14.875 total |
| Primary VNICs ×5; NetBird enrolled peers ×5 | Each host's static name above | Private IPs and corresponding static peer_names | 0 separately |
| Public L7 Load Balancer ×1 and required network/NSGs | `gru-1-api`; network/NSG names from merged TS-486 plan | OCI flexible L7 LB; exact bandwidth range, listeners, host routing and private backends from TS-486 | Recompute LB charges in native admission before edge creation |
| Cloudflare Origin CA certificate ×1 | Covers `gru.api.terrascale.tech` and `auth.terrascale.tech` | TLS certificate for the OCI L7 LB; parameters from TS-486 | Include any applicable charges in the edge estimate |
| Cloudflare DNS records ×2 | `gru.api.terrascale.tech`, `auth.terrascale.tech` | **PROXIED**, pointing at the new LB's read-back public address | Include any applicable charges in the edge estimate |

OCI generates immutable IDs for boot volumes/VNICs. Pin them per slot after
creation; static host display/host/peer names follow TS-466. Do not launch
controllers B/C manually: controller A's signed founder plan owns them after
handoff. C# database provisioning/enrollment requires a reviewed path without
`managed_oci`, `managed_placement` or `managed_member` Rust bindings; the
current managed host setup is not such a path. Do not use it to create these
hosts or claim that changing the plan's role list changes runtime enrollment.

Controller material publication creates versioned Vault secrets and bootstrap
objects through the existing signed flow. Their precise names, digests,
versions and count must be derived from generated material and reviewed in a
separate confirmation package before publication. Do not substitute invented
static secret names for the publisher's binding scheme. Do not create the
legacy `gru-1-host-live-s3-secret` policy or a LiveS3Credential merely to pass
Rust-oriented inspection; that plan field is reserved/unbound. The current
foundation inspector still requires those Rust-era fields and public API
readback; it will intentionally refuse the incomplete phase-1 plan. C#
bootstrap support must resolve that requirement before seed launch. Its
inventory admission also currently identifies workload instances through
managed-member ownership tags; a C# host path must retain explicit ownership
and cost checks while avoiding the runtime's Rust placement bindings.

The public edge follows the approved L7 design above. Use TS-486 once merged
for the flexible LB, Origin CA and proxied records; the current `public-api`
NLB implementation and unbound legacy plan fields are not the GRU rebuild
path. Do not create a gateway host or hand-roll the replacement feature.
Read back the LB, certificate binding, backends and public address before
creating the two approved proxied records. TS-487 supplies the ts-auth
deployment. ts-status's `data-api-oci-gru` remains unavailable until that
endpoint and probe succeed.

## Cost basis and admission

Use the rates already in `plan.json`, 720 hours/month, and 10 VPUs/GiB.
Five cell hosts total **5 OCPUs, 30 GiB RAM, 250 GiB boot + 100 GiB data**.
Compute is **68.40/month**, disks **14.875/month**: **83.28/month** rounded,
before free allowances. Phase 1 has no compute/disks; its 20 GiB object
growth/staging reserve is **0.51/month** before allowances. Empty buckets have
no storage charge. Standard vault and one HSM key are estimated at zero
within the first 20 key-version allowance; verify current pricing/usage
before confirmed creation. Do not select a virtual private vault.

The existing native estimator includes shared ts-ops (2 OCPUs/4 GiB and
100 GiB disks) and the plan's object, overlap, requests, egress, snapshot and
miscellaneous reserves. Using fresh live bucket sizes and one ≤10 GiB image,
the planning envelope is **128.66/month before free allowances**, or
**91.41/month** under the native
estimator's 1,500 free OCPU-hours, 9,000 free GiB-hours, 200 GiB block and
10 GiB object allowances. The actual pre-create native admission below is
**91.15/month**, with no image yet; the extra 0.255 is the proposed maximum
image storage, to be recomputed from authenticated import readback.
Additional tenancy usage can consume those allowances;
the conservative envelope does not require them. Both figures include
shared costs, reserves and image storage; neither is a spending cap. **These
five-host figures exclude the new flexible L7 LB charges.** Add TS-486's
exact bandwidth configuration and cost before the edge admission. There is
no gateway-host compute or boot-volume charge in the revised plan.

Real read-only inventory completed at `2026-10-04T21:34:42.535669Z`: all three
new compartment names were absent, with 11 shared OCI resources, two protected
buckets and no scoped custom images. `ts-forgejo` held 72,823,234,329 bytes;
`ts-forgejo-backup` held 46,167,014,592 bytes. The estimator uses these live
sizes rather than the plan's smaller historical baseline. Native `preview
admit` succeeded at `2026-10-04T21:34:58.822475Z`, expiring at
`2026-10-04T21:49:58.822487Z`: total **91.15**, ceiling **200**, headroom
**108.85** USD/month. These reads authorize no mutation.

| Evidence | SHA-256 |
|---|---|
| `deploy/oci-region/plan.json` | `31c021753154227923400d1493238c7e952bf8d45f2e849313cf0a2b8527c606` |
| `/tmp/ts470-rebuild-inventory-20261004.json` | `cc5ad94591090e39a8a47b4c8623f59536292ec79ae74f5a83a3c780436764f2` |
| `/tmp/ts470-rebuild-cost-admission-20261004.json` | `59c89a8c3f584fcbaf0d10939464c9f636c99cb1e22c1cc8ca46e8bbd1a5fd86` |

Native estimate items in USD/month: compute 58.6200; block storage 10.6250;
replacement compute 1.3680; replacement storage 0.4250; object storage
3.0809; image storage 0.0000; requests 0.6100; egress 2.5000; snapshot
reserve 8.9250; miscellaneous reserve 5.0000. Read-only OCI A1 core
resource-availability in the planned AD returned **248 available, 2 used**.
The five-host proposal needs 5 additional cores; quota availability does not
guarantee physical placement capacity.

Capture fresh real inventory and run native `preview admit`/`estimate` before
each approved stage; admission expires after 15 minutes. Recompute with OCI's
actual image billableSizeInGBs. Preserve the **USD 200/month** ceiling; OCI
capacity or quota rejection must hold the stage rather than change shape,
counts or region without a new plan. Foundation work is estimated at
**30–60 minutes after approval**; image/seed/host qualification at **60–120
minutes after prerequisites are available**. ARM64 release and replication
dependencies have no established completion date.

## Execution gates and supported commands

1. **Foundation gate.** Obtain COS-relayed approval for phase 1 and its
   shared additive updates. Capture live before-state/ETags; create only the
   listed resources through the OCI CLI/native commands; record new OCIDs in
   a reviewed plan copy. Use the [gateway runbook](../region-bootstrap.md#operator-gateway-peering)
   with this proposal's names. Confirm private routes, peer CIDRs and exact
   NSG readback, preserving ts-ops's default route and services.
2. **NetBird gate.** After approval, `ts-orch netbird sync --pat-file "$PAT"
   --apply`, then `ts-orch netbird setup-key --pat-file "$PAT" --out "$KEY"
   --apply`. `$PAT` and new `$KEY` are owner-only local files outside Git.
   Mirror the fresh setup key and automation PAT into the two approved OCI
   secrets via owner-only input files, never command-line values. Fill
   `plan.netbird` and `netbird-gru-1-pending.json` with authenticated fresh
   OCIDs. The pending template intentionally fails native validation while
   unbound. Replace the old image enrollment input and refresh its SHA-256
   pin only after exact grants and secrets are read back. The old image
   input references the pending-deletion secret (`…lqs4z6zsrdta`); **do not
   build or launch the rebuild from it**. Leave OpenBao unchanged.
3. **Image/seed gate.** Prepare and review the qualified ARM64 image,
   signed genesis/founder plan, fresh controller material and exact launch
   input with the [bootstrap sequence](../region-bootstrap.md#bootstrap-sequence).
   Run `preview inventory`, `admit`, and `inspect-foundation` only once the
   C# inspector prerequisites are supported and fully bound. Run
   `bootstrap generate-controller-material` locally; propose its exact
   secrets/objects before `bootstrap provision-controller-material`. Propose
   image import and controller-A seed with pinned digests, then let A form
   B/C after the explicit handoff. The listed phase-2 creates are approved
   per stage; unlisted controller-material secrets/objects retain their
   separate confirmation gate.
4. **C# gate.** Verify an actual `terrabase-linux-arm64` release and full
   source SHA. Generate the member CA locally with `ts-orch terrabase
   member-ca --cell gru-1 --out "$CA_DIR"`; install its key/cert on all
   controllers, inject/sign CA fields and the checked-in
   `deploy/oci-region/terrabase-gru-1-profile.json`, then register both hosts
   as role `terrabase` without Rust placement bindings. The bootstrap
   renderer does not automate those inputs today. Capture exact changed
   configs and C# asset pins before rollout approval. After clean host
   readbacks, use merged TS-486 for the approved L7 LB/Origin CA/proxied DNS
   edge and merged TS-487 for ts-auth. Refresh cost admission with the LB
   charges and verify every edge resource before advancing.
5. **Verification gate.** Confirm three healthy controllers; five connected
   static NetBird peers; clean `sync`/`prune-peers` dry runs; both C# members
   reporting the approved digest; peer-port/client-port reachability; and
   ts-status probes through the approved operator route/public endpoint.
   Capture evidence in `docs/evidence`. Replication needs real write/read
   convergence and fault/recovery tests once TerraBase implements it; a
   `running` report does not satisfy that acceptance.

After the C# gate and separate rollout confirmation, the supported deployment
command is (prepared, not executed):

```sh
ts-orch operator terrabase-release \
  --config "$OPERATOR_CONFIG" \
  --binary "$RELEASE_DIR/terrabase-linux-arm64" \
  --sha256 "$RELEASE_DIR/terrabase-linux-arm64.sha256" \
  --source-checkout "$RELEASE_DIR/terrabase" --commit "$TERRABASE_COMMIT" \
  --environment canary --profile deploy/oci-region/terrabase-gru-1-profile.json \
  --wait 10m
```

`RELEASE_DIR`, `TERRABASE_COMMIT` and the operator grant must be verified
inputs, not placeholders in a live invocation. The retired Rust
`operator terrabase-deploy` is not the rebuild path. No rollout is authorized
by merging this plan PR.
