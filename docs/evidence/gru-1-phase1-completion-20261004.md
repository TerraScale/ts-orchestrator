# TS-470: gru-1 phase-1 completion, 2026-10-04

**Phase 1 is complete.** All approved foundation, storage, IAM and NetBird
resources were created and independently read back. NetBird's final native
dry run reports `no changes`, with no warnings. No image, controller,
database host, data volume, public load balancer or Cloudflare record was
created during phase 1. The resource bindings are in
[bound-plan.json](gru-1-phase1-completion-20261004/bound-plan.json); the
checked-in regional blueprint and pending enrollment template stay unbound.

## Authority, source and execution

COS relayed approval for the exact phase-1 list in
[the merged proposal](gru-rebuild-plan-20261004.md), then explicitly instructed
completion after the recorded local preparation failure. The
[stopped snapshot](gru-1-phase1-20261004.md) remains historical evidence;
its original halt was archived as `HALTED-20261004T223259Z-resumed` before
resuming. Each live block checked for an active `HALTED` marker and used an
error trap that would halt subsequent mutations. Every resumed creation
and its resulting independent readback succeeded; separate read-only
verification command errors are recorded below.

Execution used `/tmp/ts470-phase1-ts-orch`, built from clean main
`052a96bebdb871edd197e4efaed216829ba8f04f` with `vcs.modified=false`.
OCI calls used the DEFAULT API-key profile. Regional calls and identity
writes used `sa-saopaulo-1`, independently verified as the tenancy's home
region by [region subscriptions](gru-1-phase1-completion-20261004/region-subscriptions.json).
Ownership tags remain `terrascale-cell=gru-1`,
`terrascale-owner=ts-470-gru-rebuild-2`, `terrascale-ticket=TS-470`.

The resumed [execution log](gru-1-phase1-completion-20261004/execution.log)
records UTC start and verification timestamps. The original foundation
ran from 22:09 through its 22:32 halt. Resume verification started at 22:49;
the remaining creates ran from 22:54 to 23:11. The Object Storage key grant
was read back and allowed over two minutes to propagate before bucket creation.
Clerical errors in later **read-only** verification commands (OCI CLI noun/
option spelling and an unnecessary `jq` aggregation) were corrected; these
commands made no mutation requests. A preservation comparison also excluded
volatile NetBird connection status after an existing operator laptop connected.

## Cost admissions and immutable inputs

Each admission comes from the native `oci-region preview inventory` and
`preview admit` commands, with immutable plan snapshots and inventory hashes.
The ceiling is **USD 200/month**; the native five-host forecast is
**USD 91.16/month**, with **USD 108.84 headroom**. The estimate includes
shared ts-ops and storage, five planned hosts/disks and reserves; it is not
phase-1 accrued spend or a spending cap. Phase-1 empty buckets, networking,
IAM and secrets have no separate fixed resource fee. The DEFAULT vault and
one HSM key version use the proposal's first-20-version allowance assumption.

| Admission | Admitted / expiry UTC | Plan snapshot | Purpose |
|---|---|---|---|
| [Resume](gru-1-phase1-completion-20261004/resume-admission.json) | 22:53:25 / 23:08:25 | [resume-precreate-plan.json](gru-1-phase1-completion-20261004/resume-precreate-plan.json) | Policies, buckets/retention, dynamic groups, NetBird sync |
| [Credentials stage](gru-1-phase1-completion-20261004/secrets-stage-admission.json) | 23:08:13 / 23:23:13 | [secrets-stage-plan.json](gru-1-phase1-completion-20261004/secrets-stage-plan.json) | Fresh setup key, two secrets, two exact-secret policies |
| [Final](gru-1-phase1-completion-20261004/final-admission.json) | 23:18:49 / 23:33:49 | [final-admission-plan.json](gru-1-phase1-completion-20261004/final-admission-plan.json) | Completed foundation inventory; refresh before the next stage |

The final native inventory includes the four new buckets and both shared
Forgejo buckets. Retention stays **35 DAYS and unlocked** on ledger/backup;
head/material have versioning Enabled, ledger/backup Disabled. All four
are private Standard buckets encrypted with the exact new HSM key.
The image is not yet included as a live imported resource. A maximum
10 GiB image adds at most USD 0.255/month at the plan's storage rate.
The approved OCI flexible L7 Load Balancer must be incorporated into TS-486's
reviewed plan and cost model before its admission, including its bandwidth
range and charges. The five-host forecast excludes that load balancer and
must not be represented as a final public-edge total.

## OCI identities and readbacks

There are **28 named OCI resources/rules** in the approved foundation.
The following full IDs are independently verified, rather than inferred
from name matches. Original creation and readback responses stay in the
[initial evidence directory](gru-1-phase1-20261004/); remaining creates and
fresh checks are in the [completion directory](gru-1-phase1-completion-20261004/).

The five OCI-generated DHCP/DNS children retain the full identities recorded
in the [original generated-resource table](gru-1-phase1-20261004.md#created-resources-and-independent-readbacks).
They remain scoped to the new network compartment; no additional manual
OCI DNS record or redundant route table/security list was created.

| Type | Name | Full ID | State/configuration | Independent readback |
|---|---|---|---|---|
| compartment | gru-1-control | ocid1.compartment.oc1..aaaaaaaaypdff62jbchkojfli5i22ybzm3qnptwwsbg3aa2t5ali6te52nzq | ACTIVE | [readback](gru-1-phase1-completion-20261004/compartment-control-resume-readback.json) |
| compartment | gru-1-network | ocid1.compartment.oc1..aaaaaaaalwvfqxlo5qul4f4xehx3rct5yk5dv673rlz5tqern4zd6kzjvu4a | ACTIVE | [readback](gru-1-phase1-completion-20261004/compartment-network-resume-readback.json) |
| compartment | gru-1-workload | ocid1.compartment.oc1..aaaaaaaazbzmxwi73zezjytvpp6dq3r4ys2t6akch6shdmsvwpgqnyoglzaa | ACTIVE | [readback](gru-1-phase1-completion-20261004/compartment-workload-resume-readback.json) |
| vcn | gru-1-vcn | ocid1.vcn.oc1.sa-saopaulo-1.amaaaaaappuhpdqaqb5yhudvuikbvcowjufiue2wi5jx72xujzulqkq6jvhq | AVAILABLE | [readback](gru-1-phase1-completion-20261004/vcn-resume-readback.json) |
| servicegateway | gru-1-service-gateway | ocid1.servicegateway.oc1.sa-saopaulo-1.aaaaaaaa6eqxxbtbzjg4xjhdtgatk77l5xtuufapm6hoxwdfjmiuimthuuxq | AVAILABLE | [readback](gru-1-phase1-completion-20261004/service-gateway-resume-readback.json) |
| localpeeringgateway | gru-1-netbird-lpg | ocid1.localpeeringgateway.oc1.sa-saopaulo-1.aaaaaaaayqdnpy77rzq2xvcfdlk356qchcj7hcsfysuyogxfozvffmeauhyq | AVAILABLE | [readback](gru-1-phase1-20261004/lpg-cell-peered.json) |
| localpeeringgateway | ts-ops-gru-1-lpg | ocid1.localpeeringgateway.oc1.sa-saopaulo-1.aaaaaaaaull5hl6p45bcresgenubvy3taefyid4kdvshbzpz4ox7uulnnu4a | AVAILABLE | [readback](gru-1-phase1-20261004/lpg-ops-peered.json) |
| routetable | gru-1-private-routes | ocid1.routetable.oc1.sa-saopaulo-1.aaaaaaaau4evg57oq3pjgion2qewtiy427gpvhj4ayvpmft55sbfwkdo4aoa | AVAILABLE | [readback](gru-1-phase1-completion-20261004/private-route-resume-readback.json) |
| securitylist | gru-1-private-security | ocid1.securitylist.oc1.sa-saopaulo-1.aaaaaaaa2m2udyy7rrdxgchgplt36tb6z4oao5kkt2eyfcg7xtiufdr6yqha | AVAILABLE | [readback](gru-1-phase1-completion-20261004/private-security-resume-readback.json) |
| subnet | gru-1-private | ocid1.subnet.oc1.sa-saopaulo-1.aaaaaaaaozmgldnfcv6ed4hvk2p6e5dxx4lj7aql42suvjhd4sssuosvgrcq | AVAILABLE | [readback](gru-1-phase1-completion-20261004/private-subnet-resume-readback.json) |
| networksecuritygroup | gru-1-controllers-nsg | ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaalt5nfmgj43snm7uwhatkudk5n7463vd4mgw7idu52dyfqoawfxba | AVAILABLE | [readback](gru-1-phase1-20261004/nsg-controllers-readback.json) |
| networksecuritygroup | gru-1-databases-nsg | ocid1.networksecuritygroup.oc1.sa-saopaulo-1.aaaaaaaacr2go56he4w3gz4a2v3kuavn4of46hr73n54s67vsblh226hphuq | AVAILABLE | [readback](gru-1-phase1-20261004/nsg-databases-readback.json) |
| vault | gru-1-vault | ocid1.vault.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr7ebplea4ua3memgthsupcfn3crg6d56vipsw7o2butchdrx3urmq | ACTIVE | [readback](gru-1-phase1-completion-20261004/vault-resume-readback.json) |
| key | gru-1-key | ocid1.key.oc1.sa-saopaulo-1.ffvmfu2naagt6.abtxeljr57gu27ray2ukib2irijktpd6eqa6ou5zeqstsmasvqcr7hmfu2ia | ENABLED | [readback](gru-1-phase1-completion-20261004/key-resume-readback.json) |
| bucket | gru-1-ledger | ocid1.bucket.oc1.sa-saopaulo-1.aaaaaaaabo2rgaha4aipromni7xlycj6h6naxuzyx66sv5dg2hc5eh2uh7rq | private Standard; Disabled | [readback](gru-1-phase1-completion-20261004/bucket-ledger-readback.json) |
| bucket | gru-1-head | ocid1.bucket.oc1.sa-saopaulo-1.aaaaaaaacyfv72dwi7i4lzlqoqkrwgrchshwyd27q73ow545edbaodta5qda | private Standard; Enabled | [readback](gru-1-phase1-completion-20261004/bucket-head-readback.json) |
| bucket | gru-1-backup | ocid1.bucket.oc1.sa-saopaulo-1.aaaaaaaatqi3yaului46jaitulx2nceewvb656p2ldiusd4ext6vi3glrg2q | private Standard; Disabled | [readback](gru-1-phase1-completion-20261004/bucket-backup-readback.json) |
| bucket | gru-1-material | ocid1.bucket.oc1.sa-saopaulo-1.aaaaaaaaxv6xjdruu4kgdl6sov75e2o6dkfbnrta652fhgfepxqjblkktska | private Standard; Enabled | [readback](gru-1-phase1-completion-20261004/bucket-material-readback.json) |
| retention rule | ledger-retention | ea20e32a-8a92-471a-a8e6-e0d7821b4c86 | 35 DAYS; unlocked | [readback](gru-1-phase1-completion-20261004/retention-ledger-readback.json) |
| retention rule | backup-retention | 815f8687-54f9-47af-859e-c09d8156794b | 35 DAYS; unlocked | [readback](gru-1-phase1-completion-20261004/retention-backup-readback.json) |
| dynamicgroup | gru-1-controllers | ocid1.dynamicgroup.oc1..aaaaaaaagrzcjyxnxf4uabwca7munbukusn3nvnhvnnkquk66gxb36jvu47q | ACTIVE | [readback](gru-1-phase1-completion-20261004/dynamic-group-controller-readback.json) |
| dynamicgroup | gru-1-hosts | ocid1.dynamicgroup.oc1..aaaaaaaazgthpwxmpjls4lrxqxbpv66dyxqsxjn423ieny6s7otuuliukolq | ACTIVE | [readback](gru-1-phase1-completion-20261004/dynamic-group-host-readback.json) |
| policy | gru-1-controller-policy | ocid1.policy.oc1..aaaaaaaa3q47uueq3c7oqaglwqlnjgmb5tjbbhz2vomxvkpyyic6rlsqpfoq | ACTIVE | [readback](gru-1-phase1-completion-20261004/controller-policy-readback.json) |
| policy | gru-1-objectstorage-key | ocid1.policy.oc1..aaaaaaaaqyet7moovg7nnsy365k3ftw7dtdzk4xphgiva5kbenagaa36j2ga | ACTIVE | [readback](gru-1-phase1-completion-20261004/objectstorage-key-policy-readback.json) |
| policy | gru-1-netbird-enrollment | ocid1.policy.oc1..aaaaaaaa3ro6gkfcrqwwdeolyewx54hrchvvujoqhakf6ycde5mawnd7spnq | ACTIVE | [readback](gru-1-phase1-completion-20261004/netbird-enrollment-policy-readback.json) |
| policy | gru-1-netbird-admin-pat | ocid1.policy.oc1..aaaaaaaaiecrdwbzadi3oeiojyve2qbwzg75k7j2qmytrebzz5sptlzjb4eq | ACTIVE | [readback](gru-1-phase1-completion-20261004/netbird-admin-pat-policy-readback.json) |
| vaultsecret | gru-1-netbird-setup-key | ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqaj7iuycp5pjd36u35pmekfwrubyvhtalvzvjun2xtdv3q | ACTIVE | [readback](gru-1-phase1-completion-20261004/secret-setup-key-readback.json) |
| vaultsecret | gru-1-netbird-admin-pat | ocid1.vaultsecret.oc1.sa-saopaulo-1.amaaaaaappuhpdqa47dfouwhtievxunck43w4pyccvjgwkfvfglthsopvszq | ACTIVE | [readback](gru-1-phase1-completion-20261004/secret-admin-pat-readback.json) |

## NetBird convergence and secret handling

The native `netbird sync --apply` applied exactly the previously approved
18-change diff: server group; network/resource/router; two policies; DNS
settings; zone and ten private A records. Separate native inventories and
dry runs verified convergence. The router remains the existing ts-ops peer,
metric 100, masquerade enabled, for only `10.251.0.0/25`. DNS management is
disabled for `gru-servers`, preserving prior account settings. The group has
zero enrolled peers until the approved hosts start.

The fresh `netbird setup-key --apply` created `gru-servers` into a new
owner-only local file. Independent manager metadata verifies a valid
reusable key, `usage_limit=0`, `expires=0001-01-01T00:00:00Z`, non-ephemeral,
unused, and auto-assignment **only** to the new `gru-servers` group.
Its value and the approved automation PAT were stored in the two new
OCI secrets without exposing them in command arguments, logs or evidence.
Both secrets read back ACTIVE, version 1, in the new control compartment,
new vault and exact new key. Each independent CURRENT bundle was compared
privately against its source file; both matched. Evidence contains only
allowlisted metadata, never bundle contents or value digests.

The enrollment policy has exactly two setup-secret read statements,
controllers first and hosts second. The PAT policy has exactly one
PAT-secret read statement for controllers. Both policies are ACTIVE in
the new control compartment, with matching ownership tags. The native
controller policy and regional Object Storage delegation retain their
exact approved statement lists. No Rust LiveS3Credential secret or policy
was created; their reserved plan bindings remain null.

`deploy/image/inputs/netbird-gru.json` now references both new secret OCIDs
and retains the five static IP/name mappings. Its image-manifest SHA pin is
refreshed and passes native `image inputs check`. This prepares a future
qualified image; it does not make any older artifact match the new input.

| Type | Name | ID | Independent readback |
|---|---|---|---|
| group | gru-servers | db1dl8ka0rgg00dt33l0 | [readback](gru-1-phase1-completion-20261004/netbird-group-ids.json) |
| network | gru-cell | db1dl8ka0rgg00dt33mg | [readback](gru-1-phase1-completion-20261004/netbird-networks-ids.json) |
| resource | gru-cell-private-subnet | db1dl8ka0rgg00dt33o0 | [readback](gru-1-phase1-completion-20261004/netbird-resources-ids.json) |
| router | gru-cell/ts-ops | db1dl8ka0rgg00dt33pg | [readback](gru-1-phase1-completion-20261004/netbird-routers-ids.json) |
| policy | operators-to-gru-cell-ops-ports | db1dl8ka0rgg00dt33r0 | [readback](gru-1-phase1-completion-20261004/netbird-policies-ids.json) |
| policy | operators-to-gru-servers-ssh | db1dl8ka0rgg00dt33sg | [readback](gru-1-phase1-completion-20261004/netbird-policies-ids.json) |
| zone | gru-cell | db1dl8ka0rgg00dt33ug | [readback](gru-1-phase1-completion-20261004/netbird-dns-zones-ids.json) |
| setup-key | gru-servers | db1dp3ka0rgg00dt35fg | [readback](gru-1-phase1-completion-20261004/setup-key-metadata-readback.json) |
| DNS A record | ctl-1.gru.ts.internal | db1dl8ka0rgg00dt33vg | [readback](gru-1-phase1-completion-20261004/netbird-record-ids.json) |
| DNS A record | ctl-2.gru.ts.internal | db1dl8ka0rgg00dt340g | [readback](gru-1-phase1-completion-20261004/netbird-record-ids.json) |
| DNS A record | ctl-3.gru.ts.internal | db1dl8ka0rgg00dt341g | [readback](gru-1-phase1-completion-20261004/netbird-record-ids.json) |
| DNS A record | db-1.gru.ts.internal | db1dl8ka0rgg00dt342g | [readback](gru-1-phase1-completion-20261004/netbird-record-ids.json) |
| DNS A record | db-2.gru.ts.internal | db1dl8ka0rgg00dt343g | [readback](gru-1-phase1-completion-20261004/netbird-record-ids.json) |
| DNS A record | nats.gru.ts.internal | db1dl8ka0rgg00dt344g | [readback](gru-1-phase1-completion-20261004/netbird-record-ids.json) |
| DNS A record | nats.gru.ts.internal | db1dl8ka0rgg00dt345g | [readback](gru-1-phase1-completion-20261004/netbird-record-ids.json) |
| DNS A record | nats.gru.ts.internal | db1dl8ka0rgg00dt346g | [readback](gru-1-phase1-completion-20261004/netbird-record-ids.json) |
| DNS A record | terrabase.gru.ts.internal | db1dl8ka0rgg00dt347g | [readback](gru-1-phase1-completion-20261004/netbird-record-ids.json) |
| DNS A record | terrabase.gru.ts.internal | db1dl8sa0rgg00dt348g | [readback](gru-1-phase1-completion-20261004/netbird-record-ids.json) |

## Shared resources and old teardown preserved

Only the previously approved additive changes touched shared infrastructure:
new `ts-ops-gru-1-lpg`, the cell `/25` route, and ingress TCP 443/UDP 3478 from
that `/25`. Final ts-ops route/NSG data matches the approved post-update data;
all earlier rules remain. The complete shared VNIC data matches the
pre-update snapshot, including `10.250.10.155`, public `163.176.73.79`, NSG
membership and source/destination checks. Forgejo's version API is reachable.
Shared instance, disks, buckets, public access and existing IAM remain.

Final Email Delivery domain, DKIM and sender readbacks match the protected
post-stop data and are ACTIVE. Final OpenBao metadata equals the saved
pre-resume metadata byte-for-byte: `servers-gru` remains at version 2 with
both versions retained and undestroyed. No OpenBao writes occurred.
Existing NetBird account, peers and configuration match the post-sync
inventory except the approved fresh key and volatile peer timestamps/
connected status; no peers were removed or enrolled.

The old teardown plan remains unchanged and **no teardown apply ran**.
The previously verified secret/key/vault schedules remain the approved
October 5/October 11 purge windows. Old-compartment deletion still waits
for COS's explicit post-October-11 request. No delete, termination or
purge rescheduling occurred during resumed application.

## Phase 2 authorization and current holds

COS also relayed the user's approval to create, in order, image
`gru-1-arm64`, controllers `gru-1-ctl-1..3`, databases `gru-1-db-1..2` and
their `gru-1-db-N-data` volumes, then the public edge and its NSGs.
**The user's 2026-10-04 edge change supersedes the earlier edge design:**
create an OCI flexible **L7 Load Balancer `gru-1-api`**, a Cloudflare
**Origin CA certificate**, and **PROXIED** Cloudflare records for
`gru.api.terrascale.tech` and `auth.terrascale.tech`. The Origin CA
certificate and both proxied records are explicitly approved. Remove
`gru-1-gw-1`, Caddy, Let's Encrypt and the NLB from the phase-2 create list;
there is no edge compute host. Each stage requires clean preceding
readbacks and fresh native admission below USD 200/month; stop on the first
error. Deletes and terminations still require the user.

Use the separately reviewed features as they merge; do not build replacement
paths here: TS-484 bring-up/C# inspector/host provisioning/CA/profile/ARM64,
TS-485 block volumes, TS-486 flexible L7 LB/Origin CA/proxied DNS,
TS-487 ts-auth, and TerraBase TS-483 public readiness/ARM64 release.
Current main at completion is still
`052a96bebdb871edd197e4efaed216829ba8f04f`; none of those new paths is merged.
Do not populate Rust-era fields or public API bindings just to pass the old
foundation inspector. Phase-1 correctness is established by the explicit
readbacks above, not by running that unsuitable full inspector.

The latest discovered qualified image tag is
`image-d30f42663eb4c5ba9e5f0917fd8bb5df98dbe309-run-13042-attempt-1`.
Its receipt pins obsolete enrollment input and the old Rust TerraBase
release. It requires OCI import/signing, and cannot serve the fresh C# cell.
No such stale image was imported. The next executable step is to use the
merged native C# bring-up/image paths and a newly qualified artifact that
pins the new enrollment input. Phase-2 approval remains valid; these are
code/artifact holds, not requests to reapprove the listed creates.

## Validation

Native image input validation and explicit live resource, exact IAM,
secret-bundle equality, NetBird convergence and shared-preservation checks
passed. `SHA256SUMS` in the completion directory records all evidence files;
native admission receipts retain their original plan/inventory hashes.
`TS_TEST_TIER=pr nice -n 19 make verify shellcheck build GO=go GOFMT=gofmt`
passed: formatting, generated-file checks, vet, PR-tier race tests, NetBird
backup self-check, shellcheck and local binary build. Clean-source
`nice -n 19 make release-check GO=go GOFMT=gofmt` is run after committing
and its result is recorded in the PR. Evidence is scanned for secret values
and base64 encodings before staging.
