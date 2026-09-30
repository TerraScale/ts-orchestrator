# GRU ARM preview admission — 2026-09-26

> **Historical snapshot, superseded for current ownership.** The inventory and
> proposed `ts-infra` estate below predate `ts-infra` main commit
> `e347f13a313ebb2b9d0a0b631ba0aed56af65126`. That revision completed the
> state-only regional handoff and removed the regional Terraform definitions,
> workflow, and preview scripts. Current `ts-infra` manages four Email Delivery
> resources only. Regional networking, IAM, and bootstrap inputs and controller
> A are operator-managed; use the [current manual bootstrap runbook](../region-bootstrap.md).
> This snapshot is not an apply plan, current inventory, or authorization for
> OCI changes. The old `ts-infra` preview commands below are retired.

## Historical state and proposed ownership at the recorded snapshot

Read-only OCI inventory was captured at 2026-09-27 00:37:39 UTC in
[`oci-preview-20260926.json`](oci-preview-20260926.json). The tenancy is
subscribed to GRU, Frankfurt, and San Jose. The TerraScale parent compartment
has no active instances, VCNs, boot volumes, or data volumes. The separate
`terrascale-control`, `terrascale-network`, and `terrascale-workload`
compartments do not exist. They are the three compartments owned by the
disabled-by-default `ts-infra` estate. **No OCI preview resources have been
created or changed.**

The only active compute across the inventoried tenancy root, TerraScale parent,
Forgejo, and the planned estate compartments is the unrelated Forgejo A1 in GRU:
2 OCPUs, 4 GB memory, one 50 GB boot volume and one 50 GB data volume, both
10 VPUs/GB. Its instance, volume, and VCN OCIDs are in the JSON inventory and
the [desired plan](../../scripts/oci-preview/plan.json). The two Forgejo buckets
held 47,301,636,649 bytes at capture. The cost estimate
retains a higher 57.93 GiB object-storage baseline to cover measurement drift.
The Forgejo instance, volumes, VCN, buckets, and reserved public IP are outside
preview ownership.

The proposed preview target is three controller instances and two separate managed
TerraBase host instances, all GRU `VM.Standard.A1.Flex` at 1 OCPU/6 GB. The
controllers have 50 GB boot volumes. Each member has a 50 GB boot volume and
a 50 GB retained data volume. Every volume uses balanced 10 VPUs/GB. The three
controllers span the three GRU fault domains. The earlier proposed two-apply
design assigned the dedicated foundation and single seed to `ts-infra`; the
orchestrator founder would create the other controllers, and its placement path
would create member hosts and retained volumes and launch TerraBase. This
proposed ownership was superseded by the manual runbook linked above.

## Monthly cost admission

The admission receipt at [`admission.json`](../../scripts/oci-preview/admission.json)
was calculated at 2026-09-27 00:37:47 UTC and expires at 00:52:47 UTC; refresh
the inventory and admission immediately before any creation or enlargement.
The conservative admission uses Oracle's lower published Always Free A1
allowances of 1,500 OCPU-hours and 9,000 GB-hours, plus 200 GB free block
capacity and 10 GB free object capacity. The newer 2026-09-23 catalog shows
3,000/18,000 A1 free hours; those higher allowances are not credited here.

| Item | Bound and rate basis | USD/month |
| --- | --- | ---: |
| A1 compute | Forgejo plus five planned hosts: 7 OCPUs/34 GB for 720 hours, less lower free allowances; $0.01/OCPU-hour and $0.0015/GB-hour | 58.62 |
| Block storage | 450 GB total less 200 GB free, at $0.0255/GB plus 10 × $0.0017/VPU-GB | 10.625 |
| One replacement | 1 OCPU/6 GB and up to 100 GB extra volumes for at most 72 hours | 1.793 |
| Object storage | Current Forgejo objects or 57.93 GiB baseline, whichever is larger, plus 10 GiB preview allowance | 1.4772 |
| Object requests | 1 million preview requests plus $0.27 existing Forgejo request allowance | 0.61 |
| Egress | 100 GB at $0.025/GB, with no free egress credit | 2.50 |
| Snapshot/backup reserve | Up to 350 GB at $0.0255/GB capacity-equivalent, pending an exact backup SKU | 8.925 |
| Miscellaneous | Fixed reserve for unpriced small services | 5.00 |
| **Total** | Rounded after summing exact components | **89.55** |

The **US$100/month combined qualification and preview ceiling leaves $10.45**
at this snapshot. This is an admission estimate, not a hard OCI spending cap.
The backup reserve is provisional because the current catalog audit did not
identify a separate volume-backup SKU. The baseline includes the unrelated
Forgejo object footprint and request usage; no NAT gateway or load balancer
was present. The planned preview has no paid public load balancer or NAT.
Bounded replacement overlap, snapshot retention, object growth, and actual
usage must be rechecked during operation. Stopping compute does not remove
volume or object charges.

The [sanitized OpenTofu foundation plan](ts-infra-foundation-plan-20260926.json)
was evaluated against the encrypted `ts-infra` state revision `41b8acc` with
estate enabled and seed disabled. It proposes 24 creates, zero updates or
deletes, and **no compute instance or data volume**. It includes three
compartments, the private GRU network and service gateway, scoped controller
IAM, shared HSM Vault/key, and ledger, versioned HEAD, backup, and private
versioned material buckets. The dedicated subnet security list has no ingress
rules and allows egress only to the private VCN and GRU Oracle Services Network
CIDR. The subnet explicitly attaches it, so OCI's default SSH ingress and
allow-all egress rules are not inherited. Controller IAM allows read/create
only under `material/v1/*` and encrypt/decrypt use of the named KMS key. It
does not grant overwrite, delete, or list. OCI does not combine versioning
with bucket retention rules, so privileged administrators are outside this
write-once guarantee.
The [signed OCI Identity policy read](oci-preview-iam-20260927.json) returned
HTTP 200 with zero policies directly in the TerraScale parent compartment.
The tenancy has only its Administrators policy and two Forgejo group grants;
neither names the proposed preview controller dynamic group. The reviewed
foundation policy is therefore the first controller grant for this estate.
It had not been applied at this snapshot. The then-current `ts-infra` policy
required its serialized Forgejo workflow for that proposed foundation; that
regional workflow and source were later removed by `e347f13a`. The $5
miscellaneous reserve was a provisional estimate for the proposed foundation,
not a current cost admission.

## Gates before launch and qualification

The preview has no qualified ARM64 custom image or signed paired TerraBase and
orchestrator release artifacts. CI admission must bind each full source SHA,
Forgejo API run ID, run number, and retained manifest digest. The release
signer and bootstrap must verify current signed image receipt v2 and the exact
qualified artifact bytes. The custom image's OCI OCID, base image/kernel,
systemd version, first-boot config, bootstrap identity, NATS/JetStream storage
domain, complete IAM/Vault policy, and the private route's live read-back are
still unrecorded.
No artifact gate has authorized an OCI launch.

`ts-bootstrap verify-manifest` now verifies the current root-signed anchor,
per-slot manifest, and embedded release image proof. Its explicit slot and
image OCID must come from independent launch intent. The read-only
`preview.py seed-preflight` checks the exact signed `controller-a` profile,
exact signed receipt bytes and local image candidate, live three-compartment
foundation, private subnet, and a fresh admission receipt. Neither command
creates OCI resources. The bootstrap manifest pins shape and network/placement
identities; this historical preview plan pinned 1 OCPU/6 GB and 50 GB/10 VPU
boot dimensions for its proposed seed launch. The bootstrap
manifest has no memory reserve; the managed host reserve is separately pinned
by the signed placement profile.

Member startup additionally needs production scoped signer and TLS material,
image qualification for retained volumes, a signed placement profile, and
measured management memory protection. The effective host-service and
`system.slice` memory.min/memory.low reservations must be read back with the
managed workload children at zero reservation, then CPU, memory, I/O, OOM,
and recovery behavior must be exercised on the qualified guest image.
The Go managed OCI adapter now requests explicit 50 GB/10 VPU boot dimensions,
10 VPU data tier and private-only VNICs, bounds retained data volume size to
the configured preview fleet maximum of 50 GB, and verifies running host boot,
VNIC and retained data tier read-back. This is local source/test evidence, not
an OCI launch result.

The old proposal required preserving the seed OCID and signed bootstrap handoff,
then reconciling peer and member/volume OCIDs against its plan. A running
process or health endpoint alone is not TerraBase serving proof; the real
authenticated write/read, replication, restart, recovery, and update paths
remained open at this snapshot.

## Retired pre-handoff preview tooling

The earlier `ts-infra/scripts/oci-preview/` commands inventoried and admitted
the proposed estate. That tooling was removed from current `ts-infra` main by
`e347f13a`; the commands are not executable from current source and are not
current regional instructions. The old admission and inventory files are
retained above as dated evidence only. For current operator preparation and
available read-only checks, use the [manual regional bootstrap runbook](../region-bootstrap.md).
