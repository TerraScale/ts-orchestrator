# GRU ARM preview admission — 2026-09-26

## Current state and ownership

Read-only OCI inventory was captured at 2026-09-27 00:16:02 UTC in
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
held 47,299,184,646 bytes across 11,764 objects at capture. The cost estimate
retains a higher 57.93 GiB object-storage baseline to cover measurement drift.
The Forgejo instance, volumes, VCN, buckets, and reserved public IP are outside
preview ownership.

The preview target is three controller instances and two separate managed
TerraBase host instances, all GRU `VM.Standard.A1.Flex` at 1 OCPU/6 GB. The
controllers have 50 GB boot volumes. Each member has a 50 GB boot volume and
a 50 GB retained data volume. Every volume uses balanced 10 VPUs/GB. The three
controllers span the three GRU fault domains. `ts-infra` owns the dedicated
foundation and the single seed through two Forgejo applies. The running orchestrator's
founder workflow must create the other two controllers; its durable OCI journal
must create both member hosts and retained volumes, and its host desired-state
path must launch TerraBase. Direct operator creation of those four hosts would
not qualify this preview.

## Monthly cost admission

The admission receipt at [`admission.json`](../../scripts/oci-preview/admission.json)
was calculated at 2026-09-27 00:16:06 UTC. It expires after 15 minutes; refresh
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
estate enabled and seed disabled. It proposes 22 creates, zero updates or
deletes, and **no compute instance or data volume**. It includes three
compartments, the private GRU network and service gateway, scoped controller
IAM, shared HSM Vault/key, and ledger, versioned HEAD, and backup buckets.
It has not been applied. `ts-infra` forbids local apply and state edits; only
its serialized Forgejo workflow may create the foundation. The $5 miscellaneous
reserve covers unpriced small foundation services provisionally and must be
checked against the first actual bill.

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
identities; the preview plan pins 1 OCPU/6 GB and 50 GB/10 VPU boot dimensions,
which must be read back after the separate `ts-infra` seed apply. The bootstrap
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

After the seed is admitted and launched, preserve its exact OCID and signed
bootstrap handoff. Reconcile founder-created peer OCIDs and journal-created
member/volume OCIDs against the plan. A running process or health endpoint
alone is not TerraBase serving proof; the real authenticated write/read,
replication, restart, recovery, and update paths remain open.

## Repeatable read-only commands

```sh
python3 scripts/oci-preview/preview.py inventory --out docs/evidence/oci-preview-20260926.json
python3 scripts/oci-preview/preview.py admit --inventory docs/evidence/oci-preview-20260926.json --out scripts/oci-preview/admission.json
python3 -m unittest discover -s scripts/oci-preview -p 'test_*.py'
```

The inventory command reads all ready subscribed regions for the tenancy root,
TerraScale parent, Forgejo, and any of the three estate compartments. It includes instances,
boot/data volumes and backups, reserved public IPs, VCNs, subnets, route tables,
network security groups, gateways, load balancers, and Standard bucket object
sizes. Admission fails on stale inventory, unexpected compute, volume
dimensions, retained backup size, public IPs, unexpected versioned buckets, NAT/load
balancers, or a projected total above the cap. Its OCI CLI output excludes instance
metadata, credentials, and object contents. The sole allowed versioned bucket
is the `ts-infra` bootstrap HEAD bucket; inventory counts all its object
versions. Cleanup must use exact preview
resource OCIDs and preserve Forgejo, `ts-infra` resources, bootstrap authority
records, and retained database state unless their named owner authorizes the
specific disposition.
