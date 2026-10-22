# OCI Object Storage versus Tigris: START-STORE

Keep the existing OCI adapter. This research establishes published prices and
semantic differences; it establishes neither a cheaper provider nor a qualified
replacement. A backend change remains gated on an equal-reliability comparison
using measured inventory, traffic and restore results.

Research date: **2026-10-16**. Repository baseline: **`7a7abb41`**. Scope: the
START-STORE requirement and storage/recovery/cost constraints in
[REFACTOR.md](../REFACTOR.md). Public provider pages were fetched read-only;
there was no cloud inventory request, credential access, provisioning, backend
change or live benchmark. Prices below are public USD pay-as-you-go prices,
before tax, credits, negotiated rates and operational effort.

## What this repository actually stores

| Workload and source | Required behavior and cost drivers |
| --- | --- |
| Signed release channels and binaries: `internal/releasechannel/{channel,service}.go`, `internal/release/cli/{commands,apply}.go` | Regional bucket locations; digest-named immutable binaries, conditional create, exact SHA-256 readback, ETag CAS for channel updates, bounded retries, status writes/polls and host downloads. A successful upload can include a full verification GET even when the object already exists. Preserve signature/size/digest admission and anti-rollback ordering. |
| Controller configuration: `internal/kvsnapshot/{objects,snapshot,restore}.go`, [storage runbook](storage.md#configuration-snapshots) | Changed KV buckets become complete JSON snapshot objects; GET + conditional PUT with SHA-256, version history and complete restore reads. Only an actual `ObjectNotFound` means absent; denied access or a missing bucket must fail. Retained overwritten versions consume storage. Cadence/config cleanup is separate refactor work; no unmeasured production rate is assumed here. |
| TerraBase DR: `internal/disasterrecovery/objects.go`, [DR runbook](disaster-recovery.md) | GRU and SJC each have `backup` and `head` source buckets, a read-only mirror in the other region and a separate writable versioned seed. List pagination, destination identity checks, metadata GETs closed without consuming the body, asynchronous copy polling and checksum readback all generate requests. Missing/multipart MD5 can trigger full source and destination SHA-256 reads. |
| NetBird recovery: [refactor recovery requirement](../REFACTOR.md) | A consistent off-host backup with its encryption/identity material, plus a copy outside GRU. Those are required future costs; the plan does not supply measured backup sizes, churn or recovery time. |
| Separate storage products: `internal/delivery/artifact_gc.go`, [storage policy](storage.md) | `TS_ARTIFACTS` is a NATS object store, not an OCI bucket. OCI boot/block volumes, native volume backups, OCIR images and their retention also remain separate. Replacing object storage does not remove these costs or qualify cross-CPU/database recovery. |

The source adapter is OCI Go SDK typed, authenticated through OCI principals;
an S3-compatible endpoint is not a drop-in replacement. An eventual adapter must
preserve the existing feature boundary without weakening CAS, error handling,
identity checks, checksums, encryption/key recovery or release admission.

### Historical inventory is useful, but is not today's bill

The [2026-10-08 preparation record](evidence/ts-641-replication-20261008.md)
contains these source observations before its copy runs:

| Bucket | Current objects | Recorded bytes |
| --- | ---: | ---: |
| `gru-1-backup` | 58,726 | About 12.2 GB; unit/rounding not specified in the record |
| `sjc-1-dr-gru-1-backup` mirror | 47,018 | About 9.9 GB |
| `gru-1-head` | 75 | 3,448,972,510 |
| `sjc-1-head` | 17 | 86,688,232 |
| `sjc-1-backup` | 0 | 0 |

That observation also reports about 2.3 GB missing from the GRU backup mirror.
Subsequent runs copied seeds and observed changed inventories; adding those
counts to the earlier snapshot would manufacture a simultaneous inventory.
There are no current byte-hours, version bytes, request totals, billed transfer
or full-restore measurements in this comparison. The record proves copied key
unwrap and authenticated sample chunks in SJC, **not** a full-cell restore or
measured RTO/RPO. FRA is a required milestone region, not an evidenced third
copy of those GRU/SJC buckets.

## Published prices and official sources

All sources were retrieved on **2026-10-16**. Oracle's public catalog responses
reported `lastUpdated: 2026-10-08T14:38:16.165Z`.

| Product / meter | Public USD price | Official source |
| --- | --- | --- |
| OCI Standard storage, `B91628` | First 10 billing GB-month free; then **$0.0255/GB-month** | [Oracle storage pricing](https://www.oracle.com/cloud/storage/pricing/), [public SKU response](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?partNumber=B91628&currencyCode=USD) |
| OCI object requests, `B91627` | First 50,000/month free; then **$0.0034 per 10,000**; deletes free | [Public SKU response](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?partNumber=B91627&currencyCode=USD), [Object Storage billing FAQ](https://www.oracle.com/cloud/storage/object-storage/faq/#billing) |
| OCI outbound transfer | Published first **10,240 billing GB/month** at $0; above allowance **$0.0085/GB** from North America/Europe/UK (`B88327`), **$0.025/GB** from South America/APAC/Japan (`B93455`); inbound free | [Network pricing](https://www.oracle.com/cloud/networking/pricing/), [Oracle public price catalog](https://apexapps.oracle.com/pls/apex/cetools/api/v1/products/?currencyCode=USD) |
| Tigris Standard, global / single-region | **$0.02/GiB-month**, Class A **$0.005/1,000**, Class B **$0.0005/1,000** | [Tigris pricing](https://www.tigrisdata.com/pricing/), [complete machine-readable pricing](https://www.tigrisdata.com/pricing.md) |
| Tigris Standard, multi-region | **$0.025/GiB-month**, Class A **$0.01/1,000**, Class B **$0.0005/1,000** | [Complete pricing](https://www.tigrisdata.com/pricing.md) |
| Tigris Standard, explicit dual-region | Storage **$0.02/GiB-month per underlying region**; Class A **$0.005/1,000 per region**; Class B **$0.0005/1,000** | [Complete pricing](https://www.tigrisdata.com/pricing.md), [location billing](https://www.tigrisdata.com/docs/buckets/locations/) |
| Tigris allowances and transfer | 5 GiB Standard, 10,000 A and 100,000 B requests/month free; deletes/cancels and egress free; object notifications **$0.01/1,000 events** | [Complete pricing](https://www.tigrisdata.com/pricing.md) |

Tigris explicitly defines its pricing “GB” as **2^30 bytes** and storage as
the average of daily peaks. Oracle's FAQ describes timed storage-byte hours.
Convert actual bytes using the applicable Oracle meter definition and billing
export before comparing invoices; daily peaks and byte-hour averages can differ
even with identical data. Do not allocate the full free tier or egress allowance
to each bucket, region or alternative: existing tenancy/account usage and the
actual billing aggregation determine what remains. Confirm Tigris free-tier
application to replicated location types before deducting it.

Tigris Class A includes PUT, COPY and LIST; Class B includes GET and HEAD.
Multipart calls, retries, failed/negative lookups and status polling must be
classified from actual provider billing. Tigris lists several uncharged errors,
including 412 and 304; that list does not establish all failed requests are free.

The HTML Tigris page defaults to global pricing; the linked complete pricing
page supplies the different multi/dual-region rates. Its dual-region table also
shows a three-region billing example ($0.06/GiB-month, $0.015/1,000 A), while
the location documentation describes selecting **two** regions. A three-region
product/placement must be confirmed with the provider; that pricing example
does not prove it can place GRU/SJC/FRA copies.

## Reliability and placement are different contracts

| Mode | What the official documentation establishes | Consequence here |
| --- | --- | --- |
| OCI regional bucket | Regional redundant storage, strong consistency; [FAQ](https://www.oracle.com/cloud/storage/object-storage/faq/) states designed annual durability of 99.999999999%. | Internal redundancy is included in one bucket's price. It does not establish survival of complete regional loss or count as another customer-controlled regional copy. |
| OCI source + mirror + seed | [Replication](https://docs.oracle.com/en-us/iaas/Content/Object/Tasks/usingreplication.htm) is asynchronous, starts with subsequent uploads, copies deletes, and permits one replication policy per source. Destination is read-only. | Count source, mirror and actual seed/version bytes separately. Seed fills the pre-policy gap; it is not necessarily a complete third copy. One native source policy does not directly produce two cross-region mirrors. Application fan-out/another copy mechanism would add traffic and qualification work. |
| Tigris global default | [Locations](https://www.tigrisdata.com/docs/buckets/locations/) describes a single placement copy, metadata everywhere, and data pulled/cached on demand. Cross-region consistency is eventual. | Reachability and cached bytes do not establish retained regional durability. This mode is not demonstrated equivalent to the DR contract. |
| Tigris multi-region | 2+ regional copies within USA or EUR, automatically chosen; strong consistency globally; documentation says it survives regional failures within that geography. | Potential candidate for shared mutable channel metadata, but it does not specify copies in GRU, SJC and FRA or prove the workload's restore RPO/RTO. |
| Tigris dual / single-region | Dual pins two regions, eager data replication, eventual cross-region consistency; single has in-region redundancy and routes all requests there with strong global consistency. | Dual's cross-region CAS needs do not meet the existing globally current precondition contract by assumption. Single-region lacks regional outage availability. Split buckets or additional copies must be priced and qualified, not assumed free. |

[Tigris conditional-operation documentation](https://www.tigrisdata.com/docs/objects/conditionals/)
explicitly recommends multi-region or single-region for conditional writes
spanning regions: global/dual preconditions can see stale cross-region state.
This matters for release publication and snapshot rollback protection. Signed
bytes prevent tampering; they do not replace atomic channel publication.

[Tigris regions](https://www.tigrisdata.com/docs/concepts/regions/) lists `sjc`
and `fra` on `t3.storage.dev`, but does not list `gru` as a storage region. Establish product/account availability and placement in São Paulo before
assuming local GRU storage. Keep OCI product token `sjc` mapped to
`us-sanjose-1`; Tigris's `sjc` is a different provider's identifier.

Durability describes protection against losing stored bytes. Availability
describes reaching usable bytes during a failure. Replication lag determines
recoverable data age. Versioning/retention protects historical generations from
overwrites or deletion; replication can reproduce those errors. None of these
alone proves a consistent database restore. Do not multiply advertised “nines”
across copies, infer independent failure probabilities, or present a durability
design target as measured platform reliability. Tigris contractual durability,
SLA exclusions, committed replica completion and regional-loss RPO remain to be
verified against the selected service contract.

## Reusable monthly cost model

Use measured provider-metered quantities for each object class and location.
These are analysis variables, **not new runtime configuration knobs**.

1. Inventory current source bytes, mirror bytes, retained versions/seeds,
   incomplete multipart bytes and daily churn. Keep protected backup generations
   separate from serving caches. Inventory every retained region and key copy.
2. Count requests by operation, including publication readback, polling, CAS
   conflicts/retries, list pages, DR copy work-request polls, verification and
   restore. Classify the destination-side operations that the provider bills.
3. Measure byte flows by source/destination: publisher uploads, regional copies,
   OCI hosts reading artifacts, backup creation/copy, checksum reads, restore
   and migration. Same-region/private paths and internet paths need separate
   billing evidence.
4. Price equal retention, placement and restore objectives; add migration overlap,
   staging disk, key services, required credentials, adapter maintenance and
   measured restore time. Keep existing block/registry/NATS costs visible.

For OCI Standard, let `S_o` be total charged-region storage in billing GB-month,
`Q_o` the count of billed non-delete requests, and `F_s/F_q` the genuinely
remaining applicable allowances:

```text
OCI = 0.0255 × max(S_o - F_s, 0)
    + (0.0034 / 10000) × max(Q_o - F_q, 0)
    + T_o(actual flows, remaining transfer allowances, route/SKU)
    + other recovery / key / operations costs

S_o = Σ regions(source + mirror + seed + retained versions + incomplete parts)
```

`T_o` must include billable cross-region copies/replication, backup transfers,
full checksum reads, restores and internet egress. The cited generic egress
table does not establish the exact metering treatment of each native copy path;
verify it from the applicable service terms and billing export. Do not silently
price unverified paths at zero or subtract a second free allowance. For an
internet transfer known to use the listed SKU after its allowance is consumed,
use the source geography's rate: GRU $0.025/GB; SJC/FRA $0.0085/GB.

For Tigris, let `S_t` be daily-peak-averaged GiB-month including retained
versions/backup generations, `A/B` its billed request classes, and `N` events:

```text
Tigris global/single = 0.020 × S_t + (0.005 / 1000) × A
                    + (0.0005 / 1000) × B
Tigris multi         = 0.025 × S_t + (0.010 / 1000) × A
                    + (0.0005 / 1000) × B
Tigris explicit pair = 0.040 × S_t + (0.010 / 1000) × A
                    + (0.0005 / 1000) × B
Each also adds       = (0.010 / 1000) × N + retrieval/minimum-duration costs
                    + OCI outbound writes + other recovery / operations costs
```

These formulas show gross prices; apply the eligible remaining Tigris allowances
once according to the actual account's billing. Multi-region already includes
its provider-managed regional replicas; do not multiply that rate again. An
extra independent backup bucket or separate regional bucket is additional
billable data. Tigris egress is $0, but an OCI host uploading backups to Tigris
can incur **OCI** internet egress. OCI-to-Tigris migration likewise reads OCI
data and sends it out. Restoring Tigris into OCI has free advertised Tigris
egress and OCI ingress, while GET requests, temporary storage and restore
compute still cost money.

Illustrative arithmetic, **not measured workload savings**: 1,000 billing
GB-month in each of three OCI buckets costs $76.50 in gross Standard storage.
One 1,000 GiB-month Tigris multi-region bucket costs $25, but supplies its own
USA/EUR placement rather than three exact GRU/SJC/FRA copies or historical
backup generations. Three independently retained single-region Tigris buckets
would cost $60 in storage and need their own copy/verification logic; their
placement availability and resulting recovery semantics remain unqualified.
At one million billable operations, OCI request cost is $0.34; Tigris costs
$5 for global/single Class A, $10 for multi/paired Class A, or $0.50 for Class B,
before allowances. Small control objects can therefore be request-dominated.
These unit examples cannot rank the actual monthly bill.

Standard is the initial comparison because release channels and recovery need
immediate reads. Tigris IA is $0.01/GiB-month with $0.01/GiB retrieval and a
30-day minimum; Archive/Archive Instant Retrieval are $0.004 with 90-day minima
at global/single rates. Archive requires restoration; its temporary Standard
storage costs money. Archive Instant retrieval is $0.03/GiB. Multi/dual rates
differ. OCI cold tiers also have distinct retrieval/retention terms. No cold
tier saving is credited without matching restoration deadlines and churn.

## Evidence needed to decide

1. **Current cost sample:** an authorized read-only inventory and billing export
   over one representative complete billing period, split by region, object
   class, retained version/seed, request type and transfer path. Preserve raw
   non-secret samples and normalized calculations under `benchmark/bench/`.
2. **Equivalent contract:** specify required regional copies, protected history,
   CAS consistency, key/secret availability after GRU loss and numerical restore
   objectives. Confirm Tigris GRU availability, exact pair/three-region support,
   replication completion guarantees and contractual durability/SLA.
3. **Boundary qualification:** on separately authorized disposable storage, prove
   conditional-write contention, immutable retry/readback, missing-versus-denied
   reads, version retention, partial copy/restart, and isolated-region reads.
   No backend implementation or live exercise is authorized by this report.
4. **Restore and total cost:** restore a consistent TerraBase PITR plus control
   and NetBird identity/key state with the source region unreachable; record
   bytes, API operations, recoverable age, elapsed time and resource charges.
   Price migration overlap and maintenance before choosing a provider.

Until those inputs exist, START-STORE has a sourced comparison and explicit
qualification gaps. Existing OCI adapter work and initial regional connectivity
can continue; a backend replacement or cheaper-provider claim cannot.
