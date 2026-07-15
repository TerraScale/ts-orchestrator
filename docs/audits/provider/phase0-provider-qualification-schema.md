# Phase 0 provider/TCO and OCI region qualification schema

- Audit date: 2026-07-13
- Status: blank contract and official source map only
- Cloud/API activity: none
- Prices, eligible regions, provider winner, provider selection, and production qualification: none

## Outcome

The lane creates three machine-readable inputs:

- [`provider-qualification-schema.json`](../../../testlab/pins/provider-qualification-schema.json) is a custom field-contract that enumerates the required provider, TCO, benchmark, and OCI-region fields. It is not presented as JSON Schema and does not claim JSON Schema semantics.
- [`provider-qualification-blank.json`](../../../testlab/pins/provider-qualification-blank.json) is a fail-closed four-provider dataset. All cost, benchmark, and normalized results are `null`; all four providers are unqualified; OCI has zero eligible rows; both winner and selection are `null`.
- [`provider-source-catalog.json`](../../../testlab/pins/provider-source-catalog.json) maps evidence topics to official primary documentation without treating a public catalog as account, capacity, performance, price, or regional qualification evidence.

This preserves the specification's distinction between a listed cloud region and a TerraScale-qualified region. The provider comparison must model the exact topology and all named cost components ([ORCHESTRATOR.md, lines 248-250](../../../ORCHESTRATOR.md#L248-L250)); the OCI matrix needs complete per-region evidence and at least 20 qualifying rows ([ORCHESTRATOR.md, line 252](../../../ORCHESTRATOR.md#L252)); price cannot win without the common storage/TerraBase benchmark and normalized BRL results ([ORCHESTRATOR.md, line 254](../../../ORCHESTRATOR.md#L254)).

## Required contract coverage

The schema lists every named cost input separately: compute; boot, data, NATS, and observability volumes; provisioned IOPS and throughput; snapshots/backups; inter-region and internet egress; public IPv4; NAT/gateways; load balancers; object requests/storage; KMS/secrets; logs/metrics; artifact storage; support; taxes; FX sensitivity; discounts/commitments; idle floor; burst cost; and engineer/operational cost.

A populated cost component must include amount, currency, unit, quantity, source reference, effective date, and explicit tax/discount treatment. The common benchmark contract requires immutable workload/script/raw-result digests; p50/p95/p99 read, write, and fsync latency; IOPS; throughput; noisy-neighbor results; online expansion; attach/detach/replacement time; regional capacity failure; recovery under compact load; and assumptions. Normalized results reserve BRL/day, BRL per sustained database transaction, BRL per sustained IOPS, and sensitivity bounds.

The OCI row schema includes public region/realm, subscription state, home/paired geography, availability/fault domains, A1 and approved ARM fallback/capacity evidence, images, full Block Volume size/VPU/IOPS/throughput/online-resize/benchmark evidence, required regional services, limits/quota request, inter-region path/latency/egress price, residency constraints, normalized BRL floor, qualification timestamp, evidence references, status, and reasons. The blank template exposes the complete shape while contributing zero eligible rows.

## Official primary-source catalog

The catalog is a map of where later evidence collection starts. It is not proof that a service is usable in a region, available to an account, within quota, currently in capacity, priced as assumed, or acceptable for TerraScale.

| Provider | Region/account discovery | ARM compute | Block storage | Pricing and billing evidence |
|---|---|---|---|---|
| OCI | [regions/realms/ADs](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm), [tenancy subscriptions](https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingregions.htm) | [official compute shapes](https://docs.oracle.com/en-us/iaas/Content/Compute/References/computeshapes.htm) | [VPU/IOPS/throughput](https://docs.oracle.com/en-us/iaas/Content/Block/Concepts/blockvolumeperformance.htm), [online resize](https://docs.oracle.com/en-us/iaas/Content/Block/Tasks/update-online-resize-block-boot-volume.htm) | [list-price/cost-estimator access](https://docs.oracle.com/en-us/iaas/Content/Billing/Tasks/signingup_topic-Estimating_Costs.htm), [Usage API/cost analysis](https://docs.oracle.com/en-us/iaas/Content/Billing/Concepts/costanalysisoverview.htm) |
| AWS | [regions/AZs and opt-in status](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html) | [EC2 processor families](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-types.html) | [EBS Elastic Volumes](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modify-volume.html) | [Price List APIs](https://docs.aws.amazon.com/awsaccountbilling/latest/aboutv2/price-changes.html), [Cost and Usage Reports](https://docs.aws.amazon.com/cur/latest/userguide/what-is-cur.html) |
| Google Cloud | [Compute regions/zones](https://cloud.google.com/compute/docs/regions-zones), [product locations](https://cloud.google.com/about/locations) | [general-purpose machine families](https://cloud.google.com/compute/docs/general-purpose-machines) | [Persistent Disk resize](https://cloud.google.com/compute/docs/disks/resize-persistent-disk) | [disk/image pricing](https://cloud.google.com/compute/disks-image-pricing), [Cloud Billing export](https://cloud.google.com/billing/docs/how-to/export-data-bigquery) |
| Azure | [official region list](https://learn.microsoft.com/en-us/azure/reliability/regions-list), [products by region](https://azure.microsoft.com/en-us/explore/global-infrastructure/products-by-region/) | [Arm-based Dpsv5 series](https://learn.microsoft.com/en-us/azure/virtual-machines/sizes/general-purpose/dpsv5-series) | [Linux managed-disk expansion](https://learn.microsoft.com/en-us/azure/virtual-machines/linux/expand-disks) | [Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices), [Cost Management exports](https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-export-acm-data) |

The official OCI compute-shape documentation itself warns that a new region can precede host capacity and directs users to account-visible shape discovery. That reinforces why this package records no A1 regional availability. Likewise, public price catalogs cannot establish negotiated discounts, tax, FX, measured usage, or the seven-day post-deletion residual bill.

## Fail-closed validator

The [`provider-qualification` C# command](../../../tools/TerraScale.Orchestrator.Tooling/TranslatedCommands.cs) performs no network or cloud operation. Structural validation checks the checked-in schema, blank evidence, source catalog, qualification state, and absence of any production claim.

The unit suite generates—but never writes—a clearly marked `synthetic-fixture-only` dataset with all four provider cost/benchmark/normalized result sets and 20 fully populated unique OCI rows. That positive fixture proves the structural contract can represent complete results and exercise winner/count rules. Its invented digests, amounts, regions, and outcomes are test data, are accepted only when the test explicitly disables the checked-in-blank policy, and cannot pass the CLI's normal committed-dataset validation.

The [adversarial fixtures](../../../tools/phase0/provider-qualification/fixtures/negative-cases.json) exercise stale/future/non-official sources, missing source coverage, partial OCI rows, erased schema fields, false eligibility counts/claims, winner/selection without results, false provider qualification, partial results, ambiguous currency, missing providers, a qualified row with unknown evidence, and a synthetic secret-named field.

Run:

```text
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format testlab/pins/provider-qualification-schema.json
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format testlab/pins/provider-qualification-blank.json
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- json-format testlab/pins/provider-source-catalog.json
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- provider-qualification
dotnet run --project tools/TerraScale.Orchestrator.Tooling -- test
```

Green validation proves only that the blank contract remains honest and structurally complete. It is not a provider comparison, region qualification, storage benchmark, cost approval, or permission to call cloud APIs.
