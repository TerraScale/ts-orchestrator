# ADR 0024: Greenfield bring-up remains gated by incomplete OCI residual evidence

- Status: Accepted greenfield boundary; residual inventory evidence pending
- Date: 2026-08-05
- Decision owner: Cloud
- Readiness entry: `24 / greenfield-bringup`

## Context

The intended deployment is greenfield: it adopts no prior cloud, data, identity, DNS, or control-plane resource. That policy does not establish that the legacy cloud estate is empty. The current P0-02 inventory is an incomplete, host-preflight-only record: OCI configuration material was detected without reading it, but the OCI CLI was unavailable, so no authenticated scoped discovery ran ([OCI residual inventory](../evidence/phase0/oci-residual-inventory.yaml)).

Consequently, compute, storage, backups, buckets, load balancers, public IPs, IAM, Vault/KMS, certificates, workloads, NATS, networking, and seven-day cost remain `not-queried`. OKE and node-pool absence remains explicitly unproven. No resource has an ownership classification or cleanup disposition.

## Decision

1. Preserve the greenfield policy: the new platform must not adopt a historical resource.
2. Treat the OCI residual estate as unknown until a scoped read-only inventory positively observes and classifies resources.
3. Do not infer a clean estate, deleted OKE/node pools, or zero residual cost from unavailable tooling, unread credentials, missing authorization, or unqueried APIs.
4. Allow cleanup only after positive observation, ownership evidence, and a named accountable owner assigns a disposition. Unknown resources remain outside the new ownership graph and are not mutated.
5. This ADR and its evidence authorize no OCI or other cloud-account mutation.

## Consequences and required evidence

Before first-production qualification or any residual cleanup proposal, the Cloud lane needs an approved read-only OCI client, a scoped read-only identity, inventory coverage for every P0-02 category, a positive OKE/node-pool query, sanitized seven-day cost evidence, and named owner dispositions for positively identified remnants. The evidence must be revalidated immediately before any ownership disposition or mutation proposal.

Until then, the residual-estate risk is unresolved: a legacy resource, cost, credential path, network route, or OKE resource may exist but has not been verified. The greenfield architecture remains a no-adoption rule, not a clean-account assertion.

## Rollback

This record changes no runtime or cloud state. Its rollback is a Git revert of this ADR and the linked evidence record; it does not reverse or imply any cloud action.
