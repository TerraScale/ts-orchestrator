# ADR 0024: Build a greenfield OCI estate

- Status: Accepted
- Updated: 2026-09-20
- Scope: OCI bootstrap and ownership

## Decision

TerraScale starts from a new OCI estate. Orchestrator does not adopt legacy
compute, storage, network, IAM, Vault, DNS, control-plane, or data resources.
A tag, familiar name, or matching address does not prove ownership.

Resources that change during normal operation are managed through the fenced
OCI provider. This includes compute instances, block volumes, attachments,
Object Storage objects, and work requests. Registry access is part of the
verified estate configuration, not a second state owner.

`ts-infra` controls supported-region intent and creates the first GRU seed
foundation and controller through CI. The required architecture then transfers
exact seed resources to orchestrator, which establishes and manages supported
regional clusters. This is a deliberate handoff of newly created resources,
not discovery or adoption of arbitrary existing estate.

An adoption request is read-only until CI has relinquished the exact resources
without destruction and durably published the encrypted resulting state. The
controller needs a signed release receipt before it can mutate them. This
handoff and the complete first boot remain unimplemented; tags do not authorize
ownership. See [the bootstrap contract](../operations/control-bootstrap.md).

## Legacy resources

Unrecognized resources remain outside the ownership graph and are never
mutated. Cleanup needs a separate, explicit owner decision based on a current
read-only inventory. This ADR authorizes no legacy cleanup.

## Consequences

The launch estate has a clear ownership boundary. Setup requires a reviewed
one-time procedure until ORCH-6 lands, but normal node and storage churn is
automated and restart-safe.
