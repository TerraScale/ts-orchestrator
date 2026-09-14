# ADR 0024: Build a greenfield OCI estate

- Status: Accepted
- Updated: 2026-08-30
- Scope: OCI bootstrap and ownership

## Decision

TerraScale starts from a new OCI estate. Orchestrator does not adopt legacy
compute, storage, network, IAM, Vault, DNS, control-plane, or data resources.
A tag, familiar name, or matching address does not prove ownership.

Resources that change during normal operation are managed through the fenced
OCI provider. This includes compute instances, block volumes, attachments,
Object Storage objects, and work requests. Registry access is part of the
verified estate configuration, not a second state owner.

Until the end-to-end bootstrap command lands, an operator creates the one-time
compartments, VCNs, subnets, network security groups, IAM policies, and Vault
resources from the reviewed ORCH-5 runbook. Orchestrator performs read-only
startup checks against the recorded estate identities and refuses a malformed
or broadened estate.

ORCH-6 replaces the manual creation step with a resumable bootstrap command.
It will use the same ownership model and provider fences. It must not create a
second state owner.

## Legacy resources

Unrecognized resources remain outside the ownership graph and are never
mutated. Cleanup needs a separate, explicit owner decision based on a current
read-only inventory. This ADR authorizes no legacy cleanup.

## Consequences

The launch estate has a clear ownership boundary. Setup requires a reviewed
one-time procedure until ORCH-6 lands, but normal node and storage churn is
automated and restart-safe.
