# Phase 0 work package: read-only OCI residual inventory

- Predecessor commit: `de9be9f`
- Contract version: proposed architecture dated 2026-07-13; no owner choice may be inferred
- Requirement scope: `REQ-O002`, `REQ-O010`, `REQ-O019`, `REQ-O020`, `REQ-O023`, `WRK-018`
- Allowed paths: `tools/phase0/oci-inventory/**`, `docs/audits/oci/**`, lane-owned notes under `docs/work-packages/handoffs/**`
- Prohibited paths: solution/build/package files, canonical registry, `ORCHESTRATOR.md`, composition root, sibling repository files, OCI configuration and credentials
- Inputs: local OCI CLI/config and read-only OCI APIs. Never print or persist tenancy/user/fingerprint/key material, auth headers, secret values, full OCIDs, public IPs, DNS names, or customer/resource names; hash stable identifiers when correlation is needed.
- Deliverable: a reusable fail-closed read-only inventory command/script plus sanitized report that establishes which APIs/permissions are available, proves or disproves OKE cluster/node-pool absence, inventories residual resource categories needed by Phase 0, and distinguishes `observed-empty`, `observed-present`, `permission-denied`, `not-queried`, and `query-failed`.
- Cost boundary: query billing/cost APIs read-only if permitted; report the exact time window and whether a seven-day residual bill can actually be established. Never estimate missing billing data as measured cost.
- Verification: syntax/static checks, deterministic sanitization tests using fixtures, and a live read-only run where credentials permit. A partial permission result is valid evidence but not a completion claim.
- Destructive actions: absolutely none. No create/update/delete/tag/cleanup, no Pulumi operation, no instance or VM start, no secret/Vault read, no network/DNS mutation, and no policy change.
- Handoff: commit lane changes and report commit SHA, exact read-only commands, permission gaps, sanitized category counts, and follow-up authority needed.

