# Phase 0 OCI residual inventory audit

Status: incomplete read-only evidence; account discovery was denied before any
resource-category query could safely run.

## Result

The bounded live command was:

```bash
python3 tools/phase0/oci-inventory/oci_inventory.py --live \
  --end-utc 2026-07-13T12:00:00Z \
  --output docs/audits/oci/phase0-residual-inventory.json
```

The first live API category, `iam region-subscription list`, returned an
authentication/authorization-class failure. The tool suppressed the raw OCI
response and persisted only the coarse state. Because region discovery is the
scope boundary, every resource category is correctly `not-queried`, not
`observed-empty`.

Consequences:

- OKE cluster and node-pool absence is **not proven**.
- No residual resource count is established for compute, volume/backup,
  bucket, load-balancer, public-IP, IAM, Vault/secret metadata, certificate,
  or DNS categories.
- NATS stream/consumer and runtime workload inventories are explicitly
  `not-queried`; they are not OCI control-plane inventory APIs.
- The exact intended billing window is 2026-07-06 12:00 UTC through 2026-07-13
  12:00 UTC. Billing was not queried after discovery failed, so a seven-day
  residual bill is not established and no missing amount is presented as cost.

## Required follow-up authority

Provide a locally configured OCI profile whose signing identity can perform
read-only region-subscription and accessible-compartment discovery plus the
listed metadata/cost APIs. No broader mutation authority is needed. Re-run the
same command after access is repaired. Any resulting partial denial remains a
permission gap and prevents an account-wide absence claim.

The executable plan and complete category templates are embedded in the
sanitized JSON report and can also be reviewed without API calls using:

```bash
python3 tools/phase0/oci-inventory/oci_inventory.py --plan
```

The tool has no create, update, delete, start, stop, secret-bundle retrieval,
key retrieval, policy mutation, DNS/network mutation, or Pulumi command path.
