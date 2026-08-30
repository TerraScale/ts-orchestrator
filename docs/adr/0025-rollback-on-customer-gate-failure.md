# Roll back on customer and security gate failure

Status: Accepted.

Date: 2026-08-29.

TerraScale rolls back a release when health checks, error rate, latency, tenant isolation, replication, billing reconciliation, or the synthetic customer journey fails. Rollback restores the previous qualified immutable digest without rebuilding it.
