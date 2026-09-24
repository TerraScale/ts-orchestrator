---
date: 2026-09-11
authority: ../../../GOAL.md
---

# BYOK control-state boundary

## Decision

The authenticated NATS admission journal is the durable restart and recovery
record for customer-managed encryption, but it is not a secret store. It may
contain only the validated provider reference (provider, canonical key ARN,
matching region, optional HTTPS key endpoint, backup endpoint/bucket/region,
workload role, and configuration revision) and the
wrapped database-DEK ciphertext bound to that admission. Provider credentials,
workload tokens, imported or plaintext keys, unwrapped DEKs, and customer data
must never be serialized into NATS subjects, JetStream KV, snapshots, or
operator-visible logs.

AWS web identity uses the workload token's subject, not an external ID.
External IDs are rejected in admission and renewal requests, durable catalogs,
and host configuration; no retired-field compatibility path is retained.

NATS consumers must validate the complete provider tuple and admission
operation before accepting a wrapped entry. Current snapshots and prior-state
recovery after lease expiry use the same strict decoder: unknown or retired
fields fail closed instead of being silently dropped. A restart reconstructs a provider
client from the reference and the process-local workload-identity boundary;
it never recovers credentials from NATS. AWS KMS uses the regional SDK default
when the endpoint is omitted. The omitted endpoint remains an empty reference
through the host key-lease protocol so it matches the admitted catalog entry;
it is not rewritten into an explicit URL. Customer-S3 credential requests bind
the environment, tenant, project, database, and placement revision as well as
the provider tuple before the broker may issue credentials.

This decision complements TerraBase ADR 0049. Any new provider or credential
source requires an independently reviewed wire contract and qualification
evidence.
