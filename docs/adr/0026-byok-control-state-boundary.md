---
date: 2026-09-11
authority: ../../../GOAL.md
---

# BYOK control-state boundary

## Decision

The authenticated NATS admission journal is the durable restart and recovery
record for customer-managed encryption, but it is not a secret store. It may
contain only the validated provider reference (provider, canonical key ARN,
matching region, optional HTTPS endpoint, and configuration revision) and the
wrapped database-DEK ciphertext bound to that admission. Provider credentials,
workload tokens, imported or plaintext keys, unwrapped DEKs, and customer data
must never be serialized into NATS subjects, JetStream KV, snapshots, or
operator-visible logs.

NATS consumers must validate the complete provider tuple and admission
operation before accepting a wrapped entry. A restart reconstructs a provider
client from the reference and the process-local workload-identity boundary;
it never recovers credentials from NATS. AWS KMS uses the regional SDK default
when the endpoint is omitted.

This decision complements TerraBase ADR 0049. Any new provider or credential
source requires an independently reviewed wire contract and qualification
evidence.
