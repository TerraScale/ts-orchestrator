# Cloudflare Secrets Store and rotation

Secrets Store creates secrets with an array of objects containing a name,
scopes and a string value at `/accounts/{account}/secrets_store/stores/{store}/secrets`.
Metadata reads, PATCH updates and DELETE operations address provider secret
IDs. The public API has no numbered version receipt or activation endpoint.
Editing a secret replaces its value for every service using it. An `active`
metadata status does not prove a TerraScale generation or atomic propagation.

The Cloudflare client and local provider fixture use these documented
operations. Lists validate pagination, resource identity and metadata;
reconciliation requires active secret references. Mutation requests make one
HTTP attempt. Lost responses, malformed success receipts and server errors
return an unknown-outcome error requiring observation before another mutation.
Provider messages and secret values are excluded from returned errors.

The unsupported `keyrotation.CloudflareSecretsStore` adapter and its invented
version/activation tests have been removed. `security.SecretsStore` retains
the required rotation lifecycle. A complete Cloudflare implementation needs:

- Durable generation-to-secret-ID receipts and recovery after a create
  succeeds but its response or journal commit is lost.
- A published capability-key encoding shared with consumers. The API accepts
  UTF-8 strings; it has no `value_base64` field.
- A supported consumer binding and rollout contract. The inspected scopes
  cover Workers, AI Gateway, DEX, Access, containers and web search; they do
  not establish a Secrets Store binding for Snippets.
- Consumer generation observations, overlap and retirement proof, and
  rollback behavior. Sequential updates cannot provide atomic pair activation.
- Authority checks at each dispatch and stale-owner-safe failure handling.
  Cloudflare does not consume the global lease as an update precondition;
  a request already accepted can finish after ownership changes.

Acceptance requires wiring those contracts through the production rotation
controller. Plain CRUD cannot satisfy `security.SecretsStore` activation or
consumer fencing. HTTP contract tests do not qualify propagation or rotation.
The [portable verification](../evidence/cloudflare-secrets-contract-gates-2026-09-05.txt)
passed for the integrated client, fixture and unsupported-adapter removal.

The [source record](../evidence/cloudflare-secrets-api-sources-2026-09-05.json)
pins the inspected official SDK and product documentation with SHA256 digests.
The SDK contract is at commit
[`a45114730bf2f913c5adff8f3ed7bf7534feffb9`](https://github.com/cloudflare/cloudflare-go/blob/a45114730bf2f913c5adff8f3ed7bf7534feffb9/secrets_store/storesecret.go).
The [editing documentation](https://github.com/cloudflare/cloudflare-docs/blob/b08e3ed60e843d788f301e55ca8f7d8c2caffca2/src/content/docs/secrets-store/manage-secrets/how-to.mdx)
states that changes affect all consuming services.
