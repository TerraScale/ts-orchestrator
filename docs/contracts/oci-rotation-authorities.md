# OCI rotation authorities

The production issuer uses OCI Certificates Management's `MANAGED_EXTERNALLY_ISSUED_BY_INTERNAL_CA` configuration. It submits a signed P-256 CSR containing exactly one configured SPIFFE URI. OCI's internally generated certificate configuration exposes only DNS/IP SANs, so it cannot replace this CSR flow.

Each principal gets a separate random 32-byte seed stored in OCI Vault. The seed derives a P-256 scalar; it never enters coordinator state or a file configuration. Workload and control material are JSON maps from principal ID to combined PEM certificate chain and private key. The member gateway selects one entry before transmission. A receiver must never receive another principal's map entries.

Creates use deterministic names and OCI retry tokens. OCI's resource record and freeform tags are the durable receipt: they bind the operation, generation, validity interval, and (for certificates) the Vault seed reference. Lost create acknowledgements are recovered by looking up the same unique resource name, validating its scope, and fetching version 1. Generation metadata is distinct from OCI's resource version. Resource names must remain reserved until their operation can no longer be retried.

All SDK calls, including signing and possible instance-principal refresh, execute under the shared OCI worker gate. Caller cancellation returns promptly while retaining the gate until the SDK exits. Every actual service HTTP dispatch checks the live global authority after signing. Only the configured regional OCI certificate and Vault service endpoints are allowed; redirects are disabled. SDK logging is disabled to prevent response bodies and federation credentials from entering logs.

Retirement schedules certificate and Vault-secret deletion through the actual OCI APIs. OCI enforces a deletion delay; consumer retirement and certificate validity end acceptance before physical deletion completes. Failed or ambiguous provider calls return bounded errors, never a fabricated successful receipt.

File configuration contains region, compartment, CA, Vault and encryption-key OCIDs plus principal IDs and SPIFFE URIs. Resolve the instance-principal provider only after acquiring the live global lease. Its context must last for the service lifetime because subsequent federation refreshes remain bound to that context.
