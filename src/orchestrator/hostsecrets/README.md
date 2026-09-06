# Host credential bootstrap

`ValidateSeed` and `ParseSeed` admit a public declaration of an OCI Region,
operation ID, and explicit Vault secret OCIDs, version numbers, SHA-256
hex digests, and credential destinations. The immutable host admission
manifest/configuration must bind these references and their generation.
The seed itself contains no credential bytes. `CURRENT` is never selected.

`BootstrapFile(ctx, hostsecrets.SeedPath)` reads the root-owned public seed
at `/etc/terrascale/host-secrets.json`. Only an absent seed returns
`os.ErrNotExist`; malformed, unsafe, or failed bootstrap returns a fixed error
label. Non-OCI VM qualification may explicitly omit this seed. An OCI seed
must be fetched successfully before ts-node loads its NATS credentials or
starts dependent services. `Bootstrap(ctx, Seed)` accepts an already-admitted
seed. Publication requires Linux and effective UID 0.

Up to thirteen credential leaves are allowed: `client.key` and `user.seed`
below both `/etc/terrascale/ts-node-bootstrap` and
`/etc/terrascale/ts-node-authority`; `storage-transition-receipt.key` below
`ts-node-bootstrap`; `membership.key` and `command.key` below
`/etc/terrascale/orchestrator`; and `server.key`, `client.key`, `user.seed`
below each `global` and `regional` orchestrator directory. Unit, binary,
configuration, and arbitrary absolute file destinations are refused.

The concrete client uses Oracle's pinned Go SDK v65.124.1:

- `auth.InstancePrincipalConfigurationForRegionWithCustomClient` retrieves
  the instance identity and performs official X.509 federation/signing.
- `secrets.SecretsClient.GetSecretBundle` requests the exact version number.
- The response's secret ID, version, strict base64 contents, digest, and
  expiry/deletion times are checked before publication.

The transport allows only the fixed OCI metadata address and the selected
Region's OCI authentication and Vault Secrets endpoints, disables proxies
and redirects, and uses verified TLS. Network requests have a 20-second
limit; the bootstrap has a three-minute limit shortened by the caller's
context. Secret GET automatic retries are disabled. Restart retries use the
same immutable declaration and exact version. Responses, including error
bodies, are bounded to 256 KiB; decoded secrets are bounded to 64 KiB and the
seed to 32 KiB.

The SDK's metadata and federation loops contain sleeps that cannot be
interrupted by context. One process-wide SDK worker bounds both identity
construction and signing/fetch operations. A deadline returns a fixed failure,
never a successful identity. At most one canceled worker may remain asleep;
its dispatcher refuses subsequent network attempts. Later calls wait with
their own contexts and do not create queued worker goroutines.

Importing this package installs a no-output logger for the entire official
OCI SDK through `common.SetSDKLogger`. This suppresses SDK logs even when
`OCI_GO_SDK_DEBUG` requests body dumps. Application composition must not
replace that logger with a body-logging sink. Provider response bodies and
raw SDK errors are never returned or logged by this package. Temporary byte
buffers are cleared where owned; Go/SDK string allocations cannot promise
complete memory erasure.

Publication opens every directory component without following symlinks,
requires root ownership without group/world write permission, and takes a
process-shared file lock. Before creating a journal, every destination and
pending credential name must be absent, even if an existing file has the
expected digest. A complete public seed journal is fsynced and atomically
renamed into place without replacement, followed by directory fsync. The journal owns the exact
pending credential names. Each credential is written to a root-owned 0600
regular file, fsynced, renamed with `RENAME_NOREPLACE`, and followed by directory
fsync and verified readback. Symlinks, hard links, wrong permissions, changed
bytes, and changed seed generations fail closed.

A crash before credential publication can leave an owned partial pending
file; the same journaled operation safely rewrites that pending file. A crash
after publication is recovered by verifying the final file and fsyncing its
directory again. Journal retries likewise repeat the root-directory fsync, and existing
directory admission repeats its parent fsync. Credentials are
published individually, so startup must wait for the whole bootstrap to
succeed. Initial bootstrap does not rotate or remove existing credentials;
a changed declaration requires a separate authorized lifecycle. A crash
before renaming a journal may leave a root-private temporary public journal;
it contains no secret bytes and does not grant ownership of destinations.

Tests use the real SDK request/signing implementation with test-owned RSA
keys and HTTP transports, plus unprivileged Linux filesystem operations with
the test UID. They cover pinned requests, corrupt/mismatched/oversized bundles,
metadata cancellation without further HTTP, scope rejection, durable restart,
partial pending recovery, and symlink/hardlink/unknown-file refusal. No OCI
credentials or privileged test commands are used. Real instance-principal
IAM/Vault retrieval and guest startup remain qualification requirements.

SDK sources consulted: [instance-principal provider](https://github.com/oracle/oci-go-sdk/blob/v65.124.1/common/auth/configuration.go),
[metadata retry loop](https://github.com/oracle/oci-go-sdk/blob/v65.124.1/common/auth/instance_principal_key_provider.go),
[Secrets request contract](https://github.com/oracle/oci-go-sdk/blob/v65.124.1/secrets/get_secret_bundle_request_response.go),
and [SDK logging](https://github.com/oracle/oci-go-sdk/blob/v65.124.1/common/log.go).

After the owner-signed bootstrap manifest is authenticated and durably admitted,
ts-node creates its declared `terrascale-orchestrator` account and calls
`AdmitOrchestratorOwnershipFile(ctx, SeedPath, OrchestratorUser, manifestDigest)`
before starting that service. The digest is the admitted manifest's bare
SHA-256. Only this fixed service name is accepted. A separate root-private,
immutable journal binds the full seed digest, manifest digest, and resolved
numeric UID/GID before any ownership changes. All seed credentials must
already be present and verified before this journal can be admitted.

Only the allowlisted orchestrator credential leaves move to that exact UID/GID,
remaining 0600. `/etc/terrascale` and the fixed orchestrator parent directories
remain root-owned and become 0711: the service can traverse known paths but
cannot list or modify configuration directories. Public certificate/trust/config
files supplied by the seed must independently be service-readable. The
`ts-node-bootstrap` directory and its credentials, including the transition
receipt key, retain their root-private permissions and ownership.

A retry accepts only root ownership during an interrupted handoff or the exact
journaled service UID/GID, verifies the original digest, and completes file and
directory fsyncs. A missing credential after ownership admission fails closed;
it is not fetched again. Changing a manifest binding or numeric owner is
refused. Tests use the unprivileged test UID to exercise handoff, traversal,
journal-fsync failure recovery, missing-file refusal, and binding conflicts.

The ts-node caller must hold its durable node authority lock while provisioning
and handing off credentials. On later starts, it must consult the validated
accepted runtime authority/retirement record under that same lock before
calling initial bootstrap. Once runtime authority has retired bootstrap, the
caller skips this initial seed entirely; this package must not validate or
restore old secret bytes after runtime credential rotation. Completing the
initial signed grant alone does not constitute runtime retirement.

The bootstrap-control compiler requires an opted-in storage transition to use
`/etc/terrascale/ts-node-bootstrap/storage-transition-receipt.key` and include
its exact Vault version in the seed. It validates a single P-256 private key,
rejects owner keys, regional command keys, keys reused by other seeded
credentials, and shared receipt keys across hosts. A receipt seed without a
corresponding signed transition descriptor is refused. Cloud-init carries only
the Vault reference, version, and digest; the private key is retrieved on-host.
The later owner-signed plan must still bind that key's public identity.
