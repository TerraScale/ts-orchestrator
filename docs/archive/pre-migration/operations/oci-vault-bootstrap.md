# Pinned OCI Vault credential delivery

The single orchestrator executable provides `oci-bootstrap-secrets` for the
credential-delivery stage of first boot. It runs before loading normal runtime
configuration or connecting to NATS. It uses OCI Instance Principal; there is
no user API-key or inline-secret option.

The command consumes two locally trusted files: supported-region intent from
`ts-infra`, and a manifest of pinned Vault references. The manifest is public
configuration, at most 32 KiB, with 1–32 files:

```json
{
  "schemaVersion": 1,
  "region": "GRU",
  "files": [
    {
      "name": "controller.nk",
      "secretId": "ocid1.vaultsecret.oc1.sa-saopaulo-1.example",
      "version": 1,
      "sha256": "replace-with-the-64-character-lowercase-sha256-of-decoded-secret-bytes"
    }
  ]
}
```

Replace the example OCID and digest. Entries accept basenames only, a positive
exact version, and a secret OCID in the manifest's OCI region. Unknown or
duplicate properties, duplicate names, unsafe paths and references to another
region fail before authentication. There is no `LATEST` alias. The endpoint is
derived from the canonical region mapping, never a manifest URL.

Run as the OS identity that will own this role's credential files. The output
parent must already exist with mode `0700`. The manifest must be protected from
group/other writes; region intent must be owner-private. Input and output paths
must not traverse symlinks.

```sh
terrascale-orchestrator oci-bootstrap-secrets \
  --manifest /etc/terrascale/controller-vault.json \
  --region-intent /etc/terrascale/region-intent.json \
  --output /run/terrascale/controller/credentials-v1
```

Use separate bundles and OS identities for controllers, journal provisioners,
journal writers, NATS, and workloads. A controller bundle must not contain the
journal writer's signing key. Separate Unix users on one VM do not create
separate Instance Principals: every process able to use that instance identity
can request the same Vault secrets. The controller's principal must be denied
the journal writer key, including permission to grant itself that access.
First boot therefore needs a separate journal identity with an enforceable
OCI boundary (for example, a separately administered host/compartment), or an
equivalent reviewed isolation mechanism. Merely installing the key under a
different Unix user on the controller VM is insufficient. This boundary is
still an open first-boot requirement. A separate writer VM is also insufficient
if the controller can replace its bootstrap, modify its instance, attach/read
its boot volume, or otherwise obtain its principal. The policy review must
exclude those paths as well as direct Vault access. Root IAM and signing trust
cannot be delegated to the controller as part of the resource handoff.

IAM must restrict `read secret-bundles` to the
exact approved secret IDs and principals. The command does not create policies,
Vaults, keys or secret versions.

Responses must match the requested OCID and version. Decoded secrets are bounded
to 64 KiB and must match their pinned SHA-256. Files are created as `0600` below
a private staging directory, flushed, and published together by renaming that
directory. Download/digest failures remove staging without publishing a partial
bundle. Decoded buffers are cleared after writing. Errors emit only an exception
type, never provider response bodies, credentials, or file contents. Success
emits JSON with region, file count and `state: verified`.

Repeated invocation verifies the existing bundle's complete file set,
permissions and digests without fetching it again. It never overwrites a changed
or foreign generation. This is filesystem idempotency, not a live Vault
authorization or revocation check. Use a new directory for a new generation;
the signed activation/rotation protocol must decide when to consume it.
Installing files alone does not admit a host.

The fetch phase has a three-minute cancellation budget and SDK calls use a
30-second HTTP timeout. The first-boot service must additionally enforce an
overall startup timeout, including synchronous Instance Principal discovery.
A hard process kill can leave private unpublished staging files. The next
invocation can publish a fresh complete generation; its supervisor must clean
abandoned staging directories after proving no installer is using them.
A tmpfs runtime directory is recommended.

Local TUnit tests exercise CLI composition, request version pinning, response
identity, private atomic publication, failure cleanup, redaction, cancellation,
and restart verification with an injected Vault transport. A loopback HTTP test
also exercises the real SDK request signer, pinned-version query and response
decoder with a disposable synthetic API key used only by the test. Real Instance
Principal allow/deny checks and delivery on OCI remain required, along with
enrollment renewal, the founding quorum and resource ownership transfer in
[control-bootstrap.md](control-bootstrap.md).
