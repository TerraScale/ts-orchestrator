# Local VM backup fixture, 2026-09-06

This fixture exercises local encrypted backup transport. It does not qualify
Tigris availability, geography, residency enforcement at the real provider, OCI
Vault key delivery, or the production six-member estate.

The previous declaration-only backup changes could not run: no HTTPS listener
existed, the network validator compared guest port 443 with host port 19443,
backup credentials were copied only with later database-host admission material,
and those paths were not accepted as TerraBase-owned guest files.

The runtime now binds the planned backup listener and serves signed S3
single-object PUT/GET/HEAD/DELETE requests through the existing bounded local
object-store handler. It validates SigV4 against the declaration's protected
credential files before mapping requests to the OCI-style handler. Each fixture
uses a private temporary store removed during service cleanup. The endpoint is
mapped inside the guest network; generated fixture credentials are not sent to
public Tigris.

The generated qualification TLS certificate includes the backup hostname alongside
the artifact hostname. Its per-run CA is installed by the existing Ubuntu
`update-ca-certificates` bootstrap. TerraBase's `object_store` dependency uses
`reqwest` with `rustls-tls-native-roots`, so the real Rust client consumes those
Ubuntu trust roots without disabling TLS validation or adding a product setting.

Backup credential material is independent of database-host admission, covers each
database and destination index, and is installed as mode 0400 owned by TerraBase.
It is cloned and cleared with the rest of the validated engine material.

## Verification

The focused initial-host material, NoCloud material, and HTTPS tests pass.
`TestBackupFixtureTLSAndSignedObjectRoundtrip` uses curl's independent SigV4
producer to prove trusted HTTPS PUT/GET, rejection of a wrong signature without
mutation, and removal of the fixture store. This caught and corrected an OCI
handler response mismatch: PUT advertised the stored object's Content-Length
while returning no response body.

A static diagnostic probe invokes actual TerraBase `ObjectDestination::new`,
`put_member`, `get_member`, and authenticated `ArtifactCipher` encryption/decryption.
The cipher explicitly uses local fixture key generation; it makes no production
key-provider claim. Probe source and build inputs are retained in the workspace's
`.agents/swarm-production/vm-backup-fixture/` evidence directory.

The first actual guest attempt, retained privately at
`/var/lib/tsq-astra/astra-backup/`, reached cloud-init's final stage but exceeded
the unchanged installation deadline before executing the probe. Its uncompressed
12 MiB binary made YAML parsing consume the startup budget. The next diagnostic
build uses cloud-init's supported `gz+b64` encoding for a 4.1 MiB payload. No
startup guard or deadline was changed. The second run is pending.

The diagnostic build preserves normal signed artifact installation and cleanup.
Until the admitted initial-GRU-to-production producer is integrated, these runs
explicitly defer the declaration's later engine-control/database-host objects;
backup credentials remain present. They cannot qualify the full G1 suite.

Separate full-package failures remain: the generic six-host controller-seed test
assigns an observer to unselected SFO/FRA hosts without database-host admission;
the compute fallback test reports an unknown OCI request outcome. Neither is
covered by the focused backup tests.
