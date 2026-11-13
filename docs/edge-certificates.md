# Public edge certificates

Each host loads its valid ECDSA and RSA certificate files from edge-certs
into memory before opening its listeners. HTTPS and PostgreSQL TLS handshakes
read that map. They perform no store reads, certificate issuance or disk writes.
The host continues serving its valid certificates during a mesh outage, an
election or a rollout with older mesh servers.

Every ten seconds, and when routes change, background reconciliation handles
each routed name independently. Store operations have a three-second budget.
Store initialization does not hold a lock across network calls. A valid shared
certificate replaces the local certificate only if its expiry is later. A local
certificate missing from the store, or newer than the shared one, is published
with revision fencing. Renewal uses a server-expiring lease, a shorter issuance
deadline and a revision-fenced release. A host never issues without that lease.
The resulting certificate enters the local file and memory before publication;
a failed publication is reconciled from that local copy without another order.

Readiness is recomputed every three seconds from listeners, local maintenance
state, the memory map and local backend probes. Requests only read the cached
verdict; they cause no probes or store calls. The verdict expires after ten
seconds if its background computation stops. Certificate requirements apply
only to names in this host's HTTPS and PostgreSQL route tables, after ten
minutes of continuous assignment. A newly assigned name therefore gets one
issuance-lease interval before its missing certificate can change readiness.
Removing and reassigning the name starts a new interval. An expired certificate
for an established name fails readiness.

The mesh host's private CA seed supplies the encryption input, through the same
identity derivation used in production. Tasks do not receive that seed. HKDF
with the separate "ts-orch edge certificates v1" label derives the AES-256-GCM
key. Each value includes its derivation version and key fingerprint. Unknown
versions, values from another seed and invalid ciphertext are treated as
unavailable shared copies; they never invalidate local serving. The database's
messaging token is not used to encrypt certificates.

Rotating the host-only mesh secret also rotates the mesh CA and the certificate
encryption key. Coordinate that rotation across hosts. Keep each host's local
certificate files through the rotation: upgraded hosts republish them under the
new version. A host with only the old secret cannot decrypt new shared values;
a new host with no local files needs a host holding the new secret to publish a
valid copy, or must acquire an issuance lease. Removing the old local files
before republishing would require new authority orders.

The store uses three buckets: certificates (16 MiB), issuance leases (1 MiB)
and HTTP-01 tokens (1 MiB). All use three replicas. No fourth stream is needed;
the host account retains its three-stream, 64 MiB limit.

The default authority is Let's Encrypt. A host's owner-only edge-acme.json can
name another ACME directory with a DirectoryURL member. The disposable lane
uses this file for its standalone authority process, generates the mesh secret
through its Vault stand-in, and runs the production account and key path.

## First rollout on gru, sjc and fra

Each of the three hosts first loads its existing certificate files unchanged.
For shared web and PostgreSQL names, the first upgraded host publishes its
valid local copy. Later hosts adopt a shared copy when it expires later than
their local copy; a later-expiring local copy is published instead. Existing
valid copies outside the renewal window cause no authority order.

Regional names are reconciled only by hosts whose route tables include them.
Each regional host publishes the existing certificates for its own regional
web and PostgreSQL aliases when it upgrades. Other stored files remain local
until their names are routed. Existing RSA files keep their +rsa cache names
and follow the same adoption rule. ACME account keys remain local to each host.
Hosts still on the main build serve their own existing files until upgraded.

PARKED: next slice: per-name expiry metrics, renewal-failure counters and authority-aware
failure backoff; the expiry alert rule belongs to the monitoring change.
PARKED: next slice: replace bounded HTTP-01 request reads with a local token map
maintained by a store watch. Malformed tokens already return 404 without I/O.
