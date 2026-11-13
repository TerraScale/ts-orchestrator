# Public edge certificates

Every edge host loads its valid certificate files from `edge-certs` into memory
before opening its listeners. HTTPS and PostgreSQL TLS handshakes read only
that map. They perform no store reads, certificate issuance or disk writes.
Valid local certificates continue serving through store outages and rollouts.

Background reconciliation runs every ten seconds and when routes change.
Every store call has a three-second budget. Store initialization holds no lock
across network calls. Readiness is computed every three seconds from listeners,
local maintenance state, local certificates and backend probes. Its cached
verdict expires after ten seconds. Requests cause no store calls or probes.
A continuously assigned name has ten minutes before a missing certificate can
change readiness; removing and reassigning it starts a new interval.

## Names and key variants

The unit of caching, renewal, publication, leases and failure cooldowns is the
pair `(DNS name, key variant)`. ECDSA uses the name as its key; RSA uses `name+rsa`.
ECDSA is always required. RSA is required only if a certificate for that variant
already exists locally or in the shared store, including an expired copy. The
fleet preserves existing RSA coverage and never introduces RSA for a name that
has never had it. Every variant has its own renewal decision: its remaining
lifetime must be at most the smaller of thirty days and one third of its total
validity. A missing required variant is also ordered. A healthy variant causes
no order, regardless of the other variant. RSA renewal generates an RSA key and
saves the result under `name+rsa`. The handshake selects a valid certificate
supported by the client, including RSA-only clients.

A shared certificate replaces a local copy only when its expiry is later or,
for equal expiry, its SHA-256 certificate fingerprint is lexicographically
lower. All hosts use the same tie breaker. A preferable local copy is published
without ordering another certificate. Existing local certificates are never
removed to make reconciliation succeed.

## Issuance and cooldown

Each variant has one persistent record in `edge-certs`. It contains the sealed
certificate, lease generation and expiry, and retry state. Co-locating these
fields makes publication a single-key conditional update: the record revision
must still equal the issuer’s last acquired or renewed lease revision, and the
issuer checks that lease has not expired. Acquisition and every renewal advance
that revision. An older issuer cannot replace a newer holder’s record. This
uses one record rather than a check of a lease followed by an independent
certificate write; no multi-key transaction or reader generation heuristic is
needed. The five-minute order deadline is shorter than the ten-minute lease.
The lease is renewed every minute during an order.

The issued certificate and key are atomically saved together with a local
issuance receipt, then installed in memory, before separate metadata is saved.
A metadata failure is reported and reconciled later; it never discards an issued
certificate. The receipt records the fingerprint and lease generation in the
same atomic file as the key, so a restart cannot publish an unfenced result.
If the lease is lost, the host keeps and serves that valid certificate but does
not publish it. Publication can be retried without another order only while the
same lease generation remains live, using its current record revision.
Successful fenced publication clears the receipt. A later shared certificate
can still replace it by the normal preference rule.

After each failed order, the next attempt is delayed by 30 minutes, 1 hour,
2 hours, 4 hours, 8 hours, 16 hours, then 24 hours for every subsequent failure.
Any later authority `Retry-After` deadline wins. The authority response is
journaled immediately in an atomic owner-only local file before completion is
attempted. Reconciliation conditionally publishes the maximum of the journaled
and shared deadlines, preserving the current holder's lease generation and
expiry. A failed completion therefore cannot leave a longer authority deadline
local forever. The journal is removed only after publication is confirmed. A success clears the failure
sequence. The retry state is stored with the lease and mirrored in local memory
and owner-only local state files, so store outages and host restarts retain it.
No holder may order before either its local or the shared deadline. The ACME
client does not retry failed HTTP requests inside an order; the fleet cooldown
owns retries. Before an order begins, its lease also reserves the corresponding
retry delay plus the five-minute order budget. This conservative reservation
covers an issuer that disappears before recording its failure; a fenced completion
replaces it with the exact failure-relative deadline. A later journal publication
can only move the shared deadline forward.

Under persistent failure, one variant makes at most six orders in any first or
rolling 24-hour interval, starting with no failures: at offsets 0, 0.5, 1.5,
3.5, 7.5 and 15.5 hours at the earliest. Once the 24-hour ceiling is reached it
makes at most one per day. A name with both required variants therefore makes
at most twelve orders per day initially, six when only ECDSA is required.
Longer authority deadlines, order duration and abandoned-order reservations
only reduce those bounds. Each failure emits one warning with name, variant,
attempt and next attempt time, and increments
`ts_orch_edge_certificate_order_failures_total{name,variant}`. There are at
most two series per known routed name. These counters and the current
`ts_orch_edge_certificate_unsupported` count are exposed at
`/edge/certificates/metrics`, together with the host-scrape certificate series
listed under Metrics and alerts; serving and scraping them require no store reads.

The [published Let’s Encrypt limits](https://letsencrypt.org/docs/rate-limits/)
also apply independently:

| Authority limit | Published bound | Scope |
| --- | --- | --- |
| New orders | 300 per 3 hours | Per account |
| Authorization failures | 5 per hour | Per identifier per account |
| Certificates for the exact same identifier set | 5 per 7 days | Global across accounts |
| Certificates per registered domain | 50 per 7 days | Global across accounts |

The fleet's six attempts per variant per 24 hours (twelve per name with both
variants) bound failed attempts; they do not guarantee staying below every
authority limit. RSA and ECDSA share the per-name identifier and exact-set
limits, and share the registered-domain limit with all other names in that
domain. Per-host accounts do not avoid the global issuance limits. Publishing
existing certificates and waiting for complete holdings evidence prevents
unnecessary orders; authority deadlines remain mandatory even during urgent
renewal.

## Stored envelopes and encryption

A shared read has three outcomes:

- **Usable:** decrypt, validate and adopt the preferable valid certificate.
- **Absent:** retain any local certificate, publish an eligible local copy, or
  acquire a lease only after the holdings evidence gate permits it. An expired supported copy
  remains evidence that its variant is required and follows renewal rules.
- **Present but unsupported:** preserve the stored bytes and revision, never
  overwrite or delete the entry, and place no order for this name and variant.
  Continue serving any valid local copy. Log once per name per process start
  and include the variant in the unsupported count. Unknown format versions,
  unknown key identifiers, unreadable ciphertext and invalid certificate
  contents take this conservative path.

Version 1 envelopes carry an explicit `KeyID` identifying the one supported
mesh-derived key. A fleet-shared mesh secret derives the mesh CA seed, which
then derives a separate AES-256-GCM key through HKDF with the label
`ts-orch edge certificates v1`. Associated data binds ciphertext to the variant
cache key. Every host, and anyone who can read that shared mesh secret, can
decrypt stored certificate private keys. Database messaging tokens are not
used for this encryption. ACME account keys remain local to each host.

A build that reads a new envelope version or key identifier must reach every
host before any build writes it. If shared mesh secrets are ever replaced by
per-host identities, stored certificates must be re-encrypted through a planned
change. The explicit key identifier makes later rotation a normal envelope
case: first ship readers for the new identifier and key, then enable its writer
in a subsequent build. Preserve local certificate files throughout that change;
an unknown key must never be interpreted as permission to order a replacement.

## HTTP-01 and the authority

The authority is always the standard Let’s Encrypt directory. There is no
production override file, flag or switch. The disposable lane maps the real
authority hostname to its stand-in inside each node’s network namespace and
trusts its root through the lane’s own trust store. It has no route to the real
authority.

Hosts watch certificate records to maintain a local view of live issuance
leases. Token syntax and the routed-name policy are checked before I/O.
A served name whose lease watch has not delivered yet gets one bounded token
lookup. Both this lookup and normal active-order token reads share the same
16-request concurrency cap; excess requests receive 503 immediately.
Unserved names without a live lease return 404 without store I/O.
Shared tokens are bound to the host and expire after ten minutes.

Certificates and their persistent lease/cooldown metadata share one 16 MiB,
three-replica bucket. HTTP-01 tokens use a separate 1 MiB, three-replica bucket.
The buckets use the existing fabric account and its existing storage budget,
so older metadata leaders can serve certificate operations during rollout;
introducing JetStream in an account unsupported by an older metadata leader
would prevent urgent orders. Fabric clients can access the encrypted records;
decrypting the private keys still requires the mesh-derived key. The local
root operator uses the host's owner-only fabric credential for repair.
An older unused lease bucket can remain; this build neither depends on nor
writes it.

## Holdings evidence and rollout

Every upgraded host publishes all of its valid local certificates, including
names it is not currently routing, to the shared records. It also publishes an
inventory containing names, variants, expiry, healthy-until time and SHA-256
fingerprints, without certificate keys. Inventories share the certificate bucket.

Registered edges are the configured region founders, durably admitted mesh
founders and joined serving workers reported by the mesh. Inventories retain
previously registered identities and the ordering gate follows the union of
their rosters. A temporary disconnect does not establish absence. An unresolved
configured founder still requires an inventory. Retiring a host requires an
explicit membership change; a stale roster conservatively delays additions.

A missing shared record never proves that no certificate exists elsewhere.
An ordinary order requires inventories from every registered edge and no
healthy certificate for that name and variant in any inventory. A peer that
has not upgraded delays an addition until it publishes its existing certificate.
A host that is already serving a certificate for that name expiring within
14 days may order despite missing inventories. This urgent margin leaves many
daily attempts after the 30m, 1h, 2h, 4h, 8h, 16h, then 24h cooldown sequence;
it never bypasses an unreadable record, a lease, a store outage or Retry-After.

Retain local ECDSA, RSA and account-key files while rolling hosts individually.
Each host loads them before opening listeners, publishes eligible copies and
adopts preferable shared copies. Verify HTTPS, RSA-only HTTPS, PostgreSQL TLS,
readiness and inventories as the rollout proceeds. An asymmetric rollout with
RSA only on the first host and healthy ECDSA only on an older peer makes zero
orders; the first host adopts ECDSA when that peer upgrades.

## Repairing an unreadable record

Alert on `ts_orch_edge_certificate_expiry_seconds{name,variant}` approaching
expiry and on `ts_orch_edge_certificate_blocked_names` being nonzero. The latter
counts distinct names with at least one unreadable variant; the existing
`ts_orch_edge_certificate_unsupported` counts variants. Metrics use memory only.

On a host with a validated, unexpired local certificate and matching private key,
run as root, selecting exactly one name and variant:

```sh
ts-orch edge certificates repair --state /var/lib/ts-orch example.com ecdsa
```

The command reads the local key pair, validates its name, variant and validity,
then reads the shared record and conditionally replaces only its encrypted
certificate at that revision. It preserves all lease and
cooldown fields. A concurrent update makes the command fail; inspect the new
record before explicitly running it again. It refuses absent records, readable
records, unknown key identifiers and any format version other than v1, including a newer version. A
newer reader must handle those records; repair never overwrites them.

Verify that the blocked count clears after reconciliation and that both HTTPS
and PostgreSQL continue serving. A local certificate is never deleted as part
of repair. Keep local files throughout any planned encryption-key rotation.

# Edge certificate observation

Observation requests never obtain a certificate.

## Readiness

GET or HEAD /edge/ready is available on HTTP port 80 and on the node's mesh-facing HTTP port 9108. It returns 200 when all four edge listeners are bound, routes have loaded, ingress and local application backends are ready, and every routed HTTPS or PostgreSQL name has an unexpired certificate loaded in memory, ECDSA or RSA. Otherwise it returns 503. The certificate check runs on every request, so readiness turns true as soon as a certificate is installed and never before. The JSON body includes ready, missing infrastructure conditions, and missing_names. A name without a certificate within the issuance grace window (ten minutes from assignment) is listed under missing as `certificate <name> pending`; after that window it moves to missing_names, matching the reconciliation grace above. Readiness fails in both cases.

The endpoint is an operator signal. Release health does not consume it. The `edge readiness changed` log line reports the same verdict, including certificates, at most every three seconds.

It checks local HTTP backend readiness paths without following redirects and checks PostgreSQL backend TCP connectivity, within a three-second budget.

## Inventory

Run ts-orch edge certificates inventory to read every node in the persisted node list over its mesh address. Append local to inspect this node, a node name to select one node, or all for the fleet explicitly. Fleet and named-node reads load the existing node list directly, without initializing or writing node state.

GET /edge/certificates on mesh port 9108 returns certificates, missing_names and errors arrays. This endpoint shares the mesh host telemetry listener and its network access boundary. It is not exposed through the public HTTPS router. Nodes with no edge return an empty inventory and fail readiness.

Each certificate contains names, key_type, issuer, serial, not_before, not_after, fingerprint_sha256, source, valid and problems. The fingerprint is the SHA-256 of the leaf certificate's DER bytes. Source local identifies a certificate held in the reconciler's in-memory map, which is loaded from disk before the listeners open and refreshed by reconciliation and shared-store adoption; every held certificate is also kept on disk under edge-certs. Removing a disk file does not remove a certificate that the running edge still holds in memory.

Validation checks the leaf's private-key match, all DNS names, validity dates and the full chain through the system trust roots. Certificates and intermediate chains are parsed locally. No private key bytes enter the response or command output. Missing names are computed from the current local route tables; an optional key variant may be invalid without making a name missing if another valid variant covers it.

The command prints one line per certificate. It exits nonzero when a node cannot be read, its response is invalid, its inventory reports an error, or a served name has no valid certificate. Its errors identify unreadable nodes and missing names. An unserved certificate's failed validation is visible as valid=false.

## Metrics and alerts

The existing host telemetry /metrics scrape includes these series whenever an edge runs:

| Metric | Meaning |
|---|---|
| ts_edge_certificate_not_after{name,key_type} | Expiry timestamp in Unix seconds; the earliest held certificate for each routed name and key type |
| ts_edge_certificate_names_missing | Number of routed names without a valid certificate |
| ts_edge_ecdsa_unsupported_handshakes_total | Failed automatic certificate selections where locally held certificates cover the routed name but none supports the client's key requirements |
| ts_edge_autocert_orders_total{outcome} | Automatic new-order requests accepted (success) or rejected/unreachable (error), including renewal orders |

Name labels come only from the route tables. Key types and outcomes have bounded sets. Counters reset with the process. A successful order metric means the authority accepted the order; it does not mean issuance completed.

The production operational rules emit EdgeCertificateExpiryWarning within 21 days of expiry, EdgeCertificateExpiryCritical within 5 days, and EdgeCertificateMissing after a served name has lacked a valid certificate for 10 minutes. The expiry alerts can both fire within five days. The rules operate on each scraped node independently.

## HTTP-01 challenges

Challenge tokens must contain 22 to 128 ASCII base64url characters. Malformed tokens receive 404 before any lookup.

The challenge path has no rate limit in this build because a refused validation costs a certificate. Each request checks the existing local handler and, for public requests missing locally, the same regional peers over mesh mutual TLS in the same order. Peer requests remain local-only.
