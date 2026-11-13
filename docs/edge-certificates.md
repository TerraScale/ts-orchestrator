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

The result is installed locally before publication. Its fingerprint is first
persisted as withheld from reconciliation. If the lease is lost, the host keeps
and serves that valid certificate but does not publish it, including after a
restart. Publication can be retried without another order only while the same lease generation remains live, using its current record revision. Successful fenced publication clears the withheld marker. A later
shared certificate can still replace it by the normal preference rule.

After each failed order, the next attempt is delayed by 30 minutes, 1 hour,
2 hours, 4 hours, 8 hours, 16 hours, then 24 hours for every subsequent failure.
Any later authority `Retry-After` deadline wins. A success clears the failure
sequence. The retry state is stored with the lease and mirrored in local memory
and owner-only local state files, so store outages and host restarts retain it.
No holder may order before either its local or the shared deadline. The ACME
client does not retry failed HTTP requests inside an order; the fleet cooldown
owns retries. Before an order begins, its lease also reserves the corresponding
retry delay plus the five-minute order budget. This conservative reservation
covers an issuer that disappears before recording its failure; a reported
failure replaces it with the exact failure-relative deadline.

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
`/edge/certificates/metrics`; serving and scraping them require no store reads.

## Stored envelopes and encryption

A shared read has three outcomes:

- **Usable:** decrypt, validate and adopt the preferable valid certificate.
- **Absent:** retain any local certificate, publish an eligible local copy, or
  acquire a lease for a missing required variant. An expired supported copy
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

Hosts watch the certificate records to maintain a small local view of live
issuance leases. A challenge-shaped request with no live lease for its host
returns 404 without a store call. Token syntax is checked before I/O. Active
orders allow at most `challengeReadLimit` (16) concurrent token reads per node;
excess requests receive 503 immediately. Shared tokens are bound to the host
and expire after ten minutes. Replacing active-order token reads with a
watch-fed token cache is a later change.

Certificates and their persistent lease/cooldown metadata share one 16 MiB,
three-replica bucket. HTTP-01 tokens use a separate 1 MiB, three-replica bucket.
An older unused lease bucket can remain within the existing three-stream,
64 MiB account limit; this build neither depends on nor writes it.

## First rollout across all six hosts

Roll through all six edge hosts, one host at a time. Before upgrading each host, retain its existing ECDSA, RSA and account-key
files. Each upgraded host loads those files before listeners start, publishes
eligible local certificates, and adopts preferable shared copies. Later local
expiry wins; equal expiry converges by fingerprint. A healthy existing variant
never causes an authority order. Hosts awaiting their upgrade continue serving
their existing local files.

For shared web and PostgreSQL names, the first upgraded host seeds the shared
record; the next five hosts each reconcile their own copies independently.
Regional names are reconciled only where the local route tables contain them.
Repeat local-file preservation, adoption and publication on each remaining host
so every regional web and PostgreSQL alias is published and every existing RSA
variant is retained. Verify HTTPS, RSA-only HTTPS,
PostgreSQL TLS and readiness on all six hosts before completing the rollout.
Expiry metrics and the expiry alert rule remain a separate change.
