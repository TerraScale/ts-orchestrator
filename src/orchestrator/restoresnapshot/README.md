# Control snapshot Object Storage

`Store` implements the restore drill snapshot storage and verified mirror
contracts using the real OCI Object Storage adapter. Each Region has its own
signed transport and an exact bucket ownership record. Construction requires
a durable provider mutation journal, durable ownership journal, and a live
global authorization callback; production must bind those journals to the
authoritative control store.

Snapshot keys are immutable beneath the configured prefix (default
`jetstream/control/`) and end in `.epoch-N.snapshot`. New PUTs require the
callback to verify live global mutation authority at term N and permission
for the explicit destination Region. N is the snapshot's global control term;
it is never compared with the destination's regional election term. Provider mutation records bind the
namespace, bucket, key, epoch, byte length, and digest. Existing identical
objects can be read and verified after authority advances. Conflicting bytes
cannot replace an existing key. OCI receives `If-None-Match: *`.

Every read verifies bounded complete bytes against HEAD and GET metadata.
Every write performs that readback before reporting success. Mirrors read the
configured source Region, validate the drill snapshot identity, write to the
explicit destination Region, and verify the destination bytes. An absent
object, journal failure, changed ownership generation, stale epoch, mismatched
metadata, corrupt body, or oversized response stops the operation.

This package does not provision buckets or declare successful snapshots. The
composition must provide the reconciled bucket resource ID and ownership
generation and instantiate the NATS snapshotter separately. OCI has no
application epoch conditional header; the live authority check precedes the
journaled conditional request, and does not cancel a request already accepted
by OCI. Immutable object naming and conditional PUT prevent replacement.

The tests exercise real OCI request construction through an in-process HTTP
transport, using test-owned CAS and signing fixtures. They are HTTP contract
checks, not real-tenancy qualification evidence.
