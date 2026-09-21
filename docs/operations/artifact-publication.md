# Immutable regional artifact publication

`operator artifact-push --file <path>` uses the authenticated regional TLS/JWT
or NKey connection and the existing controller artifact grants. The read-only
operator identity cannot upload. It prints `sha256:<hex>` only after confirming
the committed object. Hosts retain their restricted request/reply grants.

The command captures a private, immediately unlinked local snapshot before
publishing. Its SHA-256 and uploaded bytes come from that same snapshot, so
changing the original file cannot change the upload after hashing. Empty files
and files larger than 512 MiB are rejected. Snapshot storage is bounded per
invocation; its handle closes on success, cancellation or failure. The snapshot
and publication share a five-minute cancellation budget.

The publisher reads the infrastructure-provisioned `ORCH_ARTIFACTS` stream
configuration and checks the closed regional profile. In particular it requires
file storage, no age expiry, no message-count eviction, an 8 GiB byte cap and
`Discard.New`. Existing artifacts must not be evicted to accept another upload.
The CLI discovers the provisioned replication factor and does not create or
update the stream.

## Publication and recovery

The object name and chunk identity are both `sha256-<lowercase hex>`. Chunks use
the single subject `$O.ORCH_ARTIFACTS.C.<identity>` and fixed 128 KiB boundaries.
Before appending each chunk, the publisher reads and compares any existing
prefix byte for byte. Appends require the exact last sequence for that subject.
A concurrent publisher either appends the next chunk or observes and verifies
the winner's bytes. Sequence conflicts are bounded to eight attempts per chunk
or metadata commit, with a 25 ms delay before retrying an unresolved conflict.
An in-progress metadata winner need not be immediately visible to the losing
publisher; its conditional retry never replaces that winner.

Metadata is written once with expected last-subject sequence zero, after all
bytes are present and there are no extra chunks. The canonical JSON layout is
independent of SDK model defaults. Both metadata subjects and digest values use
the padded base64url encoding required by the pinned NATS.Net 2.7.2 object-store
reader. The last chunk may be full; an extra empty chunk is unnecessary for
these nonempty artifacts.

A retry after a lost chunk or metadata acknowledgement rereads the same durable
prefix. Concurrent uploads and restarts do not create random abandoned object
identities. Exact repeats verify stored bytes and leave stream sequence, byte
and message counts unchanged. Existing mismatched metadata, links, corrupt or
missing committed chunks, extra chunks and multiple metadata records fail
closed. The publisher does not repair or replace a conflicting digest name.

No SDK `PutAsync`, metadata rollup, stream purge, deletion, new host permission
or controller purge permission is involved. This is a conditional writer
protocol, not broker enforcement against a malicious writer with raw publish
authority. Host delivery independently verifies the requested SHA-256.

## Capacity and remaining lifecycle work

An interrupted upload leaves at most one reusable prefix per digest. A retry of
that digest reuses it; different abandoned digests still consume capacity. All
prefixes, completed objects and their message overhead share the 8 GiB stream
cap. At capacity the server rejects new writes instead of deleting existing
artifacts. An upload can run out of capacity before committing its metadata;
the caller must treat the failure as incomplete or uncertain and retry safely.

Automatic reclamation is **not implemented**. Deployment still requires a
separately authorized, durably fenced retention/retirement protocol that protects
active desired targets, rollback artifacts, readers and in-progress publishers.
Age-only deletion or granting the controller broad purge authority would not
establish those protections. No manual purge is part of this readiness work.

## Local verification

The [local receipt](../evidence/artifact-publication-local-2026-09-21.json)
records **65 passed, zero failures or skips**, a warning-free Release build and
required style checks on the same source. This focused qualification includes
publisher, existing host delivery, cache and permission tests; the earlier
full-suite receipt applies to the preceding artifact-delivery revision.

`ImmutableArtifactPublisherTests` covers concurrent writers, lost acknowledgements
after every write, stale absence, poisoned/missing/trailing content, source
mutation, snapshot bounds and cancellation with resumed publication.
`ArtifactPublisherR3Tests` invokes the actual CLI with separate restricted
controller identities on a JWT/mTLS three-member NATS cluster. It verifies SDK
and controller-cache interoperability, partial and full final chunks, unchanged
stream counts after retries, a broker member restart, corrupted existing
metadata and host denial. Lost acknowledgements are injected after a real
durable append and followed by disconnect/reconnect; this does not simulate
every network partition or a full cluster outage.

These are small-artifact tests. Release-sized transfers with real renewing host
sessions, resource measurements, native ARM64 execution and OCI authentication
remain separate readiness gates. See [host delivery](host-artifact-delivery.md)
and the [readiness record](../evidence/oci-readiness-2026-09-20.md).
