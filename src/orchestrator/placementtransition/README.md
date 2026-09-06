# Accepted epoch proofs

`New` constructs a GRU issuer using the authenticated R3 `authorityjournal`
stream transaction, pinned Ed25519 authority/genesis/member keys, and fixed
`placement.accepted` state key. The stream CAS fences the exact live authority
lease and records the proposed commit revision in the signed proof. Signing
alone is not acceptance: `Issue` returns bytes only after the durable transaction
and server commit timestamp have been verified. Unknown outcomes require the
same operation ID and request; they never authorize a new epoch.

`Request` binds a scope, epoch, generation, and sorted member identities to
Regions and each member's exact local proposal digest. Each Region contains
exactly two members. The scope must be the same environment/cluster identity
used by the engine consumer. Hash local proposals only after producer canonical
sorting and deterministic protobuf encoding.

Genesis requires a separately signed `GenesisGrant` whose request digest binds
the complete request. Empty durable state, a pending Stage receipt, a healthy
host, and a live authority lease cannot substitute for that grant. The grant ID
and every operation ID remain retained; capacity exhaustion fails closed.

Transitions require a signed `old_epoch_drained_fenced` receipt from at least one
member of **each old RF2 pair**. The receipt binds the exact prior epoch and
generation, successor request digest, and final durable frontier digest. This
quorum is valid only because every acknowledged old write requires both RF2
members and the member fence durably denies further old-epoch WAL acknowledgments
across restart. The engine receipt producer must drain in-flight work and persist
the final frontier before signing. Missing both old members cannot be automated
as an ordinary transition.

The returned grant authorizes membership acceptance, not data readiness. Before
serving, the engine must verify its exact local proposal binding and catch up
the new RF2 pair through every relevant old receipt's final frontier. The engine
must keep writes, reads and replication admission fenced until those independent
conditions hold. A controller cannot manufacture a member receipt with its
proof key.

Signed envelopes carry base64 raw UTF-8 JSON bytes and Ed25519 signatures over
`terrabase-placement-transition-v1\0` followed by those exact decoded bytes.
The receiver verifies the bytes before strict schema decoding; it does not
recanonicalize JSON. Genesis, member evidence and accepted proofs have distinct
`kind` values and pinned key roles. The proof includes the previous raw proof
payload's SHA-256 digest, commit revision, authority epoch, lease ID and complete
signed drain receipts for engine verification and catch-up.

Caller integration still needs the explicit genesis authorization workflow,
authenticated actual engine fence receipt producer, proof delivery endpoint,
engine signature verification and durable acceptance/catch-up. A successful
unit test or pending placement does not qualify that production chain.
