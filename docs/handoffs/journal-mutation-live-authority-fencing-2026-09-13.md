# Journal mutation live authority fencing handoff, 2026-09-13

The R3 operation journal mutation service cannot implement live authority
epoch/candidate/revision fencing with the current boundary. The service starts
with the operation KV store, proof-consumption KV store, a static authority
signature verifier, an eligible caller set, and a reply signer. It has no live
authority snapshot/provider. `NatsOperationJournalMutationAuthorityProof` binds
the cell, caller, action, operation key, operation CAS revision, ciphertext
digest, lease, expiry, and nonce; its `Revision` is the requested operation
revision and is not the authority KV revision. It carries no authority epoch or
candidate identity.

The dedicated journal-writer identity is intentionally denied `ORCH_LEADERS`
read access. This is now covered by
`NatsControlR3L0cTests.JournalWriterCannotObserveLiveAuthorityLeaseForMutationFencing`.
The test checks the live lease key plus the JetStream stream-info and direct-get
surfaces, so broadening writer permissions to create an implicit authority read
will fail the boundary test.

Completing the fence requires a coordinated protocol/composition change:

1. Add signed authority epoch, candidate identity, and authority KV revision to
   the mutation proof and request digest, with explicit wire validation.
2. Give the writer a read-only, bounded authority observation seam (or an
   equivalent authenticated authority assertion endpoint) that is available
   before the operation effect and again before the mutation acknowledgement.
3. Define the stale/unavailable result and proof-ledger ordering for a failed
   live fence. Keep the operation/proof writes and authority reads within their
   intended credential boundaries.

Until those interfaces exist, the mutation service continues to enforce its
existing signature, caller, expiry, single-use proof, and operation CAS checks;
it must not treat the signed lease string as a live authority fence.
