# Production CreateNode journal prerequisites

The Orchestrator can host a private NATS journal-writer substrate, but it does
not compose an enabled `NatsCreateNodeOperationJournal`, `CreateNodeCoordinator`,
or OCI provider. It must not report an authoritative CreateNode capability.

## Required code composition

The production composition root must create and retain all of the following as
one reviewed lifecycle:

- R3/R5-validated `ORCH_OPERATIONS` and `ORCH_OPERATION_PROOFS` stores, plus
  `NatsCreateNodeOperationJournal`; the latter is a five-minute, create-only
  nonce/lease consumption ledger for private mutation authority proofs;
- a rotation-aware regional envelope-key service, receipt signer/resolver,
  recovery lookup signer/resolver, and invocation-capability signer/resolver;
- a mutation authority issuer available only to the authorized controller flow,
  plus the configured reply verifier and private mutation client;
- `CreateNodeCoordinator` bound to the authoritative journal; and
- a separately reviewed, explicitly enabled provider adapter.

No in-memory key ring, development journal, generic NATS request, or OCI
client placeholder is an acceptable substitute.

## Process and credential boundary

Run the controller (`run` or `check`) and writer (`journal-writer`) as separate
native workload roles. The controller command rejects journal-writer NKey,
mTLS, and reply-private-key environment values before any file resolution. The
writer command rejects controller NKey/mTLS values and is the only command that
opens writer credentials or starts the mutation service. A controller uses its
own scoped request/reply NATS identity and only public reply-verification
material. `provision-journal` runs with only its infrastructure NKey and mTLS
identity; it must not receive or open controller or writer private material,
and it does not load the generic Infisical runtime secret environment.
The development fixture models those identities and permissions but does not
establish a deployed workload, host mount policy, or R3 boundary.

## Required external bootstrap

Production NATS ACL/bootstrap is intentionally not emitted by this repository
today. A valid artifact needs a separate owner-controlled source of truth for
regional account/JWT issuance, public NKey inventory, server host configuration,
and mTLS identities. Those inputs are not present here and private credentials
must not be written into this repository.

That external artifact must grant each eligible controller only its named
runtime subjects, the exact journal `create`/`update` publish subjects, and its
own reply namespace. It must deny both journal KV stores, both JetStream
`DIRECT.GET` and `STREAM.MSG.GET` APIs, and every consumer create/list/info/
delete/fetch/acknowledgement/flow-control path for the operation and proof
streams; it must also deny push delivery to controller-readable subjects and
must not grant broad `_INBOX` access. The regional writer queue
identity alone may publish `ORCH_OPERATIONS`, `ORCH_OPERATION_PROOFS`, and
journal replies; infrastructure alone may create or update either stream.
`provision-journal` cannot attest cross-workload private identity separation,
so that admission belongs to the external credential-delivery policy. The
proof ledger must retain a successful create for five minutes and reject a
duplicate `(cell, controller, lease, nonce)` before the writer attempts a
journal mutation. Controller, writer, infrastructure, authority, and reply
signing identities must be independently separated by that policy.

## Required qualification evidence

Before enabling composition, retain a targeted three-server regional NATS test
with TLS, account ACLs, and real credential delivery. It must prove R3 commit
and one-member loss behavior; controller denial of KV delete/purge/rollup and
stream mutation; caller-scoped reply routing and forged-reply rejection; all
eligible controllers through multiple writer instances; one atomic proof-ledger
consume across writers and restart before a journal mutation; key rotation; and
the full CreateNode crash/recovery flow against an approved provider. This is
an evidence gate, not a local RF1 or OCI claim.
