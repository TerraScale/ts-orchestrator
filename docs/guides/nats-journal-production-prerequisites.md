# Production CreateNode journal prerequisites

The Orchestrator can host a private NATS journal-writer substrate, but it does
not compose an enabled `NatsCreateNodeOperationJournal`, `CreateNodeCoordinator`,
or OCI provider. It must not report an authoritative CreateNode capability.

## Required code composition

The production composition root must create and retain all of the following as
one reviewed lifecycle:

- an R3/R5-validated `ORCH_OPERATIONS` store and `NatsCreateNodeOperationJournal`;
- a rotation-aware regional envelope-key service, receipt signer/resolver,
  recovery lookup signer/resolver, and invocation-capability signer/resolver;
- a mutation authority issuer available only to the authorized controller flow,
  plus the configured reply verifier and private mutation client;
- `CreateNodeCoordinator` bound to the authoritative journal; and
- a separately reviewed, explicitly enabled provider adapter.

No in-memory key ring, development journal, generic NATS request, or OCI
client placeholder is an acceptable substitute.

## Required external bootstrap

Production NATS ACL/bootstrap is intentionally not emitted by this repository
today. A valid artifact needs a separate owner-controlled source of truth for
regional account/JWT issuance, public NKey inventory, server host configuration,
and mTLS identities. Those inputs are not present here and private credentials
must not be written into this repository.

That external artifact must grant each eligible controller only its named
runtime subjects, the exact journal `create`/`update` publish subjects, and its
own reply namespace. It must deny journal KV and stream mutation subjects and
must not grant broad `_INBOX` access. The regional writer queue identity alone
may publish the journal KV and journal replies; infrastructure alone may create
or update the stream. Controller, writer, infrastructure, authority, and reply
signing identities must satisfy the code-level NKey/TLS/SPKI separation checks.

## Required qualification evidence

Before enabling composition, retain a targeted three-server regional NATS test
with TLS, account ACLs, and real credential delivery. It must prove R3 commit
and one-member loss behavior; controller denial of KV delete/purge/rollup and
stream mutation; caller-scoped reply routing and forged-reply rejection; all
eligible controllers through multiple writer instances; key rotation; and the
full CreateNode crash/recovery flow against an approved provider. This is an
evidence gate, not a local RF1 or OCI claim.
