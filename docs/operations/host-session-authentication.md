# Host enrollment scope and session request authentication

The signed regional node enrollment uses canonical version
`terrascale-regional-node-enrollment-v2`. Its mandatory `Scope` contains the
exact environment and a nonempty, unique set of admitted roles. Roles are
copied and sorted before signing. An enrollment for TerraBase in production
cannot authorize auth, an expanded role set, or another environment. The
host admission gate checks scope before consuming a generation; runtime
startup also checks the configured execution roles against admission scope.
There is no scope-less enrollment fallback.

`TS_ORCH_HOST_ROLES` supplies the required role set. The environment comes
from `TS_ORCH_HOST_ENVIRONMENT`, defaulting to `production`. The enrollment
issuer must sign that same scope along with the region, node, account, user
key, cluster, credential manifest digest and bootstrap grant.

## Request proof component

`RegionalHostSessionRequest` defines bounded acquire and renew messages for
the future controller-owned session service. It is a tested codec and proof
verifier; the broker, durable session authority and host renewal loop are
not yet composed. It does not replace the current one-use admission gate.

A replaced node can retain its old credentials for the same hashed NATS
subject. A public signed enrollment document alone therefore does not
authenticate the new node. Each request proves possession of the user key
in that exact document. The length-framed signature covers:

- A distinct host-session signature domain and the digest of the complete
  enrollment, including its issuer signature and workload scope.
- Region, exact provider node identity, acquire/renew operation, process
  session identifier, epoch, request nonce and UTC issue time.

Acquire requires epoch zero; renew requires a nonzero epoch. Process session
identifiers and request nonces are 32 lowercase hexadecimal characters.
Receivers accept only requests less than ten seconds old and never accept a
future timestamp. Deployment must provide synchronized clocks. Repeated
requests within that window still require durable idempotency and replay
checks; freshness alone does not implement them.

The receiver derives the allowed request subject with
`NatsSubjectTaxonomy.HostAgentObservationSubject(cell, node, "enrollment")`
and the reply with `HostAgentCommandSubject(cell, node, "enrollment-" + nonce)`.
Foreign regions, other hosts, caller-chosen inboxes, duplicate or unknown JSON
fields, missing constructor fields and payloads exceeding 16 KiB are rejected.
These are routing checks; the broker must also enforce the existing per-host
JWT/mTLS permissions.

The proof binds the NATS user key. It does not establish issuer trust, grant
authorization, revocation state, workload readiness, or which client TLS
certificate the broker observed. Controller-side grant verification and the
host's credential-manifest and certificate checks remain required.

## Cryptography and packaging

Signing uses the NATS client's public NKey API. The signer re-reads protected
seed/JWT files and rejects a changed user key. Verification uses the public
NSec.Cryptography 26.4.0 API with locked libsodium 1.0.22. The partial NATS
client key API has no public verifier. This avoids depending on its internal
implementation or adding new crypto calls to the legacy BouncyCastle package
pulled in by the OCI SDK.

The verifier checks the NATS user prefix, alphabet and checksum, canonical
64-byte signature encoding and bounded message size. Libsodium rejects
noncanonical scalars and small-order keys. Tests cover RFC 8032, actual NATS
signatures, altered requests, replaced credentials and malformed keys. Both
release RIDs include libsodium in the single-file bundle through the existing
`IncludeNativeLibrariesForSelfExtract` setting. The runtime needs a private,
writable extraction directory whose mount permits loading native libraries.

From the repository root, run the focused local checks with:

```bash
nice -n 19 dotnet build TerraScale.Orchestrator.slnx -c Release --no-restore
nice -n 19 dotnet run --project tests/TerraScale.Orchestrator.Tests \
  -c Release --no-build -- \
  --treenode-filter '/*/*/(NatsUserSignatureTests|NatsAuthenticationFilesTests|RegionalNodeEnrollmentTests|RegionalHostAdmissionTests|RegionalHostSessionRequestTests)/*' \
  --minimum-expected-tests 49 --maximum-parallel-tests 2
```

The local packaging check additionally published those tests as a single file,
copied only the executable into an isolated directory and ran the same 49
checks. Loader evidence confirms that it loaded the extracted bundled
libsodium. Publishing the test harness produced NETSDK1236 for its referenced
application runtimeconfig and coverage configuration; application publishes
produced no warning. Both application ELF architectures and their embedded
libsodium bytes were checked. The x64 application's offline runtime-plan
command ran successfully. ARM64 execution remains unqualified.

## Remaining session qualification

Before enabling remote host execution, compose and test the durable authority
over non-expiring `ORCH_NODE_ENROLLMENTS`, with exact retry results, generation
supersession, process epochs, renewal deadlines and persistent revocation.
An expired bootstrap grant must not reauthorize bootstrap operations. A
previously admitted enrollment may resume only under explicit continuing
session policy, and an old request must never extend a lease or revive a
superseded or revoked node.

Real R3 tests must cover concurrent acquisition, lost replies, controller and
host restarts, stale keys, cross-host/region denial and revoked generations.
Then route the dedicated host executable path through those services and
bounded desired/artifact/replacement-lease exchanges. Admission loss must
stop and fence work before safe replacement or drain can be qualified.
The [OCI readiness record](../evidence/oci-readiness-2026-09-20.md) remains
the deployment gate.
