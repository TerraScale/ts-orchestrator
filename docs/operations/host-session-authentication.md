# Host enrollment scope and session request authentication

The signed regional node enrollment uses canonical version
`terrascale-regional-node-enrollment-v2`. Its mandatory `Scope` contains the
exact environment and a nonempty, unique set of admitted roles. Roles are
copied and sorted before signing. An enrollment for TerraBase in production
cannot authorize auth, an expanded role set, or another environment. The
host admission component checks scope before consuming a generation. The
future dedicated host startup must bind its configured roles to that scope.
There is no scope-less enrollment fallback.

`TS_ORCH_HOST_ROLES` is rejected by controller run/check; it cannot enable a
host workload under controller credentials. The standalone convergence
configuration still describes its role set and environment (default
`production`). The enrollment issuer must sign that same scope along with the
region, node, account, user key, cluster, credential manifest digest and
bootstrap grant.

## Request proof component

`RegionalHostSessionRequest` defines bounded acquire and renew messages.
`RegionalHostSessionAuthority`, `RegionalHostSessionService` and
`NatsRegionalHostSessionClient` implement controller-owned admission over NATS.
They are exercised directly against restricted JWT/mTLS R3 credentials.
Controller startup loads the policy and starts the service as described below.
The independent host execution lease now uses the remote client and is tested
with restricted host credentials. Core convergence accepts its cancellation
token. No production host entry point is enabled; credential checks, bounded
host control protocols and physical shutdown still need composition.

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
future timestamp. Deployment must provide synchronized clocks. The durable
authority performs the idempotency and replay checks described below;
freshness alone does not implement them.

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

## Durable controller authority

`RegionalHostEnrollmentPolicy` pins region, NATS account, cluster, environment,
allowed role set, enrollment signer and bootstrap trust bundle. The signed
scope may contain only roles in that configured set. It verifies both P-256
signatures, exact system-project identity, grant audience/purpose/operations
and the grant lifetime. A session is a workload admission lease; it does not
authorize any bootstrap operation or confer OCI controller permissions.

The authority owns one `node-enrollment.<SHA-256(node)>` record in
`ORCH_NODE_ENROLLMENTS`. This must be a non-expiring, non-evicting R3 file store
with limits retention, acknowledgements and no message/tombstone expiry.
The schema-2 record preserves generation, enrollment digest, original admission
time, server-observed process start, process session and epoch, latest request digest/time, lease expiry,
revocation and bounded consumed-grant history. It contains no private keys.

Every transition uses a single compare-and-set operation. Initial creation
requires revision zero; it does not use the NATS client's create helper,
which can resurrect deleted keys. Missing required fields, unknown schema
fields and tombstones fail closed. The older one-use record and schema-1
session record cannot replace the schema-2 session record. There is no state-format migration
path; production must not enable the two admission implementations together.

Session behavior is explicit:

- An exact latest-request retry returns the same generation, epoch, expiry,
  request identity and decision. It confirms the read through an unchanged CAS
  before returning success, so stale replica reads cannot bypass revocation.
  It never extends the lease. Older requests cannot replace a later renewal.
- Each lease expires 30 seconds after the request's signed issue time.
  Renewal requires the current process and epoch, a newer signed timestamp
  and an unexpired lease. No lease may cross a signing key's acceptance
  deadline.
- A different process waits for the current lease to expire, then acquires
  a larger epoch. Restart can resume an expired bootstrap grant only for
  the exact durably admitted enrollment, with its admission time inside
  that grant's original validity and its current signer trust still valid.
- A higher bootstrap generation needs a fresh, trusted enrollment and grant.
  It waits for the old lease even if that lease has been revoked. The old
  generation and a different envelope at the same generation are rejected.
- Revocation is durable and names the observed generation and process epoch.
  A stale revoke cannot hit a replacement. A revoked enrollment cannot renew
  or resume. Only a freshly signed higher generation can supersede it.
- Up to 16 consumed grants are retained per node. Reusing any retained grant
  identifier or nonce is rejected. History can be pruned only after expiry
  at the new request's signed time. Full history holds new enrollment with
  `ReplayCapacity`; it never evicts a still-valid replay fence.

Controllers share a queue subscription, but storage CAS decides ownership.
The host client accepts only a schema-2 response bound to the exact request
digest, generation, epoch and signed lease deadline. Storage revision is not
part of this response: an unchanged CAS can advance that internal concurrency
fence without granting a new lease. Old response fields and schemas are
rejected; there is no compatibility fallback. Requests have a five-second
deadline, including an explicit bound around NATS.Net's PING/PONG wait.
The library's cancellation token does not cover waiting for PONG in 2.7.2;
a withheld-PONG loopback test covers this failure path.

Service snapshots count accepted acquire/renew requests (including retries),
rejections and storage/transport failures. Bounded failure tracking prevents
one host's success from clearing another host's pending storage retry. These
snapshots feed the authenticated operator status and process telemetry below.

## Independent host execution lease

`RegionalHostSessionLease` acquires one process session, then renews the same
enrollment, generation and epoch every three seconds. An exact lost-response
retry retains its request nonce and original expiry. A new signed renewal is
needed when the pending proof approaches its freshness limit. A successful
renewal replaces the immutable report signer. Loss is terminal: the component
never reacquires automatically or assumes an old workload has stopped.

Startup is bounded to eight seconds; material and network requests each have
a five-second bound. Transient failure retries after one second inside the
existing execution window. Authoritative rejection, invalid response binding,
missing credentials or a changed signing key cancel execution. The mandatory
material callback must eventually validate the delivered manifest and mTLS
certificate; the production callback is not yet composed.

An independent 100 ms watchdog checks both UTC and monotonic elapsed time.
The local execution budget is fourteen seconds from the signed request's
start: the thirty-second authority lease minus ten seconds of accepted clock
skew, five seconds reserved for shutdown and one second of scheduling slack.
Backward UTC changes fail closed; forward jumps and frozen UTC cannot extend
the monotonic window. This is a cooperative process watchdog, not a hard
real-time fence against a paused guest or a stalled OS. Signing file I/O does
not hold its state lock. A late success cannot restore lost permission.

Snapshots expose state, need, generation, epoch, remote expiry, local execution
deadline and renewal/failure counts. They are not yet exported by a host status
endpoint. Core `HostConvergenceRuntime` links every reconciliation to execution
loss, including a desired-state read that ignores its cancellation token.
Cancellation prevents subsequent work and reaches cooperative in-flight
operations. It does **not** stop or prove absence of existing native workloads.
Shutdown must use its own bounded token, run without NATS/report acknowledgement,
recover ownership before installation markers exist, and verify physical stop
before a replacement or writer-fencing claim is possible.

## Report proof and current-session authorization

`RegionalHostReportProof` signs a separate report domain, complete enrollment
digest, process session/epoch, exact workload role, admission/runtime report
kind, request nonce, issue time and SHA-256 of the canonical report bytes.
Proofs and report payloads each have a 16 KiB limit. The signer reloads its
protected NKey/JWT credentials; a changed user key is rejected.

The authority's typed admission/runtime report checks derive the workload
role from the report artifact, check node/cell/environment identity, verify
the signature and current enrollment trust, and compare the durable generation,
enrollment digest, process and epoch. Reports cannot predate the server's
process admission time. Request proofs expire after ten seconds; observations
must be less than thirty seconds old. Successful authorization ends at the
earliest of those deadlines and the current lease expiry.

An unchanged CAS confirms every accepted report authorization against renewal,
replacement and revocation. It changes no grant/session fields and never renews
the lease. This is authorization at that CAS point, not permission to ignore a
subsequent revoke. A readiness consumer must check current authorization when
making its decision. Repeated CAS conflicts fail closed after eight attempts.

These report components pass direct real-R3 tests, including forced stale
replica reads after revocation, expired bootstrap evidence, scope changes,
renewal, process replacement and tombstones. Controller readiness now uses
`SessionAuthorizedHostReportReader`: one strict schema-1 `StoredHostReport`
contains its proof and exactly one admission or runtime observation. The reader
checks the exact storage key, current session and unchanged report revision.
It bounds reads to five seconds, rejects unsigned/unknown/duplicate/malformed
records, and never caches successful authorization across decisions.

TerraBase recovery and health, generic OCI readiness, and operator ready counts
use this reader. Admission and serving health must share enrollment digest,
generation, session ID, epoch and artifact digest; both authorizations must
still be unexpired. OCI and operator readiness read admission after runtime,
so an already committed withdrawal invalidates an older converged report.
An unchanged report CAS prevents a stale replica from restoring an earlier
ready observation after withdrawal. The session CAS still does not stop a
physical writer or promise immunity against later revocation.

`HostObservationRelay` now requires schema-2 signed envelopes, authorizes each
CAS attempt and stores the proof and observation atomically. The host signer
uses the exact accepted session response. Acknowledgements bind the nonce and
canonical envelope digest; unsigned ingress is rejected. See
[the signed relay contract](host-report-relay.md). The dedicated host runtime,
renewal composition and physical workload fencing remain deployment blockers.

## Controller configuration and observability

Set `TS_ORCH_HOST_SESSION_POLICY_FILE`, or `hostSessionPolicyFile` in the typed
runtime configuration. The file contains public trust material, must be a
regular file without symlink traversal or group/other write permissions, and
must not exceed 32 KiB. Duplicate/unknown/missing fields, malformed public
keys, a foreign cell and invalid roles fail before connecting to NATS.
Both enrollment and bootstrap signing keys must be exact P-256 DER
SubjectPublicKeyInfo, encoded as base64. No private signing key belongs here.

The following schema template needs the actual reviewed account and public
keys, fixed system-project identities and cluster name:

```json
{
  "schemaVersion": 1,
  "cell": "gru",
  "natsAccountPublicKey": "<regional account public NKey>",
  "clusterName": "gru-cluster",
  "environment": "production",
  "roles": ["terrabase-member", "authentication"],
  "enrollmentSignerKeyId": "enrollment-key",
  "enrollmentSignerKeyVersion": 1,
  "enrollmentSignerPublicKey": "<base64 DER SPKI>",
  "systemOrganizationUlid": "<fixed system organization ULID>",
  "systemProjectUlid": "<fixed system project ULID>",
  "systemDatabaseUlid": "<fixed system database ULID>",
  "bootstrapOperation": "ensure-system-project-configuration",
  "maximumGrantLifetimeSeconds": 900,
  "bootstrapTrust": {
    "bundleVersion": 1,
    "currentGrantSigningKeyId": "grant-key",
    "currentGrantSigningKeyVersion": 1,
    "keys": [{
      "keyId": "grant-key",
      "keyVersion": 1,
      "purpose": 1,
      "subjectPublicKeyInfo": "<base64 DER SPKI>",
      "acceptedUntil": null
    }]
  }
}
```

The service requires R3 and regional NKey/JWT plus mTLS credentials. A
controller with this policy cannot also enable local host convergence/admission:
the old and new replay formats must not run together. `run` with either OCI
workload fleet requires the policy before opening any provider. Startup checks
the actual session store and has a five-second service-start deadline. Internal
timeout is a startup failure; caller cancellation retains shutdown semantics. Service
failure joins runtime completion monitoring; shutdown disposes the service.
Policy is immutable for the process lifetime. Provision the same reviewed
policy across the regional controllers; coordinated policy/key rotation still
belongs to first-boot and credential-lifecycle qualification.

The existing authenticated operator-status query includes a
`host-session-authority` action, with `listening`/100 or `retrying`/0. A storage
or response failure adds `host-session-authority:retry-request` to needs.
This progress describes the admission service, not the readiness of all hosts.
OTLP exposes `terrascale.orchestrator.host.session.requests`, labeled only by
cell and `acquired`, `renewed`, `rejected` or `failed`, and
`terrascale.orchestrator.host.session.retry_pending`, labeled only by cell.
Counters count requests, including retries, rather than active hosts or leases.

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
  --treenode-filter '/*/*/(NatsUserSignatureTests|NatsAuthenticationFilesTests|RegionalNodeEnrollmentTests|RegionalHostAdmissionTests|RegionalHostSessionRequestTests|RegionalHostSessionAuthorityTests)/*' \
  --minimum-expected-tests 57 --maximum-parallel-tests 2
```

The preceding request-authentication batch's packaging check published its
tests as a single file, copied only the executable into an isolated directory
and ran its 49 checks. That evidence predates the session authority/service.
Loader evidence confirms that it loaded the extracted bundled
libsodium. Publishing the test harness produced NETSDK1236 for its referenced
application runtimeconfig and coverage configuration; application publishes
produced no warning. Both application ELF architectures and their embedded
libsodium bytes were checked. The x64 application's offline runtime-plan
command ran successfully. ARM64 execution remains unqualified.

## Remaining runtime qualification

Local R3 tests cover acquisition races, exact retry, lost response, process
epochs, authority recreation, generation replacement, expired bootstrap
grants, durable revocation after stream-leader kill/restart, replay-history
capacity, private-store denial and the authenticated host client/service path.
Logical time controls expiry cases; the wire test also runs on the wall clock.
These are component tests, not a fresh OCI guest starting real workloads.

The publisher and relay now authorize signed session-bound reports and persist
their proofs atomically. Production readiness also rechecks the current session
and pairs admission with runtime health. A valid per-node NATS subject alone
does not distinguish a revoked process; proof and current authority are mandatory.

Production first boot must deliver the reviewed controller policy. Route the dedicated host
entry through the remote client, credential-manifest/certificate checks and
bounded desired/artifact/replacement-lease exchanges. The renewal loop must
distinguish original enrollment evidence from permission to execute bootstrap
operations. Admission loss must stop and fence work before safe replacement
or drain can be qualified. A KV lease alone does not stop a guest process or
fence a storage writer.
The [OCI readiness record](../evidence/oci-readiness-2026-09-20.md) remains
the deployment gate.
