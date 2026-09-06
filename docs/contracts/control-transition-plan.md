# Signed storage-transition plan and host pin

`controltransition.Plan` records the owner's finite intent for the temporary
standalone GRU R1 to become the permanent GRU/SFO/FRA R3. Its separate signature
domain is `TS-CONTROL-STORAGE-TRANSITION-PLAN-V1\x00`. The signature is over the
canonical Go JSON v2 payload. The complete signed envelope is bounded to 1 MiB.
Unknown fields, duplicate fields, alternate casing, noncanonical encodings,
foreign signature domains, and receipt keys equal to the owner's key are refused.

The plan binds:

- estate and transition identity, issue and expiry times, with at most 24 hours;
- `preliminaryScopeSha256`, the canonical immutable preliminary-transfer scope
  digest already defined by `preliminarytransfer.VerifiedScope.Digest`;
- the source bootstrap grant, initial and capture manifests, original launch,
  store scope, profile, store/capture/archive directories, and receipt key;
- the named destination cluster, route trust bundle, exact GRU/SFO/FRA hosts,
  bootstrap grants, prepared and activation manifests, route addresses,
  certificate hashes, receipt keys, and separate storage directories;
- separate source/target topology epochs and global/GRU regional election floors;
- the global and GRU regional account mappings, sorted stream/consumer inventory,
  and hashes of source and final configurations;
- each regional OCI bucket and ownership-observation digest, plus the object
  prefix under which keys will include the exact signed-plan digest; and
- limits for stopped-store bytes and file count, individual archives, aggregate
  transfer, and restored storage.

Directories are checked for lexical overlap on each host. Hosts may use the same
path names on separate machines. A source and destination on the same host must
use distinct directories. These checks do not replace filesystem identity,
ownership, mount, or symlink checks before effects. Configuration hashes likewise
require comparison with the actual configuration. Inventory declarations and
provider observation hashes alone cannot prove completeness or ownership.

`VerifiedPlan` keeps its fields private and returns freshly decoded plan values.
Mutating a returned inventory cannot change the verified scope. Signature
verification is separate from lifetime checks, allowing historical evidence to
be read without treating an expired plan as active authority.

`EpochStore.AdmitStorageTransitionPlan` records one agreement in
`storage-transition-plan.json` within the existing private receiver journal.
It requires trusted host ownership. Its caller must supply the owner public key
from the original verified bootstrap proof. No configuration-provided key may
establish that trust. A source pin additionally checks a live, already
authenticated `ApplyManifest` authorization against the durable regional epoch,
the exact initial/capture manifest hashes, and the committed original R1
publication. The source guard must still be live. A destination pin requires
the exact initial bootstrap admission with no ordinary runtime epoch.

The file retains the signed bytes, owner key, manifest/bootstrap bindings,
source command identity and digest where applicable, admitted epoch floor, and
admission time. It is written as a private regular file through fsync, rename,
and directory fsync. An identical retry preserves the first record, including
its admission time. Re-signing the same payload creates different signed bytes
and does not replace that pin. Recovery accepts only the expected signed-plan
digest and validates the stored signature, historical admission time, current
plan lifetime, current manifest binding, and nonregressing authority floor.

Admission checks cancellation, plan lifetime, and the source command's expiry
again after directory persistence, including identical retries. An interrupted
call can leave the original durable pin without returning successful admission.
A fresh recovery call validates that retained agreement without rewriting it or
renewing the original command. Recovery also checks cancellation after its final
directory sync.

`ResumeStorageTransitionPlan` may read the source pin after the original command
expires or the source retires. It does not renew the command or call
`AdmitBootstrap`. It preserves the permanent R1 retirement. Ordinary authority
on a destination closes this preliminary recovery path. An expired plan remains
pinned and cannot be overwritten by a renewed document.

These APIs record agreement only. They do not publish a preparation receipt,
retire a source, seal or copy files, run a broker, restore/promote a stream,
apply a manifest, mint a lease, or revoke credentials. The owner command
`plan-storage-transition` prepares a signed plan against original host grants
and preliminary candidate evidence; see the
[operator guide](../guides/control-storage-transition-plan.md). The signed
`storageTransition` configuration now admits local plan intake in `ts-node`, as
described below. Remote transfer to that location, phase-specific journal and
receipt checks, complete inventory/ownership observations, source stop and seal,
and pre-NATS phase execution remain required by
[the transition design](control-snapshot-transition.md). The existing manifest
handoff cannot use the plan pin as proof that all destinations are prepared.

## Host acknowledgements

`EpochStore.AcknowledgeStorageTransitionPlan` validates the existing private pin,
current manifest binding, and nonregressing host authority floor under receiver
ownership. It fsyncs the journal directory before signing the pin's exact digest.
It uses the host receipt key from the plan, never the owner key. The first signed
acknowledgement is retained in the private
`storage-transition-pin-receipt.json` file through fsync, rename, and directory
fsync. Retries validate and return those exact bytes without a signer. A failed
rename-directory sync can therefore recover without producing a second signature.

The receipt has only the `plan-pinned` phase and uses signature domain
`TS-CONTROL-STORAGE-PLAN-PIN-RECEIPT-V1\x00`. It binds the plan as its immediate
predecessor, the private pin digest, host and role, bootstrap/manifest hashes,
original admission time, and receipt publication time. Source receipts also
retain the admitted regional command digest and authority identity. Destination
receipts require all ordinary-authority fields to remain empty or zero. The
complete signed receipt is bounded to 8 KiB.
`PublishedAt` records when the receipt was created for publication. Successful
emission also requires the durable write and a final cancellation/lifetime check;
the timestamp alone does not prove persistence completed.

`controltransition.VerifyPinReceipt` validates historical acknowledgement
evidence against the key and identities in the verified owner plan. It does not
claim that the plan remains live. `VerifyPlanPins` requires a live plan and one
receipt per distinct host in source-first, then GRU/SFO/FRA order, skipping the
source node if it is also the GRU destination. It rejects missing, additional,
reordered, duplicate, conflicting, or future receipts. A source receipt on a
shared source/GRU host acknowledges that host's complete plan pin; it does not
assert that the GRU destination broker or directory has been prepared.

Acknowledgement recovery can run after source retirement without renewing the
old command or re-admitting R1. Ordinary runtime admission on a destination and
plan expiry close this preliminary recovery API. Historical signed bytes remain
verifiable for audit. Corrupt, unsafe, or conflicting acknowledgement files are
retained and refused, never replaced to force a retry.

These acknowledgements are stored locally and returned to the trusted caller.
Host publication is not wired yet. The independent OCI reader described below
can verify receipts once their exact bytes are present in the regional buckets.
The complete preparation barrier must combine them with synchronization,
identity, storage and health evidence before retirement. The first private
acknowledgement is not a general phase journal or permission to execute effects.

## Preliminary candidate evidence

`candidatesync.VerifyScopedReceipt` verifies candidate attribution using the
key in the owner-approved scope and matches the regional host, grants, manifest,
source receipt, capture epoch, timestamps, and complete ordered object mappings.
Every restore-evidence reference must be a canonical SHA-256 digest. The existing
candidate worker uses this check when reopening a completed receipt, before
comparing it with its newly observed local restore evidence.

`candidatesync.VerifyTransitionCandidates` checks both SFO and FRA receipts
against the scope named by the plan. It binds the scope owner and source identity,
the complete source account/stream inventory, candidate identities/manifests,
historical capture epoch, and byte limits. Aggregate transfer accounting includes
all three regional object mappings. The immutable result returns the plan, scope,
and exact signed receipt digests only while the plan remains live.

Plans without `preliminaryScopeSha256` are refused. The draft plan format has no
legacy reader; no deployed transition executor exists. The scope digest is over
its canonical payload, while candidate receipt digests cover their exact signed
bytes. These are different existing contracts and must not be interchanged.

This check establishes attribution and scope for the preliminary synchronization
prerequisite. It does not retrieve the restore evidence named by its hashes,
compare final consumer/configuration state, prove current host health, publish
receipts for independent reads, or establish the final cut. Durable host-plan
preparation and source shutdown still require their own chained evidence before
retirement can proceed.

## Local host intake

The optional `storageTransition` value in the original `initialgrant.Config`
seed configuration and `transitiongrant.Config` candidate configuration names
`transitionId`, `planFile` and `receiptPrivateKeyFile`. It contains no owner
key and no plan digest,
which would be circular with the manifest hash signed by that later plan.
The zero value is omitted from existing canonical configurations.

Both file paths must be distinct and remain outside every component's writable
data volume, source
capture output, candidate staging/receipt storage, and preparation admission
files. Once delivered, the file must be a bounded private regular file owned by
root, with no symlink traversal or additional hard links. `BootstrapAuthority`
retains a private copy of the original verified bootstrap public key. Local
intake verifies the plan with that key, its current lifetime, transition and
host identity, and exact original bootstrap/manifest bindings.

Candidate initialization pins an available plan after its initial preparation
admission. The expired-initial-grant candidate recovery path also admits a
newly delivered live plan against its retained initial host admission. It does
not renew bootstrap or change the candidate's finite preparation lifetime.
After pinning, the host creates its signed `plan-pinned` acknowledgement in the
same private journal. An absent plan permits preliminary candidate work but
creates no agreement.
A malformed, expired, foreign or conflicting delivered plan is refused.

The source's live `ApplyManifest` command may pin and acknowledge only the
plan's exact capture replacement. It then returns `ErrPreparationMissing` before retirement or
replacement effects because the complete preparation barrier is unfinished.
The published original source proof enforces that same refusal if the receiver
has only a runtime verifier. An opted-in candidate's private preparation record
also refuses ordinary epoch admission and publication revocation until that
barrier exists. Removing the bootstrap wrapper cannot bypass these checks.

Before NATS dialing, `ResumeLocalStorageTransitionPlan` verifies an existing
private agreement using the exact delivered plan and creates or recovers its
local acknowledgement. It neither creates bootstrap admission nor resumes
storage effects. The current intake covers the shared
source/GRU host and the initial SFO/FRA candidate configurations; a separate GRU
destination launch still needs its own admitted configuration and composition.
There is no remote plan-upload command, continuous file poller, or automatic
external acknowledgement publication yet. Keep the original delivered file
available for agreement recovery and do not replace its signed bytes.

## Host acknowledgement composition

`ts-node` calls `AcknowledgeStorageTransitionPlan` after successful pin admission
or recovery. It first asks for the retained receipt without supplying a signer.
Only `ErrStorageTransitionReceiptSignerRequired`, returned for a validated pin
with no receipt, permits opening the configured host private key. Corrupt,
unsafe and conflicting receipts remain errors and never trigger re-signing.

The first-signature key must be a bounded root-owned private regular file,
reached without symlinks or extra hard links. Its public identity must equal the
source or destination receipt key in the owner-signed plan. It is a dedicated
host key, distinct from the off-host owner. The read buffer is cleared after
parsing and the signer is closed after use. Missing, wrong or unsafe key material
leaves the already pinned plan intact without creating a receipt.

A completed acknowledgement is recovered byte-for-byte without reopening the
key, including after a `ts-node` restart. This permits recovery while that key
file is unavailable; it does not authorize new signatures after key retirement.
The receipt remains in `storage-transition-pin-receipt.json` inside the private
host journal. Host acknowledgement publication is not wired yet; the independent reader
below collects receipts that have already been published.
A local receipt still cannot satisfy the unfinished preparation barrier alone.

Configured `storageTransition` values now require the receipt-key path. The
previous prelaunch two-field draft is refused. Configurations without this
optional value keep their original canonical bytes; no deployed transition
history is migrated or rewritten.

## Independent OCI acknowledgement reads

`transitionreceipts.ReadPlanPins` collects each distinct host acknowledgement
without contacting NATS. `check-storage-plan-pins` exposes this as an operator
command. It requires a live verified owner plan and one OCI Object Storage
transport for each of GRU, SFO and FRA, with region identity matching the plan.

Each host's receipt belongs in that host's regional bucket from the plan. The
source uses GRU. A shared source/GRU host has only its source receipt; a separate
GRU destination has another object. `PinObjectKey` derives the exact key:

```text
<objects.prefix>/<signed-plan-sha256>/plan-pinned/<node-id>.json
```

The object contains the unmodified signed acknowledgement from the host's
private journal. OCI metadata must include its exact byte length, an ETag and
`opc-meta-terrascale-sha256` with the bare lowercase SHA-256 of those bytes.
Receipts are bounded to 8 KiB. The reader refuses redirects, missing objects,
changed or truncated bytes, incorrect metadata, foreign hosts/signatures,
future receipts, and incomplete host inventory. It returns no verified result
on a partial read failure.

Before and after object reads, the reader obtains each bucket observation and
compares its resource ID, compartment, namespace, name and observation digest
with the signed plan. `BucketObservationDigest` defines that digest as SHA-256
of `provider.OCIBucketObservation` serialized with deterministic Go JSON v2.
The projection includes `id`, `compartmentId`, `namespace`, `name` and the entire
`freeformTags` map; unrelated OCI response fields are excluded. The same utility
must be used when preparing the plan's `ownershipObservationSha256` value.

The complete source-first, then distinct GRU/SFO/FRA receipt set passes through
`VerifyPlanPins` after the reads. The returned proof and digest copies remain
usable only within the plan's lifetime. `PinObjectKey` can identify historical
objects, but key derivation itself establishes no current authority.

This is independent evidence collection, not publication or a complete
preparation barrier. Host upload, automated collection in the transition
executor, storage/health checks and source retirement remain unfinished.
The operator's JSON summary is an unsigned report and cannot substitute for
verification of the original signed receipts.

## Immutable acknowledgement publication

`transitionreceipts.PublishPlanPin` accepts the exact signed acknowledgement
recovered from the private host journal and one regional OCI transport. Host
composition must supply instance-principal credentials. The function verifies
host identity, signature, live plan, nonfuture receipt time, regional endpoint,
and the signed bucket ownership observation before creating an object at
`PinObjectKey`.

Every attempt uses `If-None-Match: *` and the exact receipt SHA-256 metadata.
After the PUT, including a failed or lost response, an independent bounded GET
must return identical bytes and matching size, digest, and a nonempty ETag.
Bucket ownership and plan lifetime are checked again before success. A conflict
is retained. A failed read leaves the outcome unresolved and the caller must
retry with the same durable signed bytes. There is no broker journal dependency
or cached success that could skip remote verification.

This function does not establish local persistence itself. Automatic host
invocation, instance-principal acquisition, and retry scheduling remain to be
connected to the existing private acknowledgement recovery path. Publication
proves neither destination preparation nor permission to retire the source.
