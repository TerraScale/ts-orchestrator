# Transfer and verify preliminary control snapshots

This guide covers the transfer phase after [source preliminary capture](control-preliminary-capture.md)
and [candidate preparation](control-candidate-preparation.md). It publishes the
immutable GRU capture to the three owner-approved OCI buckets, then lets SFO and
FRA download and restore their own objects into isolated verification stores.
Every authorization is finite and signed by the original bootstrap owner. This
phase is preliminary evidence: it does not stop GRU writers, establish a final
cut, promote a candidate, or qualify R3.

## Create the transfer bundle

Run this command on the owner's machine:

```sh
umask 077
terrascale-orchestrator plan-preliminary-transfer \
  --config /absolute/path/preliminary-transfer-input.json \
  > /absolute/path/preliminary-transfer.signed.json
```

The command performs no network or host effects. It verifies the original GRU
bootstrap grant, completed capture request and receipt, preparation grant, and
the two candidate bootstrap grants before signing one immutable scope. The
output is a public bundle containing `publicKeyPem`, `scopeSha256`, the signed
`scope`, one signed `uploadRequest`, and one signed candidate `request` for each
candidate. Preserve the exact output bytes; do not reformat or append data to
the individual signed documents extracted from it.

The protected input has these fields:

| Field | Value |
| --- | --- |
| `ownerPrivateKeyFile` | Owner P-256 private key. Keep it off every host. |
| `publicKeyFile` | Matching original bootstrap owner public PEM. |
| `sourceNodeId` | Existing GRU seed node identity. |
| `sourceBootstrapGrantFile` | Original, owner-signed GRU seed grant. |
| `captureRequestFile`, `captureReceiptFile` | Exact signed request and completed source receipt from the capture output directory. |
| `preparationGrantFile` | Signed candidate preparation grant. |
| `candidates` | Exactly two entries, SFO then FRA, each with `nodeId` and its original `bootstrapGrantFile`. |
| `prefix` | Object-store prefix reserved for this transition. |
| `destinations` | Exactly GRU, SFO, FRA `preliminarytransfer.Destination` records, including bucket IDs, compartments, ownership generations, and tags. |
| `maxSnapshotBytes`, `maxTotalBytes`, `maxRestoreBytes` | Positive bounds no larger than the source and candidate admissions. |
| `uploadControlEpoch` | Current source upload authority term. |
| `uploadIssuedAt`, `uploadExpiresAt` | Upload authorization window, within the source grant lifetime. |
| `candidateIssuedAt`, `candidateExpiresAt` | Candidate authorization window, within the preparation grant lifetime and after capture. |
| `previousUploadRequestFile` | Optional prior upload request when renewing an expired window. The scope and authority floor must remain unchanged. |

All input files are private, caller-owned regular files without symlinks or
additional hard links. Historical capture files and grants may have expired;
the newly issued transfer authorizations must still be live when the planner
finishes. The planner derives object mappings from the signed capture receipt:
each source object is mapped into every regional destination at
`prefix/requestSha256/<local-key>`. It refuses changed inventory, destination
ownership, candidate identity, byte bounds, or grant bindings.

Deliver the exact `publicKeyPem`, `scope`, and `uploadRequest` bytes to the
source publication paths configured in `preliminaryCapture.publication`.
Deliver the candidate request matching each node ID and the same `publicKeyPem`
to that candidate's configured `sync.requestFile`. The owner public key is
verification material only; it does not replace a host's pinned bootstrap or
membership trust root.

Start the already admitted processes with their normal component commands and
keep their JSON output as evidence. On GRU, `initial-gru-r1 --config FILE`
emits newline-delimited status objects for both `preliminaryCapture` and
`preliminaryPublication`; wait for capture `state: "complete"` before
delivering the transfer bundle. Publication progresses through `idle`,
`publishing`, `failed`, and `complete`. A missing upload request is `idle`, and
an authorization or provider failure is reported as the fixed public error
`preliminary publication refused or incomplete`.

On each candidate, `prepare-control-candidate --config FILE` first emits the
admission receipt and then emits `preliminary-sync` status. A missing request
is `idle`; a verified request is `syncing`, `complete`, or `failed`; a changed
scope is `scope-conflict` and a request that no longer matches the pinned
preparation is `request-refused`. The worker retries one request at most three
times, with a short backoff, and never resets that budget merely because the
request file is removed. Replace the request only with a newly signed
authorization for the same scope (and retain the old output); the replacement
starts a new bounded attempt. Preserve the complete NDJSON streams alongside
the signed receipts.

## Publish the source objects

The source publication worker is enabled only by the owner-signed
`preliminaryCapture.publication` declaration. It reads the completed local
capture and the signed upload request, then for each GRU, SFO, and FRA bucket:

1. observes the bucket and requires the exact resource ID, compartment, name,
   region, ownership generation, and managed tags from the scope;
2. records durable ownership before object mutation;
3. uploads every mapped snapshot under the exact object key;
4. reads each object back and checks its digest, size, and provider ETag; and
5. writes and republishes one signed `publication.receipt.json` containing the
   upload authorization and every object mapping.

The worker uses the source instance identity for OCI access. No owner private
key or OCI API key is delivered to it. A durable local publication receipt is
reused verbatim on retry. If a destination, object, ETag, authorization, or
local artifact differs, the attempt fails closed and leaves existing evidence
for inspection. A renewal may extend an upload window or advance its authority
term, but it cannot change the immutable scope or previously published bytes.
The source worker makes at most three publication attempts for one exact
upload request in a runtime. Once that budget is exhausted, removing and
reinstalling the same request does not retry it; issue a valid renewal with the
same scope to start a new attempt budget. A request replacement is checked
again immediately before provider effects, so replacing the ingress file while
an attempt is running aborts that attempt.

## Download and verify at each candidate

An owner-signed candidate grant with `sync` starts a finite worker on SFO or
FRA. The worker checks that its node, region, server name, receipt key, OCI
region, and all byte limits exactly match the signed scope. It then:

1. pins the canonical scope in isolated staging and receipt directories;
2. observes the expected bucket and validates the signed publication receipt;
3. HEADs and GETs only the candidate's exact object mappings, checking provider
   metadata, ETags, sizes, and SHA-256 digests;
4. retains durable copies in staging and starts isolated reference and target
   brokers; and
5. restores every snapshot into both verification stores, comparing consumer,
   checkpoint, retained-record, and stream evidence before writing a signed
   preliminary candidate receipt.

The receipt is written under the configured `receiptDir` and signed by the
candidate's dedicated P-256 receipt key. It binds the scope, source receipt,
preparation grant, candidate bootstrap grant, prepared manifest, capture epoch,
object evidence, and `preliminaryOnly: true`. It is candidate evidence, not a
promotion or readiness signal. The worker never replaces the candidate's
authoritative store, joins the control plane, elects an authority, or grants
TerraBase membership.

The candidate's OCI identity is instance-bound and must have read access only
to its scope prefix and publication receipt. Staging and receipt directories
must be separate from the candidate store and protected files. The worker
reserves space before downloading and stops at the signed authorization expiry,
on cancellation, or on any changed scope or provider observation. Retries reuse
the pinned scope and completed receipt; conflicting files remain in place and
are refused.

## Collect evidence and continue the transition

After both candidate receipts complete, retain their exact signed bytes with
the capture request, capture receipt, publication receipt, scope, and original
grants. Supply those artifacts to
[`plan-storage-transition`](control-storage-transition-plan.md) as
`preliminaryScopeFile` and `candidateReceiptFiles`. That command verifies the
lineage and prepares the separate signed storage-transition plan.

The preliminary transfer does not prove a simultaneous application cut: GRU
may advance between stream captures and later writes. Continue with the
[control snapshot transition contract](../contracts/control-snapshot-transition.md)
for source fencing, final capture, authoritative restore, plan intake,
acknowledgements, promotion, and credential retirement. Do not use a successful
publication or candidate receipt as an `add-region`, R3, or production-ready
result.
