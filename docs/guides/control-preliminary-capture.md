# Stage preliminary control snapshots on GRU

The admitted initial GRU seed can capture both control accounts into a bounded
local staging directory while its ordinary authority remains live. A signed
receipt identifies the captured envelopes. This is preliminary source evidence.
It does not synchronize SFO/FRA, upload to OCI, stop source writers, establish a
final cut, restore a candidate, or qualify R3 or production readiness.

Enable capture in a newly owner-signed seed configuration through the optional
`preliminaryCapture` object. Existing signed launches gain no new permissions,
and participants reject this field.

| Field | Value |
| --- | --- |
| `requestFile` | Absolute path to the root-owned signed request ingress |
| `outputDir` | Separate absolute directory for immutable local staging |
| `maxSnapshotBytes` | Complete-envelope limit, 1 KiB through 1 GiB |
| `maxTotalBytes` | Total retained envelope limit, at least `maxSnapshotBytes` and at most 256 GiB |
| `regional`, `global` | Separate source-held NKey and TLS connection declarations for the two accounts |

The broker's exact signed user configuration must admit the capture identities.
These credentials are privileged. Keep them on the source and never distribute
them to candidates as a read-only capability. NATS snapshot requests can direct
server publications to a supplied subject; an ordinary client publish allowlist
does not constrain that field. The local worker constructs the snapshot inbox
itself and exposes no caller-selected NATS reply or delivery subject.

The request file and its ancestry must be root-owned and protected against
group or other writes. The file must be regular, have one hard link, and be
readable by the orchestrator service. Symlinks are refused. The output directory
must be owned by that service with mode `0700`; staged files use mode `0600`.
The worker can create the final output directory under an existing permitted
parent. Keep the request, broker store, and output paths separate. The signed
staging limits reserve their total bound plus one maximum snapshot for atomic
publication, in addition to the broker budget and filesystem headroom. Startup
checks available space on the broker and staging filesystems. These disk checks
do not qualify peak memory use while encoding and verifying snapshots.

For the VM qualification configuration, set both
`TS_VM_PRELIMINARY_CAPTURE_MAX_SNAPSHOT_BYTES` and
`TS_VM_PRELIMINARY_CAPTURE_MAX_TOTAL_BYTES` to explicit positive decimal byte
counts. Both absent leaves capture disabled. Partial, invalid, or out-of-range
inputs fail configuration. This selects
`vmcontrolseed.GenerateGRUWithPreliminaryCapture`; ordinary `GenerateGRU`
keeps the capability disabled.

The VM producer signs the source request path
`/etc/terrascale/orchestrator/capture/request.json` and output path
`/var/lib/terrascale/orchestrator/capture`. It supplies separate source-only
capture NKeys and a capture TLS client identity through the protected material
delivery path. It does not generate a capture request or invent its global term.
Enabling these inputs alone does not exercise a capture or satisfy a VM gate.

Run `plan-preliminary-capture --config FILE` with a protected JSON file
containing these fields:

| Field | Value |
| --- | --- |
| `ownerPrivateKeyFile` | Protected P-256 signing key belonging to the original bootstrap owner |
| `publicKeyFile` | Matching owner public key |
| `sourceNodeId` | Existing GRU seed node identity |
| `sourceBootstrapGrantFile` | Original signed, still-live source bootstrap grant with capture enabled |
| `transitionId` | Explicit identity for this preliminary capture |
| `controlEpoch` | Actual current global authority term, greater than zero |
| `issuedAt`, `expiresAt` | RFC3339 dates within the source grant's lifetime, at most 24 hours apart; issuance is no later than now and expiry is still in the future |

The planner verifies the source grant and derives its source, store scope,
profile digest, and exact account/stream inventory. It returns a JSON bundle
with `publicKeyPem` and `request`. It has no network effects and returns no
private key or source account credentials. The request is a separately signed
canonical JSON document. Deliver the exact `request` document at the admitted
`requestFile`, preserving its bytes without pretty-printing or adding a newline.
The runtime verifies it against the owner key retained by the original initial
admission; the output public key does not install a new runtime trust root.

The worker polls a missing request as idle. An accepted request must match the
live seed admission, complete profile inventory, and exact global leadership
term. Each attempt is limited to ten minutes and to the request's remaining
lifetime. Admission expiry, global authority loss, or a changed term cancels
unfinished capture. The initial admission lock prevents retirement from
completing while capture is running; normal runtime shutdown cancels and joins
the worker before closing the embedded broker. A refused capture reports a
failure without granting authority or stopping an otherwise healthy GRU runtime.

The initial runtime emits capture status changes under `preliminaryCapture`,
with `state` set to `disabled`,
`idle`, `capturing`, `failed`, or `complete`. Status can include
`requestSha256`, `transitionId`, `capturedStreams`, `totalStreams`,
`receiptSha256`, and a fixed failure message in `error`. A `complete` status
means local preliminary staging completed under that request. It is not a
current leadership or candidate readiness signal.

The output directory holds `request.json`, one immutable `.snapshot` file per
account/stream key, `receipt.json` after completion, and its ownership lock.
Object keys bind account, stream, and control epoch; local filenames are the
SHA-256 of each object key followed by `.snapshot`. The signed receipt binds
the request digest, transition, source, control epoch, and each envelope's key,
SHA-256, size, and capture time. It explicitly marks the result preliminary and
uses a signature domain distinct from the owner request. Its signer is the
source membership identity already pinned by the original grant.

The first accepted signed request pins the output directory. Retrying the same
bytes within the same live term reuses verified immutable snapshots and the
original receipt. A corrected request can be accepted before an output pin
exists. Once pinned, changed dates, signatures, epochs, or inventory conflict
with that directory. The worker does not delete or replace prior evidence to
force a retry. A restart that establishes a newer global term cannot resume an
unfinished request from the old term. This path has no automatic request
rotation or abandoned-output cleanup protocol.

GRU can advance between stream captures. Full inventory checks and archive
readback do not make sequential snapshots an atomic application cut. Preserve
these artifacts as preliminary evidence and follow the remaining requirements
in [the control snapshot transition contract](../contracts/control-snapshot-transition.md)
before claiming final source capture, transfer, restoration, or promotion.
