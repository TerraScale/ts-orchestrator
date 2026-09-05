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

`ResumeStorageTransitionPlan` may read the source pin after the original command
expires or the source retires. It does not renew the command or call
`AdmitBootstrap`. It preserves the permanent R1 retirement. Ordinary authority
on a destination closes this preliminary recovery path. An expired plan remains
pinned and cannot be overwritten by a renewed document.

These APIs record agreement only. They do not publish a preparation receipt,
retire a source, seal or copy files, run a broker, restore/promote a stream,
apply a manifest, mint a lease, or revoke credentials. No CLI or service launch
currently delivers a plan to these APIs. Before enabling execution, implement
the original-bootstrap-key delivery chain, phase-specific host journal and
receipt checks, complete inventory/ownership observations, the source stop and
seal protocol, and pre-NATS recovery in the order required by
[the transition design](control-snapshot-transition.md). The existing manifest
handoff must not use the plan pin as proof that all destinations are prepared.

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
No external publication or independent receipt-delivery transport is wired yet.
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
