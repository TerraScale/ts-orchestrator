# In-place identity re-key

Use the CI-qualified candidate's `identity-rekey` command on each verified
controller as root. This transaction issues plain-ULID deployment and cluster
identities while retaining the physical instances, images, server names, actual
Raft node IDs, JetStream stores, broker/account keys and customer data. Retired
identity bytes are opaque predecessors; they never grant authority.

## Reviewed inputs

The root-signed v1 checkpoint binds all three slots in one cell. Each slot pins
its instance/image/VNIC/private IP, qualified binary, four config files, four
public launch files, immutable Vault material references, existing broker/store,
old acceptance bytes and both old native material-chain copies. The latter map
has exactly `installed` and `durable` SHA-256 entries. Candidate ID is
`entityid.Derive("controller", deploymentID, uppercaseCell, slot)`; physical
server names remain unchanged.

The host-state handoff plan binds independently inventoried host registrations,
sessions and desired records, the fresh controller signer and observed writer
shutdown. Every inventoried host requires an exact predecessor or explicit
absence observation for `retired` and `retirement-quarantine`; the regional
`retirement-cutover` key also requires coverage. Drain affected host agents and observe the required 32-second regional
quiescence before signing this plan. Preserve every managed member and volume.
Static TerraBase hosts without a registered block volume retain their existing
data paths; their handoff creates no volume-format confirmation. Registered
block volumes still require their exact mounted filesystem and consumed marker.
Uncommitted staging requires current-root `can_install_material` authority and
current image qualification. Installation independently authenticates the exact
shared hold before replaying its durably pinned authorization; initial-install
grants alone never authorize a re-key.

The checked `identity-rekey precommit --inputs DIRECTORY` is the sole barrier
publication entry point; the bootstrap CLI only signs reviewed artifacts.

The bootstrap CLI provides create-only signing commands:

```sh
ts-orch bootstrap sign-accepted-identity-checkpoint \
  --candidate checkpoint.json --expectation expectation.json \
  --root-key root.pub --root-chain roots.json --signing-key root.key \
  --out checkpoint.signed.json --valid-for 8760h
ts-orch bootstrap sign-host-state-handoff-plan \
  --candidate host-plan.json --expectation expectation.json \
  --checkpoint checkpoint.signed.json --observation host-observation.json \
  --root-key root.pub --root-chain roots.json --signing-key root.key \
  --out host-plan.signed.json --valid-for 1h
ts-orch bootstrap sign-identity-reset \
  --candidate reset.json --expectation expectation.json \
  --checkpoint checkpoint.signed.json --observation host-observation.json \
  --host-plan host-plan.signed.json --replicas 3 \
  --root-key root.pub --root-chain roots.json --signing-key root.key \
  --out reset.signed.json --valid-for 1h
```

`expectation.json` is canonical `identityrekey.CheckpointExpectation` JSON from
independently checked inventory, not a projection of unverified old acceptance.
`host-observation.json` is canonical `identityrekey.HostStateObservation` JSON.
Precommit and shared completion enumerate leader-backed host control subjects
and raw host/enrollment KV subjects, including tombstones, and refuse every
unreviewed local destination. Named foreign-cell state is retained; opaque keys
in these cell-local buckets require explicit root pins because their ownership
cannot be inferred from obsolete values. No unreviewed key is deleted.
For an existing KV tombstone, each predecessor observation pins its positive
revision, empty-data SHA-256 and exact `operation` (`DEL` or `PURGE`); the signed
reset carries the same `previous_operation`. A tombstone is not revision-zero
absence. Cleanup still publishes a new operation-owned tombstone before completion.
Retained enrollment requests, including retired hosts receiving a disabled grant, are checked at their
original signed issuance time and matched to independently observed instance,
node, identity and NATS keys. Their exact request bytes are retained in the
replacement grant; live enrollment still requires a request no older than 48 hours.
An obsolete static node without retained enrollment evidence may instead be
root-authorized as retired, with empty instance/request fields, all desired roles
withdrawn and no registered block volume. Its existing registration and desired
heads require positive exact predecessor revisions; sessions are deleted and no
instance enrollment grant is created, replaced or deleted. A renamed surviving
instance therefore keeps its separately verified grant. Complete broker inventory,
current root signatures and regional writer quiescence remain mandatory.
The root chain belongs to the proposed deployment and is verified from the
existing baked genesis keys. No retired-identity decoder participates.

In the topology's global home, `reset.json` also requires `global_lease` with
independently reviewed `previous_sequence`, `previous_sha256`, `epoch_floor`
and replacement `epoch`. An absent global predecessor uses sequence/floor zero
and an empty digest. Non-home regions omit this field. The regional and global
holds, and their releases, each commit in one native atomic JetStream batch;
the existing log is retained with atomic publishing enabled. A concurrent
renewal rejects the entire hold rather than leaving one scope pending.

## Serial transaction

1. Prepare one root:root `0700` inputs directory per slot. It contains canonical
   `identity-rekey.json`, `material-generations.json`, `receipt.json`,
   `delegation.json`, `controller.json`, `oci-region-intent.json`,
   `oci-region.json`, `placement.json`, `host-enrollment-public.json`, `operator-ssh-key.pub`,
   `managed-host-image-receipt.json` and `managed-host-image-delegation.json`,
   all root:root `0600`, plus the root-owned executable
   `terrascale-orchestrator`. Publish the new credential bytes to immutable
   OCI Vault versions; the installer reads and checks those versions itself.
2. On the first controller, run the candidate's
   `identity-rekey precommit --inputs DIRECTORY`. Add canonical `connection.json`
   (`{"version":1,"nats":...}`) using a root-owned exact-byte copy of the
   existing authenticated controller credentials/TLS key, and root:root `0600`
   `root-signing.key` containing the current root's PKCS#8 Ed25519 key. Preparation
   and authentication finish before the command samples the old lease floor,
   signs the final reset, fsyncs its immutable journal and publishes the held
   scopes with exact sequence CAS checks. It never widens or extends expiry.
3. Build the other slots' journals from that exact winning reset and each slot's
   checkpoint projection. Run `identity-rekey stage --inputs DIRECTORY` on each
   still-active peer, with its canonical `connection.json` and root-owned exact
   existing credential copies. Do not pre-stage the first controller with a sampled floor;
   old authority renewals can invalidate it during preparation.
4. Stop and install one controller at a time, preserving the other two broker
   peers. Run the candidate's `identity-rekey install --inputs DIRECTORY`, then
   start the controller and verify its actual node/store and quorum before the
   next stop. Installation requires the exact durable journal and inactive/dead
   systemd service with no remaining service-UID processes. It installs verified
   compatible `current` and `known-good`, replaces only the two signed opaque
   chain predecessors, verifies material as the service account, and publishes
   the new root-owned acceptance last. Shared identity/host replacements and
   completion use the controller's internal authenticated broker connection;
   the external precommit connection cannot replace those records.
5. After shared completion and all three accepted controllers are healthy, run
   `identity-rekey cleanup` on each. It rechecks rooted acceptance and immutable
   completion before deleting only named obsolete identity/anchor/manifest and
   initial-formation files. Retain genesis, the current root/material chains,
   launch pins and all stores. Complete the second region in the same order;
   verify all six members and fresh bidirectional replication before closing
   the ticket.

## Interrupted or rejected precommit

The fixed durable journal is
`/var/lib/terrascale-orchestrator-bootstrap/identity-rekey.json`. The command also
updates the inputs directory's journal with the exact finalized bytes. If a
crash interrupts that copy, obtain the SHA-256 of that fixed durable journal and
run `identity-rekey recover-inputs --inputs DIRECTORY --journal-sha256 SHA256`.
This verifies the root-owned durable evidence and requires the same reviewed
checkpoint, host plan, material, roots and predecessor before republishing its
exact finalized bytes through a unique temporary file. It does not retry the
barrier or alter the durable journal. Never reconstruct another attempt after
an unknown publish result. Retrying a committed reset requires its exact journal.
Its fixed effects may resume after grant expiry only when immutable broker
timestamps prove that the exact signed holds committed while the grant was
valid. The installer rechecks the fixed journal, opaque local predecessors and
shared hold before each effect. It uses the original acceptance time only for
that transaction's exact signed binary/material/launch pins; actual stopped
state, OCI identity, NTP and service-account credentials remain independently
checked. Install requires `connection.json` and root-owned exact-byte copies of
existing authenticated credentials, as precommit does. An expired uncommitted
proposal cannot initiate a hold.

A broker can commit after the caller checked expiry. Regional and atomic global
publish paths now refuse to report such a hold as valid. After verifying the
controller and exact operation, a root signer can authorize only the immutable
observed holds without changing the journal, record pins, epochs or CAS:

```sh
sudo /REVIEWED/terrascale-orchestrator identity-rekey authorize-resume --inputs /REVIEWED/identity-rekey
sudo /REVIEWED/terrascale-orchestrator identity-rekey install --inputs /REVIEWED/identity-rekey
```

`authorize-resume` independently reads the exact held messages and root-signs
both their full original reset fingerprint and broker sequence/timestamp/digest
pins. Its fresh one-hour authorization is appended to the immutable control
log and verified against its own broker commit time. A late authorization can
be signed again; it cannot replace or release the hold. It requires the existing
`root-signing.key` under current pinned roots. Missing, foreign or uncommitted
holds, incompatible targets and changed durable journals remain refused.

## Material contracts before cutover

Prepare reviewed v1 material-generation and interregion metadata before this
transaction. Retired generation links and source-directory metadata remain
opaque; ordinary loaders, credential issuance and generation adoption refuse
them. Keep the original immutable source directories unchanged. Do not run
`Generate` or `GenerateInterRegion` against them to resume an old deployment.

The replacement signed generation must retain the checkpoint's independently
observed regional operator, system/cell accounts and store identity. Pin exact
immutable Vault versions and verify the new role signer, credentials and
reviewed topology. Generating fresh regional account keys is not an in-place
cutover.

The installer replaces only the exact root-signed opaque predecessor hashes
for the installed and durable generation chains. The signed reset similarly
pins the old regional/global lease bytes and preserves their log history.
Ordinary self-update refuses the retired accepted/config contracts before
activation, so it cannot serve as a substitute for this transaction.

Accepted v1 records carry a required origin, bound into the acceptance digest.
Initial formation needs no rekey journal. A checkpoint-installed rekey requires
its immutable journal for every restart, root prestart and completion probe,
including after shared completion. Missing evidence refuses startup; retaining
the accepted snapshot alone does not prove completion or permit ordinary startup.

A later authorized rekey pins the exact current acceptance as its predecessor.
Before staging it, precommit and peer-stage independently verify the current
operation's immutable shared completion. They atomically retain its journal as
`identity-rekey.accepted.<accepted-wire-sha256>.json`, then create the successor's
fixed journal. A crash before staging leaves the current acceptance restartable
from its exact archive. Once the successor is staged, the old acceptance is
locally pending until installation publishes the successor. Aborting an unaffected
successor restores access to the retained evidence; archives are never erased by
cleanup or used for a different acceptance.

## Role configuration before binary activation

Version 1 is required for every role. Version 6 and unversioned configurations
are never decoded for admission or automatically converted. The controller
installer publishes the checkpoint's exact signed v1 configuration before the
new controller starts. Do not use ordinary self-update for that transition.

Replace the root-owned self-update watchdog service with this revision's
reviewed `deploy/systemd/selfupdate/terrascale-orchestrator-selfupdate-watchdog@.service`
before candidate activation, then run `systemctl daemon-reload`. Its command no
longer accepts `--restart`: activation and rollback always restart the unit.
Retain the existing timer; no image rebuild or cell refounding is required.

For each drained host, prepare a complete reviewed v1 `host.json` from its
current authenticated enrollment response, verified OCI descriptor and durable
host registration. Preserve its enrolled identity, credential paths, workload
roots, managed members and volume paths. Do not construct it by parsing a retired
configuration. With the host service stopped, install that reviewed file before
activating the candidate:

```sh
sudo install -o root -g root -m 0600 /REVIEWED/host-v1.json \
  /etc/terrascale-orchestrator/host.json
```

After activation, run the existing host-setup unit to verify or renew that same
enrollment. A retired config left in place fails closed; reenrollment is not a
config conversion mechanism. Live host replacement remains part of the held
serial handoff and must be verified before deployment is released.

Active reset enrollment grants pin the signed reset operation and exact original
host request, with no obsolete response. The normal renewal path completes them
under the new response authority after checking the live instance, descriptor,
identity key, NATS key and CSR. Host setup treats a changed root-pinned response
key as requiring renewal; retired hosts remain disabled. Renewal claim/finish CAS
and exact response replay remain enforced.

For a confirmed losing CAS while the original live controller invocation still
serves, run:

```sh
ts-orch identity-rekey abort --inputs DIRECTORY --journal-sha256 EXACT_SHA256
```

Abort independently proves that the original global `N+1` sequence is occupied
by a non-barrier message, making that exact reset permanently uncommittable. It
also requires the original live invocation, unchanged old acceptance/store and
absence of pending installation effects. It archives the exact journal with a
create-only rename and fsync; it does not change acceptance or material. An empty
sequence, matching/foreign barrier, changed local state or uncertain observation
refuses abort. After successful explicit abort, prepare a fresh reviewed attempt
and invoke precommit again. Never delete the fixed journal manually.

The source tests exercise root signatures, real JetStream CAS/record policies,
fencing and native interrupted-material recovery. Production qualification also
requires actual OCI/Vault observations, host drain, root service-account probes,
serial controller restarts and live data evidence.

## Interrupted binary recovery

Prepare and watchdog authenticate owned activation/restore records and the
recorded destination before attempting recovery. An interrupted restore may
leave `current` on the rejected, known-bad release; that release never runs or
confirms. After shared completion, native recovery finishes only the recorded
transition and retains its durable restart obligation. Unsafe records, a
foreign current selection or an untrusted/incompatible destination refuse
before recovery effects.

The read-only completion probe may execute the authenticated predecessor of
an owned recorded transition even when the target still has a valid signature
but cannot decode the accepted contract. The actual executable is measured
against that predecessor's pin/receipt. This exception grants no runtime
admission or target confirmation.
