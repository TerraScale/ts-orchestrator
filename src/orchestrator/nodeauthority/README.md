# Receiver authority

This package verifies the shared signed command envelope against the exact
admitted node, subject, authority candidate, lease and signing key. It reads
`authority.regional` through `$JS.API.STREAM.MSG.GET.KV_<bucket>` and compares
the current lease before accepting a mutation. The pinned NATS server only
answers that API from the assigned stream leader; this package does not claim
a stronger per-read quorum barrier. Production reads require authenticated
NKey/JWT plus verified TLS 1.3 and a client certificate.

`EpochStore` writes and syncs a root-owned epoch floor before effects, validates
it on restart, and retains a process-wide file lock for the receiver lifetime.
Its directory is the existing private ts-node command-journal directory.

Production ts-node JSON must contain:

```json
{
  "authorityBucket": "ORCH_LEADERS",
  "commandTrustKeys": [
    {
      "candidateId": "gru-controller-MATCH_ACTUAL_INSTANCE",
      "publicKeyFile": "/etc/terrascale/command-public.pem"
    }
  ]
}
```

The public key is P-256 SPKI PEM. Candidate IDs must match the actual regional
runtime lease. These fields supplement the existing NKey/TLS and signed
release configuration. `hostcontrol.Config.SigningKey` holds the matching
private key on the controller; it does not belong on the node.

Read-only status requires no regional lease. Runtime mutations require a live
lease. Initial installation uses the separate signed host grant described
below. There is no unsigned mutation fallback. A process crash
leaves pending outcomes in the durable journal for a freshly authorized
reissue. Already-running systemd effects cannot be made atomic with an external
lease transition and may complete after cancellation.


## Initial host admission

Fresh production nodes require `bootstrapGrantFile` and
`bootstrapPublicKeyFile` in ts-node configuration. Both are absolute paths to
protected regular files. The public key is P-256 SPKI PEM and must differ from
regional command keys. The private key stays with the owner/provisioner.

`hostagent.SignBootstrapGrant` signs a version-1 `BootstrapGrant` containing
`grantId`, `nodeId`, the complete canonical host `manifest`, `issuedAt` and
`expiresAt`. Its lifetime is at most 24 hours. The signature has a distinct
`TS-NODE-INITIAL-GRANT-V1` domain. Artifact digests, service arguments,
configuration, user, storage paths and resource limits are all covered.
The receiver persists a pin over the signing-key fingerprint and full grant
before installation or unit effects. Replacing either pin after restart fails.
An initial grant cannot replace another serving version or retire an existing
component outside its manifest.

`BootstrapCommands` derives one drain/deploy pair per initial component and
one final release, each with a deterministic command ID. The only initial
components are `orchestrator`, `terrabase` and `grafana-agent`.
`SignBootstrapCommand` signs one exact allowed command for at most 30 seconds,
using the distinct `TS-NODE-INITIAL-COMMAND-V1` domain. The command binds the
host, subject, grant pin and expiry. These messages contain no regional epoch
or lease. Rollback, manifest replacement and arbitrary command IDs are refused.

All bootstrap and runtime mutations share the receiver command lock. The
first authenticated regional command durably writes its real epoch floor
before effects, permanently retiring the host grant. A later bootstrap
message is refused even if a completed receipt exists. This host installation
grant is separate from the global pre-customer R1-to-R3 promotion authority.

Production reconciliation uses the same lock and checks the admitted full
manifest digest before any install, account, unit or service effects. Runtime
manifest CAS first records its signed admission, retains the actual prior disk
digest until the new manifest is synced, and then commits the new digest.
Repeated failed publications preserve the actual old disk admission so a
restart can receive a fresh authorized retry. Startup hydrates the lifecycle
from the exact manifest object verified by this admission check.

Pending activation requests require a fresh signed reissue after restart.
Completed requests return the recorded result only while their authority is
still valid. A sender observes current version and quiescence on retries;
a completed drain receipt can precede a later successful activation and does
not by itself prove present quiescence. Expired bootstrap grants stop new
bootstrap effects. Once runtime authority has retired bootstrap, already
admitted desired state can continue reconciling without the retired grant.


## Starting the first embedded broker

Production seed sets `bootstrapBeforeNats: true`. After root-only OCI secret
provisioning from `/etc/terrascale/host-secrets.json`, ts-node loads its config
and runs local initial admission before dialing NATS. The owner-signed grant
itself authorizes the finite initial steps; there is no private bootstrap key
on the node and no synthetic lease or temporary broker. The local executor
uses the same lifetime lock, manifest admission, command journal and pinned
transition plans as the network receiver. It bounds installation and service
readiness to two minutes, also bounded by grant expiry, and requires three
consecutive observations of the pinned current versions and active units.
The lock is released before the real NATS receiver acquires it. A persisted
runtime epoch makes later local bootstrap invocation a no-effect operation.

`bootstrapBeforeNats: false` preserves the external signed-command transport
path used to qualify the receiver with an already running authenticated broker.
Local service activation alone does not prove a regional control plane or
embedded NATS is ready. Actual runtime composition and authenticated readback
remain required after these initial host operations.

Initial secret provisioning also holds the node's epoch-store ownership lock.
Startup first reads the protected public node identity, then checks the durable
regional epoch before opening any initial-secret seed or credential pin. A
retired bootstrap skips the initial-secret fetch and validation path entirely,
so later runtime credential rotation cannot restore old secrets or make their
old digest pins block a valid restart. Corrupt state and another node's epoch
are refused; credential-file presence alone never proves completion.

`hostbootstrap` owns offline activation order. Its authenticated hostagent
session creates the exact signed orchestrator account, then calls the journaled
hostsecrets ownership handoff with that user and the full signed manifest
digest before reconciliation can start any service. The handoff admits only
the declared orchestrator credential leaves to that service account; ts-node
credentials remain root-only. An interrupted handoff stops activation and
resumes under the same initial grant and credential journal on retry.
