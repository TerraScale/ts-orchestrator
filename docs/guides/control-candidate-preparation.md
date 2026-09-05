# Prepare the first SFO and FRA candidates

`plan-control-candidates --config FILE` signs the initial SFO and FRA host
manifests and a separate candidate preparation grant. This is the first host
admission phase of [the storage transition](../contracts/control-snapshot-transition.md).
It does not start NATS, capture or restore streams, establish R3, elect an
authority, or report Region or customer readiness.

The planner requires a protected JSON file with these exact fields:

| Field | Value |
| --- | --- |
| `ownerPrivateKeyFile` | Protected P-256 owner signing key file |
| `publicKeyFile` | Matching owner public key file |
| `sourceNodeId` | Existing GRU seed node identity |
| `sourceBootstrapGrantFile` | Existing signed, still-live GRU seed bootstrap grant |
| `transitionId` | Explicit identity for this preparation |
| `targetEpoch`, `minimumControlEpoch` | Explicit transition epoch and accepted control floor |
| `issuedAt` | RFC3339 issuance time, no later than now |
| `bootstrapExpiresAt` | Initial host admission deadline, after now and no later than `expiresAt` |
| `expiresAt` | Preparation deadline, at most 24 hours after issuance |
| `candidates` | Exactly two entries, ordered SFO then FRA |

Each candidate entry contains `manifest`, `config`, and `bootstrapGrantId`.
`manifest` is the complete existing host manifest with actual signed artifact
identities. The planner replaces the orchestrator launch arguments and
configuration, then derives its immutable configuration version. Other
components retain their independently owner-authorized initial bootstrap
behavior. The planner neither allocates hosts nor invents artifact identities.

Candidate `config` contains exactly `version` set to `1`, `mode` set to
`prepare-control-candidate`, `transitionId`, `nodeId`, `region`, `serverName`,
`storeDir`, `grantFile`, and `grantPublicKeyFile`. The Region must be `sfo` or
`fra`, match its candidate entry, and match the node identity prefix. All paths
are absolute. The store must be inside the orchestrator component's data
volume. The grant paths identify host-owned files that will be delivered before
bootstrap. They do not embed the grant digest in the manifest, which would
create a circular signature binding.

The planner returns one JSON bundle containing `publicKeyPem`, the signed
`preparationGrant`, and `candidates`. Each output candidate contains `nodeId`,
the prepared `manifest`, and its signed `bootstrapGrant`. GRU bindings come
from verification of the source grant. Candidate bindings come from the exact
newly signed grants and manifests. The private key is never output.

Deliver each candidate's manifest and bootstrap grant through the existing
first-host bootstrap path. Set the ts-node `bootstrapGrantFile` and
`bootstrapPublicKeyFile` to that candidate's grant and the matching owner key.
Deliver the common preparation grant and owner key at the candidate config's
`grantFile` and `grantPublicKeyFile`. These files and their ancestry must pass
the host ownership checks. Preserve the signed JSON bytes. Use
`bootstrapBeforeNats` for local bootstrap admission before a broker exists.

The host verifies both signatures against the same bootstrap owner and pins
the exact preparation identity in its command-journal directory. It publishes
service-readable evidence at
`/var/lib/terrascale/host-admission/control-candidate/preparation.json`.
The unprivileged candidate trusts this fixed root-owned publication. A caller
cannot replace that trust root with a key path in the component config.

The installed launch is `prepare-control-candidate --config @config`.
It prints one admission receipt and remains inert. It exits on expiry or
changed, missing, or invalid published evidence. The receipt proves admitted
preparation only. It is not broker health or transition completion evidence.

Choose an earlier `bootstrapExpiresAt` when preparation must survive initial
bootstrap expiry. A restart during that later window requires a previously
pinned matching preparation record. It can activate only that exact candidate
component; it cannot recover unrelated pending commands or extend authority
for other components. An ordinary runtime epoch permanently retires candidate
preparation and revokes its public evidence.

Source fencing, consistent inventory capture, independent storage receipts,
grant-authorized restore and R3 promotion, and final runtime activation remain
separate acceptance work. The preparation command must not be used as a
successful `add-region` or production qualification result.
