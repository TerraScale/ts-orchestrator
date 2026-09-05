# Bootstrap control configuration

`bootstrap` and `add-region` use the production OCI provider and authenticated
NATS control runtime. Set `TS_ORCH_CONTROL_CONFIG_FILE` to an absolute,
owner-private JSON file and `TS_ORCH_CONTROL_JOURNAL_FILE` to the durable control
journal. The commands validate configuration and local credential references
before provisioning. Dry runs do not read credential files.

The configuration has these fields:

| Field | Meaning |
| --- | --- |
| `version` | `1` |
| `generation` | Positive immutable admission generation |
| `compartmentName` | `terrascale` |
| `receiptFile` | Absolute path for durable actual OCI member bindings |
| `stores` | Named TLS NATS connection declarations |
| `regions` | Estate region code, OCI region, member count, host and authority stores, command candidate and signing-key reference |
| `members` | Logical host ID, region, slot index, architecture, controller instance, NATS server name, pinned membership public key and regional store |
| `actions` | Exact runtime action plans, including host manifests, complete stream assignments and mirror proofs |
| `activations` | Per-host signed initial grant and owner public-key references |
| `seeds` | Per-host initial public files, NATS identity references, runtime command trust and pinned Vault secret versions |

A store declares `url`, `caFile`, `certificateFile`, `privateKeyFile`, and
`nkeySeedFile`. URLs use `tls://host:port`. Credentials require a current client
certificate under the declared CA, a matching private key, and a user NKey.
Connections verify TLS 1.3 and require NATS authentication.

A region declares `code`, `ociRegion`, `memberCount`, `hostStore`,
`authorityStore`, `commandCandidateId`, and `commandSigningKeyFile`. Its shape
must match the estate. Its command candidate must name an admitted regional
controller. Regional lease terms come from leader-only JetStream reads; a
configuration generation never stands in for an election term.

Member `membershipPublicKey` values are canonical Base64 PKIX P-256 public
keys. `architecture` is required: `0` means arm64 and `1` means amd64.
A member's `hostId` is its logical identity before provisioning. The
provider resolves its `region` and `index` to the actual owned OCI instance
and checks the instance architecture. The command never invents an OCID.
A full launch declaration can include GRU, SFO and FRA: initial bootstrap reads
only GRU, and each add-region operation reads the prior admitted regions plus
its target. Global R3 actions remain unavailable until every required region
is admitted. Existing OCI bindings cannot change within a generation.

Action fields follow `bootstrap.ControlRuntimeActionPlan`. Each handoff's
`MemberID` and each check's `Members` entries use logical host IDs in the
configuration. Use `revokedStore` to reference retired credentials; inline
credential options are prohibited. Global proofs and candidate mirrors must
cover the complete authoritative topology. Global R3 assignments must occupy
GRU, SFO and FRA. Pinned signed membership is checked against its regional
lease, separately from the global authority lease.

Each activation declares `hostId`, `grantFile`, and `ownerPublicKeyFile`.
The grant binds the complete initial manifest and finite activation commands.
`ownerSigningKeyFile` is optional for an explicit owner-operated transport
activation; the private signer is never installed on the host. Production
seeds set `bootstrapBeforeNats: true`, allowing the signed initial activation
to start the first embedded broker before ts-node connects to it.

Each seed declares `hostId`, `nats`, `commandTrust`, and optional `files`.
`commandTrust` contains `candidateId` and `publicKeyFile` entries. Each must
match the admitted regional candidate and its P-256 signing key. The bootstrap
owner key cannot act as runtime command authority. The NATS
fields reference local owner files for validation. `privateKeySecretId` and
`privateKeyVersion` identify the corresponding TLS private-key secret;
`nkeySecretId` and `nkeyVersion` identify the NKey seed secret. Additional
private file references declare `sourceFile`, `path`, `private: true`,
`secretId`, and `versionNumber`. Runtime configuration, certificates and public
trust files must declare `private: false`; cloud-init installs them as `0644`
so the orchestrator service can read them. Private runtime credentials use the
Vault references and authenticated service ownership handoff.

Private file contents do not enter OCI user-data. The seed contains the exact
Vault secret OCID, version, SHA-256 and allowed credential destination.
The instance retrieves these files using its OCI instance principal before
loading ts-node's configuration. Vault versions and the dynamic-group/IAM
permissions needed to read them must exist. Public configuration, certificates,
trust keys, the initial manifest and owner grant are installed through the
per-slot cloud-init. The shared `tsnodebootstrap` unit runs ts-node with its
required root authority.

The ordinary runtime path continues to require real regional authority.
Failed authorization never selects the owner-grant path. Successful actions
require fresh host facts, live signed membership, durable stream assignments
and content evidence. OCI tags and journals record those results; they cannot
supply evidence for a process or broker that did not start.
