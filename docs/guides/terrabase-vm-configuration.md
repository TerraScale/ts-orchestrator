# TerraBase production configuration in qualification guests

`TS_VM_TERRABASE_DECLARATION_FILE` selects an explicit JSON declaration for
the VM runner. `vmengineconfig` validates it against the verified network plan
and signed TerraBase artifact, renders production TOML for each declared host,
and reads the matching TLS files through protected, bounded file handles.
The GRU bootstrap path installs that configuration through the ordinary signed
host manifest and ts-node. It does not admit engine membership or mark the
guest ready.

The declaration is required by the `smoke`, `stack`, and `test` qualification
profiles. Omitting it is rejected during command preflight, before host
resources are allocated. The `doctor`, `image`, and `clean` commands do not
start guests and do not require this declaration. The runner supplies no
default database, key, placement, or development-mode configuration. A
selected but invalid declaration fails service construction before guest
creation.

## Input contract

The JSON uses the exported `vmengineconfig.Declaration` field names below.
Unknown members, duplicate names, trailing JSON, oversized files, unsafe paths,
and missing required values are rejected. Relative declaration paths resolve
against the repository. TLS file references must be absolute and protected.
Do not put credentials or PEM material in this document.

| Fields | Required values |
| --- | --- |
| `version`, `contract` | `1` and `terrabase-worktree-config-bafba567958b96de5c63563e85ed975f9f681ba1e0b74eeb99eb5af46089c21b` |
| `artifactSha256`, `release` | Exact bare SHA-256 and version of the supplied signed TerraBase artifact |
| `environment`, `cluster` | Explicit bounded environment name and canonical cluster ULID |
| `generation`, `epoch` | Positive declared placement values representable as TOML integers; these claims do not establish admitted membership |
| `hosts` | One entry for every launch host in GRU/SFO/FRA, with `nodeId`, unique canonical `member` ULID, `certificateFile`, `privateKeyFile`, and `caFile` |
| `databases` | Explicit database records containing `tenant`, `project`, `database`, home `region`, `selectedRegions`, `allowedRegions`, `encryptionKey`, `maxStorageBytes`, `maxDocuments`, and `maxInflight` |
| `backupDisk` | Explicit `stagingBytesPerStream`, `inventoryBytesPerStream`, and `totalStagingBytes` reserved on each member backup filesystem |
| `limits` | Explicit `maxMessageBytes`, `maxInflight`, `requestTimeoutMillis`, `tlsHandshakeTimeoutMillis`, and `shutdownGraceMillis` |

Database scope and encryption-key versions are canonical ULIDs. The key
version is not an OCI key OCID or raw key. Each project belongs to one tenant,
database IDs are unique, and each database's `selectedRegions` must be
nonempty, unique, limited to GRU/SFO/FRA, backed by exactly two hosts, include
the declared home `region`, and be contained by `allowedRegions`. The renderer
supports the producer's current GRU/SFO/FRA schema, with exactly two hosts per
selected Region and at least one selected database on each rendered host.
The normal launch network plan requires all six host declarations.
The full suite also reserves IAD networking for a later expansion scenario.
Those reserved hosts are excluded from the initial engine bindings and peer
list. A network reservation does not admit engine placement. IAD bootstrap
still requires admitted allocation and supported controller/engine configuration.

Every database requires an explicit `allowedRegions` lock. `selectedRegions`
is the authoritative placement selection for that database; the renderer
places storage on a host only when that host's Region is selected. A GRU-only
database may coexist with a GRU/SFO database. `allowedRegions` remains a
broader policy lock and cannot add a selected Region.

TLS certificates must bind the exact identity
`spiffe://terrascale.tech/<environment>/terrabase-member/<cluster>/<member>`
and the guest IP SAN. The certificate and private key must match, the chain
must validate for both server and client authentication, and all hosts must
share the declared CA bundle. Private key files must not be accessible to
group or other users. The runner does not mint these inputs from host liveness
or an orchestrator lease.

Database bounds are 1 through 2^50 storage bytes, 1 through 1,000,000,000
documents, and 1 through 1,000,000 concurrent operations. Transport bounds are
1,024 through 16,777,216 message bytes, 1 through 4,096 concurrent requests,
100 through 300,000 milliseconds for requests and shutdown, and 100 through
30,000 milliseconds for TLS handshakes. These are parser limits, not measured
production recommendations.

`backupDisk` is disk capacity, independent of the guest RAM limit. Half of each
stream allowance holds the active encrypted archive chain; the other half is
reserved for root rotation, provider migration, or restoring a retained chain.
Two MiB within the active half is reserved for manifests. The archive ceiling
must exceed the database storage quota, and every destination's `maxPointBytes`
must hold the complete active half. Each `maxArtifactBytes` must be at least
16 MiB to hold the default 8 MiB member, a final encoded document, and its
authenticated envelope. Encoded record and encryption overhead also
consume this allowance: the quota check is only a necessary floor. Size the
explicit allowance from the database's encoded backup size and document count;
a larger logical quota alone does not guarantee its backups fit.

`inventoryBytesPerStream` separately bounds retained encrypted manifests and
must be at least 4 MiB, allowing two maximum-size manifests during rotation.
The worker refuses new captures before they could exceed this allowance;
retention cleanup and inspection remain available. Inventory exhaustion requires
more declared disk capacity or expiry under the existing retention policy.

Each member checks `max(enabled database count, 1) * (stagingBytesPerStream +
inventoryBytesPerStream)` against `totalStagingBytes` without integer overflow. The total must fit a signed
64-bit TOML integer. Supply real disk capacity for this reservation in addition
to database files; the declaration does not
provision a filesystem or prove available disk space. The qualification fixture
reserves 32 MiB archive disk plus 16 MiB inventory disk for its single 1 MiB database; production has no default.

## Installed result

The renderer derives all peer addresses and exact SPIFFE identities from the
network plan and assigned member IDs. It binds TBEP to `127.0.0.1:8421`, metrics
to `127.0.0.1:8423`, and QUIC to the guest's private IP on port 8422. Database,
policy, and backup paths occupy separate directories below
`/var/lib/terrascale/terrabase`. Each host receives only the selected local
database storage entries, and the TOML `region` for those entries is that
host's Region. The complete selected Region set remains in `selected_regions`.

The manifest carries the nonsecret TOML and `--config @config`. The existing
launch planner derives the immutable `ctl-` version from the complete component
configuration before the owner signs the bootstrap grant. ts-node installs the
configuration beside the exact binary, expands `@config`, and owns subsequent
service changes. Changing the configuration changes the immutable launch
version while preserving the signed artifact URL and digest.

The NoCloud root files carry `server.pem`, `key.pem`, and `ca.pem` below
`/etc/terrascale/terrabase/`. They are installed with mode 0400 and transferred
to `terrascale-terrabase` during initial bootstrap, before ts-node starts.
NoCloud user data contains ownership commands and references, never the TLS
contents. Wrong-host material, changed configuration, and another service's
file ownership are refused.

To use an already prepared declaration, retain the ordinary artifact and
privilege setup and add this environment variable:

```sh
TS_VM_TERRABASE_DECLARATION_FILE=/absolute/protected/member-declaration.json make vm-test
```

## Qualification limits

The contract marker pins the inspected producer parser source, not an immutable
published launch contract. A matching marker and artifact digest do not attest
that this parser produced that binary. The required capability names emitted
in TOML are producer configuration claims, not qualification evidence.

The production engine's durable orchestrator membership source remains
unwired. SFO/FRA guest admission also remains separate from this GRU bootstrap
integration. The renderer does not supply a key provider, engine admission,
replication readiness, or a lifecycle mutation adapter. Portable tests cover
declaration, certificate, signature, manifest, and image-material boundaries;
they do not prove parser acceptance by an engine binary or successful
Firecracker service startup. A subsequent
[configured guest attempt](../evidence/engine-pem-rebuild-2026-09-05.md) using the
producer's committed PEM decoder fix reached the missing durable membership
source after catalog and transport construction. It did not become ready.
Production and full VM acceptance remain open.

Heterogeneous residency uses explicit control-only declarations. Every host
receives every database declaration with the complete selected Region set;
local declarations are enabled and other declarations are disabled. A host
with no selected local database may use an empty observer binding while it is
pending. Dynamic remote declaration and admission remain separate work.

### Host placement control material

A production `run` host additionally supplies `engineControl` on its engine
host declaration, plus the same exact SPIFFE URI in `orchestratorPrincipals`.
The object contains `identity`, `certificateFile`, `privateKeyFile`, `natsUrl`,
`natsAccount`, `nkeyFile`, `natsCertificateFile`, `natsPrivateKeyFile`, and
`natsCaFile`. These are explicit admitted references. The engine control,
read-only observer, member transport, and NATS client private keys must all be
distinct. Every host uses its own NKey; the global R3 account must already exist.

The renderer copies private material into `/etc/terrascale/placement/`, owned
by `terrascale-orchestrator` with mode `0400`, and writes the shared
`placementpublisher.HostFileConfig` schema to `host.json`. The signed
orchestrator run configuration includes `TS_ORCH_PLACEMENT_HOST_FILE` and
`TS_ORCH_PLACEMENT_BROKER_GRANTS_FILE`. Public `broker-hosts.json` binds each
host NKey to its exact engine-identity control subjects; it carries no private
keys or caller-defined wildcard permissions. Selected embedded global brokers
apply these grants before opening their listeners. A reused key with broader
or conflicting permissions is rejected. Non-broker hosts do not start a broker
merely because they carry the public grant inventory.

This control material applies only to the production `run --config` manifest.
It cannot be layered onto the temporary initial-R1 or transition-grant command;
those retain their own admission and startup rules. Pending placement receipts
do not establish accepted membership, catch-up, writer authority, or serving
readiness. The declaration and bridge material are inputs for qualification,
not evidence that the production runtime or three-Region estate is ready.

An optional declaration-level `transitionTrust` supplies `authority`, `genesis`,
and `members` arrays of `{ "keyId": "...", "publicKeyFile": "/..." }`. The
renderer accepts only exact raw32 Ed25519 public key files, copies them to
fixed hashed paths below `/etc/terrascale/terrabase/transition/`, and renders the
producer's `[control.transition]` signing pins. Their files are readable only
by the engine service. Authority and explicit genesis sets are mandatory when
this object is supplied; absence denies acceptance, never permits implicit
bootstrap. Private signer keys are not generated from this trust configuration.
