# Broker enrollment grants

Each selected broker's admitted `run` settings include
`TS_ORCH_BROKER_ADMISSION_FILE`, pointing to a protected JSON file. Include that
file, its signer public key, and all reader credential files in the signed run
material inventory. The broker keeps its writable checkpoint under its admitted
service state directory.

The JSON contains:

| Field | Meaning |
| --- | --- |
| `version` | `1` |
| `broker_id` | This broker's exact admitted identity |
| `broker_ids` | Complete required broker identity list |
| `readers` | One `{broker_id, public_nkey, account}` for every required broker |
| `environment`, `cluster` | Exact member enrollment scope |
| `signer_public_key_file`, `signer_sha256` | Delegated grant signer's public PEM and SHA-256 of its PKIX DER |
| `regions` | Region to `{Global, Regional, Node}` account names in the immutable local broker configuration |
| `reader` | Captured `bootstrapcredentials.Reference`: `url`, `caFile`, `certificateFile`, `privateKeyFile`, `nkeySeedFile` |
| `checkpoint_path` | Protected persistent signed-grant checkpoint |
| `minimum_revision` | Required desired journal revision before opening a new broker's listener |
| `allow_initial_bootstrap` | Explicit one-time baseline bootstrap, only before the first desired publication |

Every reader grant must name a global account admitted by `regions`; the local
reader's captured NKey must match its `broker_id` entry. Install the same complete
public reader inventory on every broker that accepts the reader connections.
The runtime derives permissions: read the global leaders stream and publish
only that broker's acknowledgment. These keys cannot publish enrollment state,
change authority leases, or acknowledge another broker.

The GRU production runtime's `compute.enrollment.broker_ids` lists the same
required brokers. After publishing durable enrollment keys, its lease-fenced
journal publishes signed desired grants. Provisioning waits until every listed
broker has applied and durably acknowledged that exact revision and digest.
After exact completed OCI removal, the existing completion callback retires
the enrolled incarnation and waits for acknowledged credential revocation.
Pending acknowledgments remain retryable and do not complete autoscale removal.

Existing brokers recover their last signed checkpoint before opening a listener
and preserve it through control outages. New brokers need a positive admitted
`minimum_revision` and an authenticated connection to an existing global peer
before startup. The one-time bootstrap option consumes a durable marker; losing
a checkpoint or restarting before the first signed desired publication cannot
silently restore bootstrap grants. Recovery must supply a verified checkpoint
or reach the source with a positive minimum revision.
