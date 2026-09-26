# Completed production restart packet recipe

`EmitCompletedRestartPacket` is the offline integration entrypoint. Its
`SignedHistoryRecipe.Prepare` callback verifies a schema-v3 production GRU
anchor, founder plan, three signed manifests, and the current signed founder
selection. It signs one external `seed-a` history and schema-v2 managed
histories for `controller-a` and `controller-b` through public trust and
bootstrap APIs. The emitter completes all three through the public ledger
over an initially empty `CapturingObjectStorage`, then rereads both peers
through `NewHistoricalLedger`.

The caller supplies a `MaterialPreparer` that receives the completed ledger
states. `BuildVerifiedGuestMaterial` uses those states to construct accepted
install markers and asks `bootstrapstart` to verify and stage each founder
floor and lock. It uses a separate, host-only exact-key founder selection
source for that preparation. Its selector and immutable objects are excluded
from restart simulator routes. The signed directory plan requires both
`/var/lib/terrascale-orchestrator-controller` and
`/var/lib/terrascale-orchestrator-secrets` at mode `0700`, owned by each
controller's actual service UID and GID. The service-owned floor, lock, and
credential files have mode `0600`; root-owned baked identity, anchor, and
public roots have mode `0444`. The plan's numeric UID/GID must match the
packaged guest account.

`BuildComputeInventory` derives three exact SDK request URIs and JSON response
bodies per controller: `GetInstance`, `ListVnicAttachments`, and `GetVnic`.
The example caller supplies that inventory. The emitter restricts prepared
routes to the Compute host, and packet validation restricts their URI shapes;
it does not prove that an arbitrary caller used `BuildComputeInventory`. The
emitter derives Object Storage 200/404 routes from the captured ledger's keys and
bytes. `VerifiedPacket.SimulatorRoutes(slot)` isolates the combined route
inventory by instance. The synthetic integration test sends real OCI SDK
instance-principal requests through each isolated simulator. Under the
`fixturetest` build tag, it repeats those reads through
`OCIInstanceObserver.ObserveInstance` using a test-only transport seam. Both
paths check decoded identities and unlisted requests. Run the caller gate with
`go test -tags fixturetest ./tests/firecracker/production/fixturegen -run TestCompletedPacketEmitsSignedThreeSlotCaptureAndVerifiedFloors -count=1`.
This exercises the real observer validation path, but not the packaged
restart process or production transport constructor.

`CurrentCompletedSourcePins` inventories non-test Go and deployment sources
under the recipe's declared directories. Emission checks both their hashes
and complete directory coverage, including newly added runtime source files.
The emitter also verifies the embedded signed image receipt against the exact
`input/orchestrator` bytes, architecture, image OCID, and fixed guest path
`/usr/local/bin/terrascale-orchestrator`. Source pins and executable/image
binding are separate checks: source pins do not establish the receipt's
`SourceRevision`.

`ValidateProductionGuests` additionally checks canonical production configs,
real-format NATS JWT/TLS credentials, credential digests, the guest OCI CA,
host-only HTTPS and per-slot IMDS identities, and exact private network/time
files. `fixturegen production-preflight` applies those gates with the source
and image checks. `fixturegen stage` also rejects `/` or a plain host
directory, requires a distinct ext4 mount, checks the guest service UID/GID
and shipped units, installs the executable and signed guest files, refreshes
the **guest** CA bundle, and runs the executable's credential check as the
service user. Neither the offline signing key nor any simulator private key
is installed in a guest.

The current integration test uses a synthetic executable, synthetic OCI
identities, and offline signing keys. It demonstrates packet construction and
SDK/simulator compatibility; it is not a production binary build or a VM
restart result. After the runtime source freeze, build and inspect the actual
single executable and image receipt, refresh source pins, and emit a new
packet bound to those bytes and the accepted image OCID. Emit it immediately
before staging because the trusted-clock window is five minutes. Supply an
independently SHA-256-pinned ext4 base image, kernel, Firecracker binary,
fixturegen verifier, SSH client key, known-hosts file, and trusted root PEM to
`tests/firecracker/production/qualify.py`. Its default mode prepares disposable
images; `--run` boots and sequentially reboots all three VMs, checks time,
bootstrap, controller UID/GID and invocation evidence, then audits isolated
simulator requests. A production pass requires that real VM run and its report.
