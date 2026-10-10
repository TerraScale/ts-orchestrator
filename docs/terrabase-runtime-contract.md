# TerraBase runtime contract

The [zero-configuration contract](zero-configuration.md) is required production policy.
Configuration fields, manual bootstrap paths and dated observations below are
legacy implementation inventory, not feature/region activation or credential-copy
instructions. Removing runtime guards and completing automatic NetBird admission,
region inference and OCI Vault provisioning/delivery remain TS-796. Integrity,
authorization, quorum, residency and destructive-operation safeguards still apply.

Status: **implemented in source and tested locally against a published
release; not deployed or tested on OCI.** This is the contract between the
orchestrator and the C# TerraBase single-file binary (repository
`TerraScale/terrabase`). Package [`internal/terrabase`](../internal/terrabase)
holds the orchestrator side: release assets
([`release.go`](../internal/terrabase/release.go)), settings, peer list,
layout and health probe ([`contract.go`](../internal/terrabase/contract.go)),
member certificates ([`ca.go`](../internal/terrabase/ca.go)) and the
`ts-orch terrabase` command ([`cli.go`](../internal/terrabase/cli.go)). The
host side is [`internal/host/terrabase.go`](../internal/host/terrabase.go).

The operator workflow is in [TerraBase deployment](terrabase-deployment.md);
what serving, replication and scale-in still need is in
[TerraBase serving lifecycle](terrabase-serving-lifecycle-plan.md).

## Release

Every TerraBase `main` push that passes CI publishes the prerelease
`ci-<commit>-run-<run id>`; a version tag `v<Version>` publishes the release
`v<Version>`. Each carries two assets: `terrabase-linux-amd64` and
`terrabase-linux-amd64.sha256` (one `sha256sum` line). The first published
release is `ci-641274f7482bcf0ce2ae556af8be162d49e445be-run-13121`, SHA-256
`69d132e76471089268ef1a807e69d4aef1e00a92995930817b0457ada0c02194`.

**ARM64 gap.** OCI workload hosts are ARM64 (`VM.Standard.A1.Flex`), but
TerraBase CI builds only `linux-x64` and publishes only
`terrabase-linux-amd64`. A live OCI deployment needs TerraBase CI to also
publish `terrabase-linux-arm64` and `terrabase-linux-arm64.sha256`
(TerraBase TS-483). The orchestrator side is ready: `operator
terrabase-release` and the attempt's `terrabase` phase consume the arm64
asset, tested with the checked-in stand-in
`internal/terrabase/testdata/terrabase-linux-arm64` (a bare aarch64 ELF
header) and its `.sha256` until TerraBase publishes the real asset.

`terrabase.VerifyRelease` checks that the file is named
`terrabase-linux-amd64` or `terrabase-linux-arm64`, starts with an ELF64
little-endian header whose machine matches the asset name (`EM_X86_64` for
amd64, `EM_AARCH64` for arm64, so an x86-64 build published under the arm64
name is refused before it reaches a host), is at most 512 MiB (the
controller's artifact admission limit), and matches the single line of its
`.sha256` asset. The verified digest is the
artifact digest the rollout pins. TerraBase publishes no source digest, so
the artifact's source claim is repository
`https://git.terrascale.tech/TerraScale/terrabase`, the commit, and the
SHA-256 of `git archive --format=tar <commit>` in a TerraBase checkout.

## The binary

The executable is a self-contained single-file .NET 11 JIT build with
invariant globalization (no ICU). Its native libraries are extracted at
startup to `DOTNET_BUNDLE_EXTRACT_BASE_DIR`, or to a writable `HOME`; with
neither it exits with `DOTNET_BUNDLE_EXTRACT_BASE_DIR is not set`. The host
sets that variable.

Every setting is a `TERRABASE_<NAME>` environment variable or a
`--name=value` argument. The argument wins, and an empty value means unset.
An unknown `--name` exits with code 2; unknown `TERRABASE_*` variables are
ignored. A configuration error exits with code 2 and never prints a value.

| Setting | Default | Meaning |
| --- | --- | --- |
| `admin-port` | 9464 | Loopback-only (`127.0.0.1`) HTTP listener: `GET /healthz` answers 200 `{"status":"ok","version":"0.1.0"}`; also `/metrics` (Prometheus) and OpenAPI. |
| `data-directory` | `data` | One SQLite file per database. |
| `client-port`, `client-certificate`, `client-private-key` | unset | HTTPS client API on all interfaces, HTTP/1.1 and HTTP/2. All three or none. |
| `peer-port`, `peer-certificate`, `peer-private-key`, `peer-client-ca` | unset | Inter-node gRPC service `terrabase.v1.Replication/Sync` over HTTP/2 with mutual TLS on all interfaces. A connecting peer's client certificate must chain to `peer-client-ca` and carry the clientAuth EKU. All four or none. |

TerraBase `origin/main` `807ad714` serves `GET /readyz` on the client
listener (`Features/Health/ReadyzEndpoint.cs`, `ListenerMetadata.Probe`).
`/healthz` remains liveness on the admin listener. The `Sync` service exists
but rejects the handshake with `Unimplemented` until TerraBase TS-464. The
binary has no peer-list setting yet; N-node membership is TerraBase TS-469.

On SIGTERM the binary runs ASP.NET Core shutdown: it stops accepting,
drains in-flight requests (default host shutdown timeout 30 s), and exits 0.

## Workload profile

A member is a native workload of role `terrabase`. Its settings come from
the signed controller config `controller.workloads.terrabase`
(`{resources, env}`); every member of the role gets the same `env`. A C#
profile sets no `args`: the binary lets an argument override the host-owned
settings, so the controller rejects them and the host refuses a member with
arguments. When a `terrabase` profile has a non-empty `env`, the controller
validates it at startup and refuses to start when it fails these checks:

| Key | Rule |
| --- | --- |
| `TERRABASE_PEER_PORT` | Required port. |
| `TERRABASE_ADMIN_PORT` | Optional port, default 9464. |
| `TERRABASE_CLIENT_PORT` | Optional port; unset disables the client listener. |
| `TERRABASE_PEERS` | Required. Comma-separated `name=ip:port` for every member of the cell, this one included. `name` is the member host's node name (lowercase letters, digits and `-`, at most 63 characters). IPs must not have zone identifiers or be link-local. Names and addresses are unique, every port equals `TERRABASE_PEER_PORT`, at most 64 entries. |

The admin, peer and client ports must differ. A profile must not set the
host-owned keys `TERRABASE_DATA_DIRECTORY`, `TERRABASE_PEER_CERTIFICATE`,
`TERRABASE_PEER_PRIVATE_KEY`, `TERRABASE_PEER_CLIENT_CA`,
`TERRABASE_CLIENT_CERTIFICATE`, `TERRABASE_CLIENT_PRIVATE_KEY`,
`DOTNET_BUNDLE_EXTRACT_BASE_DIR` or `TERRABASE_NODE_NAME`.
Nor may it set the `TERRABASE_NATS_*` keys the host sets for the member's
NATS identity ([role files](#role-files)). Its `secrets` may name only
secret files: keys ending in `_FILE`, such as
`TERRABASE_BACKUP_SECRET_KEY_FILE` and
`TERRABASE_BACKUP_KMS_PRIVATE_KEY_FILE` for TS-633's backups.

Recommended GRU values: `TERRABASE_PEER_PORT=9443`,
`TERRABASE_CLIENT_PORT=9465`, admin port 9464 (loopback). Cell and host
names follow `<region>-<index>`: cell `gru-1`, members `gru-1-db-1`,
`gru-1-db-2`, `gru-1-db-3`:

```text
TERRABASE_PEERS=gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443,gru-1-db-3=10.251.0.23:9443
```

**`TERRABASE_PEERS` is a PROPOSED setting.** The current binary ignores it as
an unknown variable. TerraBase TS-469 must adopt a `peers` setting with this
`name=ip:port` format, or the orchestrator renames it. The orchestrator uses
it today to decide which hosts may hold a member certificate and which name
and address the certificate carries. The list is static per signed profile:
a membership change needs a signed controller config change and a new
release, and a running member reads it only at start.

## Member CA and certificates

`ts-orch terrabase member-ca --cell gru-1 --out DIR` creates a new directory
`DIR` (0700) with `member-ca.pem` (0644) and the owner-only `member-ca.key`
(0600): an ECDSA P-256 CA valid for 10 years. It refuses an existing `DIR`,
so a CA is never overwritten. The controller config keys
`controller.terrabase_ca_cert_file` and `controller.terrabase_ca_key_file`
point at the two files; the key must be a regular file, not a symlink,
owned and readable only by the controller's user. Without them the
controller refuses every member certificate request, and members never
start. Hosts never see the CA key.

The host agent creates `<terrabase_root>/tls/member.key` (ECDSA P-256, PKCS#8)
once; the key never leaves the host. When the member certificate is missing,
does not match the key, does not chain to `ca.pem`, does not name this
member, or has fewer than 30 days left, the host sends a certificate request
over its authenticated session as host operation `terrabase-peer`. The
controller signs it only when the CSR is a valid ECDSA P-256 request, the
host's registration has role `terrabase` and no `managed_oci` binding, and
the host's current desired for `terrabase` is active, non-managed, valid for
its current registration (including its environment), and has a profile
whose `TERRABASE_PEERS` lists this node. It ignores any names in the
request and issues:

- CN and DNS SAN: the node name; IP SAN: the listed IP;
- EKU serverAuth and clientAuth; validity 90 days, capped at the CA's expiry.

The host writes `member.pem` and `ca.pem` atomically. The same certificate is
the peer listener's server certificate, the client certificate a member
presents to other members, and, when `TERRABASE_CLIENT_PORT` is set, the
client HTTPS certificate; clients trust `member-ca.pem`.

Renewal runs on every poll while the member runs and is best effort: an
error is reported but does not stop the member. The host replaces each file
atomically (write, fsync, rename). A binary with TerraBase TS-464 re-reads
the peer certificate, key and CA on its next TLS handshake after they
change, so peer renewal is live; its client listener still loads its
certificate once, so a member with a client port still restarts once per
renewal. The current release binary loads all of them only at start. Between one and seven days (a fixed offset per node, so a cell's
members do not restart together) before the certificate the member started
with expires, the host completes a TLS handshake with the member's peer
listener, and client listener when set, on loopback, presenting the
member's own certificate. If a listener still serves an expiring
certificate, or the handshake fails, the host restarts the member with a
drain so it loads the renewed one; a member whose listeners already serve
the renewed certificate keeps running. If the stop fails, the host retries
on the next poll. Releases restart members long before
that.

## Host layout and launch

Host config `host.terrabase_root` enables C# members on a host. It must be
absolute, clean, not `/`, and separate from the install and state roots.
Every ancestor must already exist; only the member root may be created.
The root and every ancestor must be real directories, not symlinks, that
the workload identity can traverse but not replace, the workload must not
be able to create entries in the root's parent (sticky or not), and the
path must resolve to itself; the agent checks this at start and again before every
member preparation. It changes the owner and mode of each managed
directory through a descriptor opened with `O_NOFOLLOW`, so a symlink is
never followed.
Use `/srv/ts-managed/terrabase` on the image: the host unit
(`ProtectSystem=strict`) can write only below `/srv/ts-managed`, so another
root needs a unit drop-in. It is a host-local option: a host credential
renewal that rewrites `host.json` keeps it. On such a host a
non-managed `terrabase` desired is launched as a C# member.

| Path | Owner, group, mode | Content |
| --- | --- | --- |
| `<root>` | supervisor, workload group, 0750 | |
| `<root>/tls` | supervisor, workload group, 0750 | `member.key`, `member.pem`, `ca.pem`, each supervisor-owned, workload group, 0440 |
| `<root>/data` | workload user, 0700 | SQLite databases. With `terrabase_data_volume` set, the mount of the member's data volume; see [Data volume](#data-volume). |
| `<root>/bundle` | workload user, 0700 | Extracted native libraries |

The member's environment is the host base environment
(`HOME=/ LANG=C PATH=/usr/bin:/bin`), then the profile `env`, then:

| Variable | Value |
| --- | --- |
| `TERRABASE_DATA_DIRECTORY` | `<root>/data` |
| `DOTNET_BUNDLE_EXTRACT_BASE_DIR` | `<root>/bundle` |
| `TERRABASE_PEER_CERTIFICATE` | `<root>/tls/member.pem` |
| `TERRABASE_PEER_PRIVATE_KEY` | `<root>/tls/member.key` |
| `TERRABASE_PEER_CLIENT_CA` | `<root>/tls/ca.pem` |
| `TERRABASE_CLIENT_CERTIFICATE`, `TERRABASE_CLIENT_PRIVATE_KEY` | The member certificate and key, only when `TERRABASE_CLIENT_PORT` is set |
| `TERRABASE_NODE_NAME` | The host's node, the member's name in `TERRABASE_PEERS`; without it the binary would take the OS hostname (TS-609) |

### Role files

The host keeps a member's secret files and NATS identity in
`<managed runtime root>/roles/terrabase` (`/srv/ts-managed/roles/terrabase`
on the image; supervisor, workload group, 0750). Each file is 0600 and
owned by the workload user, so only the member's process reads it. A
profile secret `KEY_FILE` is written to `key_file` (the key in lower case),
and the member gets `KEY_FILE=<that path>`; the value never enters the
environment. The host reads these secrets from the Vault at every start and
every hour while the member runs; TerraBase reads its backup keys only at
start, so rotating one takes a member restart (a release).

Its NATS identity ([role identities](nats-fabric.md#role-identities)) lets
the member use the KV bucket `terrabase_backup_leases` on the cell's NATS,
which TS-633's backup shipper leases need:

| Variable | Value |
| --- | --- |
| `TERRABASE_NATS_URL` | The host's own NATS servers (`nats.url` of `host.json`) |
| `TERRABASE_NATS_CREDENTIALS_FILE` | `nats.creds`: the member's user JWT and nkey seed |
| `TERRABASE_NATS_CERTIFICATE`, `TERRABASE_NATS_PRIVATE_KEY` | `nats.pem`, `nats.key`: its client certificate for the client port's mutual TLS |
| `TERRABASE_NATS_CA` | `nats-ca.pem`: the cell CA bundle |

The client port is ts-orch's broker bridge: it completes mutual TLS before
any NATS byte, and the server's INFO then says `tls_required=false`. A
client must dial TLS first (NATS.Net `TlsMode.Implicit`, nats.go a TLS
dialer as in `natscell/tls_dialer.go`); a client that waits for INFO before
it upgrades never connects.

Both last 48 hours. The host renews them once half has passed. A running
member re-reads them at every connect and reconnect (terrabase#60), and the
server closes a connection whose JWT expires. The host
sets these variables only while it holds a current identity. A member that
starts without one runs without NATS until its next start. The host
reports why in its running report.

The process runs as the workload user (`terrascale-workload`, uid/gid 2000 on
the image) in its own cgroup under the host agent. There is no per-member
systemd unit: the host agent
([`terrascale-orchestrator-host.service`](../deploy/systemd/terrascale-orchestrator-host.service))
is the supervisor, and the member's stdout and stderr go to that unit's
journal.

### Data volume

Host config `host.terrabase_data_volume: true` keeps `<root>/data` on the
member's OCI block volume. It requires `terrabase_root` and
`host.terrabase_data_volume_id`, the recorded volume OCID. The operator
sets the same `terrabase_data_volume_id` in the trusted host registration.
These host-local options survive credential renewal. Without the option, `<root>/data` is
a directory on the boot disk and does not survive replacement of the host.

**OCI side.** `oci.MemberVolumes`
([`member_volume.go`](../internal/oci/member_volume.go)) manages one volume
per member, named `<member>-data` (for example `gru-1-db-1-data`).
`Ensure(ctx, oci.MemberVolumeRequest{Member, InstanceID, SizeGB, VolumeID})`:

- creates the volume once, in the member compartment and availability
  domain with the plan's VPUs per GB, tagged like the fleet's retained
  volumes (create key = volume name, owner = cell name, generation 1), and
  waits until it is AVAILABLE. It creates a volume only while no volume of
  that name exists outside the retired set and `VolumeID` is empty. A new
  member using a retired name gets a fresh volume; its retry token includes
  the sorted retired volume IDs, so a retry cannot resurrect the old volume;
- assigns the cell's backup policy (see [Backups](#backups)) before the
  attach;
- attaches it paravirtualized, read-write, not shareable, with in-transit
  encryption, at the fixed device `/dev/oracleoci/oraclevdb`, to the
  RUNNING instance whose display name is the member. The instance must have
  consistent volume naming.

`VolumeID` is the member's recorded volume, plan.json
`resource_ids.data_volumes.<slot>`. Once it is recorded, `Ensure` never
creates a volume: a missing recorded volume fails with an instruction to
restore it from a backup, and a volume of that name with another ID fails
with `ErrForeignResource`. Callers record the returned `VolumeID` after the
first `Ensure`.

`Ensure` is idempotent. It refuses a volume attached (any state but
DETACHED) to another instance with `ErrRetainedVolumeInUse` and never
detaches it. OCI detaches the volume when that instance terminates; `Ensure`
then attaches the same volume to the replacement instead of creating a new
one. A TERMINATED or FAULTY volume of the member fails closed; no empty
volume replaces it. `Resize(ctx, member, recordedID, sizeGB)` checks the
recorded OCID before growing online under the volume's ETag.
`NewOperatorMemberVolumes` uses the operator's
`~/.oci/config` DEFAULT profile. There is no controller journal or
authority fence: this is the operator and autoscaler path. The operator
commands are `ts-orch terrabase data-volume`, `restore-volume` and
`restore-check`; see
[TerraBase deployment](terrabase-deployment.md#gru-1-live-deployment-runbook)
and its [restore drill](terrabase-deployment.md#restore-drill).

**Host side**
([`terrabase_volume.go`](../internal/host/terrabase_volume.go)). With the
option set, the agent does not create `<root>/data`. It asks the root
volume initializer (`terrascale-orchestrator-host-volume-init`, socket
activated) to mount the volume, and launches the member only after it has
verified that `<root>/data` is the only mount of `/dev/oracleoci/oraclevdb`,
ext4, hardened (`nosuid,nodev,noexec,noatime`), owned by the workload user
and group with mode 0700. If the volume is missing or cannot be mounted,
the member stays stopped and the host reports the error; it never falls
back to the boot disk. Before the first launch on a filesystem the agent
also records it with the controller (below): a filesystem other than the
one recorded for the member is refused, also when it replaces a confirmed
one. Every reconcile first checks, locally and before any controller
request or remount, that the data directory is still the verified mount of
the confirmed filesystem; otherwise it stops the member, also when the
runner cannot observe it, and goes no further while a stop fails. The
generation-update path fences again immediately before volume preparation,
after fetching the artifact. A failed stop prevents repair. The running
report checks again before and after preparation, whose
maintenance request is bounded to 2 minutes, and a launch checks once more
right before the process starts. A stopped member stays reported `failed`
until the mount verifies again. The empty boot-disk directory under the
mount is root-owned with mode 0700, so after any unmount the workload
cannot create a file there. The initializer:

- rejects the boot disk and its partitions;
- mounts an existing ext4 filesystem;
- formats only a device with no filesystem signature whose sampled blocks
  are all zero, and only with the member's first-format grant (below),
  through the managed initializer's ordered effects: it consumes the grant
  durably first, then runs `mkfs.ext4` and mounts only a filesystem that
  reads back the granted UUID. It refuses anything else;
- refuses to mount over a non-empty `<root>/data`, whose boot disk files
  would be hidden, and makes the empty mount point root-owned 0700;
- gives the mounted root to the workload user and group with mode 0700;
- records `UUID=<uuid> <root>/data ext4 nosuid,nodev,noexec,noatime,errors=remount-ro,nofail,x-systemd.device-timeout=30s,x-systemd.before=terrascale-orchestrator-host.service 0 2`
  in `/etc/fstab`, replacing any previous entry for that mount point, so
  systemd mounts it at boot before the host agent starts. `nofail` lets a
  boot without the volume continue; the agent then keeps the member
  stopped;
- grows the filesystem online after an OCI resize.

The unit's bounding set is `CAP_SYS_ADMIN CAP_CHOWN CAP_SYS_RESOURCE
CAP_DAC_READ_SEARCH`: `CAP_DAC_READ_SEARCH` opens the workload-owned 0700
volume root for the ownership check and online growth, and
`CAP_SYS_RESOURCE` allows `EXT4_IOC_RESIZE_FS`. The initializer has no
`CAP_FOWNER`, so it takes the root back, sets the mode and hands it to the
workload last. The host agent prepares its workload-owned directories
(`<root>/bundle`, and `<root>/data` without the option) the same way: it
has `CAP_CHOWN` but not `CAP_FOWNER`.

While the mount is verified, the agent asks the initializer again at most
every 10 minutes for this maintenance, so a filesystem grows within about
10 minutes of a resize. ext4's `lost+found` appears inside the data
directory.

**First-format grant.** A blank device is formatted only once per registered volume,
with the controller's grant:

1. The initializer finds the device blank and unconsumed. Before any
   controller request, it creates and syncs a random attempt ID in
   `/var/lib/terrascale-orchestrator-volume-init/terrabase-data-format-<SHA-256(volume OCID)>-attempt`.
   It reuses that ID across restarts and answers the agent with result
   byte 2 followed by the 32-byte hexadecimal ID. It formats nothing.
2. Only then the agent sends host operation `terrabase-format` to the leader
   controller, naming the registered volume OCID and initializer attempt. The controller rejects
   requests naming a different OCID and records
   a canonical ULID key derived from cell, node and volume OCID =
   `{"uuid":...,"attempt_id":...,"host_key":...,"generation":...}` in
   the host state KV (`TS_HOST_STATE`) before it answers `Granted=true`.
   Retries from that exact attempt, host key and registration generation
   receive the same UUID in a fresh signed envelope. A lost response or an
   expired envelope therefore does not allocate or consume another grant.
3. The agent passes the controller-signed reply to the initializer. The
   initializer verifies the signature, operation, node, configured volume OCID,
   exact locally recorded attempt ID and its
   freshness (10 seconds), writes and syncs
   `/var/lib/terrascale-orchestrator-volume-init/terrabase-data-format-<SHA-256(volume OCID)>`,
   and only then runs `mkfs.ext4` with that UUID. A host with that marker
   never formats that volume again, so a replayed grant holds.

A host that mounts an existing filesystem sends `terrabase-format` with its
mounted UUID. Initial adoption records a closed grant immediately; confirmation
of an issued grant's exact recorded UUID clears its pending attempt under CAS. Later requests receive
the recorded UUID with `Granted=false`. UUID-only legacy records also stay
closed: their consumption history is uncertain.

A crash before the consumption marker is written can retry the original
attempt, including after a lost controller response or agent/helper restart.
A crash after the marker is written holds a blank device, even if `mkfs` never
finished. The initializer refuses it before requesting another grant. A
replacement host or missing/replaced initializer journal has a different attempt
and cannot recover the original grant, even with copied host credentials. A
previously issued envelope also fails its local attempt check on that host.
Preserve the complete initializer journal, including consumption markers;
never copy an attempt file alone or delete either the journal or controller
record to regain format authority.

Ambiguous or consumed blank volumes require operator investigation; restore
existing data from a backup when necessary. Restored backups keep the recorded
UUID. Grant records are retained. A new member after scale-in has a new
registered volume OCID, so it gets a separate one-time grant; changing the host
key alone never resets a volume's grant.

### Backups

Every member data volume carries the cell's OCI volume backup policy
`<cell>-db-data` (for example `gru-1-db-data`), assigned before the volume
is attached. Its schedules are `oci.MemberBackupSchedules`, in UTC:

| Type | Period | Time | Kept |
| --- | --- | --- | --- |
| INCREMENTAL | daily | 03:00 | 7 days |
| FULL | weekly | Sunday 04:00 | 28 days |

OCI runs the policy; no orchestrator process takes these backups. `Ensure`
creates the policy once, tagged as owned by the cell. It refuses, with
`ErrForeignResource`, a volume that carries another policy and a policy of
that name with other schedules or tags, instead of changing them. These are
crash-consistent volume backups; SQLite's WAL makes them restorable, and the
[restore drill](terrabase-deployment.md#restore-drill) proves one.

The controller's [placement backup runner](storage.md#fixed-storage-policy)
(`internal/storage/backup`) is not used for static C# member volumes: it needs the controller leader,
placement and a single count-based cadence. The OCI provider seam in
[`volume_backup.go`](../internal/oci/volume_backup.go) is reused.
Incremental backups bill changed blocks; the plan's budget allows
`snapshot_gb_max` 350.

**Restore.** `MemberVolumes.Restore`
([`member_volume_restore.go`](../internal/oci/member_volume_restore.go))
restores the newest AVAILABLE backup of the member's volume, or a named
one, into a new volume `restore-<member>-data`. The backup must be of the
member's current volume or of its recorded volume (`SourceVolumeID`,
plan.json `resource_ids.data_volumes`); when the volume is gone, the
recorded ID is required. That volume has its own create key, resource tag
`member-data-restore` and no backup policy. It is attached at
`oci.RestoreVolumeDevice` (`/dev/oracleoci/oraclevdz`), a device no member
volume uses, only to a RUNNING scratch instance in the cell's compartment
and availability domain, with consistent volume naming, that is not named
as a member and holds no other volume; the attachments are read back
before and after the attach. A rerun for the same member and backup reuses
the restored volume. Record its output `volume_id` and pass that exact OCID
as `--restored-volume` to `ts-orch terrabase restore-check`
([`restore_check.go`](../internal/terrabase/restore_check.go)) then mounts
it on the scratch host, never formatting it, starts the release binary on
it as a single member and reads one document. It mounts only
`/dev/oracleoci/oraclevdz`, only on the instance whose OCID instance
metadata reports as `--scratch-instance`, refuses a host with
`/etc/terrascale-orchestrator/host.json`, a partition, the boot disk and
any mounted device, and mounts the device descriptor it checked. Before
mounting, `VerifyRestoredAttachment` re-reads OCI and requires exactly that
OCID at the restore device, its restore resource and scope tags, and
AVAILABLE state. A swapped volume fails before any database read.
The binary and HTTP verification run in a network namespace containing
only loopback, so the client listener cannot expose restored data to the
scratch host's network. Readiness defaults to client HTTPS `/readyz`; the
document read remains the restore proof.

**Autoscaler integration.** After the cell autoscaler (PR #150,
`internal/cellscale`) launches node `<cell>-db-N`, it calls
`oci.NewOperatorMemberVolumes(...)` once and
`volumes.Ensure(ctx, oci.MemberVolumeRequest{Member: name, InstanceID: instance.ID, SizeGB: sizeGB})`.
It must record the returned `VolumeID`, bind it in the host registration
and `host.json`, and pass it as `VolumeID` on later calls. Its launch must set `LaunchOptions.IsConsistentVolumeNamingEnabled`
to true: OCI defaults it to false, and `Ensure` rejects such instances.
On scale-in, after the node has drained and before terminating its host,
call `volumes.Retire(ctx, oci.MemberVolumeRequest{Member: name,
InstanceID: instance.ID, VolumeID: recordedID})`. It detaches only that
instance's exact recorded volume, marks it retired with node name and time,
and retains it. A failure holds scale-in. Retain its OCID in the retirement
record and clear the active member's volume ID only after retirement
succeeds. A new member with the same name calls `Ensure` without an active
recorded ID and receives a fresh volume and first-format grant. Host
replacement passes the existing ID and reattaches the existing volume.
Retired volumes are never automatically deleted; deletion requires a
separate explicit user-confirmed action. `internal/cellscale` is not edited
here; these hooks are its integration contract.

## Readiness

After launch the host reports the member `starting`. On every poll (5 s by
default) it calls `GET http://127.0.0.1:<admin-port>/healthz` and, when the
profile sets a client port, `GET https://127.0.0.1:<client-port>/readyz`
over TLS verified against the member CA under the member's peer address
(TS-571). It reports `running` only when `/healthz` answers 200 with
`{"status":"ok"}` and `/readyz` answers 200: the path the public load
balancer checks. A member that stops answering either goes back to
`starting` with the probe error. A member
whose process exits is reported `failed` once and relaunched on the next
poll, so a release that crashes after start fails its gate at once.
`operator terrabase-release` counts only `running` as ready.
`/readyz` claims serving; once TerraBase TS-561 makes it wait for
replication catch-up, `running` also means caught up.

## Stop and drain

Stopping or replacing a C# member sends SIGTERM through a pidfd and waits up
to 45 s for its cgroup to empty, then kills the cgroup. The host unit's
`TimeoutStopSec=90s` leaves room for it. Session loss, agent shutdown and
agent restart recovery still kill the cgroup at once: workloads must stop before the host lease
reserve runs out. The drain is not a durable drain receipt.

## Qualification

T0 unit tests in [`internal/terrabase`](../internal/terrabase) cover profile
and peer parsing, the host-owned environment, release verification, CA and
member certificate issue and renewal checks, and the health probe.
`TestTerraBaseReleaseGateWithFakeMember` (`internal/app`, T0) runs
`operator terrabase-release` against an in-process controller and host agent
with an in-process stand-in for the binary that serves `/healthz` only when
the host prepared its data directory and a member certificate chaining to
the cell CA: deploy, upgrade, and a release that crashes after start, which
fails the gate at once and is rolled back in place.
`TestTerraBasePlacementKeepsMembersOnListedHosts` checks that members are
placed only on listed hosts and replaced in place. In `internal/host`,
`TestTerraBaseMemberRestartsBeforeLoadedCertificateExpires` (against a TLS
listener serving the renewed or the expiring certificate),
`TestTerraBaseExitReportedOnceBeforeRelaunch`,
`TestTerraBasePeerCertificateFollowsCurrentRegistration`,
`TestTerraBaseRootMustBeSeparate` and `TestTerraBaseMemberRefusesArguments`
cover the certificate restart, exit reporting, certificate signing against
the current registration, root validation and argument refusal. In
`internal/app`, `TestTerraBaseReleaseStateRules`,
`TestTerraBaseProfileRejectsArguments` and the broken-stdout step of the
fake-member test cover the gate's state rules, profile arguments and
output errors. `TestNativeDrainSendsTermBeforeKill`
(`internal/host`) checks the cgroup runner's SIGTERM drain and its kill after
the timeout; like the other native runner tests it needs root and a
delegated cgroup and skips otherwise.

The data volume has fake-OCI and pure-function T0 tests; none ran on OCI.
In `internal/oci`, `TestMemberVolumeCreatesAndAttachesOnceIdempotently`,
`TestMemberVolumeLostCreateResponseReplaysOneVolume`,
`TestMemberVolumeReattachesSameVolumeAfterHostReplacement`,
`TestMemberVolumeRefusesToStealLiveAttachment`,
`TestMemberVolumeFailsClosedOnTerminatedVolume`,
`TestMemberVolumeRejectsInstancesAndNamesOutsideTheMember`,
`TestMemberVolumeHoldsWhenDeviceIsBusy`,
`TestMemberVolumeResizeGrowsOnlyUnderETag`,
`TestMemberVolumeDuplicateCreateKeyHolds`,
`TestMemberVolumeRecordedVolumeIsNeverRecreated`,
`TestMemberVolumeCarriesTheCellBackupPolicy` and
`TestMemberVolumeRestoreDrill`. In `internal/terrabase`,
`TestDataVolumeDryRunSizesFromThePlan`,
`TestDataVolumeRejectsUnplannedMembersAndAmbiguousFlags`,
`TestRestoreVolumeDryRunMakesNoOCICall`,
`TestRestoreCheckPlanWithoutApply`, `TestRestoreCheckRejectsBadFlags`,
`TestRestoreCheckEnvHasOnlyHostPathsAndNoPeers`,
`TestVerifyRestoreReadsTheDocumentWithAReadOnlyKey` and
`TestRestoreCheckRefusesLiveDevices`,
`TestRestoreCheckRunsOnlyOnTheVerifiedScratchInstance`; in `internal/storage/hostvolume`,
`TestBlockDeviceMountedMatchesExactDevice`. In
`internal/host` (Linux), `TestTerraBaseDataVolumeNeverFormatsExistingData`,
`TestTerraBaseDataVolumeFstab`, `TestTerraBaseDataVolumeWriteFstab`,
`TestTerraBaseDataVolumeEmptyMountTarget`,
`TestTerraBaseDataVolumeFilesystemUUID`,
`TestTerraBaseDataVolumeExchangeFraming`,
`TestTerraBaseDataVolumeAgentFailsClosed`,
`TestTerraBaseDataVolumeNeedsTerraBaseRoot`,
`TestTerraBaseDataVolumeFirstFormatIsGrantedOnce`,
`TestTerraBaseDataVolumeFormatGrantVerification`,
`TestTerraBaseDataVolumeAsksForGrantOnlyWhenBlank`,
`TestTerraBaseDataVolumeEffectsFormatOnlyWithAnUnspentGrant`,
`TestTerraBaseDataVolumeAdoptedFilesystemIsRecorded`,
`TestTerraBaseDataVolumeLossStopsTheRunningMember`,
`TestTerraBaseDataVolumeFilesystemSwapIsRefused`,
`TestTerraBaseDataVolumeFenceStopsBeforeRepair`,
`TestTerraBaseDataVolumeReadsTheSuperblockUUID`,
`TestTerraBaseDataVolumeFenceFailsClosed`,
`TestTerraBaseDataVolumeLostDuringMaintenanceStopsTheMember`,
`TestEnsureOwnedDirWithoutFowner` and
`TestTerraBaseDataVolumeRootWithInitializerCapabilities`. The last two run
with exactly the host agent's and the initializer unit's capabilities, the
second also taking back a workload-owned mount point; they need root and
skip otherwise, and passed as root locally, as did the root-only part of
`TestTerraBaseDataVolumeEmptyMountTarget`.

Two T2 tests run the real binary. They skip unless `TS_TERRABASE_BINARY`
names a `terrabase-linux-<arch>` asset with its `.sha256` file beside it:

- `TestTerraBaseBinaryPeerMesh` (`internal/terrabase`): three members on
  local ports, configured only through the host's environment contract. The
  mutual-TLS mesh accepts orchestrator-issued peer certificates and rejects
  foreign-CA and certificate-less clients; SIGTERM drains and exits 0.
- `TestTerraBaseReleaseDeployUpgradeRollback` (`internal/app`): an
  in-process controller and host agent with the real binary: deploy,
  readiness, upgrade to a second digest, and a broken release rolled back
  automatically.

Run them with `make terrabase-release-process TERRABASE_BINARY=<path>`, or
as the `terrabase-binary` and `terrabase-release` suites of
`scripts/ci/qualify-image.sh`. Both passed locally against the linux-amd64
asset of `ci-641274f7482bcf0ce2ae556af8be162d49e445be-run-13121`: the mesh
members answered `Replication/Sync` with gRPC status 12 (`Unimplemented`)
over mutual TLS, which shows the call reached the service.

`TestLiveOCITerraBaseHostsReadOnly` (`internal/terrabase`) is an opt-in,
read-only check against the real OCI API through the shared client factory
and the operator's `~/.oci/config` DEFAULT profile. With
`TS_OCI_LIVE_COMPARTMENT_ID` set (optional `TS_OCI_LIVE_REGION`,
`TS_OCI_LIVE_HOST_PREFIX`, default `gru-1-db-`, and `TS_OCI_LIVE_PEER_PORT`,
default 9443) it checks that the region offers `VM.Standard.A1.Flex`
(Ampere, 1 OCPU, 6 GB per OCPU), that A1 cores are left, and that an Ubuntu
ARM64 image fits A1. For the running hosts of the prefix it checks the A1
shape, distinct fault domains and that every member's NSGs let the others
reach the peer port, and logs the `TERRABASE_PEERS` value their primary
private IPs give. It only lists and gets. On 2026-10-04 it passed for
`sa-saopaulo-1` (A1 offered, 248 A1 cores available, 17 Ubuntu A1 images;
GRU had no TerraBase hosts during its rebuild), and its host path read the
VNIC and private IP of the running `ts-ops` A1 instance.

Not tested: any live OCI host running a member, ARM64, the cgroup process runner as root with
the real binary (its drain is covered by a root-only runner test), a real
OCI data volume attach, format, mount and resize, a real backup restore
drill, and real replication, which the binary does not implement yet.

## Retired terrabase-rust managed path

Before this contract, TerraBase was the Rust `tb-server`, launched through a
managed-member path: schema-5 placement in `internal/placement`, pinned
member material in `internal/managedmaterial`, retained OCI volumes mounted
by the host, and a native serving proof read through `internal/memberstatus`.
That code remains in the repository with its operator commands, but it
targets the retired binary and must not be used for the C# binary. Git
history keeps the full previous text of this document, including its source
identities and qualification records.
