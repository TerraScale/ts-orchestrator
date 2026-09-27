# Managed member two-VM qualification

This profile checks one bounded runtime path: two networked Firecracker guests
each mount and claim a separate, preformatted ext4 volume; each guest runs the
real signed host controller, `Agent.Run`, native `processRunner`, and a pinned
TerraBase signed-v2 binary as UID/GID 65534. The driver requests a local,
CA-verified HTTPS transaction on member A and a local, CA-verified point read
on member B. Before the write, the driver requires B's read of the same
fixture-unique document ID to return `state=absent` with no siblings. The
signed generation-1 schema has no fields, so A writes a live document with an
empty field list; after the write, B must return one live empty-field sibling
with the exact signed schema generation and digest. The driver records both
read responses in its evidence. Their replication traffic crosses the private
VM bridge. A
`local_durable` write receipt alone is insufficient: the driver also requires
member B's durable and applied ACK counters to rise and member A's sender lag
gauges to reach zero. The guest test's controller uses an exact test-only
registration verifier, so this result does **not** qualify OCI ownership,
serving proof, drain, scaling, cloud deployment, or multiple regions.

Use an exporter-produced immutable JSON manifest with
`"profile":"managed-member-serving-v1"`, full `source_commits` for
`orchestrator` and `terrabase`, and these exact top-level `inputs`:
`kernel`, `rootfs`, `firecracker`, `go_host_test`, `tb_server`. Each input is
`{"path":"/absolute/direct/file","sha256":"64 lowercase hex digits"}`.
`members` contains exactly `a` and `b`. Each member contains `guest_config`
and exact `inputs` for `volume_ext4`, `authority_tbca`,
`trusted_public_key`, `server_crt`, `server_key`, `client_ca_pem`,
`server_ca_pem`, `client_managed_manifest`, `client_config`, `client_chain`,
`client_private_key`, `client_api_keys`, `client_api_token`, and
`client_https_ca_pem`. The driver checks every input hash before resource
creation and again before boot. Its parser checks that the guest configs pin
the expected member, reciprocal peer address, material hashes, separate
filesystem UUIDs, shared authority, and one document/schema binding.

The fixed private subnet is `10.77.39.0/24`, with the host bridge at `.1`,
member A at `.11`, and member B at `.12`. The driver checks host routes and
addresses for overlap before creating a randomly named bridge or TAP. The
members listen for replication on port `7000` with the signer-exported TLS
names `member-a.terrabase.test` and `member-b.terrabase.test`. HTTPS listens
only on each guest's `127.0.0.1:9465`; a root-owned guest test sends the
authenticated requests. A separate token-gated test endpoint binds each
guest's private bridge IP on port `9540`, accepts only the host bridge IP,
and returns bounded evidence or accepts a finish signal. It is not a
TerraBase client endpoint.

The driver uses two 6-GiB VMs with two vCPUs each. The guest host service
has systemd `MemoryMax=5G`; the signed profile sets 4 GiB of allocatable
capacity, a 1-GiB system reserve, a 4-GiB process limit and role
`memory.max`, and 1-GiB of headroom. Allocatable capacity plus reserve equals
the service limit, leaving 1 GiB of guest memory outside that service cgroup.
The host checks the allocatable-plus-reserve total against physical memory and
every ancestor `memory.max`. The test verifies the process's actual real,
effective, saved and filesystem UID/GID, cgroup membership and `memory.max`
against the signed 4-GiB cap, exact signed claim, filesystem UUID/mount, and
accepted member-control report.

Root-owned material files are installed with GID 65534 and mode `0440` under
each binding-derived material directory. The HTTPS root and raw fixture API
token are separate pinned root-only files, outside TerraBase's managed
material directory.

Build the focused Go test binary from a separate full-copy source snapshot
whose accepted production B files, guest test, and all included package-host
test helpers have a recorded SHA-256 inventory. Do not build from the moving
shared tree: `go test -c` includes the other guest test in the same package.
Coordinate this snapshot with the prepare-only profile owner. Build and pin
the TerraBase binary separately. The exporter writes a disposable two-member
signer packet into a new private directory; its ephemeral signing key is
discarded when the process exits. Supply full source revisions and the
qualified TerraBase source digest from the independent build record:

```sh
# Run inside the pinned, full-copy Go snapshot:
nice -n 10 go test -c -o /path/to/host.test ./internal/host
nice -n 10 go run ./tests/firecracker/managedmember/exporter \
  --output-dir /path/to/new/private-packet-directory \
  --kernel /path/to/pinned/vmlinux \
  --rootfs /path/to/pinned/rootfs.ext4 \
  --firecracker /path/to/pinned/firecracker \
  --go-host-test /path/to/host.test \
  --tb-server /path/to/pinned/tb-server \
  --orchestrator-revision FULL_ORCHESTRATOR_COMMIT \
  --terrabase-revision FULL_TERRABASE_COMMIT \
  --source-digest LOWERCASE_TERRABASE_SOURCE_SHA256 \
  --ephemeral-test-signer
python3 tests/firecracker/managedmember/qualify.py check \
  --manifest /path/to/new/private-packet-directory/managed-member-serving-manifest.json
python3 tests/firecracker/managedmember/qualify.py run \
  --manifest /path/to/new/private-packet-directory/managed-member-serving-manifest.json \
  --run-dir /path/to/new/private-evidence-directory
```

For a retained local authority key, replace `--ephemeral-test-signer` with
`--authority-seed-file /absolute/protected/seed` and
`--authority-public-sha256 LOWERCASE_SHA256_OF_DERIVED_PUBLIC_KEY`. The seed
must be a direct, 32-byte, mode-`0600` regular file owned by root or the
current user. The public-key pin must come from an independent trusted record.
This exporter uses fixed Firecracker identities and guest addresses; it is not
an OCI credential or instance provisioning producer. The source revision and
source digest flags are claims supplied by the caller. Packet hashing does not
prove that a binary was built from those sources; retain the build provenance
record separately.

`check` is read-only. `run` needs a new absolute evidence directory under an
existing parent, KVM, TUN, and passwordless `sudo` for the owned bridge/TAP,
loop mounts, and guest staging. It copies each pinned image privately,
collects bounded command/serial/VMM/Go-test logs and `summary.json`, and
requires both guests to report one explicit non-skipped Go pass and terminal
runner pass before their natural VMM exits. It removes only owned mounts,
links, and sockets after both VMMs stop. Private images remain on failure for
inspection. No VM qualification is implied by a successful build or `check`.
