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

The driver uses two 9-GiB VMs with two vCPUs each. The guest service has an
8-GiB systemd memory limit; the native TerraBase role has a signed 6-GiB
`memory.max`, 4-GiB process limit and 1-GiB headroom. The test verifies the
process's actual real, effective, saved and filesystem UID/GID, cgroup
membership and `memory.max`, exact
signed claim, filesystem UUID/mount, and accepted member-control report.
Root-owned material files are installed with GID 65534 and mode `0440` under
each binding-derived material directory. The HTTPS root and raw fixture API
token are separate pinned root-only files, outside TerraBase's managed
material directory.

Build the focused Go test binary from a separate full-copy source snapshot
whose accepted production B files, guest test, and all included package-host
test helpers have a recorded SHA-256 inventory. Do not build from the moving
shared tree: `go test -c` includes the other guest test in the same package.
Coordinate this snapshot with the prepare-only profile owner, and use the
exporter-produced TerraBase binary and two-member signer packet. The driver
never builds either binary or creates the signer fixture:

```sh
# Run inside the pinned, full-copy Go snapshot:
go test -c -o /path/to/host.test ./internal/host
python3 tests/firecracker/managedmember/qualify.py check \
  --manifest /path/to/managed-member-serving-manifest.json
python3 tests/firecracker/managedmember/qualify.py run \
  --manifest /path/to/managed-member-serving-manifest.json \
  --run-dir /path/to/new/private-evidence-directory
```

`check` is read-only. `run` needs a new absolute evidence directory under an
existing parent, KVM, TUN, and passwordless `sudo` for the owned bridge/TAP,
loop mounts, and guest staging. It copies each pinned image privately,
collects bounded command/serial/VMM/Go-test logs and `summary.json`, and
requires both guests to report one explicit non-skipped Go pass and terminal
runner pass before their natural VMM exits. It removes only owned mounts,
links, and sockets after both VMMs stop. Private images remain on failure for
inspection. No VM qualification is implied by a successful build or `check`.
