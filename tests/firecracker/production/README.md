# Offline production restart qualification

`qualify.py` prepares three disposable ext4 images for `controller-a`,
`controller-b`, and `seed-a`. It runs the shipped single orchestrator binary
through the packaged bootstrap and controller systemd units. The default
invocation stops after image staging; `--run` starts the private Firecracker
network and VMs. The first local simulated-OCI run booted all three VMs and
reached SSH, but controller-a never met production health. Its simulator audit
had no OCI requests and no restart pass was recorded. The precise failed
health stage was not captured; the driver now names that stage on failure.
The run's source-guard record was timestamped after VMM startup, so it does
not independently prove the source bytes present at launch.

The signed packet must be emitted immediately before a run: verification
requires the trusted host clock to be within five minutes of its fixture
clock. `fixturegen production-preflight` checks the packet signature, complete
source inventory, signed image receipt and exact executable, three
production-mode controller configs, service credential digests, guest CA,
host-only HTTPS server key, per-slot IMDS identities, and exact network and
time files. The separate external root certificate is never copied to a VM.
See [fixturegen/RECIPE.md](fixturegen/RECIPE.md) for packet construction.

The driver requires a pinned ext4 base image built with the shipped systemd
units, `systemd-timesyncd`, `systemd-time-wait-sync`, `systemd-networkd`,
`update-ca-certificates`, and an enabled SSH service. The image must already
contain a root SSH authorized key and host key; its SHA-256 pins those bytes.
Supply the matching private client key and a strict known-hosts file with
entries for `10.44.0.10`, `.11`, and `.12`. Each of the kernel, base image,
Firecracker binary, host fixturegen binary, SSH key, known-hosts file and
trusted root PEM needs an independent SHA-256 argument. The image receipt
binds the orchestrator binary, not the local Firecracker ext4 base image.
The driver refuses an overlapping `10.44.0.0/24` route or address and refuses
an existing `169.254.169.254` address.

Example, with paths and hashes replaced by reviewed artifacts:

```sh
python3 tests/firecracker/production/qualify.py \
  --packet /path/to/signed-packet --root-cert /path/to/root.pem \
  --root-cert-sha256 HASH --source-root /path/to/frozen-source \
  --image-ocid ocid1.image.oc1.sa-saopaulo-1.EXAMPLE \
  --rootfs /path/to/base.ext4 --rootfs-sha256 HASH \
  --kernel /path/to/vmlinux --kernel-sha256 HASH \
  --firecracker /path/to/firecracker --firecracker-sha256 HASH \
  --fixturegen /path/to/fixturegen --fixturegen-sha256 HASH \
  --ssh-key /path/to/client-key --ssh-key-sha256 HASH \
  --known-hosts /path/to/known_hosts --known-hosts-sha256 HASH
```

The prepare step copies the pinned image before resizing it, mounts each
copy, and calls `fixturegen stage`. Staging checks that the destination is an
exact ext4 mount point, not `/` or a host directory. It checks the real
numeric service UID/GID against the packet before chowning, compares the
installed sysusers policy and packaged systemd units with source pins, installs
only signed guest files, refreshes the **guest** system CA bundle, and runs
the shipped binary's production credential check under the service account.
It then verifies that networkd, timesyncd, time-wait-sync, SSH and the
controller unit are enabled. The host trust store is untouched.

Add `--run` to perform the VM qualification. After checking host routes and
host NTP, the driver enters a private network namespace. Its bridge, taps,
firewall, NTP server, OCI simulator, VMMs, and SSH client remain inside that
namespace, so the host's separate INPUT firewall cannot discard guest
requests after the fixture firewall accepts them. The driver drops all
forwarding except signed peer NATS
ports, and allows only the per-slot packet-backed IMDS/OCI HTTPS simulator
and the bridge NTP service. It requires the host clock to be NTP synchronized
before serving NTP to the guests. It starts all three VMs, checks guest NTP
health and the two packaged units, checks the controller process's four
UID/GID values, then reboots each VM in turn and requires a new boot ID and
controller invocation. It stops the VMs before collecting the simulator's
request audit. A pass requires zero unlisted or write requests, no simulator
overflow or unknown sources, expected IMDS/federation/Compute/ledger reads,
NTP replies for every VM, and zero unexpected firewall drops. The driver
removes owned processes, mounts, links and nft tables on every exit and writes
`report.json` and logs in its private run directory. Even on failure, the
report records per-slot NTP requests and replies and saves counters from only
its owned firewall tables before deleting them.

`simulator.go` has no OCI client or upstream proxy. It permits exactly six
fixed IMDS GETs, a signed `POST /v1/x509` on the pinned GRU Auth host, and
fixture-listed exact Compute or Object Storage GETs on the pinned GRU hosts.
An expected missing object gets a 404 only after service-signature
verification. Unlisted routes and all OCI writes fail and enter the audit.
The federation session is bound to the packet's instance certificate and a
new RSA session public key. Request logs redact unlisted URI details and
contain no private key, federation body, JWT or signature header.

The offline tests are `go test ./tests/firecracker/production/...`,
`go test -tags fixturetest ./tests/firecracker/production/fixturegen`, and
`python3 tests/firecracker/production/test_qualify.py`. They exercise packet,
SDK, simulator and driver contracts. They do not prove a VM restart until a
reviewed production packet and image are supplied and `--run` completes.
