# Four-VM Firecracker qualification

Run from the repository root on the authorized local lab host:

```sh
python3 tests/firecracker/qualify.py check
python3 tests/firecracker/qualify.py run
```

`check` verifies the exact read-only kernel and Ubuntu ext4 image at
`/tmp/vm-inputs/vmlinux` and `/tmp/vm-inputs/rootfs.ext4`, Firecracker,
`/dev/kvm`, `/dev/net/tun`, and required host commands. It creates no VMs or
network devices. `run` needs passwordless `sudo` for `ip`, `mount`, `umount`,
`install`, and `systemctl`. Options `--kernel`, `--rootfs`, `--firecracker`, and
`--run-dir` select alternate assets or a new evidence directory; asset hashes
must still match. Do not reuse `/tmp/vm-inputs/certs`.

The run builds the current static Go binary, checks that Go source did not
change during the build, creates fresh Ed25519 identities with the actual
`identity-new` CLI, test NKey identities, and per-guest SSH host keys pinned in
the private run's `known_hosts`, then boots three controller/NATS
guests and one host guest (each 1 vCPU, 512 MiB). Each private ext4 copy is
checked with `e2fsck` and grown sparsely to 8 GiB before boot; embedded NATS is capped at 2 GiB and the
artifact store at 64 MiB. A unique bridge and four TAPs
carry only the private `198.19.x.0/24` test subnet. No uplink, NAT, or TCP
Firecracker API listener is created. The operator CLI runs on the lab host and
talks to the guest NATS cluster over that bridge.

The qualification registers the host, uploads and admits a signed executable,
deploys it, and requires an accepted receipt plus a running guest process and
marker. It then reboots the host and verifies recovery, crashes one controller
VMM and deploys a replacement on the surviving quorum, restores that controller,
crashes two controller VMMs and requires the rollback command to be refused
before submission while quorum is absent, restores quorum, and performs an
accepted rollback with guest execution.
An `accepted` receipt is followed by guest observation; receipt alone is not
treated as runtime readiness.
If the one-controller-loss intent is rejected solely because its authority
epoch was fenced before acceptance, the harness records that receipt and makes
one new signed submission with a fresh operation ID. A second rejection fails
the run.

The private run directory defaults to `/tmp/ts-orch-fc-*`. It retains
`summary.json`, `logs/events.json`, build output and VM serial/VMM logs. Events
record the exact guest process IDs and task-owned network names. At the first
failed host report, or on a scenario failure, the harness also saves bounded
read-only host journal, process, cgroup, runner-inventory, workload-marker,
and installed-artifact diagnostics before stopping the VMs. If the one-node-loss
receipt stays pending for 20 seconds, it also saves each live controller's
journal and a read-only JetStream snapshot from direct NKey-authenticated
connections to each controller, plus an operator-style multi-URL connection.
It saves a curated operator host-status snapshot at that point and on host
failure, including session expiry and currentness, capacity, and report state.
The diagnostic uses each identity's permitted reply inbox. It records stream
and controller-consumer leadership, replica activity in nanoseconds, pending
work, lease state, and the active operation's claim and receipt metadata without
dumping guest configuration, raw control-log payloads, or private keys. The harness
stops only its own VMM processes, unmounts its guest copies, deletes only its
own TAPs and bridge, and removes copied images and credentials in a `finally`
cleanup. On cleanup failure it retains images for manual inspection and marks
the run `CLEANUP_FAILED`; those images may contain ephemeral lab credentials.
The original kernel and rootfs are never modified.

## Kernel and runner qualification boundary

Runner and four-VM results apply to the pinned image only: Linux 6.1.155 with
kernel SHA-256
`e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2` and Ubuntu
root filesystem SHA-256
`dd49aee1d9c28f8e781a627bec744db3a961ce4402950130ff9268504c551314`. On this
kernel, the reproduced `cgroup.kill` condition involved `clone3(CLONE_INTO_CGROUP)`
reading the creator cgroup's `kill_seq` before it resolves the destination.
The runner recreates an emptied role cgroup before reuse and seals cgroups
during shutdown or cancellation. A creator or parent cgroup killed and reused
externally remains outside the tested contract. This qualification does not
establish compatibility with arbitrary or custom kernels. The production host
image is operator-provided and unqualified; managed OCI placement stops at
`awaiting-runtime-contract` without starting or verifying a serving TerraBase
process. See [the latest qualification record](../../docs/local-development.md#latest-local-qualification).
