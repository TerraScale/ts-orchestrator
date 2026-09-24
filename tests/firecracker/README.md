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
crashes two controller VMMs and requires a rollback submission to fail without
quorum, restores quorum, and performs an accepted rollback with guest execution.
An `accepted` receipt is followed by guest observation; receipt alone is not
treated as runtime readiness.

The private run directory defaults to `/tmp/ts-orch-fc-*`. It retains
`summary.json`, `logs/events.json`, build output and VM serial/VMM logs. Events
record the exact guest process IDs and task-owned network names. The harness
stops only its own VMM processes, unmounts its guest copies, deletes only its
own TAPs and bridge, and removes copied images and credentials in a `finally`
cleanup. On cleanup failure it retains images for manual inspection and marks
the run `CLEANUP_FAILED`; those images may contain ephemeral lab credentials.
The original kernel and rootfs are never modified.
