# Four-VM Firecracker qualification

## Native member-status qualification

Use the dedicated one-guest driver for the native cgroup recovery and
cross-language member-status tests. It consumes a JSON manifest containing the
orchestrator and TerraBase source commit IDs, the exact Rust test name, and
SHA-256 records for these seven inputs: `kernel`, `rootfs`, `firecracker`,
`go_host_test`, `memberstatus_probe`, `rust_server`, and `rust_test`. Each input
record has the form `{"path":"/absolute/path/to/file","sha256":"64 lowercase hex digits"}`.
The source commit fields are recorded as supplied; the per-file hashes bind the
executed inputs. The driver validates all paths and hashes before creating its
run directory or any VM resources.

Run it with a new durable evidence directory whose parent already exists:

```sh
python3 tests/firecracker/memberstatus/qualify.py \
  --manifest /path/to/member-status-manifest.json \
  --run-dir /home/mariogk/Projects/TerraScale/.qualification/ts-orchestrator/20260926-member-driver/run-01
```

The guest has 6 GiB RAM, two vCPUs, and no network interface. The driver copies
the supplied ext4 image to a private sparse writable image, stages the four
executables and one enabled systemd service, and unmounts that copy before
boot. The service requires systemd 255 or newer and configures root execution,
`Delegate=yes`, `DelegateSubgroup=supervisor`, `MemoryMax=5G`,
`NoNewPrivileges=yes`, an empty ambient capability set, and the
`CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP` bounding set. It runs
`TestNativeTenantReadsFiniteCgroupAccountingAfterRecovery` with verbose output
and a 120-second timeout, then runs the manifest's exact Rust test with
`--exact --nocapture --test-threads=1`. The host accepts a result only when
both test summaries explicitly pass, the nested Go probe reports
`MEMBER_STATUS_GO_OK` and its sender-enabled success marker, and the guest emits
the final `MEMBER_STATUS_QUALIFICATION_RESULT=PASS` sentinel after both tests.
On any runner exit, the guest records one terminal PASS or a FAILED stage and
exit status, then requests poweroff. The guest service has a 270-second start
timeout and the host retains a 300-second shutdown deadline for stuck guests;
completed test failures are reported with their exact stage and status.

The driver does not build Go or Rust artifacts or configure networking. It
keeps command logs, guest serial and VMM logs, collected guest test output,
events, source/input identities, and `summary.json` under `--run-dir`. The
summary is `PASS`, `FAILED`, or `CLEANUP_FAILED`; only `PASS` returns zero. The
source rootfs and executable inputs remain unchanged. The private writable
image is removed only after the VMM is confirmed stopped and the image is
confirmed unmounted; otherwise the image is retained for inspection.

Run from the repository root on the authorized local lab host:

```sh
python3 tests/firecracker/qualify.py check
python3 tests/firecracker/qualify.py run
```

`check` verifies the exact read-only kernel and Ubuntu ext4 image at its
default paths:
`/home/mariogk/Projects/TerraScale/.qualification/ts-orchestrator/20260926-firecracker/inputs/vmlinux-6.1.186`
and
`/home/mariogk/Projects/TerraScale/.qualification/ts-orchestrator/20260926-firecracker/inputs/rootfs-noble-20260911.ext4`.
It also checks Firecracker,
`/dev/kvm`, `/dev/net/tun`, and required host commands. It creates no VMs or
network devices. `run` needs passwordless `sudo` for `ip`, `mount`, `umount`,
`install`, `systemctl`, and `nft`. The host also needs `openssl`, `ss`, and the
pinned Chrony 4.8 binaries named in `qualify.py`. Options
`--kernel`, `--rootfs`, `--firecracker`, and
`--run-dir` select alternate assets or a new evidence directory; asset hashes
must still match. The default evidence directory is temporary under `/tmp`;
pass a new path such as
`/home/mariogk/Projects/TerraScale/.qualification/ts-orchestrator/20260926-firecracker/run-01`
to retain logs and guest-side evidence durably. The harness creates fresh
credentials under each private run directory.
Firecracker API sockets live in a separate short private directory under
`/tmp`, so long durable run paths stay within the Unix socket path limit. The
harness removes that socket directory only after every VMM process group is
quiescent; failed qualifications and cleanup failures retain private guest
images for inspection.

The run builds the current static Go binary, checks that Go source did not
change during the build, creates fresh Ed25519 identities with the actual
`identity-new` CLI, private operator/account/user JWT credentials, a private two-day CA with distinct
P-256 TLS 1.3 client/server certificates for each guest and the operator, a
shared private route password, and per-guest SSH host keys pinned in
the private run's `known_hosts`, then boots three controller/NATS
guests and one host guest (each 1 vCPU, 512 MiB). Each private ext4 copy is
checked with `e2fsck` and grown sparsely to 8 GiB before boot; embedded NATS is capped at 2 GiB and the
artifact store at 64 MiB. A unique bridge and four TAPs
carry only the private `198.19.x.0/24` test subnet. No uplink, NAT, or TCP
Firecracker API listener is created. The operator CLI runs on the lab host and
talks to the guest NATS cluster over that bridge. All NATS clients and
embedded client and route listeners use production mode (`lab: false`), TLS
and mutual certificate verification. Production JWT account and user grants
authorize the regional controllers, operator, and host. A private Chrony server
serves only the run's bridge while selecting a real remote upstream; each guest
uses timesyncd against that bridge before its production kernel-clock predicate
releases the service.
The native fixture runs as dedicated UID/GID 2000 and writes its marker and
PID in a private `/run/ts-orch-workload` directory prepared by the host unit.
The host supervisor remains root with `NoNewPrivileges=yes` and an exact
`CAP_CHOWN CAP_KILL CAP_SETUID CAP_SETGID CAP_SETPCAP` bounding set (mask
`0x1e1`). `CAP_CHOWN` prepares the root-owned, tenant-group-readable admitted
artifact; `CAP_KILL` lets the root supervisor deliver parent-death `SIGKILL`
to its UID 2000 child.
The unit delegates its cgroup subtree; native role cgroups remain beneath the
service cgroup. The qualification binds the observed native role path to the
unit's current `ControlGroup` and its exact `terrascale-host-<16 lowercase hex>/terrabase`
subtree, rejecting traversal and symlinks before checking `cgroup.events`.
The supervisor drops every capability before executing the UID/GID 2000 workload.

The qualification registers the host, uploads and admits a signed executable,
deploys it, and requires an accepted receipt plus a running guest process and
marker. It then reboots the host and verifies recovery. To test 2/3 quorum,
it identifies the host's established controller socket, blackholes only that
host-to-controller NATS flow in a uniquely owned bridge-family `nft` table,
crashes the connected controller, and requires a post-fault renewal event emitted
only after the host verifies the signed controller response, a current report
bound to that session, and unchanged host agent and native workload process
identities. It deploys a replacement on the surviving quorum and restores the
controller. The post-quorum renewal check has a 25-second deadline; each
operator `hosts` attempt is capped at five seconds and the remaining deadline.
Failed operator attempts record their stage, elapsed time, and bounded stderr.
Guest renewal events captured after a timeout are diagnostic only; they cannot
replace a successful operator status read or the matching process and lease
checks. The `host.session_trace` option emits the verified lease epoch,
expiry, and a 128-bit hash of the session ID for this qualification. To test
1/3 quorum, it blackholes the host's newly connected controller socket,
matches the latest durable session expiry to that verified lease event, then
crashes the connected controller and
one other controller, requires the native process to stop and its cgroup to
empty before the original signed session expiry, checks that it stays stopped,
and requires the rollback command to be refused before submission. It then
restores quorum and performs an accepted rollback with guest execution.
The five-second execution reserve is the agent's fence threshold; shutdown can
complete during that reserve and must complete before signed expiry. Events
record the fault time, expected fence threshold, actual post-cancellation
fence-start event, first failed renewal observed in the guest journal, and a
conservative process/cgroup stop observation.
On every boot, the guest service waits on a root-owned `/run` marker until
timesyncd reports NTP synchronization, the test-only clockprobe passes the exact
production `KernelClockProbe.Measure()` predicate, and the measured guest clock
offset plus SSH uncertainty is within one second. The marker disappears on reboot.
After cluster readiness, the harness keeps a JWT-authenticated read connection
pinned to c1, deliberately jumps c1's clock while timesyncd is stopped, requires
the kernel predicate to fail, observes the existing connection close, and rejects
fresh admission. It restarts timesyncd and requires genuine resynchronization
before testing admission recovery. This fault step occurs after service start;
startup never manually sets the guest clock.
Guest clocks are checked again before the 1/3 fault; later drift and SSH
observation latency limit subsecond timing claims. The stop deadline subtracts
the measured upper bound of host clock
offset plus 250 ms from the signed expiry. The operator's read-only `hosts`
view has `Verified: false`; its
session and report binding is cross-checked against the host's post-verification
event before using the expiry as the safety deadline.
An `accepted` receipt is followed by guest observation; receipt alone is not
treated as runtime readiness.
If the one-controller-loss intent is rejected solely because its authority
epoch was fenced before acceptance, the harness records that receipt and makes
one new signed submission with a fresh operation ID. A second rejection fails
the run.

The private run directory defaults to `/tmp/ts-orch-fc-*`. It retains
`summary.json`, `logs/events.json`, build output and VM serial/VMM logs. The
summary includes the Git revision, Go source manifest hash, harness manifest
hash, and final hashes so a run against a moving shared tree fails. Events
record the exact guest process IDs and task-owned network names. At the first
failed host report, or on a scenario failure, the harness also saves bounded
read-only host journal, process, cgroup, runner-inventory, workload-marker,
and installed-artifact diagnostics before stopping the VMs. If the one-node-loss
receipt stays pending for 20 seconds, it also saves each live controller's
journal and a read-only JetStream snapshot from direct JWT-authenticated
connections to each controller, plus an operator-style multi-URL connection.
It saves a curated operator host-status snapshot at that point and on host
failure, including session expiry and currentness, capacity, report state,
and a 128-bit session ID hash.
The diagnostic uses each identity's permitted reply inbox. It records stream
and controller-consumer leadership, replica activity in nanoseconds, pending
work, lease state, and the active operation's claim and receipt metadata without
dumping guest configuration, raw control-log payloads, or private keys. The harness
deletes only its uniquely named `nft` table, stops only its own VMM processes,
unmounts its guest copies, deletes only its own TAPs and bridge, and removes
copied images and credentials in a `finally`
cleanup. On cleanup failure it retains images for manual inspection and marks
the run `CLEANUP_FAILED`; those images may contain ephemeral lab credentials.
The original kernel and rootfs are never modified.

## Kernel and runner qualification boundary

The latest recorded four-VM results apply to the older pinned image only: Linux
6.1.155 with kernel SHA-256
`e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2` and Ubuntu
root filesystem SHA-256
`dd49aee1d9c28f8e781a627bec744db3a961ce4402950130ff9268504c551314`. The
current harness defaults to Linux 6.1.186 with kernel SHA-256
`586a02db8ea1fd331d45efa6ebf502fff21ceddfedf010ef70ba389b8e095523` and Ubuntu
root filesystem SHA-256
`a6c1cb9c712d8bb9e67b05dd8f46b7e88827250b445e76015e6bb536a15e1af6`; the older
qualification results below do not apply to those newer inputs. On the 6.1.155
kernel, the reproduced `cgroup.kill` condition involved `clone3(CLONE_INTO_CGROUP)`
reading the creator cgroup's `kill_seq` before it resolves the destination.
The runner recreates an emptied role cgroup before reuse and seals cgroups
during shutdown or cancellation. A creator or parent cgroup killed and reused
externally remains outside the tested contract. This qualification does not
establish compatibility with arbitrary or custom kernels. The production host
image is operator-provided and unqualified; managed OCI placement stops at
`awaiting-runtime-contract` without starting or verifying a serving TerraBase
process. See [the latest qualification record](../../docs/local-development.md#latest-local-qualification).
