# Stage a disposable Source renewal VM

This test-only harness uses `internal/qualification/firecracker.Start/Process`
to own a single rootless QEMU process group. Its initramfs contains explicit
SHA256-pinned runtime files, the compiled APP test executable and a static
guest PID 1. It uses no host loop, mount, sudo, cgroup, NIC, shared filesystem,
home directory, physical disk, cloud service or downloaded workload. All ext4,
loop, cgroup, IMDS and containerd effects occur inside the disposable guest.

**HOLD:** source only. Compilation, staging-tool execution and VM boot need
the corresponding exact QA grants. The complete APP owner supplies the actual
successfully compiled test executable; this branch does not repair or retry
the failed 697 source composition. No executable/image built by this harness
has been qualified.

## Inputs and source builds

The future QA request must pin a source freeze and two build outputs:

1. Host command: `./tests/source_renewal_vm` (linux/amd64).
2. Static guest init: `CGO_ENABLED=0`, `./tests/source_renewal_vm/guest`
   (linux/amd64).
3. Complete APP's actual `go test -c` output with default vet.

Builds use the pinned toolchain, readonly modules and the QA CPU/time envelope.
No build command is authorized by this document. No production dependency,
production command wiring or module change is needed.

`stage MANIFEST NEW_DIRECTORY` accepts a JSON object matching `manifest` in
main.go. Kernel/QEMU/Env/Nice/TestBinary/GuestInit each contain an absolute
`path` and `sha256`. Files are explicit Nix-store regular-file sources with
`path`, `sha256`, `guest` and numeric permission `mode`; Links contain Guest
and Target. Modules use the same file format and are loaded in the supplied
dependency order. SudoPluginDirectory and PAMDirectory are guest Nix paths.
The host helper does not query Nix, realize packages, download files, run ldd,
or execute any input while staging.

Generate and review the exact file/symlink manifest from the read-only
`nix-store -qR` closure of the selected installed tool roots. Include sudo's
dlopened sudoers/PAM modules and configurations in that closure, not only
ELF DT_NEEDED entries. Preserve Nix symlinks, their immutable targets and every
ELF interpreter/library at its original Nix path. No source file from a host
home or `/etc` is copied into the guest. Only the test/init build outputs may
come from outside the Nix store. passwd/group/hosts/sudoers/PAM configuration
is generated specifically for the guest; there are no user secrets.

Required executable aliases are `/bin/env`, `/bin/nice`, `/bin/unshare`,
`/bin/sudo` (the actual store binary, not the host security wrapper), `/bin/ip`,
`/bin/containerd`, `/bin/containerd-shim-runc-v2`, `/bin/runc`, `/bin/losetup`,
`/bin/blkid`, `/usr/sbin/mkfs.ext4`, and `/sbin/kmod`. The installed host has
no `/usr/sbin/mkfs.ext4`; the guest alias must point to the pinned real Nix
e2fsprogs executable. Tool argv0 is significant for multicall binaries.

For Linux 7.2.10, the minimum observed load order for the unchanged guest-loop
fixture is crc16, mbcache, jbd2, ext4, overlay and loop. Copy the matching
`.ko.xz` files and real kmod decompressor closure; never run host modprobe.
Kernel config and complete runtime module needs still require source review.
The archive writes UID/GID 0 directly in newc headers and includes a guest
console device entry, so host chown, mknod and loop mounts are unnecessary.

The existing fixture's `renewalMemberImage` searches standard library
directories. Supply explicit standard-directory aliases for the test ELF's
actual dependencies. The fixture retains each library at both the discovered
alias and its canonical Nix destination inside the nested OCI image. The
compiled test executable is copied unchanged; no patchelf rewriting is used.

## Guest behavior and current clock prerequisite

PID 1 mounts guest proc, sysfs, devtmpfs, devpts, /run and a 2 GiB /tmp. It
loads only manifest-listed modules, creates the guest UUID directory, mounts
cgroup2 and enables cpu/memory/pids only in the guest hierarchy. The actual
runtime retains `/terrascale/ts-<task-id>`, a 4 GiB workload memory limit,
zero swap and pids 256. Root's guest-local cgroup changes affect no host state.

It invokes `/qa/app.test` for exactly
`^TestSourceBackupRenewalIntegration$`, count 1, parallel 1, timeout 205 s,
GOMAXPROCS=2 and nice 19. The fixture's actual root child keeps its own 180 s
timeout, sudo/env/unshare path and fixed-address IMDS setup. No child dispatch
marker is injected by PID 1. The original 32 MiB backing file, loop allocation,
original retained UUID format and actual observer checks remain unchanged.

The test fixture injects the existing `testBrokerClock` only into its Agent's
`ClockCheck`. Each measurement samples real `time.Now()`; guest time and all
original receipt/session expiries and broker validation remain unchanged.
The VM does not clear STA_UNSYNC, alter kernel clock bounds or change a
production clock check. This prerequisite earns **zero clock/NTP qualification
credit**. Real synchronized bounded-clock qualification remains **OPEN**;
booting this offline guest does not establish it.

## Fixed launch, evidence and cleanup

`run STAGED_DIRECTORY` verifies the staged kernel/initramfs and host launcher
hashes, then uses the existing unreaped process-group owner. The exact argv is:

```text
<pinned-nice> -n 19 <pinned-env> -i HOME=<owned-stage> LANG=C.UTF-8
  PATH=/nonexistent <pinned-qemu>
  -no-user-config -nodefaults -machine q35,accel=kvm -cpu host
  -smp 2 -m 8192 -display none -serial stdio -monitor none -nic none
  -no-reboot -kernel <owned-bzImage> -initrd <owned-guest.cpio.gz>
  -append 'console=ttyS0 panic=1 rdinit=/init cgroup_no_v1=all'
```

There is no fallback to TCG, host networking, shared directory, device
passthrough, mutable host disk, QEMU daemonization or host cgroup setup.
Pin QEMU's host runtime/firmware closure in the QA packet as well. Availability
of a kernel file does not prove its config or KVM compatibility.

The host deadline is 240 s and group-stop budget is 5 s; propose a 300 s
outer QA limit and no retry/extension. QEMU has 2 vCPUs/8 GiB; it still needs
an approved physical host CPU/memory resource envelope. The guest and archive
size are not host memory enforcement. Propose a fresh 16 GiB available RAM
gate and an exclusive native fixture lease. Final resource authority stays QA.

Raw combined serial is limited to 64 MiB; exhaustion fails the check and
stops the VM. Evidence contains staged.json, started.json, serial.log and
receipt.json. Success requires exactly one matching ready and zero-exit guest
marker, one unindented PASS for the exact requested test, zero QEMU exit,
unchanged input hashes and confirmed process-group cleanup/reap. An empty or
skipped test selection cannot pass. The ready marker means guest bootstrap
completed, not that the clock/runtime scenario is qualified. PID 1 emits the actual test exit and
requests guest poweroff. A timeout, failed poweroff, duplicate marker,
missing marker or uncertain group cleanup cannot pass.

The host always stops the exact owned unreaped QEMU group, even after a guest
failure. Pending ownership produces a failing retained receipt and
PendingCommandError, and all files remain for the external QA controller.
No cleanup guesses a PID by process name. VM destruction removes all guest
loops, mounts, shims, logger processes and cgroups without any host detach or
unmount. Inputs and logs are retained for independent terminal review.
