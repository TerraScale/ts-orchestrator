set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'sudo rm -rf "$work"' EXIT
mkdir -p "$work/root/etc" "$work/root/dev"
CGO_ENABLED=0 go build -p 1 -o "$work/root/init" "$here"
CGO_ENABLED=0 go build -p 1 -o "$work/root/alert-lane" "$here/../alert-prepare"
CGO_ENABLED=0 go build -p 1 -o "$work/root/host-lane" "$here/../host-credentials"
cp "$bin" "$work/root/ts-orch"
printf 'root:x:0:0:root:/root:/bin/sh\nts-alerts:x:32123:32123:Alert relay:/nonexistent:/bin/false\n' > "$work/root/etc/passwd"
printf 'root:x:0:\nts-alerts:x:32123:\n' > "$work/root/etc/group"
sudo -n mknod "$work/root/dev/console" c 5 1
sudo -n mknod "$work/root/dev/null" c 1 3
(cd "$work/root" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1) > "$work/initramfs.gz"
kernel=/boot/vmlinuz-$(uname -r)
if [[ ! -f $kernel ]]; then kernel=/run/current-system/kernel; fi
timeout 180 qemu-system-x86_64 -accel kvm -m 1024 -smp 2 -nodefaults -nographic -serial stdio -no-reboot -kernel "$kernel" -initrd "$work/initramfs.gz" -append 'console=ttyS0 rdinit=/init panic=-1' > "$work/output" 2>&1
grep -E 'ok |e2e:|FAIL|panic' "$work/output"
grep -q 'credential-vm e2e: PASS' "$work/output"
