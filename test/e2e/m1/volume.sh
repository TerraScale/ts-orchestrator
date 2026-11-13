#!/usr/bin/env bash
set -euo pipefail
repo=$1
work=$2
go -C "$repo" run ./test/e2e/m1/cloudinit > "$work/cloud-init.sh"
bash -n "$work/cloud-init.sh"
sed -n "/^echo .*base64 -d > \\/usr\\/local\\/lib\\/ts-orch\\/data-volume.sh/p" "$work/cloud-init.sh" | cut -d "'" -f2 | base64 -d > "$work/data-volume.sh"
bash -n "$work/data-volume.sh"
test "$(grep -n '^bash /usr/local/lib/ts-orch/data-volume.sh false$' "$work/cloud-init.sh" | cut -d: -f1)" -lt "$(grep -n '^systemctl restart ts-orch.service' "$work/cloud-init.sh" | cut -d: -f1)"
truncate -s 3G "$work/data-volume.img"
data_loop=$(sudo losetup --find --show "$work/data-volume.img")
stop_data_volume() {
	sudo systemctl stop ts-orch.service netbird-server.service 2>/dev/null || true
	sudo umount /var/lib/ts-orch 2>/dev/null || true
	sudo umount /var/lib/ts-data 2>/dev/null || true
	sudo rm -f /dev/oracleoci/oraclevdb
	sudo losetup -d "$data_loop"
}
trap stop_data_volume EXIT
sudo install -d -m 0755 /dev/oracleoci
sudo ln -s "$data_loop" /dev/oracleoci/oraclevdb
before=$(sudo sha256sum "$data_loop")
if sudo bash -c 'exec bash "$1" true > "$2" 2>&1' bash "$work/data-volume.sh" "$work/formatted-empty.log"; then
	echo "retained blank disk was accepted" >&2
	exit 1
fi
test "$(sudo sha256sum "$data_loop")" = "$before"
for offset in 0 1073741824 3221225471; do
	printf x | sudo dd of="$data_loop" bs=1 seek="$offset" conv=notrunc status=none
	before=$(sudo sha256sum "$data_loop")
	if sudo bash -c 'exec bash "$1" false > "$2" 2>&1' bash "$work/data-volume.sh" "$work/raw-data.log"; then
		echo "nonempty disk was accepted for formatting" >&2
		exit 1
	fi
	test "$(sudo sha256sum "$data_loop")" = "$before"
	printf '\0' | sudo dd of="$data_loop" bs=1 seek="$offset" conv=notrunc status=none
done
sudo bash "$work/data-volume.sh" false
sudo touch /var/lib/ts-data/terrabase/kept /var/lib/ts-orch/identity-kept
uuid=$(sudo blkid -s UUID -o value "$data_loop")
sudo umount /var/lib/ts-orch /var/lib/ts-data
sudo bash "$work/data-volume.sh" true
test "$(sudo blkid -s UUID -o value "$data_loop")" = "$uuid"
sudo test -f /var/lib/ts-data/terrabase/kept
sudo test -f /var/lib/ts-orch/identity-kept
sudo umount /var/lib/ts-orch /var/lib/ts-data
sudo bash "$work/data-volume.sh" false
test "$(sudo blkid -s UUID -o value "$data_loop")" = "$uuid"
sudo test -f /var/lib/ts-data/terrabase/kept
sudo test -f /var/lib/ts-orch/identity-kept
test "$(grep -Fc "UUID=$uuid /var/lib/ts-data ext4 defaults 0 2" /etc/fstab)" = 1
test "$(grep -Fc '/var/lib/ts-data/ts-orch /var/lib/ts-orch none bind 0 0' /etc/fstab)" = 1
cmp /etc/systemd/system/ts-orch.service.d/data-volume.conf /etc/systemd/system/netbird-server.service.d/data-volume.conf
echo "data volume: formatted blank and nonzero raw disks refused unchanged; blank interrupted creates format; existing filesystems keep UUID, service data and identity"
