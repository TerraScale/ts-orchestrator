#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
stop_data_volume() {
	if [[ -f $work/data-loop ]]; then
		sudo systemctl stop ts-orch.service netbird-server.service 2>/dev/null || true
		sudo umount /var/lib/ts-orch 2>/dev/null || true
		sudo umount /var/lib/ts-data 2>/dev/null || true
		sudo rm -f /dev/oracleoci/oraclevdb
		sudo losetup -d "$(cat "$work/data-loop")"
	fi
}
trap 'stop_data_volume; report' EXIT
begin "data volume safety, format-once and adoption drills"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=ts-e2e-ca -addext keyUsage=critical,keyCertSign,cRLSign -keyout "$work/ca.key" -out "$work/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=127.0.0.1 -keyout "$work/localhost.key" -out "$work/localhost.csr" 2>/dev/null
openssl x509 -req -in "$work/localhost.csr" -CA "$work/ca.pem" -CAkey "$work/ca.key" -days 2 -extfile <(echo "subjectAltName=IP:127.0.0.1") -out "$work/localhost.pem" 2>/dev/null
sudo --preserve-env=PATH unshare --mount --net --fork bash -c 'ip link set lo up; exec bash "$@"' bash \
	"$here/volume.sh" "$repo" "$work" "$(dirname "$bin")"
sudo --preserve-env=PATH bash "$here/volume-install.sh" "$work"
end "volume refusals preserve bytes; format once and adoption preserve identity"
(
	volume_work=$work
	source "$here/setup.sh"

	begin "node startup and live volume growth preserve mounted data"
	sudo python3 "$here/volume-growth.py" "$volume_work" "$first"
	test "$(edge data.e2e.test /boots | head -1)" = "$first"
	end "startup grows to 32 GiB; live growth reaches 33 GiB without restarting services"

	begin "a failed rescan after the volume grew leaves the verified node serving until growth recovers"
	data_loop=$(readlink -f /dev/oracleoci/oraclevdb)
	data_sys=$(readlink -f "/sys/class/block/${data_loop#/dev/}")
	sudo install -d -m 0755 /run/ts-e2e-block/device
	sudo touch /run/ts-e2e-block/device/rescan
	sudo systemctl stop ts-orch.service
	printf '[Service]\nBindReadOnlyPaths=/run/ts-e2e-block:%s\n' "$data_sys" | sudo tee /etc/systemd/system/ts-orch.service.d/e2e-rescan.conf >/dev/null
	sudo systemctl daemon-reload
	blocks=$(stat -f -c %b /var/lib/ts-data)
	sudo truncate -s 34G "$volume_work/data-volume.img"
	sudo losetup --set-capacity "$data_loop"
	cursor=$(sudo journalctl -u ts-orch -n 1 -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["__CURSOR"])')
	sudo systemctl start ts-orch.service
	wait_for 30 edge data.e2e.test /boots
	test "$(edge data.e2e.test /boots | head -1)" = "$first"
	failed=$(sudo journalctl -u ts-orch --after-cursor "$cursor" -o cat | grep 'data filesystem growth failed')
	[[ $failed == *'read-only file system'* ]]
	test "$(stat -f -c %b /var/lib/ts-data)" = "$blocks"
	pid=$(systemctl show ts-orch -p MainPID --value)
	cursor=$(sudo journalctl -u ts-orch -n 1 -o json | python3 -c 'import json,sys; print(json.load(sys.stdin)["__CURSOR"])')
	sudo rm /run/ts-e2e-block/device/rescan
	grep -q -m1 'data filesystem growth recovered' < <(sudo timeout 15 journalctl -u ts-orch --after-cursor "$cursor" -f -o cat)
	test "$(stat -f -c %b /var/lib/ts-data)" -gt "$blocks"
	test "$(sudo cat /var/lib/ts-data/terrabase/kept)" = 'retained database bytes'
	test "$(systemctl show ts-orch -p MainPID --value)" = "$pid"
	sudo rm /etc/systemd/system/ts-orch.service.d/e2e-rescan.conf
	sudo systemctl daemon-reload
	sudo systemctl restart ts-orch.service
	wait_for 30 edge data.e2e.test /boots
	end "rescan EROFS: node serves at its old size and logs the failure; a device without a rescan attribute grows online to 34 GiB"

	begin "data mount loss stops both dependent units and mounting restores state"
	sudo systemctl stop netbird-server.service
	printf '[Service]\nExecStart=\nExecStart=/usr/bin/tail -f /dev/null\n' | sudo tee /etc/systemd/system/netbird-server.service.d/e2e.conf >/dev/null
	sudo systemctl daemon-reload
	sudo systemctl start netbird-server.service
	sudo systemctl is-active --quiet netbird-server.service
	sudo systemctl stop 'var-lib-ts\x2ddata.mount'
	if sudo systemctl is-active --quiet ts-orch; then
		exit 1
	fi
	if sudo systemctl is-active --quiet netbird-server.service; then
		exit 1
	fi
	if sudo /usr/bin/mountpoint -q /var/lib/ts-data; then
		exit 1
	fi
	sudo systemctl start ts-orch
	sudo /usr/bin/mountpoint -q /var/lib/ts-data
	sudo /usr/bin/mountpoint -q /var/lib/ts-orch
	test "$(sudo head -1 "$data/boots")" = "$first"
	sudo systemctl stop netbird-server.service
	sudo rm /etc/systemd/system/netbird-server.service.d/e2e.conf
	sudo systemctl daemon-reload
	end "mount dependency restores the retained filesystem before the agent"
)
echo "M1 data volume e2e passed"
