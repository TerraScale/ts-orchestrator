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
	source "$here/setup.sh"

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
