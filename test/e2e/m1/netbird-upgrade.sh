#!/usr/bin/env bash
set -euo pipefail
umask 077
helper=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=$(mktemp -d)
trap 'sudo rm -rf "$work"' EXIT
source "$here/runtime.sh"
previous=$(python3 - "$repo/deploy/image/debian/base.json" "$arch" <<'PY'
import json
import sys
from pathlib import Path

current = json.loads(Path(sys.argv[1]).read_text())["netbird"]
pin = current["previous"]
version = pin["version"]
if tuple(map(int, version.split("."))) >= tuple(map(int, current["version"].split("."))):
    raise SystemExit("the upgrade journey needs a release older than the image pin")
print(version, f"https://github.com/netbirdio/netbird/releases/download/v{version}/netbird_{version}_linux_{sys.argv[2]}.tar.gz", pin["sha256"][sys.argv[2]])
PY
)
read -r old_version old_url old_sha <<< "$previous"
archive=$(basename "$old_url")
pinned "$archive" "$old_url" "$old_sha"
mkdir "$work/previous"
tar -C "$work/previous" -xzf "$packages/$archive" netbird
cp /usr/local/bin/netbird "$work/pinned"
sudo /usr/local/bin/netbird status --json > "$work/status.json"
dropin=/run/systemd/system/netbird.service.d/e2e-upgrade.conf
profile=e2e-netbird-upgrade-$$
sudo /usr/local/bin/netbird profile add "$profile" >/dev/null
cleanup() {
	sudo rm -f "$dropin"
	sudo systemctl daemon-reload
	sudo /usr/local/bin/netbird profile remove "$profile" >/dev/null
	sudo rm -rf "$work"
}
trap cleanup EXIT
snapshot() {
	sudo python3 - <<'PY'
import hashlib
import json
from pathlib import Path

files = sorted(path for root in (Path("/etc/netbird"), Path("/var/lib/netbird"))
               for path in root.rglob("*.json") if path.is_file())
def has_identity(value):
    if isinstance(value, dict):
        return any((key.lower().replace("_", "") == "privatekey" and isinstance(item, str) and item)
                   or has_identity(item) for key, item in value.items())
    if isinstance(value, list):
        return any(has_identity(item) for item in value)
    return False

values = [json.loads(path.read_text()) for path in files]
if not any(has_identity(value) for value in values):
    raise SystemExit("NetBird has no persisted private identity")
for path in files:
    value = json.loads(path.read_text())
    digest = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
    print(path, digest)
PY
}
snapshot > "$work/config"
pid() { systemctl show --property=MainPID --value netbird; }
old_daemon() {
	sudo /usr/local/bin/netbird status --json > "$work/status.json"
	old_pid=$(pid)
	test "$old_pid" -gt 0
	sudo "/proc/$old_pid/exe" version | grep -Fxq "$old_version"
}
seed_old() {
	sudo systemctl stop netbird
	sudo install -m 0755 "$work/previous/netbird" /usr/local/bin/netbird.next
	sudo mv -f /usr/local/bin/netbird.next /usr/local/bin/netbird
	sudo systemctl start netbird
	old_daemon
}
verify() {
	local current
	sudo /usr/local/bin/netbird status --json > "$work/status.json"
	current=$(pid)
	test "$current" -gt 0
	test "$current" != "$old_pid"
	echo "$netbird_binary_sha256  /proc/$current/exe" | sudo sha256sum -c --status
	systemctl show --property=ExecStart --value netbird | grep -Fq 'path=/usr/local/bin/netbird ;'
	snapshot > "$work/config-after"
	cmp "$work/config" "$work/config-after"
}

seed_old
sudo bash "$repo/deploy/m1/host-runtime.sh"
verify
echo 'netbird-upgrade: installer replaced the old running executable and preserved configuration'

seed_old
sudo install -m 0755 "$work/pinned" /usr/local/bin/netbird.next
sudo mv -f /usr/local/bin/netbird.next /usr/local/bin/netbird
sudo systemctl enable --now netbird
test "$(pid)" = "$old_pid"
sudo "/proc/$old_pid/exe" version | grep -Fxq "$old_version"
echo 'netbird-upgrade: enable --now left the older executable running after disk replacement'
sudo "$helper" "$netbird_binary_sha256"
verify
echo 'netbird-upgrade: manager restarted the old daemon despite an already pinned file on disk'

for entry in runtime manager; do
	sudo systemctl stop netbird
	sudo "$work/previous/netbird" service reconfigure
	sudo systemctl start netbird
	old_daemon
	if [[ $entry == runtime ]]; then
		sudo bash "$repo/deploy/m1/host-runtime.sh"
	else
		sudo "$helper" "$netbird_binary_sha256"
	fi
	verify
	echo "netbird-upgrade: $entry repaired the service executable and preserved configuration"
done

for entry in runtime manager; do
	old_pid=$(pid)
	sudo mkdir -p "$(dirname "$dropin")"
	busctl --json=short get-property org.freedesktop.systemd1 /org/freedesktop/systemd1/unit/netbird_2eservice org.freedesktop.systemd1.Service ExecStart |
		sudo python3 -c '
import json
import sys
from pathlib import Path

argv = json.load(sys.stdin)["data"][0][1] + ["--log-level", "error"]
Path(sys.argv[1]).write_text("[Service]\nExecStart=\nExecStart=" + " ".join(json.dumps(arg) for arg in argv) + "\n")
' "$dropin"
	sudo systemctl daemon-reload
	if [[ $entry == runtime ]]; then
		sudo bash "$repo/deploy/m1/host-runtime.sh"
	else
		sudo "$helper" "$netbird_binary_sha256"
	fi
	verify
	sudo python3 - "$(pid)" <<'PY_ARGS'
import sys
from pathlib import Path

args = Path(f"/proc/{sys.argv[1]}/cmdline").read_bytes().split(b"\0")[:-1]
assert args[-2:] == [b"--log-level", b"error"]
PY_ARGS
	old_pid=$(pid)
	sudo rm "$dropin"
	sudo systemctl daemon-reload
	sudo "$helper" "$netbird_binary_sha256"
	verify
	echo "netbird-upgrade: $entry restarted the daemon for changed service arguments and their restoration"
done

stable=$(pid)
sudo "$helper" "$netbird_binary_sha256"
test "$(pid)" = "$stable"
sudo bash "$repo/deploy/m1/host-runtime.sh"
test "$(pid)" = "$stable"
snapshot > "$work/config-after"
cmp "$work/config" "$work/config-after"
echo 'netbird-upgrade: both reconciliation entry points leave a current daemon and its configuration unchanged'

old_pid=$(pid)
sudo systemctl stop netbird
sudo /usr/local/bin/netbird service uninstall
sudo "$helper" "$netbird_binary_sha256"
verify
echo 'netbird-upgrade: a missing service is recreated without changing persisted identity'
