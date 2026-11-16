#!/usr/bin/env bash
set -euo pipefail
lane_dir=$(cd "$(dirname "$0")" && pwd)
candidate=$(realpath "$1")
production=3f3f17eaaca84fd73d2c95683171df2a924a68da
production_digest=8300a1f6fccb137ab77a56adc565132579dcb5c15b1c435419c34be66f316917
previous=$(mktemp -d)
curl -fsSL --retry 3 -o "$previous/terrascale-orchestrator" \
	"https://github.com/TerraScale/ts-orchestrator/releases/download/ci-$production-run-43936422160/terrascale-orchestrator-linux-arm64"
echo "$production_digest  $previous/terrascale-orchestrator" | sha256sum -c --quiet
chmod 0755 "$previous/terrascale-orchestrator"
checkout=$(git -C "$lane_dir" rev-parse --show-toplevel)
git -C "$checkout" cat-file -e "$production^{commit}" 2>/dev/null || git -C "$checkout" fetch -q --depth 1 origin "$production"
git -C "$checkout" archive "$production" deploy/m1 | tar -x -C "$previous"
set -- "$previous/terrascale-orchestrator" "$previous/deploy/m1"
source "$lane_dir/setup.sh"

unit=/etc/systemd/system/ts-orch.service
pairing_dropin=/run/systemd/system/ts-orch.service.d/ts-orch-unit.conf
installed=/usr/local/bin/terrascale-orchestrator
serving() {
	systemctl is-active --quiet ts-orch.service &&
		cmp -s "$unit" "$1" &&
		cmp -s "$installed" "$2" &&
		edge whoami.e2e.test /health
}
swap_as_installed_release() {
	local pid
	pid=$(systemctl show ts-orch.service -p MainPID --value)
	sudo install -m 0755 "$1" "$installed.next"
	sudo nsenter -t "$pid" -m -- "$installed.next" release preflight
	sudo cp --preserve=mode "$installed" "$installed.prev"
	sudo mv "$installed.next" "$installed"
	sudo kill -TERM "$pid"
}

begin "production release serves under its own unit"
serving "$previous/deploy/m1/ts-orch.service" "$previous/terrascale-orchestrator"
sudo cat "$state/swarm/admission.json" >"$work/admission-before.json"
node_before=$(orch member ls | awk 'NR == 2 {print $1}')
end "production release, its unit and its admission"

begin "upgrade to this build the way the production installer swaps a release"
swap_as_installed_release "$candidate"
wait_for 180 serving "$repo/deploy/m1/ts-orch.service" "$candidate"
test ! -e "$pairing_dropin"
systemctl show ts-orch.service -p ExecStart --value | grep -q " node --state /var/lib/ts-orch "
sudo cmp "$state/swarm/admission.json" "$work/admission-before.json"
test "$(orch member ls | awk 'NR == 2 {print $1}')" = "$node_before"
jq '.args = ["--port", "18081", "--verbose"]' "$here/whoami.json" >"$work/whoami-verbose.json"
orch service apply -f "$work/whoami-verbose.json"
wait_for 30 edge whoami.e2e.test /health
orch service ls | grep -Eq '^e2e-whoami +1/1 running'
edge data.e2e.test /boots | head -1 | grep -qx "$first"
end "candidate preflight in the old sandbox, swap, restart: this build serves under its own unit with the stored admission unchanged"

begin "rollback to the production release the way its recovery unit restores it"
sudo systemctl stop ts-orch.service
sudo mv "$installed.prev" "$installed"
sudo systemctl reset-failed ts-orch.service
if sudo systemctl start ts-orch.service; then
	echo "the first start of the restored binary ran under the unit of the build it replaced" >&2
	exit 1
fi
wait_for 180 serving "$previous/deploy/m1/ts-orch.service" "$previous/terrascale-orchestrator"
sudo cmp "$state/swarm/admission.json" "$work/admission-before.json"
orch service ls | grep -Eq '^e2e-whoami +1/1 running'
end "production release restored with the unit recorded for it, serving"

begin "upgrade again after the rollback"
swap_as_installed_release "$candidate"
wait_for 180 serving "$repo/deploy/m1/ts-orch.service" "$candidate"
sudo cmp "$state/swarm/admission.json" "$work/admission-before.json"
sudo ls "$state/units" | tee "$work/pairs.txt"
test "$(wc -l <"$work/pairs.txt")" -le 3
end "this build serves again; only the pairs of the installed, previous and candidate binaries remain"
