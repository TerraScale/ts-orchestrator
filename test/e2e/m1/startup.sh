set -euo pipefail
bin=$(realpath "$1")
work=$(mktemp -d)
trap 'sudo rm -rf "$work"' EXIT
mkdir -p "$work/sys/class/dmi/id"
printf 'OracleCloud.com\n' > "$work/sys/class/dmi/id/chassis_asset_tag"
sudo unshare --mount --net bash -s -- "$bin" "$work" <<'SH'
set -euo pipefail
bin=$1
work=$2
mount --make-rprivate /
mount --bind "$work/sys" /sys
for role in fresh manager container; do
	state=$work/$role
	mkdir -p "$state"
	if [[ $role != fresh ]]; then
		mkdir -p "$state/swarm"
		host=single-host
		[[ $role == manager ]] || host=worker
		printf '{"Region":"local","HostID":"%s","InstanceID":"instance","FounderID":"single-host","Role":"%s"}\n' "$host" "$role" > "$state/swarm/admission.json"
		cp "$state/swarm/admission.json" "$work/$role-before.json"
	fi
	if "$bin" single-host --state "$state" > "$work/$role-output" 2>&1; then
		cat "$work/$role-output"
		exit 1
	fi
	grep 'read host metadata: read OCI region from IMDS:' "$work/$role-output"
	if [[ $role == fresh ]]; then
		test ! -e "$state/swarm"
	else
		cmp "$state/swarm/admission.json" "$work/$role-before.json"
	fi
	echo "Oracle $role metadata failure returned without founding a cluster"
done
printf 'Local\n' > "$work/sys/class/dmi/id/chassis_asset_tag"
mkdir -p "$work/orphan/swarm"
if "$bin" single-host --state "$work/orphan" > "$work/orphan-output" 2>&1; then
	exit 1
fi
grep 'cluster state exists without stored admission' "$work/orphan-output"
SH
