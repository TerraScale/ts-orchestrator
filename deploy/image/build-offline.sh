#!/usr/bin/env bash
set -euo pipefail
repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
cd "$repository_root"

usage() {
	cat >&2 <<'USAGE'
usage: build-offline.sh --base QCOW2 --binary FILE --receipt FILE \
  --delegation FILE --root-key PEM --environment canary|production \
  --release-tool FILE --out QCOW2

Creates a local QCOW2 candidate from a verified, pinned offline base image.
It makes no OCI calls and does not install credentials or host configuration.
USAGE
}

base=
binary=
receipt=
delegation=
root_key=
environment=
release_tool=
output=
while (($#)); do
	case "$1" in
		--base) base=${2:?}; shift 2 ;;
		--binary) binary=${2:?}; shift 2 ;;
		--receipt) receipt=${2:?}; shift 2 ;;
		--delegation) delegation=${2:?}; shift 2 ;;
		--root-key) root_key=${2:?}; shift 2 ;;
		--environment) environment=${2:?}; shift 2 ;;
		--release-tool) release_tool=${2:?}; shift 2 ;;
		--out) output=${2:?}; shift 2 ;;
		*) usage; exit 2 ;;
	esac
done

if [[ -z "$base" || -z "$binary" || -z "$receipt" || -z "$delegation" || -z "$root_key" || -z "$environment" || -z "$release_tool" || -z "$output" ]]; then
	usage
	exit 2
fi
if [[ "$environment" != canary && "$environment" != production ]]; then
	echo "environment must be canary or production" >&2
	exit 2
fi
for command in cp ln mktemp python3 qemu-img realpath virt-customize; do
	command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
[[ -x "$release_tool" ]] || { echo "release tool must be executable" >&2; exit 1; }
base=$(realpath -e -- "$base")
binary=$(realpath -e -- "$binary")
receipt=$(realpath -e -- "$receipt")
delegation=$(realpath -e -- "$delegation")
root_key=$(realpath -e -- "$root_key")
release_tool=$(realpath -e -- "$release_tool")
output_parent=$(realpath -e -- "$(dirname -- "$output")")
output="$output_parent/$(basename -- "$output")"
if [[ -e "$output" || -L "$output" || "$output" == "$base" ]]; then
	echo "output must be a new path distinct from the base image" >&2
	exit 1
fi

temporary_directory=$(mktemp -d "$output_parent/.ts-orchestrator-image.XXXXXX")
cleanup() { rm -rf -- "$temporary_directory"; }
trap cleanup EXIT
cp -- "$binary" "$temporary_directory/terrascale-orchestrator"
chmod 0755 "$temporary_directory/terrascale-orchestrator"
binary="$temporary_directory/terrascale-orchestrator"
"$release_tool" verify-binary \
	--receipt "$receipt" --delegation "$delegation" --root-key "$root_key" \
	--binary "$binary" --environment "$environment"
qemu-img check -- "$base"
qemu-img info --output=json -- "$base" | python3 -c '
import json, sys
image = json.load(sys.stdin)
if image.get("format") != "qcow2" or image.get("backing-filename"):
    raise SystemExit("base must be standalone QCOW2 with no backing file")
'

candidate="$temporary_directory/image.qcow2"
cp --reflink=auto --sparse=always -- "$base" "$candidate"
virt-customize --no-network -a "$candidate" \
	--upload deploy/image/terrascale-orchestrator.sysusers:/etc/sysusers.d/terrascale-orchestrator.conf \
	--upload deploy/systemd/terrascale-orchestrator-controller.service:/etc/systemd/system/terrascale-orchestrator-controller.service \
	--upload deploy/systemd/terrascale-orchestrator-host.service:/etc/systemd/system/terrascale-orchestrator-host.service \
	--upload "$binary:/usr/local/bin/terrascale-orchestrator" \
	--run-command 'chmod 0644 /etc/sysusers.d/terrascale-orchestrator.conf /etc/systemd/system/terrascale-orchestrator-controller.service /etc/systemd/system/terrascale-orchestrator-host.service && chmod 0755 /usr/local/bin/terrascale-orchestrator && SYSTEMD_OFFLINE=1 systemctl enable terrascale-orchestrator-controller.service terrascale-orchestrator-host.service'
qemu-img check -- "$candidate"
ln -- "$candidate" "$output"
trap - EXIT
rm -rf -- "$temporary_directory"
printf 'offline QCOW2 candidate created at %s\n' "$output"
