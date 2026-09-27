#!/usr/bin/env bash
set -euo pipefail
repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
cd "$repository_root"

usage() {
	cat >&2 <<'USAGE'
usage: build-offline.sh --base QCOW2 --binary FILE --receipt FILE --qualification FILE \
  --delegation FILE --root-key PEM --environment canary|production \
  --native-verifier-binary FILE --native-verifier-sha256 LOWERCASE_HEX \
  --release-tool FILE --bootstrap-tool FILE --bootstrap-anchor FILE \
  --bootstrap-identity FILE --bootstrap-root PEM... --timesyncd-config FILE \
  --runtime-priority-profile-id TOKEN --runtime-priority-system-reserve-bytes BYTES \
  --host-memory-min-bytes BYTES --host-memory-low-bytes BYTES \
  --controller-memory-min-bytes BYTES --controller-memory-low-bytes BYTES \
  --system-slice-memory-min-bytes BYTES --system-slice-memory-low-bytes BYTES \
  [--host-enrollment-public FILE --host-enrollment-public-sha256 LOWERCASE_HEX] \
  --out QCOW2

Creates a local QCOW2 candidate from a verified, pinned offline base image.
It makes no OCI calls and installs no private keys or runtime secrets. The
release root key verifies the binary; repeatable bootstrap root keys verify
the baked anchor and are installed as public trust roots. The explicit
timesyncd configuration supplies deployment NTP endpoints; no endpoint is
selected or installed by default.
The native verifier is the exact qualified TerraBase ARM64 tb-server artifact.
Its SHA-256 must match the independently supplied artifact digest; the image
installs it at the fixed managed-material verifier path. This digest is
separate from the orchestrator binary receipt's BinarySHA256.
The optional host enrollment bundle is public, reviewed by its exact SHA-256,
and installed only in managed-host images with its setup service and timer.
Host images reserve workload UID/GID 2000:2000, use separate install and state
roots under /var/lib/terrascale-orchestrator-host, and provision /srv/ts-managed
as root:2000 0750 for persistent member volumes.

The runtime-priority memory-floor arguments have no defaults. Prefer values
measured with the selected image and service configuration; if measurements
are unavailable, label the supplied values as selected allocations rather
than measured results. The image carries those floors and the selected reserve
in root-owned profile/drop-in files before either orchestrator service is
enabled. For the 1 OCPU/6 GiB preview, select the 1 GiB reserve used by the
signed managed-host placement profile. The host compares the baked reserve
with that signed profile before launching workloads.
USAGE
}

base=
binary=
native_verifier_binary=
native_verifier_sha256=
receipt=
qualification=
delegation=
root_key=
environment=
release_tool=
bootstrap_tool=
bootstrap_anchor=
bootstrap_identity=
bootstrap_roots=()
timesyncd_config=
host_enrollment_public=
host_enrollment_public_sha256=
runtime_priority_profile_id=
runtime_priority_system_reserve_bytes=
host_memory_min_bytes=
host_memory_low_bytes=
controller_memory_min_bytes=
controller_memory_low_bytes=
system_slice_memory_min_bytes=
system_slice_memory_low_bytes=
bootstrap_root_limit=16
bootstrap_root_max_bytes=16384
bootstrap_roots_max_total_bytes=65536
bootstrap_identity_max_bytes=4096
bootstrap_anchor_max_bytes=65536
timesyncd_config_max_bytes=16384
output=
while (($#)); do
	case "$1" in
		--base) base=${2:?}; shift 2 ;;
		--binary) binary=${2:?}; shift 2 ;;
		--native-verifier-binary) native_verifier_binary=${2:?}; shift 2 ;;
		--native-verifier-sha256) native_verifier_sha256=${2:?}; shift 2 ;;
		--receipt) receipt=${2:?}; shift 2 ;;
		--qualification) qualification=${2:?}; shift 2 ;;
		--delegation) delegation=${2:?}; shift 2 ;;
		--root-key) root_key=${2:?}; shift 2 ;;
		--environment) environment=${2:?}; shift 2 ;;
		--release-tool) release_tool=${2:?}; shift 2 ;;
		--bootstrap-tool) bootstrap_tool=${2:?}; shift 2 ;;
		--bootstrap-anchor) bootstrap_anchor=${2:?}; shift 2 ;;
		--bootstrap-identity) bootstrap_identity=${2:?}; shift 2 ;;
		--bootstrap-root) bootstrap_roots+=("${2:?}"); shift 2 ;;
		--timesyncd-config) timesyncd_config=${2:?}; shift 2 ;;
		--host-enrollment-public) host_enrollment_public=${2:?}; shift 2 ;;
		--host-enrollment-public-sha256) host_enrollment_public_sha256=${2:?}; shift 2 ;;
		--runtime-priority-profile-id) runtime_priority_profile_id=${2:?}; shift 2 ;;
		--runtime-priority-system-reserve-bytes) runtime_priority_system_reserve_bytes=${2:?}; shift 2 ;;
		--host-memory-min-bytes) host_memory_min_bytes=${2:?}; shift 2 ;;
		--host-memory-low-bytes) host_memory_low_bytes=${2:?}; shift 2 ;;
		--controller-memory-min-bytes) controller_memory_min_bytes=${2:?}; shift 2 ;;
		--controller-memory-low-bytes) controller_memory_low_bytes=${2:?}; shift 2 ;;
		--system-slice-memory-min-bytes) system_slice_memory_min_bytes=${2:?}; shift 2 ;;
		--system-slice-memory-low-bytes) system_slice_memory_low_bytes=${2:?}; shift 2 ;;
		--out) output=${2:?}; shift 2 ;;
		*) usage; exit 2 ;;
	esac
done

if [[ -z "$base" || -z "$binary" || -z "$native_verifier_binary" || -z "$native_verifier_sha256" ||
	-z "$receipt" || -z "$qualification" || -z "$delegation" || -z "$root_key" ||
	-z "$environment" || -z "$release_tool" || -z "$bootstrap_tool" || -z "$bootstrap_anchor" ||
	-z "$bootstrap_identity" || ${#bootstrap_roots[@]} -eq 0 || -z "$timesyncd_config" || -z "$output" ||
	-z "$runtime_priority_profile_id" || -z "$runtime_priority_system_reserve_bytes" ||
	-z "$host_memory_min_bytes" || -z "$host_memory_low_bytes" ||
	-z "$controller_memory_min_bytes" || -z "$controller_memory_low_bytes" ||
	-z "$system_slice_memory_min_bytes" || -z "$system_slice_memory_low_bytes" ]]; then
	usage
	exit 2
fi
if ((${#bootstrap_roots[@]} > bootstrap_root_limit)); then
	echo "bootstrap root set must contain at most $bootstrap_root_limit files" >&2
	exit 2
fi
if [[ "$environment" != canary && "$environment" != production ]]; then
	echo "environment must be canary or production" >&2
	exit 2
fi
if [[ ! $native_verifier_sha256 =~ ^[0-9a-f]{64}$ ]]; then
	echo "native verifier SHA-256 must be 64 lowercase hex characters" >&2
	exit 2
fi
if [[ -n "$host_enrollment_public" && ! $host_enrollment_public_sha256 =~ ^[0-9a-f]{64}$ ]] ||
	[[ -z "$host_enrollment_public" && -n "$host_enrollment_public_sha256" ]]; then
	echo "host enrollment public bundle requires a paired file and lowercase SHA-256" >&2
	exit 2
fi
for command in cat cp ln mktemp python3 qemu-img realpath virt-cat virt-customize; do
	command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
[[ -x "$release_tool" ]] || { echo "release tool must be executable" >&2; exit 1; }
[[ -x "$bootstrap_tool" ]] || { echo "bootstrap tool must be executable" >&2; exit 1; }
base=$(realpath -e -- "$base")
binary=$(realpath -e -- "$binary")
native_verifier_binary=$(realpath -e -- "$native_verifier_binary")
[[ -f "$native_verifier_binary" ]] || { echo "native verifier must be a regular file" >&2; exit 1; }
receipt=$(realpath -e -- "$receipt")
qualification=$(realpath -e -- "$qualification")
delegation=$(realpath -e -- "$delegation")
root_key=$(realpath -e -- "$root_key")
bootstrap_tool=$(realpath -e -- "$bootstrap_tool")
bootstrap_anchor=$(realpath -e -- "$bootstrap_anchor")
bootstrap_identity=$(realpath -e -- "$bootstrap_identity")
timesyncd_config=$(realpath -e -- "$timesyncd_config")
release_tool=$(realpath -e -- "$release_tool")
if [[ -n "$host_enrollment_public" ]]; then
	host_enrollment_public=$(realpath -e -- "$host_enrollment_public")
	[[ -f "$host_enrollment_public" ]] || { echo "host enrollment public bundle must be a regular file" >&2; exit 1; }
fi
[[ -f "$bootstrap_anchor" ]] || { echo "bootstrap anchor must be a regular file" >&2; exit 1; }
[[ -f "$bootstrap_identity" ]] || { echo "bootstrap identity must be a regular file" >&2; exit 1; }
[[ -f "$timesyncd_config" ]] || { echo "timesyncd config must be a regular file" >&2; exit 1; }
resolved_bootstrap_roots=()
for bootstrap_root in "${bootstrap_roots[@]}"; do
	bootstrap_root=$(realpath -e -- "$bootstrap_root")
	[[ -f "$bootstrap_root" ]] || { echo "bootstrap roots must be regular files" >&2; exit 1; }
	resolved_bootstrap_roots+=("$bootstrap_root")
done
bootstrap_roots=("${resolved_bootstrap_roots[@]}")

output_parent=$(realpath -e -- "$(dirname -- "$output")")
output="$output_parent/$(basename -- "$output")"
if [[ -e "$output" || -L "$output" || "$output" == "$base" ]]; then
	echo "output must be a new path distinct from the base image" >&2
	exit 1
fi

temporary_directory=$(mktemp -d "$output_parent/.ts-orchestrator-image.XXXXXX")
cleanup() { rm -rf -- "$temporary_directory"; }
trap cleanup EXIT
timesyncd_config_image="$temporary_directory/timesyncd.conf"
host_enrollment_public_image="$temporary_directory/host-enrollment-public.json"
runtime_priority_root="$temporary_directory/runtime-priority"
runtime_priority_profile="$temporary_directory/runtime-priority.json"
python3 tests/runtime_priority/qualify.py render-drop-ins \
	--profile-id "$runtime_priority_profile_id" \
	--service-memory-min-bytes "$host_memory_min_bytes" \
	--service-memory-low-bytes "$host_memory_low_bytes" \
	--controller-memory-min-bytes "$controller_memory_min_bytes" \
	--controller-memory-low-bytes "$controller_memory_low_bytes" \
	--system-slice-memory-min-bytes "$system_slice_memory_min_bytes" \
	--system-slice-memory-low-bytes "$system_slice_memory_low_bytes" \
	--system-reserve-bytes "$runtime_priority_system_reserve_bytes" \
	--output-root "$runtime_priority_root"
python3 - "$runtime_priority_profile" "$runtime_priority_profile_id" "$runtime_priority_system_reserve_bytes" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

profile_path = Path(sys.argv[1])
profile_id = sys.argv[2]
reserve_text = sys.argv[3]
if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", profile_id):
	raise SystemExit("runtime-priority profile ID must be a 1-128 character safe token")
if not re.fullmatch(r"[1-9][0-9]*", reserve_text):
	raise SystemExit("runtime-priority system reserve must be a positive canonical byte count")
reserve = int(reserve_text)
if reserve > (1 << 63) - 1:
	raise SystemExit("runtime-priority system reserve exceeds signed byte range")
profile = {"version": 1, "profile_id": profile_id, "system_reserve_bytes": reserve}
encoded = json.dumps(profile, separators=(",", ":"), ensure_ascii=True).encode("ascii")
with profile_path.open("xb") as output:
	output.write(encoded)
print(f"{profile_path} sha256={hashlib.sha256(encoded).hexdigest()}")
PY

bootstrap_identity_cell=$(python3 - \
	"$bootstrap_anchor" "$bootstrap_identity" "$environment" \
	"$bootstrap_anchor_max_bytes" "$bootstrap_identity_max_bytes" \
	"$bootstrap_root_max_bytes" "$bootstrap_roots_max_total_bytes" \
	"${bootstrap_roots[@]}" <<'PY'
import json
import re
import sys
from pathlib import Path

(
    anchor_path,
    identity_path,
    release_environment,
    anchor_max_bytes,
    identity_max_bytes,
    root_max_bytes,
    roots_total_max_bytes,
    *root_paths,
) = sys.argv[1:]
anchor_max_bytes = int(anchor_max_bytes)
identity_max_bytes = int(identity_max_bytes)
root_max_bytes = int(root_max_bytes)
roots_total_max_bytes = int(roots_total_max_bytes)
anchor_bytes = Path(anchor_path).stat().st_size
if anchor_bytes <= 0 or anchor_bytes > anchor_max_bytes:
	raise SystemExit(f"bootstrap anchor must be between 1 byte and {anchor_max_bytes} bytes")

identity_size = Path(identity_path).stat().st_size
if identity_size <= 0 or identity_size > identity_max_bytes:
	raise SystemExit(f"bootstrap identity must be between 1 byte and {identity_max_bytes} bytes")
identity_wire = Path(identity_path).read_bytes()
try:
	identity = json.loads(identity_wire)
except (UnicodeDecodeError, json.JSONDecodeError) as error:
	raise SystemExit(f"bootstrap identity must be valid canonical JSON: {error}")
if not isinstance(identity, dict) or set(identity) != {
	"schemaVersion", "deploymentId", "environment", "cell"
}:
	raise SystemExit("bootstrap identity must contain schemaVersion, deploymentId, environment, and cell")
if type(identity["schemaVersion"]) is not int or identity["schemaVersion"] != 1:
	raise SystemExit("bootstrap identity schemaVersion must be 1")
if not isinstance(identity["deploymentId"], str) or not re.fullmatch(
	r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", identity["deploymentId"]
):
	raise SystemExit("bootstrap identity deploymentId is invalid")
if identity["environment"] not in ("canary", "production"):
	raise SystemExit("bootstrap identity environment must be canary or production")
if identity["environment"] != release_environment:
	raise SystemExit("bootstrap identity environment must match the release environment")
if identity["cell"] not in ("GRU", "SFO", "FRA"):
	raise SystemExit("bootstrap identity cell must be GRU, SFO, or FRA")
canonical_identity = {
	"schemaVersion": identity["schemaVersion"],
	"deploymentId": identity["deploymentId"],
	"environment": identity["environment"],
	"cell": identity["cell"],
}
canonical_wire = json.dumps(canonical_identity, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
if identity_wire != canonical_wire:
	raise SystemExit("bootstrap identity must use canonical schema-version-1 JSON")

total_root_bytes = 0
for root_path in root_paths:
	root_bytes = Path(root_path).stat().st_size
	if root_bytes <= 0 or root_bytes > root_max_bytes:
		raise SystemExit(f"each bootstrap root must be between 1 byte and {root_max_bytes} bytes")
	total_root_bytes += root_bytes
if total_root_bytes > roots_total_max_bytes:
	raise SystemExit(f"bootstrap roots must total no more than {roots_total_max_bytes} bytes")
print(identity["cell"])
PY
)

host_setup_uploads=()
if [[ -n "$host_enrollment_public" ]]; then
	cp -- "$host_enrollment_public" "$host_enrollment_public_image"
	python3 deploy/image/validate-host-enrollment-public.py \
		"$host_enrollment_public_image" "$host_enrollment_public_sha256" \
		"$environment" "$bootstrap_identity_cell"
	python3 - "$host_enrollment_public_image" <<'PY'
import json
import sys
from pathlib import Path

bundle = json.loads(Path(sys.argv[1]).read_bytes())
fixed = {
	"workload_uid": 2000,
	"workload_gid": 2000,
	"install_root": "/var/lib/terrascale-orchestrator-host/install",
	"state_root": "/var/lib/terrascale-orchestrator-host/state",
	"managed_runtime_root": "/srv/ts-managed",
}
if any(type(bundle[key]) is not type(value) or bundle[key] != value for key, value in fixed.items()):
	raise SystemExit("host enrollment bundle differs from the fixed image workload identity or paths")
PY
	host_setup_uploads=(
		--upload "$host_enrollment_public_image:/etc/terrascale-orchestrator/host-enrollment-public.json"
		--upload deploy/systemd/terrascale-orchestrator-host-setup.service:/etc/systemd/system/terrascale-orchestrator-host-setup.service
		--upload deploy/systemd/terrascale-orchestrator-host-setup.timer:/etc/systemd/system/terrascale-orchestrator-host-setup.timer
	)
fi

python3 - "$timesyncd_config" "$timesyncd_config_max_bytes" "$timesyncd_config_image" <<'PY'
import re
import sys
from pathlib import Path

config_path = Path(sys.argv[1])
max_bytes = int(sys.argv[2])
normalized_path = Path(sys.argv[3])
config_bytes = config_path.stat().st_size
if config_bytes <= 0 or config_bytes > max_bytes:
	raise SystemExit(f"timesyncd config must be between 1 byte and {max_bytes} bytes")
try:
	config = config_path.read_text(encoding="utf-8")
except UnicodeDecodeError as error:
	raise SystemExit(f"timesyncd config must be UTF-8: {error}")

section = None
server_lists = {"NTP": [], "FallbackNTP": []}
preserved_lines = []
for line_number, line in enumerate(config.splitlines(keepends=True), 1):
	stripped = line.strip()
	if not stripped or stripped.startswith(("#", ";")):
		preserved_lines.append(line)
		continue
	if stripped.endswith("\\"):
		raise SystemExit(
			f"timesyncd config line {line_number} uses a continuation; use single-line server assignments"
		)
	if stripped.startswith("[") and stripped.endswith("]"):
		section = stripped[1:-1].strip()
		preserved_lines.append(line)
		continue
	key, separator, value = stripped.partition("=")
	if not separator:
		raise SystemExit(f"invalid timesyncd config line {line_number}")
	key = key.strip()
	if section == "Time" and key in server_lists:
		value = value.strip()
		if any(character in value for character in ("#", ";", chr(34), chr(39), chr(92))):
			raise SystemExit(
				f"timesyncd config line {line_number} uses unsupported inline comments, quoting, or escapes"
			)
		if not value:
			server_lists[key].clear()
		else:
			server_lists[key].extend(value.split())
		continue
	preserved_lines.append(line)

if not server_lists["NTP"]:
	raise SystemExit("timesyncd config must contain nonempty [Time] NTP endpoints")
for setting, endpoints in server_lists.items():
	for endpoint in endpoints:
		if re.search(r"(?<![0-9])198\.19(?:\.[0-9]{1,3}){2}(?![0-9])", endpoint):
			raise SystemExit(
				f"timesyncd config effective {setting} list must not contain the Firecracker lab NTP address range"
			)

normalized = "".join(preserved_lines)
if normalized and not normalized.endswith(("\n", "\r")):
	normalized += "\n"
if section != "Time":
	normalized += "[Time]\n"
normalized += "NTP=\nNTP=" + " ".join(server_lists["NTP"]) + "\nFallbackNTP=\n"
if server_lists["FallbackNTP"]:
	normalized += "FallbackNTP=" + " ".join(server_lists["FallbackNTP"]) + "\n"
normalized_path.write_bytes(normalized.encode("utf-8"))
PY

bootstrap_verify_args=(verify-anchor --anchor "$bootstrap_anchor" --identity "$bootstrap_identity")
for bootstrap_root in "${bootstrap_roots[@]}"; do
	bootstrap_verify_args+=(--root-key "$bootstrap_root")
done
"$bootstrap_tool" "${bootstrap_verify_args[@]}" >/dev/null

cp -- "$native_verifier_binary" "$temporary_directory/terrabase-server"
native_verifier_binary="$temporary_directory/terrabase-server"
python3 - "$native_verifier_binary" "$native_verifier_sha256" <<'PY'
import hashlib
import os
import struct
import sys

path, expected = sys.argv[1:]
size = os.stat(path).st_size
if not 0 < size <= (128 << 20):
	raise SystemExit("native verifier must be between 1 byte and 128 MiB")
with open(path, "rb") as binary:
	header = binary.read(64)
	if (len(header) != 64 or header[:4] != b"\x7fELF" or header[4:6] != b"\x02\x01"
		or struct.unpack_from("<H", header, 16)[0] not in (2, 3)
		or struct.unpack_from("<H", header, 18)[0] != 183
		or struct.unpack_from("<I", header, 20)[0] != 1
		or struct.unpack_from("<H", header, 52)[0] != 64):
		raise SystemExit("native verifier must be an ELF64 little-endian AArch64 executable")
	digest = hashlib.sha256()
	digest.update(header)
	for chunk in iter(lambda: binary.read(1 << 20), b""):
		digest.update(chunk)
if digest.hexdigest() != expected:
	raise SystemExit("native verifier bytes do not match the supplied SHA-256")
print(f"native verifier artifact sha256={expected} bytes={size} architecture=aarch64")
PY
chmod 0755 "$native_verifier_binary"
cp -- "$binary" "$temporary_directory/terrascale-orchestrator"
chmod 0755 "$temporary_directory/terrascale-orchestrator"
binary="$temporary_directory/terrascale-orchestrator"
chmod 0644 "$timesyncd_config_image"
timesyncd_config_image_sha256=$(python3 - "$timesyncd_config_image" <<'PY'
import hashlib
import sys
from pathlib import Path

print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
)
printf 'timesyncd image config sha256=%s\n' "$timesyncd_config_image_sha256"
"$release_tool" verify-binary \
	--receipt "$receipt" --delegation "$delegation" --root-key "$root_key" \
	--binary "$binary" --qualification "$qualification" --environment "$environment"
qemu-img check -- "$base"
qemu-img info --output=json -- "$base" | python3 -c '
import json, sys
image = json.load(sys.stdin)
if image.get("format") != "qcow2" or image.get("backing-filename"):
    raise SystemExit("base must be standalone QCOW2 with no backing file")
'

candidate="$temporary_directory/image.qcow2"
cp --reflink=auto --sparse=always -- "$base" "$candidate"

bootstrap_directory=/etc/terrascale-orchestrator/bootstrap
native_verifier_guest_path=/usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server
bootstrap_roots_directory="$bootstrap_directory/trust-roots"
timesyncd_config_guest=/etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf
bootstrap_uploads=(
	--upload "$bootstrap_anchor:$bootstrap_directory/anchor.json"
	--upload "$bootstrap_identity:$bootstrap_directory/identity.json"
)
root_index=1
for bootstrap_root in "${bootstrap_roots[@]}"; do
	printf -v bootstrap_root_name '%03d.pem' "$root_index"
	bootstrap_root_guest_path="$bootstrap_roots_directory/$bootstrap_root_name"
	bootstrap_uploads+=(--upload "$bootstrap_root:$bootstrap_root_guest_path")
	root_index=$((root_index + 1))
done

bootstrap_directory_setup=$(cat <<'COMMAND'
set -eu
install -d -o root -g root -m 0755 /etc/terrascale-orchestrator
install -d -o root -g root -m 0755 /etc/terrascale-orchestrator/bootstrap/trust-roots
[ ! -e /etc/terrascale-orchestrator/host-enrollment-public.json ] &&
	[ ! -L /etc/terrascale-orchestrator/host-enrollment-public.json ] || {
	echo 'base image has a conflicting host enrollment public bundle' >&2
	exit 1
}
rm -f /etc/terrascale-orchestrator/bootstrap/anchor.json /etc/terrascale-orchestrator/bootstrap/identity.json
find /etc/terrascale-orchestrator/bootstrap/trust-roots -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
COMMAND
)
runtime_priority_setup=$(cat <<'COMMAND'
set -eu
for runtime_priority_file in \
	/etc/terrascale-orchestrator/runtime-priority.json \
	/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf \
	/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf \
	/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf \
	/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py; do
	[ ! -e "$runtime_priority_file" ] && [ ! -L "$runtime_priority_file" ] || {
		echo "base image has a conflicting runtime-priority profile artifact: $runtime_priority_file" >&2
		exit 1
	}
done
install -d -o root -g root -m 0755 /etc/terrascale-orchestrator
install -d -o root -g root -m 0755 /etc/systemd/system/system.slice.d
install -d -o root -g root -m 0755 /etc/systemd/system/terrascale-orchestrator-host.service.d
install -d -o root -g root -m 0755 /etc/systemd/system/terrascale-orchestrator-controller.service.d
install -d -o root -g root -m 0755 /usr/local/lib/terrascale-orchestrator/runtime-priority
COMMAND
)
native_verifier_setup=$(cat <<'COMMAND'
set -eu
for directory in / /usr /usr/local /usr/local/lib /usr/local/lib/terrascale-orchestrator; do
	[ ! -L "$directory" ] && [ -d "$directory" ] && [ "$(stat -c '%u' "$directory")" = 0 ] || {
		echo "native verifier parent must be a root-owned nonwritable directory: $directory" >&2
		exit 1
	}
	mode=$(stat -c '%a' "$directory") || exit 1
	[ $((0$mode & 022)) -eq 0 ] || {
		echo "native verifier parent is writable by group or other: $directory" >&2
		exit 1
	}
done
native_directory=/usr/local/lib/terrascale-orchestrator/managed-material
[ ! -e "$native_directory" ] && [ ! -L "$native_directory" ] || {
	echo "base image has a conflicting managed-material verifier directory" >&2
	exit 1
}
install -d -o root -g root -m 0755 "$native_directory"
COMMAND
)
time_sync_setup=$(cat <<'COMMAND'
set -eu
check_timesyncd_config_file() {
	config_file=$1
	[ -e "$config_file" ] || [ -L "$config_file" ] || return 0
	if [ -L "$config_file" ] && [ ! -e "$config_file" ]; then
		echo "unresolvable systemd timesyncd config symlink: $config_file" >&2
		return 1
	fi
	if awk '
		{
			line = $0
			sub(/^[[:space:]]+/, "", line)
			if (line == "" || line ~ /^[#;]/) next
			if (line ~ /^\[/) {
				section = line
				sub(/^\[/, "", section)
				sub(/\].*$/, "", section)
				sub(/^[[:space:]]+/, "", section)
				sub(/[[:space:]]+$/, "", section)
				in_time = (section == "Time")
				next
			}
			if (in_time && line ~ /^(NTP|FallbackNTP)[[:space:]]*=/) found = 1
		}
		END { exit(found ? 0 : 1) }
	' "$config_file"; then
		echo "base image has active NTP/FallbackNTP configuration: $config_file" >&2
		return 1
	else
		inspect_status=$?
		if [ "$inspect_status" -ne 1 ]; then
			echo "could not inspect systemd timesyncd config: $config_file" >&2
			return 1
		fi
	fi
}

timesyncd_main_config=/etc/systemd/timesyncd.conf
if [ ! -e "$timesyncd_main_config" ] && [ ! -L "$timesyncd_main_config" ]; then
	timesyncd_main_config=/usr/lib/systemd/timesyncd.conf
fi
check_timesyncd_config_file "$timesyncd_main_config"

for config_file in \
	/etc/systemd/timesyncd.conf.d/*.conf \
	/run/systemd/timesyncd.conf.d/*.conf \
	/usr/local/lib/systemd/timesyncd.conf.d/*.conf \
	/usr/lib/systemd/timesyncd.conf.d/*.conf; do
	[ -e "$config_file" ] || [ -L "$config_file" ] || continue
	config_name=${config_file##*/}
	case "$config_file" in
		/etc/systemd/timesyncd.conf.d/*)
			;;
		/run/systemd/timesyncd.conf.d/*)
			if [ -e "/etc/systemd/timesyncd.conf.d/$config_name" ] || [ -L "/etc/systemd/timesyncd.conf.d/$config_name" ]; then
				continue
			fi
			;;
		/usr/local/lib/systemd/timesyncd.conf.d/*)
			if [ -e "/etc/systemd/timesyncd.conf.d/$config_name" ] || [ -L "/etc/systemd/timesyncd.conf.d/$config_name" ] ||
				[ -e "/run/systemd/timesyncd.conf.d/$config_name" ] || [ -L "/run/systemd/timesyncd.conf.d/$config_name" ]; then
				continue
			fi
			;;
		/usr/lib/systemd/timesyncd.conf.d/*)
			if [ -e "/etc/systemd/timesyncd.conf.d/$config_name" ] || [ -L "/etc/systemd/timesyncd.conf.d/$config_name" ] ||
				[ -e "/run/systemd/timesyncd.conf.d/$config_name" ] || [ -L "/run/systemd/timesyncd.conf.d/$config_name" ] ||
				[ -e "/usr/local/lib/systemd/timesyncd.conf.d/$config_name" ] || [ -L "/usr/local/lib/systemd/timesyncd.conf.d/$config_name" ]; then
				continue
			fi
			;;
	esac
	check_timesyncd_config_file "$config_file"
done

install -d -o root -g root -m 0755 /etc/systemd/timesyncd.conf.d
install -d -o root -g root -m 0755 /etc/systemd/system/systemd-time-wait-sync.service.d
cat > /etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf <<'TIMEOUT'
[Service]
TimeoutStartSec=300s
TIMEOUT
chown root:root /etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf
chmod 0644 /etc/systemd/system/systemd-time-wait-sync.service.d/terrascale-timeout.conf
COMMAND
)
bootstrap_permissions_setup=$(cat <<'COMMAND'
set -eu
if getent passwd 2000 >/dev/null || getent group 2000 >/dev/null ||
	getent passwd terrascale-workload >/dev/null || getent group terrascale-workload >/dev/null; then
	echo 'base image already uses the reserved managed workload UID, GID, or name' >&2
	exit 1
fi
systemd-sysusers /etc/sysusers.d/terrascale-orchestrator.conf
[ "$(id -u terrascale-workload)" = 2000 ] &&
	[ "$(id -g terrascale-workload)" = 2000 ] &&
	[ "$(getent group terrascale-workload | cut -d: -f3)" = 2000 ] || {
	echo 'managed workload identity was not created as UID/GID 2000:2000' >&2
	exit 1
}
chown root:root /etc/terrascale-orchestrator/bootstrap /etc/terrascale-orchestrator/bootstrap/trust-roots
chmod 0755 /etc/terrascale-orchestrator/bootstrap /etc/terrascale-orchestrator/bootstrap/trust-roots
chown root:root /etc/terrascale-orchestrator/bootstrap/anchor.json /etc/terrascale-orchestrator/bootstrap/identity.json /etc/terrascale-orchestrator/bootstrap/trust-roots/*.pem
chmod 0444 /etc/terrascale-orchestrator/bootstrap/anchor.json /etc/terrascale-orchestrator/bootstrap/identity.json /etc/terrascale-orchestrator/bootstrap/trust-roots/*.pem
install -d -o root -g root -m 0755 /var/lib/terrascale-orchestrator-bootstrap
install -d -o terrascale-orchestrator -g terrascale-orchestrator -m 0700 /var/lib/terrascale-orchestrator-secrets
install -d -o terrascale-orchestrator -g terrascale-orchestrator -m 0700 /var/lib/terrascale-orchestrator-controller
chown root:root /etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf
chown root:root \
	/etc/terrascale-orchestrator/runtime-priority.json \
	/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf \
	/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf \
	/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf \
	/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py
chown root:root /usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server
chmod 0755 /usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server
[ ! -L /usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server ] &&
	[ -f /usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server ] &&
	[ "$(stat -c '%u:%g:%a:%h' /usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server)" = '0:0:755:1' ] || {
	echo 'installed native verifier has unexpected ownership, mode, or link count' >&2
	exit 1
}
chmod 0644 \
	/etc/terrascale-orchestrator/runtime-priority.json \
	/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf \
	/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf \
	/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf
chmod 0755 /usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py
SYSTEMD_OFFLINE=1 systemctl enable systemd-timesyncd.service systemd-time-wait-sync.service terrascale-orchestrator-controller.service terrascale-orchestrator-host.service
if [ -f /etc/terrascale-orchestrator/host-enrollment-public.json ]; then
	chown root:root /etc/terrascale-orchestrator/host-enrollment-public.json \
		/etc/systemd/system/terrascale-orchestrator-host-setup.service \
		/etc/systemd/system/terrascale-orchestrator-host-setup.timer
	chmod 0444 /etc/terrascale-orchestrator/host-enrollment-public.json
	chmod 0644 /etc/systemd/system/terrascale-orchestrator-host-setup.service \
		/etc/systemd/system/terrascale-orchestrator-host-setup.timer
	SYSTEMD_OFFLINE=1 systemctl enable terrascale-orchestrator-host-setup.service terrascale-orchestrator-host-setup.timer
fi
for time_unit in systemd-timesyncd.service systemd-time-wait-sync.service; do
	time_unit_state=$(SYSTEMD_OFFLINE=1 systemctl is-enabled "$time_unit") || {
		echo "required time-sync unit is not enabled: $time_unit" >&2
		exit 1
	}
	[[ "$time_unit_state" == enabled ]] || {
		echo "required time-sync unit has unexpected enablement state: $time_unit ($time_unit_state)" >&2
		exit 1
	}
done
COMMAND
)
managed_root_commands=()
if [[ -n "$host_enrollment_public" ]]; then
	managed_root_setup=$(cat <<'COMMAND'
set -eu
[ ! -L /srv ] && [ -d /srv ] && [ "$(stat -c '%u:%g:%a' /srv)" = '0:0:755' ] || {
	echo 'base /srv must be a direct root:root 0755 directory' >&2
	exit 1
}
[ ! -e /srv/ts-managed ] && [ ! -L /srv/ts-managed ] || {
	echo 'base /srv/ts-managed must be absent' >&2
	exit 1
}
install -d -o root -g terrascale-workload -m 0750 /srv/ts-managed
[ "$(stat -c '%u:%g:%a' /srv/ts-managed)" = '0:2000:750' ]
COMMAND
	)
	managed_root_commands=(--run-command "$managed_root_setup")
fi
virt-customize --no-network -a "$candidate" \
	--run-command "$bootstrap_directory_setup" \
	--run-command "$runtime_priority_setup" \
	--run-command "$native_verifier_setup" \
	--run-command "$time_sync_setup" \
	--upload deploy/image/terrascale-orchestrator.sysusers:/etc/sysusers.d/terrascale-orchestrator.conf \
	--upload deploy/systemd/terrascale-orchestrator-bootstrap.service:/etc/systemd/system/terrascale-orchestrator-bootstrap.service \
	--upload deploy/systemd/terrascale-orchestrator-controller-install.service:/etc/systemd/system/terrascale-orchestrator-controller-install.service \
	--upload deploy/systemd/terrascale-orchestrator-controller.service:/etc/systemd/system/terrascale-orchestrator-controller.service \
	--upload deploy/systemd/terrascale-orchestrator-host.service:/etc/systemd/system/terrascale-orchestrator-host.service \
	"${host_setup_uploads[@]}" \
	--upload "$runtime_priority_root/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf:/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf" \
	--upload "$runtime_priority_root/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf:/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf" \
	--upload "$runtime_priority_root/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf:/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf" \
	--upload "$runtime_priority_profile:/etc/terrascale-orchestrator/runtime-priority.json" \
	--upload tests/runtime_priority/qualify.py:/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py \
	--upload "$binary:/usr/local/bin/terrascale-orchestrator" \
	--upload "$native_verifier_binary:$native_verifier_guest_path" \
	--upload "$timesyncd_config_image:$timesyncd_config_guest" \
	"${bootstrap_uploads[@]}" \
	--run-command "$bootstrap_permissions_setup" \
	"${managed_root_commands[@]}" \
	--run-command 'chmod 0644 /etc/sysusers.d/terrascale-orchestrator.conf /etc/systemd/system/terrascale-orchestrator-bootstrap.service /etc/systemd/system/terrascale-orchestrator-controller-install.service /etc/systemd/system/terrascale-orchestrator-controller.service /etc/systemd/system/terrascale-orchestrator-host.service /etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf && chmod 0755 /usr/local/bin/terrascale-orchestrator'
qemu-img check -- "$candidate"
installed_verifier_sha256=$(virt-cat -a "$candidate" "$native_verifier_guest_path" | python3 -c '
import hashlib
import sys
digest = hashlib.sha256()
for chunk in iter(lambda: sys.stdin.buffer.read(1 << 20), b""):
	digest.update(chunk)
print(digest.hexdigest())
')
if [[ "$installed_verifier_sha256" != "$native_verifier_sha256" ]]; then
	echo "installed native verifier bytes do not match the supplied SHA-256" >&2
	exit 1
fi
printf 'native verifier image sha256=%s guest_path=%s\n' "$installed_verifier_sha256" "$native_verifier_guest_path"
if [[ -n "$host_enrollment_public" ]]; then
	installed_host_enrollment_sha256=$(virt-cat -a "$candidate" /etc/terrascale-orchestrator/host-enrollment-public.json | python3 -c '
import hashlib
import sys
digest = hashlib.sha256()
for chunk in iter(lambda: sys.stdin.buffer.read(1 << 20), b""):
	digest.update(chunk)
print(digest.hexdigest())
')
	if [[ "$installed_host_enrollment_sha256" != "$host_enrollment_public_sha256" ]]; then
		echo "installed host enrollment bundle differs from the reviewed SHA-256" >&2
		exit 1
	fi
	printf 'host enrollment image sha256=%s guest_path=%s\n' \
		"$installed_host_enrollment_sha256" /etc/terrascale-orchestrator/host-enrollment-public.json
fi
ln -- "$candidate" "$output"
trap - EXIT
rm -rf -- "$temporary_directory"
printf 'offline QCOW2 candidate created at %s\n' "$output"
