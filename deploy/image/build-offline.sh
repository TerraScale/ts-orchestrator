#!/usr/bin/env bash
set -euo pipefail
repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
cd "$repository_root"

usage() {
	cat >&2 <<'USAGE'
usage: build-offline.sh --base QCOW2 --binary FILE --receipt FILE --qualification FILE \
  --delegation FILE --root-key PEM --environment canary|production \
  --release-tool FILE --bootstrap-tool FILE --bootstrap-anchor FILE \
  --bootstrap-identity FILE --bootstrap-root PEM... --timesyncd-config FILE \
  --runtime-priority-profile-id TOKEN --runtime-priority-system-reserve-bytes BYTES \
  --host-memory-min-bytes BYTES --host-memory-low-bytes BYTES \
  --controller-memory-min-bytes BYTES --controller-memory-low-bytes BYTES \
  --system-slice-memory-min-bytes BYTES --system-slice-memory-low-bytes BYTES \
  [--managed-workload-gid NONZERO_GID] --out QCOW2

Creates a local QCOW2 candidate from a verified, pinned offline base image.
It makes no OCI calls and installs no private keys or runtime secrets. The
release root key verifies the binary; repeatable bootstrap root keys verify
the baked anchor and are installed as public trust roots. The explicit
timesyncd configuration supplies deployment NTP endpoints; no endpoint is
selected or installed by default.
The optional managed workload GID provisions /srv/ts-managed as root:GID 0750.
It must match host.workload_gid when host.managed_runtime_root uses that path.
For another managed root, omit --managed-workload-gid, provision root:GID 0750,
and use a host-service systemd drop-in that resets the canonical exception:
[Service]
ReadWritePaths=
ReadWritePaths=-/absolute/custom/root
Install the drop-in before starting the host.

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
managed_workload_gid=
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
		--managed-workload-gid) managed_workload_gid=${2:?}; shift 2 ;;
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

if [[ -z "$base" || -z "$binary" || -z "$receipt" || -z "$qualification" || -z "$delegation" || -z "$root_key" ||
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
for command in cat cp ln mktemp python3 qemu-img realpath virt-customize; do
	command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
if [[ -n "$managed_workload_gid" ]]; then
	python3 - "$managed_workload_gid" <<'PY'
import re
import sys

value = sys.argv[1]
if not re.fullmatch(r"[1-9][0-9]{0,9}", value) or int(value) >= 4294967295:
	raise SystemExit("managed workload GID must be a canonical nonzero Linux GID")
PY
fi
[[ -x "$release_tool" ]] || { echo "release tool must be executable" >&2; exit 1; }
[[ -x "$bootstrap_tool" ]] || { echo "bootstrap tool must be executable" >&2; exit 1; }
base=$(realpath -e -- "$base")
binary=$(realpath -e -- "$binary")
receipt=$(realpath -e -- "$receipt")
qualification=$(realpath -e -- "$qualification")
delegation=$(realpath -e -- "$delegation")
root_key=$(realpath -e -- "$root_key")
bootstrap_tool=$(realpath -e -- "$bootstrap_tool")
bootstrap_anchor=$(realpath -e -- "$bootstrap_anchor")
bootstrap_identity=$(realpath -e -- "$bootstrap_identity")
timesyncd_config=$(realpath -e -- "$timesyncd_config")
release_tool=$(realpath -e -- "$release_tool")
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

python3 - \
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
PY

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
systemd-sysusers /etc/sysusers.d/terrascale-orchestrator.conf
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
chmod 0644 \
	/etc/terrascale-orchestrator/runtime-priority.json \
	/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf \
	/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf \
	/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf
chmod 0755 /usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py
SYSTEMD_OFFLINE=1 systemctl enable systemd-timesyncd.service systemd-time-wait-sync.service terrascale-orchestrator-controller.service terrascale-orchestrator-host.service
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
if [[ -n "$managed_workload_gid" ]]; then
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
install -d -o root -g __MANAGED_GID__ -m 0750 /srv/ts-managed
[ "$(stat -c '%u:%g:%a' /srv/ts-managed)" = '0:__MANAGED_GID__:750' ]
COMMAND
	)
	managed_root_setup=${managed_root_setup//__MANAGED_GID__/$managed_workload_gid}
	managed_root_commands=(--run-command "$managed_root_setup")
fi
virt-customize --no-network -a "$candidate" \
	--run-command "$bootstrap_directory_setup" \
	--run-command "$runtime_priority_setup" \
	--run-command "$time_sync_setup" \
	"${managed_root_commands[@]}" \
	--upload deploy/image/terrascale-orchestrator.sysusers:/etc/sysusers.d/terrascale-orchestrator.conf \
	--upload deploy/systemd/terrascale-orchestrator-bootstrap.service:/etc/systemd/system/terrascale-orchestrator-bootstrap.service \
	--upload deploy/systemd/terrascale-orchestrator-controller.service:/etc/systemd/system/terrascale-orchestrator-controller.service \
	--upload deploy/systemd/terrascale-orchestrator-host.service:/etc/systemd/system/terrascale-orchestrator-host.service \
	--upload "$runtime_priority_root/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf:/etc/systemd/system/system.slice.d/50-terrascale-memory-protection.conf" \
	--upload "$runtime_priority_root/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf:/etc/systemd/system/terrascale-orchestrator-host.service.d/50-terrascale-memory-protection.conf" \
	--upload "$runtime_priority_root/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf:/etc/systemd/system/terrascale-orchestrator-controller.service.d/50-terrascale-memory-protection.conf" \
	--upload "$runtime_priority_profile:/etc/terrascale-orchestrator/runtime-priority.json" \
	--upload tests/runtime_priority/qualify.py:/usr/local/lib/terrascale-orchestrator/runtime-priority/qualify.py \
	--upload "$binary:/usr/local/bin/terrascale-orchestrator" \
	--upload "$timesyncd_config_image:$timesyncd_config_guest" \
	"${bootstrap_uploads[@]}" \
	--run-command "$bootstrap_permissions_setup" \
	--run-command 'chmod 0644 /etc/sysusers.d/terrascale-orchestrator.conf /etc/systemd/system/terrascale-orchestrator-bootstrap.service /etc/systemd/system/terrascale-orchestrator-controller.service /etc/systemd/system/terrascale-orchestrator-host.service /etc/systemd/timesyncd.conf.d/99-terrascale-orchestrator.conf && chmod 0755 /usr/local/bin/terrascale-orchestrator'
qemu-img check -- "$candidate"
ln -- "$candidate" "$output"
trap - EXIT
rm -rf -- "$temporary_directory"
printf 'offline QCOW2 candidate created at %s\n' "$output"
