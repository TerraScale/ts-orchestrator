#!/usr/bin/env bash
set -euo pipefail
repository_root=$(cd -- "$(dirname -- "$(realpath -- "$0")")/../.." && pwd)
cd "$repository_root"

usage() {
	cat >&2 <<'USAGE'
usage: build-offline.sh --base QCOW2 --kernel-release RELEASE \
  --binary FILE --qualification FILE --source-revision SHA \
  --native-verifier-binary FILE --native-verifier-sha256 LOWERCASE_HEX \
  --release-tool FILE --bootstrap-root PEM... --timesyncd-config FILE \
  --runtime-priority-profile-id TOKEN --runtime-priority-system-reserve-bytes BYTES \
  --host-memory-min-bytes BYTES --host-memory-low-bytes BYTES \
  --controller-memory-min-bytes BYTES --controller-memory-low-bytes BYTES \
  --system-slice-memory-min-bytes BYTES --system-slice-memory-low-bytes BYTES \
  --out QCOW2 --kernel-out FILE

Creates a local QCOW2 candidate from a verified, pinned offline base image.
It makes no OCI calls and installs no private keys or runtime secrets.
`ts-release binary-candidate` checks the orchestrator binary against its CI
qualification manifest and exact source revision: static ARM64 ELF, Go
toolchain, clean embedded VCS revision, size and SHA-256. The binary's signed
release receipt is checked when the image is promoted (`image-candidate`,
`sign-image`), not here, so every qualified CI candidate can be imaged
without waiting for a signer.

Repeatable bootstrap root keys are installed as the only public trust roots.
The image is deployment-neutral: it carries no deployment identity, signed
anchor or host enrollment bundle. Each controller and host receives those in
OCI launch metadata and verifies them against these roots. The explicit
timesyncd configuration supplies deployment NTP endpoints; no endpoint is
selected or installed by default.

The base image must contain exactly one /boot/vmlinuz-RELEASE AArch64 kernel
with its /lib/modules/RELEASE directory. The builder writes that kernel to
--kernel-out; image receipts sign it together with the QCOW2.

The native verifier is the exact qualified TerraBase ARM64 tb-server artifact.
Its SHA-256 must match the independently supplied artifact digest; the image
installs it at the fixed managed-material verifier path. This digest is
separate from the orchestrator binary receipt's BinarySHA256.

Every image can serve as a controller or a managed host. It reserves workload
UID/GID 2000:2000, uses separate install and state roots under
/var/lib/terrascale-orchestrator-host, and provisions /srv/ts-managed as
root:2000 0750 for persistent member volumes.

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
kernel_release=
binary=
qualification=
source_revision=
native_verifier_binary=
native_verifier_sha256=
release_tool=
bootstrap_roots=()
timesyncd_config=
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
timesyncd_config_max_bytes=16384
output=
kernel_output=
while (($#)); do
	case "$1" in
		--base) base=${2:?}; shift 2 ;;
		--kernel-release) kernel_release=${2:?}; shift 2 ;;
		--binary) binary=${2:?}; shift 2 ;;
		--qualification) qualification=${2:?}; shift 2 ;;
		--source-revision) source_revision=${2:?}; shift 2 ;;
		--native-verifier-binary) native_verifier_binary=${2:?}; shift 2 ;;
		--native-verifier-sha256) native_verifier_sha256=${2:?}; shift 2 ;;
		--release-tool) release_tool=${2:?}; shift 2 ;;
		--bootstrap-root) bootstrap_roots+=("${2:?}"); shift 2 ;;
		--timesyncd-config) timesyncd_config=${2:?}; shift 2 ;;
		--runtime-priority-profile-id) runtime_priority_profile_id=${2:?}; shift 2 ;;
		--runtime-priority-system-reserve-bytes) runtime_priority_system_reserve_bytes=${2:?}; shift 2 ;;
		--host-memory-min-bytes) host_memory_min_bytes=${2:?}; shift 2 ;;
		--host-memory-low-bytes) host_memory_low_bytes=${2:?}; shift 2 ;;
		--controller-memory-min-bytes) controller_memory_min_bytes=${2:?}; shift 2 ;;
		--controller-memory-low-bytes) controller_memory_low_bytes=${2:?}; shift 2 ;;
		--system-slice-memory-min-bytes) system_slice_memory_min_bytes=${2:?}; shift 2 ;;
		--system-slice-memory-low-bytes) system_slice_memory_low_bytes=${2:?}; shift 2 ;;
		--out) output=${2:?}; shift 2 ;;
		--kernel-out) kernel_output=${2:?}; shift 2 ;;
		*) usage; exit 2 ;;
	esac
done

if [[ -z "$base" || -z "$kernel_release" || -z "$binary" || -z "$qualification" ||
	-z "$source_revision" || -z "$native_verifier_binary" || -z "$native_verifier_sha256" ||
	-z "$release_tool" || ${#bootstrap_roots[@]} -eq 0 || -z "$timesyncd_config" ||
	-z "$output" || -z "$kernel_output" ||
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
if [[ ! $source_revision =~ ^[0-9a-f]{40}$ ]]; then
	echo "source revision must be a full lowercase Git SHA-1" >&2
	exit 2
fi
if [[ ! $kernel_release =~ ^[0-9][A-Za-z0-9._+-]{0,127}$ ]]; then
	echo "kernel release must be a plain Linux release string" >&2
	exit 2
fi
if [[ ! $native_verifier_sha256 =~ ^[0-9a-f]{64}$ ]]; then
	echo "native verifier SHA-256 must be 64 lowercase hex characters" >&2
	exit 2
fi
for command in cat cp ln mktemp python3 qemu-img realpath sha256sum; do
	command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
if [[ -n ${TS_OFFLINE_GUESTFS_RUNNER:-} ]]; then
	[[ -x $TS_OFFLINE_GUESTFS_RUNNER ]] || {
		echo "offline guestfs runner must be executable" >&2
		exit 1
	}
else
	for command in guestfish systemctl systemd-sysusers; do
		command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
	done
fi
[[ -x "$release_tool" ]] || { echo "release tool must be executable" >&2; exit 1; }
base=$(realpath -e -- "$base")
binary=$(realpath -e -- "$binary")
native_verifier_binary=$(realpath -e -- "$native_verifier_binary")
[[ -f "$native_verifier_binary" ]] || { echo "native verifier must be a regular file" >&2; exit 1; }
qualification=$(realpath -e -- "$qualification")
timesyncd_config=$(realpath -e -- "$timesyncd_config")
release_tool=$(realpath -e -- "$release_tool")
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
kernel_output="$(realpath -e -- "$(dirname -- "$kernel_output")")/$(basename -- "$kernel_output")"
if [[ -e "$kernel_output" || -L "$kernel_output" || "$kernel_output" == "$output" ]]; then
	echo "kernel output must be a new path distinct from the image output" >&2
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

python3 - "$bootstrap_root_max_bytes" "$bootstrap_roots_max_total_bytes" "${bootstrap_roots[@]}" <<'PY'
import sys
from pathlib import Path

root_max_bytes, roots_total_max_bytes, *root_paths = sys.argv[1:]
root_max_bytes = int(root_max_bytes)
roots_total_max_bytes = int(roots_total_max_bytes)
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
	if section == "Time" and key in ("PollIntervalMinSec", "PollIntervalMaxSec"):
		# The kernel clock bound requires a short, image-pinned NTP poll interval.
		# Do not let the input image asset replace this safety setting.
		continue
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
normalized += "PollIntervalMinSec=32\nPollIntervalMaxSec=64\n"
normalized_path.write_bytes(normalized.encode("utf-8"))
PY

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
"$release_tool" binary-candidate \
	--binary "$binary" --source-revision "$source_revision" --qualification "$qualification" \
	--out "$temporary_directory/binary-candidate.json"
binary_sha256=$(sha256sum -- "$binary" | cut -d ' ' -f 1)
printf 'qualified orchestrator binary sha256=%s source=%s\n' "$binary_sha256" "$source_revision"
qemu-img check -- "$base"
qemu-img info --output=json -- "$base" | python3 -c '
import json, sys
image = json.load(sys.stdin)
if image.get("format") != "qcow2" or image.get("backing-filename"):
    raise SystemExit("base must be standalone QCOW2 with no backing file")
'

candidate="$temporary_directory/image.qcow2"
cp --reflink=auto --sparse=always -- "$base" "$candidate"

offline_args=(
	--image "$candidate"
	--kernel-release "$kernel_release"
	--kernel-out "$temporary_directory/guest-kernel"
	--work "$temporary_directory"
	--sysusers deploy/image/terrascale-orchestrator.sysusers
	--profile "$runtime_priority_profile"
	--priority-root "$runtime_priority_root"
	--binary "$binary"
	--native-verifier "$native_verifier_binary"
	--timesyncd-config "$timesyncd_config_image"
)
for bootstrap_root in "${bootstrap_roots[@]}"; do
	offline_args+=(--bootstrap-root "$bootstrap_root")
done
offline_guestfs_runner=${TS_OFFLINE_GUESTFS_RUNNER:-python3}
"$offline_guestfs_runner" deploy/image/offline-guestfs.py build "${offline_args[@]}"
qemu-img check -- "$candidate"
# One read-only appliance reads every executable and the kernel back from the
# final QCOW2, so a dropped or reordered write cannot yield a candidate.
kernel_sha256=$(sha256sum -- "$temporary_directory/guest-kernel" | cut -d ' ' -f 1)
"$offline_guestfs_runner" deploy/image/offline-guestfs.py verify --image "$candidate" \
	--expect "/usr/local/bin/terrascale-orchestrator=$binary_sha256" \
	--expect "/usr/local/lib/terrascale-orchestrator/managed-material/terrabase-server=$native_verifier_sha256" \
	--expect "/boot/vmlinuz-$kernel_release=$kernel_sha256"
cp -- "$temporary_directory/guest-kernel" "$kernel_output"
ln -- "$candidate" "$output"
trap - EXIT
rm -rf -- "$temporary_directory"
printf 'offline QCOW2 candidate created at %s kernel=%s sha256=%s\n' "$output" "$kernel_output" "$kernel_sha256"
