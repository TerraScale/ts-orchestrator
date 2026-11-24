#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLEET_JSON="$ROOT/deploy/fleet.json"
DAEMON_JSON="$ROOT/deploy/cloud-init/docker-daemon.json"
REGIONS_CSV=""
SHAPE="VM.Standard.A1.Flex"
OCPUS=2
MEMORY_GB=12
BOOT_GB=50
IMAGE_PREFIX="ts-orch-ubuntu-2404-arm64"
TIMEOUT_SECONDS=1200

usage() {
  echo "usage: $0 [--regions gru,fra,sjc] [--shape VM.Standard.A1.Flex] [--ocpus 2] [--memory-gb 12] [--boot-gb 50] [--prefix ts-orch-ubuntu-2404-arm64]" >&2
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --regions)
      [[ $# -ge 2 ]] || usage
      REGIONS_CSV="$2"
      shift 2
      ;;
    --shape)
      [[ $# -ge 2 ]] || usage
      SHAPE="$2"
      shift 2
      ;;
    --ocpus)
      [[ $# -ge 2 ]] || usage
      OCPUS="$2"
      shift 2
      ;;
    --memory-gb)
      [[ $# -ge 2 ]] || usage
      MEMORY_GB="$2"
      shift 2
      ;;
    --boot-gb)
      [[ $# -ge 2 ]] || usage
      BOOT_GB="$2"
      shift 2
      ;;
    --prefix)
      [[ $# -ge 2 ]] || usage
      IMAGE_PREFIX="$2"
      shift 2
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

for tool in oci jq base64 date; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done

[[ -f "$FLEET_JSON" ]] || { echo "missing fleet config: $FLEET_JSON" >&2; exit 1; }
[[ -f "$DAEMON_JSON" ]] || { echo "missing docker daemon config: $DAEMON_JSON" >&2; exit 1; }

TENANCY_ID="$(jq -er '.oci.tenancyId' "$FLEET_JSON")"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
GIT_SHA="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ts-orch-bake.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [[ -z "$REGIONS_CSV" ]]; then
  mapfile -t REGIONS < <(jq -r '.regions[].label' "$FLEET_JSON")
else
  IFS=',' read -r -a REGIONS <<<"$REGIONS_CSV"
fi

DAEMON_B64="$(base64 -w0 "$DAEMON_JSON")"
USER_DATA_FILE="$WORK/bake-cloud-init.sh"
{
  printf '\043!/usr/bin/env bash\n'
  cat <<EOF
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt_lock="-o DPkg::Lock::Timeout=300"
case "\$(uname -m)" in
  x86_64) deb_arch=amd64 ;;
  aarch64) deb_arch=arm64 ;;
  *) exit 1 ;;
esac
apt-get "\$apt_lock" update
apt-get "\$apt_lock" install -y --no-install-recommends ca-certificates curl jq gnupg software-properties-common iptables-persistent
install -d -m 0755 /etc/docker /etc/apt/keyrings
printf '%s' '$DAEMON_B64' | base64 -d >/etc/docker/daemon.json
chmod 0644 /etc/docker/daemon.json
. /etc/os-release
curl -fsSL "https://download.docker.com/linux/ubuntu/gpg" -o /etc/apt/keyrings/docker.asc
chmod 0644 /etc/apt/keyrings/docker.asc
echo "deb [arch=\$deb_arch signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \$VERSION_CODENAME stable" >/etc/apt/sources.list.d/docker.list
curl -fsSL "https://packages.microsoft.com/keys/microsoft.asc" -o /etc/apt/keyrings/microsoft.asc
chmod 0644 /etc/apt/keyrings/microsoft.asc
echo "deb [arch=\$deb_arch signed-by=/etc/apt/keyrings/microsoft.asc] https://packages.microsoft.com/ubuntu/\$VERSION_ID/prod \$VERSION_CODENAME main" >/etc/apt/sources.list.d/microsoft-prod.list
cat >/etc/apt/preferences.d/microsoft-prod <<'PIN'
Package: *
Pin: origin packages.microsoft.com
Pin-Priority: -10

Package: libmsquic
Pin: origin packages.microsoft.com
Pin-Priority: 500
PIN
curl -fsSL "https://pkgs.netbird.io/debian/public.key" -o /etc/apt/keyrings/netbird.asc
chmod 0644 /etc/apt/keyrings/netbird.asc
echo "deb [signed-by=/etc/apt/keyrings/netbird.asc] https://pkgs.netbird.io/debian stable main" >/etc/apt/sources.list.d/netbird.list
add-apt-repository -y ppa:dotnet/backports
apt-get "\$apt_lock" update
apt-get "\$apt_lock" install -y --no-install-recommends docker-ce docker-ce-cli containerd.io aspnetcore-runtime-11.0 libmsquic netbird systemd-oomd
apt-get "\$apt_lock" clean
rm -rf /var/lib/apt/lists/*
printf 'baked_at=%s\ngit_sha=%s\n' '$STAMP' '$GIT_SHA' >/etc/ts-orch-baked
chmod 0644 /etc/ts-orch-baked
rm -f /etc/ssh/ssh_host_* /home/ubuntu/.ssh/authorized_keys /root/.ssh/authorized_keys
truncate -s 0 /etc/machine-id
if [[ -f /var/lib/dbus/machine-id ]]; then
  truncate -s 0 /var/lib/dbus/machine-id
fi
cloud-init clean --logs || rm -rf /var/lib/cloud/instances
sync
systemctl poweroff
EOF
} >"$USER_DATA_FILE"

bake_region() {
  local label="$1"
  local oci_region compartment_id ad base_image vcn_id igw_id rt_id subnet_id instance_id image_id image_name
  oci_region="$(jq -er --arg label "$label" '.regions[] | select(.label == $label) | .ociRegion' "$FLEET_JSON")"
  compartment_id="$(jq -er --arg label "$label" '.regions[] | select(.label == $label) | .compartmentId' "$FLEET_JSON")"
  image_name="${IMAGE_PREFIX}-${label}-${STAMP}"
  vcn_id=""
  igw_id=""
  rt_id=""
  subnet_id=""
  instance_id=""

  cleanup_region() {
    set +e
    if [[ -n "$instance_id" ]]; then
      oci compute instance terminate --region "$oci_region" --instance-id "$instance_id" --preserve-boot-volume false --force --wait-for-state TERMINATED >/dev/null 2>&1 || true
    fi
    if [[ -n "$subnet_id" ]]; then
      oci network subnet delete --region "$oci_region" --subnet-id "$subnet_id" --force --wait-for-state TERMINATED >/dev/null 2>&1 || true
    fi
    if [[ -n "$rt_id" ]]; then
      oci network route-table update --region "$oci_region" --rt-id "$rt_id" --route-rules '[]' --force >/dev/null 2>&1 || true
    fi
    if [[ -n "$igw_id" ]]; then
      oci network internet-gateway delete --region "$oci_region" --ig-id "$igw_id" --force --wait-for-state TERMINATED >/dev/null 2>&1 || true
    fi
    if [[ -n "$vcn_id" ]]; then
      oci network vcn delete --region "$oci_region" --vcn-id "$vcn_id" --force --wait-for-state TERMINATED >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_region EXIT

  echo "[$label] resolving availability domain and Ubuntu 24.04 ARM64 image in $oci_region" >&2
  ad="$(oci iam availability-domain list --region "$oci_region" --compartment-id "$TENANCY_ID" --query 'data[0].name' --raw-output)"
  base_image="$(oci compute image list \
    --region "$oci_region" \
    --compartment-id "$compartment_id" \
    --operating-system "Canonical Ubuntu" \
    --operating-system-version "24.04" \
    --shape "$SHAPE" \
    --sort-by TIMECREATED \
    --sort-order DESC \
    --all \
    | jq -er '[.data[] | select(.["lifecycle-state"] == "AVAILABLE" and (.["display-name"] | test("^Canonical-Ubuntu-24\\.04-(aarch64-)?[0-9]{4}\\.")))][0].id')"

  echo "[$label] creating temporary builder network" >&2
  vcn_id="$(oci network vcn create \
    --region "$oci_region" \
    --compartment-id "$compartment_id" \
    --cidr-block "10.254.0.0/24" \
    --display-name "ts-bake-${label}-${STAMP}" \
    --wait-for-state AVAILABLE \
    --query 'data.id' \
    --raw-output)"
  igw_id="$(oci network internet-gateway create \
    --region "$oci_region" \
    --compartment-id "$compartment_id" \
    --vcn-id "$vcn_id" \
    --is-enabled true \
    --display-name "ts-bake-${label}-igw" \
    --wait-for-state AVAILABLE \
    --query 'data.id' \
    --raw-output)"
  rt_id="$(oci network vcn get --region "$oci_region" --vcn-id "$vcn_id" --query 'data."default-route-table-id"' --raw-output)"
  oci network route-table update \
    --region "$oci_region" \
    --rt-id "$rt_id" \
    --route-rules "[{\"destination\":\"0.0.0.0/0\",\"destinationType\":\"CIDR_BLOCK\",\"networkEntityId\":\"$igw_id\"}]" \
    --force >/dev/null
  subnet_id="$(oci network subnet create \
    --region "$oci_region" \
    --compartment-id "$compartment_id" \
    --vcn-id "$vcn_id" \
    --cidr-block "10.254.0.0/25" \
    --route-table-id "$rt_id" \
    --display-name "ts-bake-${label}-subnet" \
    --wait-for-state AVAILABLE \
    --query 'data.id' \
    --raw-output)"

  echo "[$label] launching builder VM ($SHAPE ${OCPUS} OCPU / ${MEMORY_GB} GiB)" >&2
  instance_id="$(oci compute instance launch \
    --region "$oci_region" \
    --compartment-id "$compartment_id" \
    --availability-domain "$ad" \
    --shape "$SHAPE" \
    --shape-config "{\"ocpus\":$OCPUS,\"memoryInGBs\":$MEMORY_GB}" \
    --image-id "$base_image" \
    --boot-volume-size-in-gbs "$BOOT_GB" \
    --subnet-id "$subnet_id" \
    --assign-public-ip true \
    --display-name "ts-bake-${label}-${STAMP}" \
    --user-data-file "$USER_DATA_FILE" \
    --wait-for-state RUNNING \
    --query 'data.id' \
    --raw-output)"

  echo "[$label] waiting for cloud-init bake and clean poweroff ($instance_id)" >&2
  local deadline=$((SECONDS + TIMEOUT_SECONDS))
  local state=""
  while (( SECONDS < deadline )); do
    state="$(oci compute instance get --region "$oci_region" --instance-id "$instance_id" --query 'data."lifecycle-state"' --raw-output)"
    if [[ "$state" == "STOPPED" ]]; then
      break
    fi
    if [[ "$state" == "TERMINATED" || "$state" == "TERMINATING" ]]; then
      echo "[$label] builder VM entered unexpected state: $state" >&2
      exit 1
    fi
    sleep 10
  done
  if [[ "$state" != "STOPPED" ]]; then
    echo "[$label] timed out after ${TIMEOUT_SECONDS}s waiting for builder VM to stop (state=$state)" >&2
    exit 1
  fi

  echo "[$label] capturing custom OCI image $image_name" >&2
  image_id="$(oci compute image create \
    --region "$oci_region" \
    --compartment-id "$compartment_id" \
    --instance-id "$instance_id" \
    --display-name "$image_name" \
    --wait-for-state AVAILABLE \
    --max-wait-seconds 1800 \
    --query 'data.id' \
    --raw-output)"

  echo "$image_id" >"$WORK/image-${label}.id"
  echo "[$label] custom image ready: $image_id" >&2
}

pids=()
for label in "${REGIONS[@]}"; do
  ( bake_region "$label" ) &
  pids+=("$!")
done

failed=0
for pid in "${pids[@]}"; do
  if ! wait "$pid"; then
    failed=1
  fi
done
if [[ $failed -ne 0 ]]; then
  echo "one or more regional image bakes failed" >&2
  exit 1
fi

result="{}"
for label in "${REGIONS[@]}"; do
  image_id="$(cat "$WORK/image-${label}.id")"
  result="$(jq --arg label "$label" --arg id "$image_id" '. + {($label): $id}' <<<"$result")"
done
printf '%s\n' "$result"
