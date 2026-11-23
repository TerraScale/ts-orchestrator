#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

readonly orch_root=/opt/ts-orch
readonly data_device=/dev/oracleoci/oraclevdb

case "$(uname -m)" in
  x86_64) deb_arch=amd64 ;;
  aarch64) deb_arch=arm64 ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

apt-get update
apt-get install -y --no-install-recommends ca-certificates curl jq gnupg software-properties-common iptables-persistent

metadata="$(curl -fsS -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/metadata/)"
pool="$(jq -r '.ts_pool' <<<"$metadata")"
vcn_cidr="$(jq -r '.ts_vcn_cidr' <<<"$metadata")"
netbird_udp_ports="$(jq -r '.ts_netbird_udp_ports // empty' <<<"$metadata")"
bundle_url="$(jq -r '.ts_orch_bundle_url' <<<"$metadata")"
bundle_sha256="$(jq -r '.ts_orch_bundle_sha256' <<<"$metadata")"

case "$pool" in
  stateful | worker) ;;
  *)
    echo "unknown ts_pool metadata: $pool" >&2
    exit 1
    ;;
esac

iptables -I INPUT -p tcp -m multiport --dports 80,443,5432 -j ACCEPT
iptables -I INPUT -p udp --dport 443 -j ACCEPT
iptables -I INPUT -s "$vcn_cidr" -j ACCEPT
if [[ -n "$netbird_udp_ports" ]]; then
  iptables -I INPUT -p udp -m multiport --dports "$netbird_udp_ports" -j ACCEPT
fi
iptables -N DOCKER-USER
iptables -A DOCKER-USER -d 169.254.169.254/32 -p udp --dport 53 -j RETURN
iptables -A DOCKER-USER -d 169.254.169.254/32 -p tcp --dport 53 -j RETURN
iptables -A DOCKER-USER -d 169.254.0.0/16 -j REJECT
netfilter-persistent save

download_dir="$(mktemp -d)"
curl -fsSL -o "$download_dir/ts-orch.tar.gz" "$bundle_url"
echo "$bundle_sha256  $download_dir/ts-orch.tar.gz" | sha256sum -c -
release_dir="$orch_root/releases/$bundle_sha256"
install -d -m 0755 "$release_dir"
tar -xzf "$download_dir/ts-orch.tar.gz" -C "$release_dir"
ln -sfn "$release_dir" "$orch_root/current"
rm -rf "$download_dir"

install -d -m 0755 /etc/docker
install -m 0644 "$orch_root/current/docker-daemon.json" /etc/docker/daemon.json

. /etc/os-release
install -d -m 0755 /etc/apt/keyrings
curl -fsSL "https://download.docker.com/linux/ubuntu/gpg" -o /etc/apt/keyrings/docker.asc
chmod 0644 /etc/apt/keyrings/docker.asc
echo "deb [arch=$deb_arch signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" >/etc/apt/sources.list.d/docker.list
curl -fsSL "https://packages.microsoft.com/keys/microsoft.asc" -o /etc/apt/keyrings/microsoft.asc
chmod 0644 /etc/apt/keyrings/microsoft.asc
echo "deb [arch=$deb_arch signed-by=/etc/apt/keyrings/microsoft.asc] https://packages.microsoft.com/ubuntu/$VERSION_ID/prod $VERSION_CODENAME main" >/etc/apt/sources.list.d/microsoft-prod.list
cat >/etc/apt/preferences.d/microsoft-prod <<'PIN'
Package: *
Pin: origin packages.microsoft.com
Pin-Priority: -10

Package: libmsquic
Pin: origin packages.microsoft.com
Pin-Priority: 500
PIN
add-apt-repository -y ppa:dotnet/backports

apt-get update
apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io aspnetcore-runtime-11.0 libmsquic systemd-oomd

systemctl enable --now docker.service systemd-oomd.service

install -m 0644 "$orch_root"/current/systemd/*.slice "$orch_root"/current/systemd/*.service /etc/systemd/system/
systemctl daemon-reload

if [[ "$pool" == stateful ]]; then
  install -d -m 0755 /etc/systemd/system/ts-orch-agent.service.d
  cat >/etc/systemd/system/ts-orch-agent.service.d/data-volume.conf <<'UNIT'
[Unit]
BindsTo=ts-data-volume.service
After=ts-data-volume.service
UNIT
  systemctl daemon-reload
  systemctl enable ts-data-volume.service
  systemctl add-wants ts-data-volume.service ts-orch-agent.service
  systemctl enable --now ts-orch-edge.service
  if [[ -b "$data_device" ]]; then
    systemctl start ts-data-volume.service
  fi
else
  systemctl enable --now ts-orch-edge.service ts-orch-agent.service
fi
