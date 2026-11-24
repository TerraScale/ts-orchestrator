#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

readonly orch_root=/opt/ts-orch
readonly data_device=/dev/oracleoci/oraclevdb
readonly -a apt_lock_opts=(-o DPkg::Lock::Timeout=300)

case "$(uname -m)" in
  x86_64)
    deb_arch=amd64
    dotnet_rid=linux-x64
    dotnet_sha512=4f94d65a7c534b82d25153e1c740d1a87d9bcbc9187935d69fb14f9dde5fb284e69302bde3fe2818ff96e9ac0c62d4385aaa68d8f6f3cb6002aa39c859a252f3
    ;;
  aarch64)
    deb_arch=arm64
    dotnet_rid=linux-arm64
    dotnet_sha512=11a625c5a16627cfb301795670f3ee21deb40b0d1f16aca401251b3b5ab10205cb5ef84cdaa2725a4e6a9a627ecb9ee582318b76081503975fedab884ef7ea48
    ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

if [[ ! -f /etc/ts-orch-baked ]]; then
  apt-get "${apt_lock_opts[@]}" update
  apt-get "${apt_lock_opts[@]}" install -y --no-install-recommends ca-certificates curl jq gnupg libicu74 iptables-persistent
fi

metadata="$(curl -fsS -H 'Authorization: Bearer Oracle' http://169.254.169.254/opc/v2/instance/metadata/)"
pool="$(jq -r '.ts_pool' <<<"$metadata")"
vcn_cidr="$(jq -r '.ts_vcn_cidr' <<<"$metadata")"
netbird_udp_ports="$(jq -r '.ts_netbird_udp_ports // empty' <<<"$metadata")"
release_tag="$(jq -r '.ts_orch_release_tag // empty' <<<"$metadata")"
bundle_url="$(jq -r '.ts_orch_bundle_url' <<<"$metadata")"
bundle_sha256="$(jq -r '.ts_orch_bundle_sha256' <<<"$metadata")"
release_version="${release_tag:-$bundle_sha256}"

case "$pool" in
  stateful | worker) ;;
  *)
    echo "unknown ts_pool metadata: $pool" >&2
    exit 1
    ;;
esac

iptables -I INPUT -i wt0 -j ACCEPT
iptables -I INPUT -i docker0 -p tcp -m multiport --dports 18081,18082 -j ACCEPT
iptables -I INPUT -p tcp -m multiport --dports 80,443,5432 -j ACCEPT
iptables -I INPUT -p udp --dport 443 -j ACCEPT
iptables -I INPUT -s "$vcn_cidr" -j ACCEPT
iptables -I INPUT -p udp -m multiport --dports "51820${netbird_udp_ports:+,$netbird_udp_ports}" -j ACCEPT
iptables -N DOCKER-USER 2>/dev/null || true
iptables -F DOCKER-USER
iptables -A DOCKER-USER -d 169.254.169.254/32 -p udp --dport 53 -j RETURN
iptables -A DOCKER-USER -d 169.254.169.254/32 -p tcp --dport 53 -j RETURN
iptables -A DOCKER-USER -d 169.254.0.0/16 -j REJECT
iptables -A DOCKER-USER -j RETURN
netfilter-persistent save

download_dir="$(mktemp -d)"
curl -fsSL -o "$download_dir/ts-orch.tar.gz" "$bundle_url"
echo "$bundle_sha256  $download_dir/ts-orch.tar.gz" | sha256sum -c -
release_dir="$orch_root/releases/$release_version"
install -d -m 0755 "$release_dir"
tar -xzf "$download_dir/ts-orch.tar.gz" -C "$release_dir"
ln -sfn "releases/$release_version" "$orch_root/current"
rm -rf "$download_dir"

install -d -m 0755 /etc/docker
install -m 0644 "$orch_root/current/docker-daemon.json" /etc/docker/daemon.json

if [[ ! -f /etc/ts-orch-baked ]]; then
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
  curl -fsSL "https://pkgs.netbird.io/debian/public.key" -o /etc/apt/keyrings/netbird.asc
  chmod 0644 /etc/apt/keyrings/netbird.asc
  echo "deb [signed-by=/etc/apt/keyrings/netbird.asc] https://pkgs.netbird.io/debian stable main" >/etc/apt/sources.list.d/netbird.list

  apt-get "${apt_lock_opts[@]}" update
  apt-get "${apt_lock_opts[@]}" install -y --no-install-recommends docker-ce docker-ce-cli containerd.io libmsquic netbird systemd-oomd

  dotnet_dir="$(mktemp -d)"
  curl -fsSL "https://builds.dotnet.microsoft.com/dotnet/aspnetcore/Runtime/11.0.0/aspnetcore-runtime-11.0.0-${dotnet_rid}.tar.gz" -o "$dotnet_dir/aspnetcore.tar.gz"
  echo "${dotnet_sha512}  ${dotnet_dir}/aspnetcore.tar.gz" | sha512sum -c -
  install -d -m 0755 /usr/share/dotnet
  tar -xzf "$dotnet_dir/aspnetcore.tar.gz" -C /usr/share/dotnet
  ln -sfn /usr/share/dotnet/dotnet /usr/bin/dotnet
  rm -rf "$dotnet_dir"
fi

systemctl enable --now docker.service systemd-oomd.service netbird.service

install -m 0644 "$orch_root"/current/systemd/*.slice "$orch_root"/current/systemd/*.service "$orch_root"/current/systemd/*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now ts-orch-netbird.timer
systemctl start --no-block ts-orch-netbird.service

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
