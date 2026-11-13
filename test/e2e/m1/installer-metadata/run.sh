set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
work=$(mktemp -d)
python=$(python3 -c 'import os,sys;print(os.path.realpath(sys.executable))')
nft=$(command -v nft)
real_curl=$(command -v curl)
trap 'sudo rm -rf "$work"' EXIT
mkdir "$work/etc"
for file in passwd group nsswitch.conf hosts resolv.conf; do
 cp -L "/etc/$file" "$work/etc/$file"
done
rm -rf "$work/etc/systemd" "$work/etc/terrascale-orchestrator"
mkdir -p "$work/etc/systemd/system" "$work/usr/local/bin" "$work/varlib" "$work/sys/class/dmi/id" "$work/run"
printf 'Local\n' > "$work/sys/class/dmi/id/chassis_asset_tag"
sudo -n unshare --mount --net bash -s -- "$bin" "$here" "$repo" "$work" "$python" "$nft" "$real_curl" <<'INNER'
set -euo pipefail
bin=$1
here=$2
repo=$3
work=$4
python=$5
nft=$6
real_curl=$7
mount --make-rprivate /
ip link set lo up
mount --bind "$work/etc" /etc
mount --bind "$work/usr" /usr
mount --bind "$work/varlib" /var/lib
mount --bind "$work/sys" /sys
current_system=$(readlink /run/current-system 2>/dev/null || true)
mount -t tmpfs -o mode=0755 tmpfs "$work/run"
if [[ -n $current_system ]]; then
 ln -s "$current_system" "$work/run/current-system"
fi
mount --bind "$work/run" /run
export lane_binary="$bin" lane_nft="$nft" python here
ssh() { "$python" "$here/tools.py" ssh "$@"; }
curl() { "$python" "$here/tools.py" curl "$@"; }
systemctl() { "$python" "$here/tools.py" systemctl "$@"; }
netbird() { return 0; }
export -f ssh curl systemctl netbird
ip netns add metadata-peer
ip link add metadata-host type veth peer name metadata-peer
ip link set metadata-peer netns metadata-peer
ip addr add 192.0.2.2/24 dev metadata-host
ip link set metadata-host up
ip netns exec metadata-peer ip link set lo up
ip netns exec metadata-peer ip addr add 192.0.2.1/24 dev metadata-peer
ip netns exec metadata-peer ip addr add 169.254.169.254/32 dev metadata-peer
ip netns exec metadata-peer ip link set metadata-peer up
ip route add 169.254.169.254/32 via 192.0.2.1
mkfifo "$work/ready"
ip netns exec metadata-peer "$python" "$here/metadata.py" > "$work/ready" &
metadata_pid=$!
trap 'kill "$metadata_pid"; ip netns del metadata-peer' EXIT
read -r ready < "$work/ready"
test "$ready" = ready
allow() { setpriv --reuid=32123 --regid=32123 --clear-groups "$real_curl" -fsS --noproxy "*" --max-time 2 -o /dev/null http://169.254.169.254/; }
deny() { if setpriv --reuid=65534 --regid=65534 --clear-groups "$real_curl" -fsS --noproxy "*" --max-time 1 -o /dev/null http://169.254.169.254/; then return 1; fi; }
sum=$(sha256sum "$bin" | cut -d' ' -f1)
install_host() { bash "$repo/deploy/m1/install.sh" lane https://example.com/binary "$sum"; }
rules=/etc/terrascale-orchestrator/ts-auth-metadata.nft
unit=terrascale-ts-auth-metadata.service
install_host
test -s "$rules"
systemctl restart "$unit"
"$nft" list chain inet terrascale_metadata output | grep -q 'ip daddr 169.254.169.254 counter.*drop'
deny
echo 'ok installer fresh: rules installed and metadata unit restart reloads them'
printf '\ninsert rule inet terrascale_metadata output ip daddr 169.254.169.254 meta skuid 32123 accept\nadd rule inet terrascale_metadata output ip daddr 192.0.2.1 counter accept\n' >> "$rules"
before=$(sha256sum "$rules")
install_host
test "$(sha256sum "$rules")" = "$before"
systemctl restart "$unit"
test "$(sha256sum "$rules")" = "$before"
"$nft" -n list chain inet terrascale_metadata output | grep -q 'ip daddr 169.254.169.254 meta skuid 32123 accept'
"$nft" -n list chain inet terrascale_metadata output | grep -q 'ip daddr 192.0.2.1 counter.*accept'
allow
deny
echo 'ok installer upgrade: persistent exception and local addition unchanged across installation and unit restart'
rm "$rules"
install_host
test ! -e "$rules"
echo 'ok installer existing host without rules: no restrictions introduced'
"$bin" ts-auth metadata-rules > "$rules"
mkdir -p "/etc/systemd/system/$unit.d"
printf '[Service]\nExecStartPost=/usr/sbin/nft insert rule inet terrascale_metadata output ip daddr 169.254.169.254 meta skuid 32123 accept\n' > "/etc/systemd/system/$unit.d/relay.conf"
systemctl restart "$unit"
systemctl restart "$unit"
test "$("$nft" -n list chain inet terrascale_metadata output | grep -c 'ip daddr 169.254.169.254 meta skuid 32123 accept')" = 1
mv "/etc/systemd/system/$unit.d/relay.conf" "$work/relay.conf"
systemctl restart "$unit"
if "$nft" -n list chain inet terrascale_metadata output | grep -q 'meta skuid 32123'; then exit 1; fi
cp "$work/relay.conf" "/etc/systemd/system/$unit.d/relay.conf"
systemctl restart "$unit"
test "$("$nft" -n list chain inet terrascale_metadata output | grep -c 'ip daddr 169.254.169.254 meta skuid 32123 accept')" = 1
allow
deny
echo 'ok metadata exception: generated unit post-start command survives reloads; checked removal and restoration'
echo 'installer-metadata e2e: PASS'
INNER
