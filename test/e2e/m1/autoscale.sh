source "$(dirname "$0")/common.sh"
mode=$2
begin "$mode"
source "$here/runtime.sh"
restore_runtime
image=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"])' "$here/data.json")
tools=$(mktemp -d /tmp/autoscale-tools.XXXXXX)
chmod 0755 "$tools"
install -m 0755 "$(dirname "$bin")/lifecycle" "$(dirname "$bin")/server" "$tools/"
source "$here/certificates.sh"
root=$work/autoscale
mkdir -p "$root/c18a/edge-certs"
cp "$work/ca.pem" "$root/ca.pem"
for host in c11.e2e.test fixed.c11.e2e.test; do
	leaf "$host" "DNS:$host"
	cat "$host.key" "$host.pem" >"$root/c18a/edge-certs/$host"
done
sudo env "PATH=$PATH" unshare --mount --fork bash "$here/lifecycle/prepare.sh" "$work" "$tools" "$image"
sudo env "PATH=$PATH" unshare --mount --net --fork bash "$here/lifecycle/run.sh" "$root" "$tools/lifecycle" "$image" "$work/busybox.tar" "$tools/server" "$mode"
end "$mode"
