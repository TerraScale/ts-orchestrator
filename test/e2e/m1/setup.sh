#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
ntp_pid=""
stop_ntp() { [[ -n $ntp_pid ]] && sudo kill "$ntp_pid" 2>/dev/null || true; }
trap 'stop_ntp; report' EXIT
begin "169.254.169.254 NTP stand-in for the clock gate"
sudo systemctl stop chrony chronyd 2>/dev/null || true
if ! ip -o -4 addr show | grep -q 'inet 169\.254\.169\.254/'; then
	if sudo ip link add ntp-ci type dummy 2>/dev/null; then
		sudo ip addr add 169.254.169.254/32 dev ntp-ci
		sudo ip link set ntp-ci up
	else
		sudo ip addr add 169.254.169.254/32 dev lo
	fi
fi
sudo python3 "$here/ntp_responder.py" >"$work/ntp-responder.log" 2>&1 &
ntp_pid=$!
ntp_up() {
	python3 -c 'import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(bytes([0x23]) + bytes(47), ("169.254.169.254", 123))
r = s.recvfrom(64)[0]
sys.exit(0 if len(r) == 48 and r[0] & 7 == 4 else 1)'
}
wait_for 10 ntp_up
end "NTP stand-in answers on 169.254.169.254"

begin "local CA, ssh and https binary server"
source "$here/certificates.sh"
leaf localhost DNS:localhost
sudo install -m 0644 ca.pem /usr/local/share/ca-certificates/ts-e2e-ca.crt
sudo update-ca-certificates >/dev/null
sudo install -d -m 0700 "$state" "$state/edge-certs"
for host in whoami.e2e.test data.e2e.test; do
	leaf "$host" "DNS:$host"
	cat "$host.key" "$host.pem" | sudo install -m 0600 /dev/stdin "$state/edge-certs/$host"
done
install -m 0755 "$bin" terrascale-orchestrator-linux-arm64
openssl s_server -quiet -WWW -accept 8443 -cert localhost.pem -key localhost.key >/dev/null 2>&1 &
mkdir -p ~/.ssh
ssh-keygen -q -t ed25519 -N '' -f ~/.ssh/ts-e2e
cat ~/.ssh/ts-e2e.pub >>~/.ssh/authorized_keys
chmod 0600 ~/.ssh/authorized_keys
printf 'Host ts-e2e\n  HostName 127.0.0.1\n  IdentityFile ~/.ssh/ts-e2e\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n' >>~/.ssh/config
command -v sshd >/dev/null || sudo apt-get install -y -qq openssh-server
sudo systemctl start ssh
wait_for 10 curl -fsSo /dev/null https://localhost:8443/terrascale-orchestrator-linux-arm64
end "setup (CA, ssh, binary server)"

begin "pinned containerd, runc and NetBird client from the Actions cache"
source "$here/runtime.sh"
restore_runtime
end "pinned packages: cache hit $cache_hit (a miss leaves the downloads to install.sh)"

begin "install.sh (containerd 2.4.2, runc, NetBird client, ts-orch)"
sudo install -d -o 65532 -g 65532 -m 0755 /var/lib/ts-data "$data"
"$repo/deploy/m1/install.sh" ts-e2e https://localhost:8443/terrascale-orchestrator-linux-arm64 \
	"$(sha256sum "$bin" | cut -d' ' -f1)"
/usr/local/bin/containerd --version | grep -q ' v2.4.2 '
end "install -> ts-orch active (cache hit $cache_hit)"
if $cache_hit; then
	echo "NetBird client tested: $(netbird version), the pin restored from the runtime cache" | tee -a "$summary"
else
	echo "NetBird client tested: $(netbird version), apt's current release (runtime cache miss)" | tee -a "$summary"
	begin "save the pinned packages for the next run"
	cache_pins
	end "cache miss -> pinned packages saved for the next run"
fi

begin "service apply -> served through the edge"
orch service apply -f "$here/whoami.json"
orch service apply -f "$here/data.json"
wait_for 180 edge whoami.e2e.test /health
end "apply -> e2e-whoami ready (edge 200)"
wait_for 60 edge data.e2e.test /boots
end "apply -> e2e-data ready (edge 200)"
edge whoami.e2e.test / | grep -q '^Host: whoami.e2e.test'
edge data.e2e.test /dns | grep -Eq '^Name:[[:space:]]+github.com' || { echo "container DNS lookup failed" >&2; edge data.e2e.test /dns; exit 1; }
first=$(edge data.e2e.test /boots | head -1)
orch service ls | tee ls.txt
grep -Eq '^e2e-whoami +1/1 running' ls.txt
grep -Eq '^e2e-data +1/1 running' ls.txt
