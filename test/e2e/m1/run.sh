#!/usr/bin/env bash
# Milestone 1 end to end on a disposable arm64 host (the GitHub runner):
# install with deploy/m1/install.sh, serve two services through the built-in
# edge, survive a ts-orch and a task restart, roll back a never-ready deploy,
# then remove them.
#   test/e2e/m1/run.sh <terrascale-orchestrator binary>
# Needs passwordless sudo. No OCI or Vault credentials: the services declare no
# secrets, and the edge certificates come from a throwaway local CA.
set -euo pipefail

bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
work=$(mktemp -d)
summary=${GITHUB_STEP_SUMMARY:-/dev/stdout}
state=/var/lib/ts-orch
data=/var/lib/ts-data/e2e

timings=()
started=0
begin() { started=$(date +%s%N); echo "::group::$1"; }
end() {
	local ms=$((($(date +%s%N) - started) / 1000000))
	timings+=("| $1 | $((ms / 1000)).$(printf %03d $((ms % 1000))) |")
	echo "::endgroup::"
	echo "$1: ${ms} ms"
}
report() {
	{
		echo "### M1 e2e timings (seconds)"
		echo "| step | s |"
		echo "|---|---|"
		printf '%s\n' "${timings[@]}"
	} >>"$summary"
}

# wait_for <seconds> <command...>: poll once a second until the command succeeds.
wait_for() {
	local deadline=$((SECONDS + $1))
	shift
	until "$@" >/dev/null 2>&1; do
		((SECONDS < deadline)) || { echo "timed out: $*" >&2; "$@" || true; return 1; }
		sleep 1
	done
}
# edge <host> <path>: GET through the edge on 127.0.0.1:443 with the local CA.
edge() { curl -fsS --max-time 5 --cacert "$work/ca.pem" --resolve "$1:443:127.0.0.1" "https://$1$2"; }
orch() { sudo /usr/local/bin/ts-orch "$@"; }
dump() {
	echo "::group::diagnostics"
	orch service ls || true
	sudo journalctl -u ts-orch --no-pager -n 200 || true
	sudo cat "$work/ntp-responder.log" 2>/dev/null || true
	echo "::endgroup::"
}
trap dump ERR

# host-runtime.sh disciplines chrony against OCI's metadata NTP
# (169.254.169.254) only; nothing answers there on a GitHub runner. Put the
# address on a dummy interface and serve NTP from a stdlib Python responder,
# so the unmodified clock gate has a reachable source: the runner's own
# platform clock. This is CI-only; production hosts use the real OCI server.
ntp_pid=""
stop_ntp() { [[ -n $ntp_pid ]] && sudo kill "$ntp_pid" 2>/dev/null || true; }
trap 'stop_ntp; report' EXIT
begin "169.254.169.254 NTP stand-in for the clock gate"
sudo systemctl stop chrony chronyd 2>/dev/null || true # free UDP :123 for the responder
if ! ip -o -4 addr show | grep -q 'inet 169\.254\.169\.254/'; then
	if sudo ip link add ntp-ci type dummy 2>/dev/null; then
		sudo ip addr add 169.254.169.254/32 dev ntp-ci
		sudo ip link set ntp-ci up
	else # no dummy module on this kernel: the address works on loopback too
		sudo ip addr add 169.254.169.254/32 dev lo
	fi
fi
sudo python3 "$here/ntp_responder.py" >"$work/ntp-responder.log" 2>&1 &
ntp_pid=$!
# ntp_up: one mode-3 packet out, one 48-byte mode-4 packet back.
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
cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=ts-e2e-ca -addext keyUsage=critical,keyCertSign,cRLSign \
	-keyout ca.key -out ca.pem 2>/dev/null
# leaf <name> <san>: an ECDSA key and certificate from the local CA.
leaf() {
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$1" -keyout "$1.key" -out "$1.csr" 2>/dev/null
	openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -days 90 -extfile <(echo "subjectAltName=$2") -out "$1.pem" 2>/dev/null
}
leaf localhost DNS:localhost
sudo install -m 0644 ca.pem /usr/local/share/ca-certificates/ts-e2e-ca.crt
sudo update-ca-certificates >/dev/null
# The edge's autocert cache: key then chain, named by hostname (ECDSA). It is
# served as-is, standing in for Let's Encrypt, which cannot reach a runner.
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
packages=$HOME/.cache/ts-m1-runtime
mkdir -p "$packages"
runtime_pins=$repo/deploy/m1/host-runtime.sh
containerd_version=$(sed -n 's/^containerd_version=//p' "$runtime_pins")
runc_version=$(sed -n 's/^runc_version=//p' "$runtime_pins")
containerd_sha256=$(sed -n '/^aarch64)/,/;;/s/^\tcontainerd_sha256=//p' "$runtime_pins")
runc_sha256=$(sed -n '/^aarch64)/,/;;/s/^\trunc_sha256=//p' "$runtime_pins")
netbird_pin=$repo/internal/netbird/manager/server_cli.go
netbird=$(sed -n 's/.*Arm64 = client.Archive{URL: "\([^"]*\)".*/\1/p' "$netbird_pin")
netbird_sha256=$(sed -n '/Arm64 = client.Archive/{n;s/.*SHA256: "\([0-9a-f]*\)".*/\1/p}' "$netbird_pin")
containerd_file=containerd-$containerd_version-linux-arm64.tar.gz
runc_file=runc-$runc_version.arm64
netbird_file=${netbird##*/}
pinned() {
	[[ -e $packages/$1 ]] || { curl -fsSL -o "$work/$1" "$2" && mv "$work/$1" "$packages/$1"; }
	echo "$3  $packages/$1" | sha256sum -c --quiet
}
cache_pins() {
	pinned "$containerd_file" "https://github.com/containerd/containerd/releases/download/v$containerd_version/$containerd_file" "$containerd_sha256"
	pinned "$runc_file" "https://github.com/opencontainers/runc/releases/download/v$runc_version/runc.arm64" "$runc_sha256"
	pinned "$netbird_file" "$netbird" "$netbird_sha256"
}
cache_hit=false
if [[ -e $packages/$containerd_file && -e $packages/$runc_file && -e $packages/$netbird_file ]]; then
	cache_hit=true
	cache_pins
	sudo tar -C /usr/local -xzf "$packages/$containerd_file"
	sudo install -m 0755 "$packages/$runc_file" /usr/local/sbin/runc
	tar -C "$work" -xzf "$packages/$netbird_file" netbird
	sudo install -m 0755 "$work/netbird" /usr/local/bin/netbird
fi
end "pinned packages: cache hit $cache_hit (a miss leaves the downloads to install.sh)"

begin "install.sh (containerd 2.4.2, runc, NetBird client, ts-orch)"
sudo install -d -o 65532 -g 65532 -m 0755 /var/lib/ts-data "$data"
"$repo/deploy/m1/install.sh" ts-e2e https://localhost:8443/terrascale-orchestrator-linux-arm64 \
	"$(sha256sum "$bin" | cut -d' ' -f1)"
/usr/local/bin/containerd --version | grep -q ' v2.4.2 '
end "install -> ts-orch active (cache hit $cache_hit)"
if ! $cache_hit; then
	begin "save the pinned packages for the next run"
	netbird version
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

begin "websocket upgrade through the edge"
python3 - "$work/ca.pem" whoami.e2e.test <<'EOF'
import base64, hashlib, os, socket, ssl, sys
ca, host = sys.argv[1:3]
key = base64.b64encode(os.urandom(16)).decode()
tls = ssl.create_default_context(cafile=ca).wrap_socket(socket.create_connection(("127.0.0.1", 443), timeout=5), server_hostname=host)
tls.sendall(f"GET /echo HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket, foo\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n".encode())
stream = tls.makefile("rb")
status = stream.readline()
headers = {name.strip().lower(): value.strip() for name, value in (line.decode().split(":", 1) for line in iter(stream.readline, b"\r\n"))}
accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
if status.split()[1] != b"101" or headers.get("sec-websocket-accept") != accept:
	sys.exit(f"websocket upgrade refused: {status!r} {headers}")
mask, payload = os.urandom(4), b"ts-e2e websocket"
tls.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
echo = stream.read(2 + len(payload))
if echo != bytes([0x81, len(payload)]) + payload:
	sys.exit(f"websocket echo missing: {echo!r}")
print(status.decode().strip(), "and echo", echo[2:].decode())
EOF
end "upgrade -> whoami /echo echoed one frame through the edge"

begin "regional path through a second edge in its own network namespace"
install -d -m 0700 "$work/regional/edge-certs"
for host in regional.e2e.test upgrade.e2e.test; do
	leaf "$host" "DNS:$host"
	cat "$host.key" "$host.pem" >"$work/regional/edge-certs/$host"
done
go -C "$repo" build -trimpath -o "$work/regional-edge" ./test/e2e/m1/regional
sudo unshare -n sh -c 'ip link set lo up && exec "$0" "$@"' "$work/regional-edge" "$work/regional" "$work/ca.pem" regional.e2e.test upgrade.e2e.test
end "regional edge -> REST, two WebSockets, a drain with both open, REST after it, an upload after a backend's half-close"

begin "restart ts-orch"
sudo systemctl restart ts-orch
wait_for 120 edge whoami.e2e.test /health
wait_for 60 edge data.e2e.test /boots
end "ts-orch restart -> both served"

begin "restart the e2e-data task"
before=$(edge data.e2e.test /boots | wc -l)
sudo fuser -k -n tcp 18082
wait_for 120 bash -c "test \$(curl -fsS --max-time 5 --cacert $work/ca.pem --resolve data.e2e.test:443:127.0.0.1 https://data.e2e.test/boots | wc -l) -gt $before"
test "$(edge data.e2e.test /boots | head -1)" = "$first" || { echo "bind-mount data lost across restarts" >&2; exit 1; }
end "task kill -> restarted, data kept"

begin "never-ready deploy rolls back"
# whoami on the wrong port never answers /health on 18081.
jq '.args = ["--port", "18083"] | .readyTimeoutSeconds = 5' "$here/whoami.json" >"$work/never-ready.json"
if orch service apply -f "$work/never-ready.json" >"$work/apply.txt" 2>&1; then
	cat "$work/apply.txt"
	echo "a never-ready deploy reported success" >&2
	exit 1
fi
cat "$work/apply.txt"
grep -q 'rolled back' "$work/apply.txt"
edge whoami.e2e.test /health
orch events | grep 'e2e-whoami' | tail -5
orch events | grep -q 'service e2e-whoami updated .* update=rollback_completed'
orch service ps e2e-whoami
end "never-ready deploy -> rolled back, previous task serves"

begin "service rm"
orch service rm e2e-whoami
orch service rm e2e-data
gone() { ! orch service ls | grep -q '^e2e-' && ! edge whoami.e2e.test /health && ! sudo fuser -n tcp 18081 18082; }
wait_for 60 gone
end "rm -> services, routes and tasks gone"
test "$(sudo head -1 "$data/boots")" = "$first"
echo "M1 e2e passed"
