#!/usr/bin/env bash
# Milestone 1 end to end on a disposable arm64 host (the GitHub runner):
# install with deploy/m1/install.sh, serve two services through the built-in
# edge, survive a ts-orch and a task restart, then remove them.
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
trap report EXIT

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
	echo "::endgroup::"
}
trap dump ERR

begin "local CA, ssh and https binary server"
cd "$work"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=ts-e2e-ca \
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

begin "install.sh (containerd 2.4.2, runc, NetBird client, ts-orch)"
sudo install -d -o 65532 -g 65532 -m 0755 /var/lib/ts-data "$data"
"$repo/deploy/m1/install.sh" ts-e2e https://localhost:8443/terrascale-orchestrator-linux-arm64 \
	"$(sha256sum "$bin" | cut -d' ' -f1)"
/usr/local/bin/containerd --version | grep -q ' v2.4.2 '
end "install -> ts-orch active"

begin "service apply -> served through the edge"
orch service apply -f "$here/whoami.json"
orch service apply -f "$here/data.json"
wait_for 180 edge whoami.e2e.test /health
end "apply -> e2e-whoami ready (edge 200)"
wait_for 60 edge data.e2e.test /boots
end "apply -> e2e-data ready (edge 200)"
edge whoami.e2e.test / | grep -q '^Host: whoami.e2e.test'
first=$(edge data.e2e.test /boots | head -1)
orch service ls | tee ls.txt
grep -Eq '^e2e-whoami +1/1 running' ls.txt
grep -Eq '^e2e-data +1/1 running' ls.txt

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

begin "service rm"
orch service rm e2e-whoami
orch service rm e2e-data
gone() { ! orch service ls | grep -q '^e2e-' && ! edge whoami.e2e.test /health && ! sudo fuser -n tcp 18081 18082; }
wait_for 60 gone
end "rm -> services, routes and tasks gone"
test "$(sudo head -1 "$data/boots")" = "$first"
echo "M1 e2e passed"
