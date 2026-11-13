#!/usr/bin/env bash
source "$(dirname "$0")/setup.sh"

begin "service rm"
orch service rm e2e-whoami
orch service rm e2e-data
gone() {
	orch service ls >"$work/gone.txt" 2>/dev/null || return 1
	! grep -q '^e2e-' "$work/gone.txt" || return 1
	! edge whoami.e2e.test /health 2>/dev/null || return 1
	! sudo fuser -n tcp 18081 18082 2>/dev/null
}
wait_for 60 gone
end "rm -> services, routes and tasks gone"
test "$(sudo head -1 "$data/boots")" = "$first"
echo "M1 core e2e passed"
