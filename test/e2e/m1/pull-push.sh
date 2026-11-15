#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "pull updates beside release pushes: preemption, owner handover, a slow worker"
nice -n 19 "$(dirname "$bin")/pull-update" "$bin" push
end "a push preempts a pull rollout and wins; a killed owner hands over; the pull never runs beside an in-flight push"
