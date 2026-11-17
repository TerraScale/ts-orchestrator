#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "pull updates: regional order, poll, attestation refusals, rollback and its bound"
nice -n 19 "$(dirname "$bin")/pull-update" "$bin" pull
end "host polling -> verified one-host-at-a-time rollout; bad releases refused; unhealthy rolled back; a stalled rollback reports critical and stops holding"
