#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "pull rollout from each region's OCIR channel, with no GitHub network"
nice -n 19 "$(dirname "$bin")/pull-update" "$bin" degraded
end "a channel document its bundle does not sign is refused without marking its release, which then installs in region order; an unavailable worker blocks later regions; replayed seq and tampered artifact refused; zero GitHub calls"
