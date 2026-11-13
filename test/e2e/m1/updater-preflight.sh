#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

begin "candidate preflight, refusal classes, rollout gates and main's probation behind the preflight"
bash "$here/updater-preflight/run.sh" "$bin"
end "release -> candidate preflight before main's install, classified refusals, region gates, files identical to main's updater"
