#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "pull bake: a draining worker during the regional bake"
nice -n 19 "$(dirname "$bin")/pull-update" "$bin" bake
end "a drain that ends passes the bake; a drain that stays or keeps returning rolls the release back within its bound"
