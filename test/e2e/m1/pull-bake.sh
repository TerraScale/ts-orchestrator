#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"
trap 'rm -rf "$work"' EXIT

begin "pull gate: the regional health gate against the state before the release"
nice -n 19 "$(dirname "$bin")/pull-update" "$bin" bake
end "a formed region adopts the release its hosts booted; an app release during the gate is excluded; a degraded region takes a release; sjc passes first, then fra and gru together; a canary that fails holds fra and gru; a later region that fails rolls back alone"
