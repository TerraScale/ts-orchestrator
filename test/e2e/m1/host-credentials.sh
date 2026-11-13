#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

begin "prepared runtime credentials, relay health and activation gate"
sudo swapoff --all
bash "$here/host-credentials/run.sh" "$bin"
end "relay startup and health validate protected files; activation validates preparation"
