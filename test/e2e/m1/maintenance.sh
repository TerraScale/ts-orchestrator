#!/usr/bin/env bash
source "$(dirname "$0")/common.sh"

begin "bootstrap maintenance: a stalled activation, an expired deadline and an unclean exit each end with ingress released"
sudo unshare -n -p -f --mount-proc sh -c 'ip link set lo up && exec "$0" "$@"' "$(dirname "$bin")/maintenance" "$work/maintenance"
end "bootstrap maintenance -> writer window, recover after the deadline ends failed with the target stopped and ingress released, a late writer verifies on recover and its release is journaled, an unclean exit needs the journaled flag"
