#!/usr/bin/env bash
clock_python=$(python3 -c 'import os,sys;print(os.path.realpath(sys.executable))')
stop_ntp
clock_interface=$(ip -o -4 addr show to 169.254.169.254/32 | awk '{print $2}')
sudo ip addr del 169.254.169.254/32 dev "$clock_interface"
sudo ip netns add metadata-clock
trap 'stop_ntp; sudo ip netns del metadata-clock; report' EXIT
sudo ip link add metadata-clock type veth peer name clock-peer
sudo ip link set clock-peer netns metadata-clock
sudo ip addr add 192.0.2.2/30 dev metadata-clock
sudo ip link set metadata-clock up
sudo ip netns exec metadata-clock ip link set lo up
sudo ip netns exec metadata-clock ip addr add 192.0.2.1/30 dev clock-peer
sudo ip netns exec metadata-clock ip addr add 169.254.169.254/32 dev clock-peer
sudo ip netns exec metadata-clock ip link set clock-peer up
sudo ip route add 169.254.169.254/32 via 192.0.2.1
sudo ip netns exec metadata-clock "$clock_python" "$here/ntp_responder.py" >"$work/ntp-responder.log" 2>&1 &
ntp_pid=$!
wait_for 10 ntp_up
