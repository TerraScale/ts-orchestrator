#!/usr/bin/env python3
"""NTP stand-in for 169.254.169.254 on the GitHub runner.

deploy/m1/host-runtime.sh configures chrony with OCI's metadata NTP
(169.254.169.254) as its only server and waits for a real synchronisation.
The GitHub runner is not an OCI instance and nothing answers on that
address, so test/e2e/m1/run.sh puts it on a dummy interface and runs this
stdlib-only responder. The clock gate then runs unmodified against a
reachable, sane time source: the runner's own platform clock.

   sudo python3 ntp_responder.py [address]
"""
import socket
import struct
import sys
import time

NTP_TO_UNIX = 2208988800  # seconds from 1900-01-01 to 1970-01-01


def timestamp(t):
    """Seconds since the Unix epoch as an NTP 32.32 fixed-point pair."""
    whole = int(t)
    frac = int((t - whole) * (1 << 32))
    return struct.pack(">II", whole + NTP_TO_UNIX, frac)


def reply(request, received, transmitted):
    """A mode-4 server answer: stratum 2, refid LOCL, sane root fields."""
    header = bytes([0x24, 2, request[2] or 4, 0xEC])  # LI=0 VN=4 mode=4, poll, precision -20
    root = struct.pack(">ii", 0, 33)  # root delay 0 s, root dispersion ~0.5 ms (16.16)
    reference = timestamp(time.time())  # "synced just now"
    originate = request[40:48]  # echo the client's transmit timestamp
    return header + root + b"LOCL" + reference + originate + received + transmitted


def main():
    address = sys.argv[1] if len(sys.argv) > 1 else "169.254.169.254"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, 123))
    print(f"serving NTP on {address}:123", flush=True)
    while True:
        request, peer = sock.recvfrom(1024)
        if len(request) != 48 or request[0] & 0x07 != 3:
            continue  # not an NTP client request
        received = timestamp(time.time())
        transmitted = timestamp(time.time())
        sock.sendto(reply(request, received, transmitted), peer)


if __name__ == "__main__":
    main()
