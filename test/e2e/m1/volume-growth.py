import json
import os
import struct
import subprocess
import sys
from pathlib import Path

work = Path(sys.argv[1])
first = sys.argv[2]
device = Path("/dev/oracleoci/oraclevdb").resolve()
gib = 1024**3


def filesystem_bytes():
    with device.open("rb") as stream:
        stream.seek(1024)
        header = stream.read(1024)
    assert struct.unpack_from("<H", header, 56)[0] == 0xEF53
    blocks = struct.unpack_from("<I", header, 4)[0]
    if struct.unpack_from("<I", header, 96)[0] & 0x80:
        blocks |= struct.unpack_from("<I", header, 336)[0] << 32
    return blocks * (1024 << struct.unpack_from("<I", header, 24)[0])


assert filesystem_bytes() == 32 * gib
assert Path("/var/lib/ts-data/terrabase/kept").read_bytes() == b"retained database bytes\n"
assert Path("/var/lib/ts-orch/identity-kept").is_file()
boots = Path("/var/lib/ts-data/e2e/boots").read_bytes()
assert boots.splitlines()[0].decode() == first
payload = os.urandom(65536)
retained = Path("/var/lib/ts-data/terrabase/growth-kept")
retained.write_bytes(payload)
pid = subprocess.check_output(
    ["systemctl", "show", "ts-orch", "-p", "MainPID", "--value"]
)
assert int(pid) > 0
cursor = json.loads(
    subprocess.check_output(["journalctl", "-u", "ts-orch", "-n", "1", "-o", "json"])
)["__CURSOR"]
image = work / "data-volume.img"
with image.open("r+b") as stream:
    stream.truncate(33 * gib)
subprocess.run(["losetup", "--set-capacity", str(device)], check=True)
watch = subprocess.Popen(
    [
        "timeout",
        "15",
        "journalctl",
        "-u",
        "ts-orch",
        "--after-cursor",
        cursor,
        "-f",
        "-o",
        "cat",
    ],
    stdout=subprocess.PIPE,
    text=True,
)
try:
    for line in watch.stdout:
        if "data filesystem grown" in line:
            break
    else:
        raise AssertionError("node did not observe live data volume growth")
finally:
    watch.terminate()
    watch.wait()
assert filesystem_bytes() == 33 * gib
assert (
    os.stat("/var/lib/ts-data").st_dev
    == os.stat("/var/lib/ts-orch").st_dev
    == device.stat().st_rdev
)
assert retained.read_bytes() == payload
assert Path("/var/lib/ts-data/terrabase/kept").read_bytes() == b"retained database bytes\n"
assert Path("/var/lib/ts-data/e2e/boots").read_bytes() == boots
assert (
    subprocess.check_output(
        ["systemctl", "show", "ts-orch", "-p", "MainPID", "--value"]
    )
    == pid
)
print(
    "data volume: startup and online growth fill the device; mounted data and running services preserved"
)
