import os
import pathlib
import shutil
import subprocess
import sys

tool, *args = sys.argv[1:]
if tool == "ssh":
    script = sys.stdin.read()
    if "names=()" in script:
        subprocess.run(["bash", "-s"], input=script, text=True, check=True)
elif tool == "curl":
    shutil.copyfile(os.environ["lane_binary"], args[args.index("-o") + 1])
elif (
    tool == "systemctl"
    and args[0] in ("start", "restart")
    and "terrascale-ts-auth-metadata.service" in args
):
    unit = pathlib.Path("/etc/systemd/system/terrascale-ts-auth-metadata.service")
    files = [unit, *sorted(pathlib.Path(str(unit) + ".d").glob("*.conf"))]
    commands = []
    for file in files:
        for line in file.read_text().splitlines():
            key, _, value = line.partition("=")
            if key in ("ExecStartPre", "ExecStart", "ExecStartPost"):
                commands.append(
                    (
                        {"ExecStartPre": 0, "ExecStart": 1, "ExecStartPost": 2}[key],
                        value,
                    )
                )
    for _, command in sorted(commands, key=lambda item: item[0]):
        command = command.replace("/usr/sbin/nft", os.environ["lane_nft"])
        subprocess.run(["/bin/sh", "-c", command], check=True)
