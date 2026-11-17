import base64
import contextlib
import errno
import fcntl
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import urllib.request


def command(arguments, payload=None):
    result = subprocess.run(arguments, input=payload, capture_output=True, check=False)
    if result.returncode:
        raise RuntimeError("staging host operation failed; output withheld")
    return result.stdout


@contextlib.contextmanager
def image_lock():
    descriptor = os.open("/var/lib/containerd", os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def attest(request):
    prefix = request["prefix"]
    if not re.fullmatch(r"abuse-[a-f0-9]{12}", prefix):
        raise RuntimeError("invalid abuse namespace")
    if "staging" not in request["region"].split("-"):
        raise RuntimeError("staging label required")
    query = urllib.request.Request("http://169.254.169.254/opc/v2/instance/",
                                   headers={"Authorization": "Bearer Oracle"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(query, timeout=10) as response:
        identity = json.load(response)
    if identity["id"] != request["instance"] or identity["compartmentId"] != request["compartment"]:
        raise RuntimeError("remote host is outside staging compartment")
    return pathlib.Path("/var/lib/ts-data") / prefix


def snapshot():
    pid = int(command(["systemctl", "show", "ts-orch", "--property", "MainPID", "--value"]))
    rss = 0
    if pid:
        for row in pathlib.Path(f"/proc/{pid}/status").read_text().splitlines():
            if row.startswith("VmRSS:"):
                rss = int(row.split()[1]) * 1024
    sockets = command(["ss", "-Htn", "state", "established",
                       "( sport = :443 or sport = :5432 )"]).splitlines()
    memory = pathlib.Path("/proc/meminfo").read_text()
    available = int(re.search(r"MemAvailable:\s+(\d+)", memory)[1]) * 1024
    disk = os.statvfs("/var/lib/ts-orch")
    counters = dict(line.split() for line in pathlib.Path("/proc/vmstat").read_text().splitlines())
    return {"rss": rss, "sockets": len(sockets), "available": available,
            "disk_free": disk.f_bavail * disk.f_frsize, "pid": pid,
            "oom_kill": int(counters["oom_kill"])}


def disk_fault(request):
    path = pathlib.Path("/var/lib/ts-orch") / (request["prefix"] + "-fill")
    marker = pathlib.Path("/run") / (request["prefix"] + "-disk.json")
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        with path.open("xb", buffering=0) as stream:
            os.chmod(path, 0o600)
            count = 0
            try:
                while True:
                    os.posix_fallocate(stream.fileno(), count, 1 << 20)
                    count += 1 << 20
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
            try:
                while True:
                    os.posix_fallocate(stream.fileno(), count, os.statvfs(path).f_frsize)
                    count += os.statvfs(path).f_frsize
            except OSError as error:
                if error.errno != errno.ENOSPC:
                    raise
            marker.write_text(json.dumps({"filled": count, "enospc": True}))
            while True:
                signal.pause()
    finally:
        path.unlink(missing_ok=True)
        marker.unlink(missing_ok=True)


def run(request):
    root = attest(request)
    operation = request["operation"]
    if operation == "install":
        root.mkdir(mode=0o700, exist_ok=False)
        for name in ("probe", "control", "host.py", "image.tar"):
            path = root / name
            path.write_bytes(base64.b64decode(request["files"][name], validate=True))
            path.chmod(0o700)
        for name in ("postgres", "pgsocket"):
            (root / name).mkdir(mode=0o777)
            (root / name).chmod(0o777)
        shutil.copyfile(root / "probe", root / "postgres/probe")
        (root / "postgres/probe").chmod(0o755)
        (root / "image.json").write_text(json.dumps(request["image"]))
        with image_lock():
            command(["ctr", "--namespace", "terrascale", "images", "import", str(root / "image.tar")])
            command(["ctr", "--namespace", "terrascale", "images", "tag", request["image"]["tag"], request["image"]["ref"]])
            command(["ctr", "--namespace", "terrascale", "images", "rm", request["image"]["tag"]])
        return {"installed": True}
    if operation == "control":
        payload = dict(request["control"])
        payload.update(region=request["region"], compartment=request["compartment"],
                       prefix=request["prefix"])
        data = command([str(root / "control")], json.dumps(payload).encode())
        return json.loads(data)
    if operation == "watch":
        payload = dict(request["control"])
        payload.update(region=request["region"], compartment=request["compartment"],
                       prefix=request["prefix"])
        process = subprocess.Popen([str(root / "control")], stdin=subprocess.PIPE)
        process.communicate(json.dumps(payload).encode())
        if process.returncode:
            raise RuntimeError("staging control watch failed")
        return None
    if operation == "snapshot":
        return snapshot()
    if operation == "disk-start":
        path = "/var/lib/ts-orch/" + request["prefix"] + "-fill"
        payload = dict(request, operation="disk-run")
        config = root / "disk.json"
        config.write_text(json.dumps(payload))
        config.chmod(0o600)
        command(["systemd-run", "--quiet", "--collect", "--unit", request["prefix"] + "-disk",
                 "--property", "RuntimeMaxSec=" + str(request["seconds"]),
                 "--property", "ExecStopPost=/usr/bin/rm -f " + path + " /run/" + request["prefix"] + "-disk.json",
                 "python3", str(root / "host.py"), str(config)])
        return {"started": True}
    if operation == "disk-run":
        disk_fault(request)
        return {"released": True}
    if operation == "disk-status":
        marker = pathlib.Path("/run") / (request["prefix"] + "-disk.json")
        return json.loads(marker.read_text()) if marker.exists() else {"enospc": False}
    if operation == "disk-stop":
        command(["systemctl", "stop", request["prefix"] + "-disk"])
        path = pathlib.Path("/var/lib/ts-orch") / (request["prefix"] + "-fill")
        if path.exists():
            raise RuntimeError("disk fault file survived cleanup")
        return snapshot()
    if operation == "cleanup":
        if root.exists():
            if (root / "image.json").exists():
                image = json.loads((root / "image.json").read_text())
                with image_lock():
                    existing = set(command(["ctr", "--namespace", "terrascale", "images", "ls", "-q"]).decode().splitlines())
                    owned = [name for name in (image["ref"], image["tag"]) if name in existing]
                    if owned:
                        command(["ctr", "--namespace", "terrascale", "images", "rm", *owned])
            shutil.rmtree(root)
        return {"removed": True}
    raise RuntimeError("unknown host operation")


if __name__ == "__main__":
    try:
        if len(sys.argv) == 2:
            request = json.loads(pathlib.Path(sys.argv[1]).read_text())
        else:
            request = json.load(sys.stdin)
        result = run(request)
        if result is not None:
            print(json.dumps(result), flush=True)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError):
        print("staging host operation failed; output withheld", file=sys.stderr)
        sys.exit(1)
