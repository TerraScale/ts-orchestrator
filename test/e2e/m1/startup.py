import concurrent.futures
import ctypes
import http.server
import itertools
import json
import os
import re
import selectors
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

CASES = (
    "fresh-outage",
    "worker-outage",
    "manager-match",
    "manager-mismatch",
    "manager-no-identity",
    "manager-no-record",
    "fresh-record",
    "fresh-delay",
    "worker-delay",
    "manager-delay",
    "cancel",
    "local",
)


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def read_until(process, needle, timeout):
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    output = bytearray()
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                break
            data = os.read(process.stdout.fileno(), 65536)
            if not data:
                break
            output.extend(data)
            if needle in output:
                return output.decode(errors="replace")
    finally:
        selector.close()
    raise AssertionError(
        f"missing {needle!r}: {output.decode(errors='replace')[-5000:]}"
    )


def record_watch(state):
    libc = ctypes.CDLL(None, use_errno=True)
    fd = libc.inotify_init1(os.O_CLOEXEC)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "open metadata record watcher")
    if libc.inotify_add_watch(fd, os.fsencode(state), 128) < 0:
        os.close(fd)
        raise OSError(ctypes.get_errno(), "watch metadata record moves")
    return fd


def run_case(binary, seed_binary, root, case):
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    units = root / case / "units"
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "addr", "add", "169.254.169.254/32", "dev", "lo"], check=True)
    work = root / case
    work.mkdir()
    units.mkdir()
    (units / "ts-orch.service").write_bytes(subprocess.check_output([binary, "release", "unit"]))
    subprocess.run(["mount", "--bind", str(units), "/etc/systemd/system"], check=True)
    firmware = work / "sys/class/dmi/id"
    firmware.mkdir(parents=True)
    for field in ("board_asset_tag", "product_serial", "product_uuid"):
        (firmware / field).write_text("unknown\n")
    if case == "manager-no-identity":
        for field in ("board_asset_tag", "product_serial", "product_uuid"):
            (firmware / field).unlink()
    (firmware / "chassis_asset_tag").write_text("OracleCloud.com\n")
    if case == "manager-match":
        (firmware / "board_asset_tag").write_text("instance\n")
    if case == "manager-mismatch":
        (firmware / "board_asset_tag").write_text("another-instance\n")
    subprocess.run(["mount", "--bind", str(work / "sys"), "/sys"], check=True)
    state = work / "state"
    state.mkdir()
    processes = []
    record_events = None
    samples = []
    notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    notify.bind(str(work / "notify.sock"))
    notify.settimeout(1)
    environment = dict(os.environ, NOTIFY_SOCKET=str(work / "notify.sock"))
    began = time.monotonic()
    delayed = case.endswith("-delay")

    class Metadata(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            now = time.monotonic()
            samples.append((now, self.path))
            require(
                self.headers.get("Authorization") == "Bearer Oracle",
                "missing IMDS authorization",
            )
            values = {
                "/opc/v2/instance/canonicalRegionName": "us-sanjose-1",
                "/opc/v2/instance/id": "instance",
                "/opc/v2/vnics/": '[{"privateIp":"127.0.0.2"}]',
            }
            value = values.get(self.path)
            ready = delayed and now - began >= (125 if case == "manager-delay" else 2)
            self.send_response(200 if ready and value else 503)
            self.end_headers()
            self.wfile.write(
                (value if ready and value else "metadata unavailable").encode()
            )

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("169.254.169.254", 80), Metadata)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        if case.startswith(("worker-", "manager-")):
            role = "worker" if case.startswith("worker-") else "manager"
            seed = subprocess.Popen(
                [seed_binary, str(work / "seed"), role],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            processes.append(seed)
            read_until(seed, b"seed ready", 40)
            state = work / "seed" / role
            if role == "manager":
                seed.stdin.write(b"stop\n")
                seed.stdin.flush()
                require(seed.wait(timeout=20) == 0, "seed manager did not stop cleanly")
        record = state / "host-metadata.json"
        old = {"Region": "gru", "ID": "instance", "PrivateIP": "127.0.0.1"}
        if case not in (
            "fresh-outage",
            "fresh-delay",
            "manager-no-record",
            "cancel",
            "local",
        ):
            record.write_text(json.dumps(old))
        if case == "local":
            (firmware / "chassis_asset_tag").write_text("Local\n")
            for retained in ("mesh", "host-metadata.json", "worker", "orphan"):
                local = work / retained
                local.mkdir()
                if retained == "mesh":
                    (local / "mesh").mkdir()
                elif retained == "host-metadata.json":
                    (local / retained).write_text(json.dumps(old))
                else:
                    (local / "swarm").mkdir()
                    if retained == "worker":
                        (local / "swarm/admission.json").write_text(
                            json.dumps(
                                {
                                    "Region": "local",
                                    "HostID": "worker",
                                    "InstanceID": "instance",
                                    "FounderID": "single-host",
                                    "Role": "container",
                                }
                            )
                        )
                result = subprocess.run(
                    [binary, "single-host", "--state", str(local)],
                    check=False,
                    capture_output=True,
                    timeout=5,
                )
                require(
                    result.returncode != 0
                    and (
                        b"not Oracle but stored mesh" in result.stdout + result.stderr
                        if retained != "orphan"
                        else b"cluster state exists without stored admission"
                        in result.stdout + result.stderr
                    ),
                    f"accepted contradictory {retained} state",
                )
            process = subprocess.Popen(
                [binary, "single-host", "--state", str(state)],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            processes.append(process)
            output = read_until(process, b"ready; advertise", 30)
            require(
                re.search(
                    r"single-host manager \w+ ready; advertise 127\.0\.0\.1:4242",
                    output,
                ),
                "local host did not serve on loopback",
            )
            require(
                not record.exists()
                and all(
                    path not in ("/opc/v2/instance/id", "/opc/v2/vnics/")
                    for _, path in samples
                ),
                "local planning queried metadata",
            )
            print(
                "ok local: fresh local host serves; contradictory mesh state is refused",
                flush=True,
            )
            return
        admission = state / "swarm/admission.json"
        previous_admission = admission.read_bytes() if admission.exists() else None
        if case == "fresh-delay":
            record_events = record_watch(state)
        began = time.monotonic()
        process = subprocess.Popen(
            [binary, "single-host", "--state", str(state)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
        )
        processes.append(process)
        require(
            notify.recv(4096) == b"EXTEND_TIMEOUT_USEC=600000000",
            "startup did not reserve time for recovery after the metadata window",
        )
        if case == "cancel":
            read_until(process, b"retrying within startup window", 5)
            stop(process)
            require(
                not (state / "swarm").exists() and not record.exists(),
                "cancelled host founded a cluster",
            )
            print("ok cancellation stops metadata lookup without founding", flush=True)
            return
        if case == "fresh-delay":
            with selectors.DefaultSelector() as moves:
                moves.register(record_events, selectors.EVENT_READ)
                require(moves.select(10), "delayed metadata did not publish a record")
                require(
                    b"host-metadata.json\0" in os.read(record_events, 4096),
                    "metadata record was not published atomically",
                )
            output = read_until(process, b"retrying within startup window", 5)
            require(process.poll() is None, "fresh host did not proceed to admission")
        elif delayed or case in ("worker-outage", "manager-match"):
            output = read_until(process, b"ready; advertise", 340)
            role = "container" if case.startswith("worker-") else "manager"
            address = (
                "127.0.0.1:4242"
                if case.startswith("worker-") or case == "manager-match"
                else "127.0.0.2:4242"
            )
            require(
                re.search(
                    rf"single-host {role} \w+ ready; advertise {re.escape(address)}",
                    output,
                ),
                f"wrong recovered role or address: {output[-1000:]}",
            )
        else:
            data, _ = process.communicate(timeout=320)
            output = data.decode(errors="replace")
            require(
                process.returncode != 0 and "read host metadata:" in output,
                f"accepted metadata outage: {output[-1000:]}",
            )
            if case in ("manager-mismatch", "manager-no-identity"):
                require(
                    "does not match a network-independent firmware identity" in output,
                    "missing identity contradiction",
                )
            if case == "manager-no-record":
                require(
                    "read stored host metadata:" in output,
                    "missing recovery record error",
                )
        elapsed = time.monotonic() - began
        require(
            output.count("retrying within startup window") <= 11,
            "metadata failures logged too often",
        )
        if (delayed and case != "fresh-delay") or case in (
            "worker-outage",
            "manager-match",
        ):
            require(
                notify.recv(4096).startswith(b"READY=1"),
                "recovered host did not notify readiness",
            )
        attempts = [
            at - began
            for at, path in samples
            if path.endswith("canonicalRegionName") and at >= began
        ]
        require(len(attempts) >= 4, "metadata was not retried")
        require(
            attempts[1] - attempts[0] >= 0.20 and attempts[2] - attempts[1] >= 0.40,
            "missing exponential backoff",
        )
        if not delayed:
            require(
                elapsed >= 299 and attempts[-1] >= 294,
                f"metadata window ended early at {elapsed:.2f}s",
            )
            require(
                max(b - a for a, b in itertools.pairwise(attempts)) < 8,
                "backoff exceeded cap",
            )
        if delayed:
            require(
                json.loads(record.read_text())
                == {"Region": "sjc", "ID": "instance", "PrivateIP": "127.0.0.2"},
                "successful metadata did not refresh the record",
            )
            require(
                record.stat().st_mode & 0o777 == 0o600,
                "recovery record is not owner-only",
            )
        elif record.exists():
            require(
                json.loads(record.read_text()) == old,
                "failed lookup changed recovery record",
            )
        if previous_admission is not None:
            require(
                admission.read_bytes() == previous_admission,
                "restart changed stored admission",
            )
        elif case.startswith("fresh"):
            require(
                not (state / "swarm").exists(),
                "fresh host founded during metadata outage or before Vault admission",
            )
        print(f"ok {case}: {len(attempts)} attempts across {elapsed:.2f}s", flush=True)
    finally:
        for process in reversed(processes):
            stop(process)
        server.shutdown()
        server.server_close()
        thread.join()
        notify.close()
        if record_events is not None:
            os.close(record_events)


def main(cases=CASES):
    binary, seed, root = sys.argv[1:4]
    root = Path(root)
    if len(sys.argv) == 5:
        run_case(binary, seed, root, sys.argv[4])
        return

    def child(case):
        result = subprocess.run(
            [
                "unshare",
                "--mount",
                "--net",
                sys.executable,
                __file__,
                binary,
                seed,
                str(root),
                case,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=400,
        )
        if result.returncode != 0:
            print(
                f"FAIL {case}: {result.stdout[-1000:]}{result.stderr[-6000:]}",
                flush=True,
            )
        require(
            result.returncode == 0,
            f"{case}: {result.stdout[-1000:]}{result.stderr[-6000:]}",
        )
        print(result.stdout.strip(), flush=True)

    runtime = subprocess.Popen(
        [
            str(root / "bin/containerd"),
            "--root",
            str(root / "containerd-root"),
            "--state",
            str(root / "containerd-state"),
            "--address",
            "/run/containerd/containerd.sock",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        read_until(runtime, b"containerd successfully booted", 10)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(cases)) as executor:
            list(executor.map(child, cases))
    finally:
        stop(runtime)


if __name__ == "__main__":
    main()
