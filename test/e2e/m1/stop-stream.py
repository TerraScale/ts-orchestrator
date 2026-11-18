import http.client
import os
import pathlib
import socket
import ssl
import subprocess
import sys
import time

ca, data = sys.argv[1:]
root = pathlib.Path(data)
fifo = root / "stop-stream"
script = root / "cgi-bin" / "stop-stream"
subprocess.run(["sudo", "install", "-d", "-m", "0755", str(script.parent)], check=True)
subprocess.run(["sudo", "mkfifo", "-m", "0666", str(fifo)], check=True)
subprocess.run(
    ["sudo", "tee", str(script)],
    input=b"#!/bin/sh\nprintf 'Content-Type: text/event-stream\\r\\n\\r\\ndata: held\\n\\n'\ncat /tmp/stop-stream\n",
    stdout=subprocess.DEVNULL,
    check=True,
)
subprocess.run(["sudo", "chmod", "0755", str(script)], check=True)
try:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(("192.0.2.1", 80))
        source = route.getsockname()[0]
    assert not source.startswith("127."), source
    probe = http.client.HTTPConnection(
        "127.0.0.1", 80, timeout=5, source_address=(source, 0)
    )
    try:
        probe.request("GET", "/healthz", headers={"Host": "data.e2e.test"})
        response = probe.getresponse()
        assert response.status in (200, 404), response.status
        response.read()
    finally:
        probe.close()
    context = ssl.create_default_context(cafile=ca)
    with (
        socket.create_connection(("127.0.0.1", 443), timeout=10) as raw,
        context.wrap_socket(raw, server_hostname="data.e2e.test") as client,
    ):
        client.sendall(
            b"GET /cgi-bin/stop-stream HTTP/1.1\r\nHost: data.e2e.test\r\n\r\n"
        )
        response = http.client.HTTPResponse(client)
        response.begin()
        assert response.status == 200, response.status
        assert response.read(12) == b"data: held\n\n"
        started = time.monotonic()
        subprocess.run(["sudo", "systemctl", "stop", "ts-orch"], check=True, timeout=30)
        elapsed = time.monotonic() - started
        assert 20 <= elapsed < 30, elapsed
        exit_code = subprocess.check_output(
            [
                "sudo",
                "systemctl",
                "show",
                "ts-orch",
                "--property=ExecMainCode",
                "--value",
            ],
            text=True,
        ).strip()
        assert exit_code == "1", (
            f"manager did not exit normally: ExecMainCode={exit_code}"
        )
        try:
            assert response.read(1) == b"", "stream still sending after stop"
        except http.client.IncompleteRead as error:
            assert not error.partial, error.partial
        print(
            f"probed manager stop with held SSE: {elapsed:.3f}s; 20s health drain kept; stream closed; no SIGKILL",
            flush=True,
        )
finally:
    descriptor = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    os.close(descriptor)
    subprocess.run(["sudo", "rm", str(fifo), str(script)], check=True)
