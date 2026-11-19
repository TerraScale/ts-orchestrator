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
        probe.request("GET", "/readyz", headers={"Host": "127.0.0.1"})
        response = probe.getresponse()
        assert response.status == 200, response.status
        window = int(response.getheader("X-TerraScale-Drain-Milliseconds")) / 1000
        assert 0 < window <= 20, window
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
        stopping = subprocess.Popen(["sudo", "systemctl", "stop", "ts-orch"])
        withdrew = False
        samples = 0
        while time.monotonic() - started < window - 1:
            health = http.client.HTTPConnection(
                "127.0.0.1", 80, timeout=1, source_address=(source, 0)
            )
            try:
                health.request("GET", "/readyz", headers={"Host": "127.0.0.1"})
                reply = health.getresponse()
                if withdrew:
                    assert reply.status == 503, reply.status
                else:
                    assert reply.status in (200, 503), reply.status
                    withdrew = reply.status == 503
                reply.read()
            finally:
                health.close()
            with (
                socket.create_connection(("127.0.0.1", 443), timeout=2) as application_raw,
                context.wrap_socket(application_raw, server_hostname="data.e2e.test") as application,
            ):
                application.sendall(b"GET /boots HTTP/1.1\r\nHost: data.e2e.test\r\nConnection: close\r\n\r\n")
                reply = http.client.HTTPResponse(application)
                reply.begin()
                assert reply.status == 200, reply.status
                assert reply.read(), "empty application response during propagation"
                samples += 1
        assert withdrew and samples > 0, (withdrew, samples)
        stopping.wait(timeout=30 - (time.monotonic() - started))
        assert stopping.returncode == 0, stopping.returncode
        elapsed = time.monotonic() - started
        assert window <= elapsed < 30, (window, elapsed)
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
            f"probed manager stop with held SSE: {elapsed:.3f}s; {window:g}s withdrawal window; health 503 while application responses completed ({samples} samples); stream closed; no SIGKILL",
            flush=True,
        )
finally:
    descriptor = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
    os.close(descriptor)
    subprocess.run(["sudo", "rm", str(fifo), str(script)], check=True)
