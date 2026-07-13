#!/usr/bin/env python3
"""Run bounded credential-free local x64 NATS smoke checks with guaranteed cleanup."""

from __future__ import annotations

import hashlib
import json
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_BINARY_SHA256 = "4eb890bba37997898c81ef16c736f2c34cb594f4279b194c0404c7508dad5149"
EXPECTED_VERSION = "2.14.3"


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class Protocol:
    def __init__(self, port: int) -> None:
        self.socket = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.file = self.socket.makefile("rb")
        info = self.file.readline()
        if not info.startswith(b"INFO "):
            raise RuntimeError(f"expected INFO, received {info[:40]!r}")
        self.send(b'CONNECT {"verbose":false,"pedantic":true}\r\nPING\r\n')
        self.wait_for_line(b"PONG")

    def close(self) -> None:
        self.file.close()
        self.socket.close()

    def send(self, payload: bytes) -> None:
        self.socket.sendall(payload)

    def wait_for_line(self, wanted: bytes) -> None:
        for _ in range(20):
            line = self.file.readline().strip()
            if line == wanted:
                return
            if line.startswith(b"-ERR"):
                raise RuntimeError(line.decode())
        raise RuntimeError(f"did not receive {wanted!r}")

    def next_message(self) -> tuple[str, str | None, bytes]:
        for _ in range(30):
            line = self.file.readline().strip()
            if line.startswith(b"-ERR"):
                raise RuntimeError(line.decode())
            if not line.startswith(b"MSG "):
                continue
            fields = line.decode().split()
            if len(fields) == 4:
                subject, reply, size = fields[1], None, int(fields[3])
            elif len(fields) == 5:
                subject, reply, size = fields[1], fields[3], int(fields[4])
            else:
                raise RuntimeError(f"malformed MSG line {line!r}")
            payload = self.file.read(size)
            if self.file.read(2) != b"\r\n":
                raise RuntimeError("message payload missing CRLF")
            return subject, reply, payload
        raise RuntimeError("no message received")

    def request(self, subject: str, payload: bytes, sid: int) -> bytes:
        inbox = f"_INBOX.L0C.{sid}"
        self.send(f"SUB {inbox} {sid}\r\nPUB {subject} {inbox} {len(payload)}\r\n".encode() + payload + b"\r\n")
        _, _, response = self.next_message()
        return response


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    binary_text = shutil.which("nats-server")
    if binary_text is None:
        raise SystemExit("nats-server is absent")
    binary = Path(binary_text).resolve()
    observed_digest = sha256(binary)
    version_output = subprocess.run(
        [str(binary), "-v"], check=True, text=True, capture_output=True, timeout=5
    ).stdout.strip()
    observed_version = version_output.removeprefix("nats-server: v")
    if observed_digest != EXPECTED_BINARY_SHA256 or observed_version != EXPECTED_VERSION:
        raise SystemExit("local nats-server does not match the checked smoke candidate")

    client_port, monitor_port = free_port(), free_port()
    while monitor_port == client_port:
        monitor_port = free_port()
    checks = {
        "corePubSub": False,
        "coreRequestReply": False,
        "jetStreamCreatePublishGet": False,
        "monitoringLoopback": False,
        "processCleanup": False,
        "temporaryStoreCleanup": False,
    }
    process: subprocess.Popen[str] | None = None
    temporary_path = ""
    with tempfile.TemporaryDirectory(prefix="terrascale-nats-l0c-") as directory:
        temporary_path = directory
        log_path = Path(directory) / "server.log"
        store_path = Path(directory) / "store"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(binary), "-js", "-a", "127.0.0.1", "-p", str(client_port),
                 "-m", str(monitor_port), "-sd", str(store_path)],
                stdout=log, stderr=subprocess.STDOUT, text=True,
            )
            protocol: Protocol | None = None
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("nats-server exited before readiness")
                    try:
                        protocol = Protocol(client_port)
                        break
                    except OSError:
                        time.sleep(0.05)
                if protocol is None:
                    raise RuntimeError("nats-server readiness deadline exceeded")

                protocol.send(b"SUB l0c.core 10\r\nPUB l0c.core 5\r\nhello\r\n")
                subject, _, payload = protocol.next_message()
                checks["corePubSub"] = subject == "l0c.core" and payload == b"hello"

                protocol.send(b"SUB l0c.service 11\r\nSUB _INBOX.L0C.REPLY 12\r\nPUB l0c.service _INBOX.L0C.REPLY 4\r\nping\r\n")
                subject, reply, payload = protocol.next_message()
                if subject == "l0c.service" and reply == "_INBOX.L0C.REPLY" and payload == b"ping":
                    protocol.send(b"PUB _INBOX.L0C.REPLY 4\r\npong\r\n")
                    reply_subject, _, reply_payload = protocol.next_message()
                    checks["coreRequestReply"] = reply_subject == "_INBOX.L0C.REPLY" and reply_payload == b"pong"

                config = json.dumps({"name": "L0C_SMOKE", "subjects": ["l0c.events"], "storage": "file"}, separators=(",", ":")).encode()
                created = json.loads(protocol.request("$JS.API.STREAM.CREATE.L0C_SMOKE", config, 20))
                if "error" in created:
                    raise RuntimeError(f"stream create failed: {created['error']}")
                ack = json.loads(protocol.request("l0c.events", b"event", 21))
                fetched = json.loads(protocol.request("$JS.API.STREAM.MSG.GET.L0C_SMOKE", b'{"seq":1}', 22))
                checks["jetStreamCreatePublishGet"] = ack.get("seq") == 1 and fetched.get("message", {}).get("seq") == 1

                with socket.create_connection(("127.0.0.1", monitor_port), timeout=2) as monitor:
                    monitor.sendall(b"GET /healthz?js-enabled-only=true HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
                    checks["monitoringLoopback"] = b"200 OK" in monitor.recv(4096)
            finally:
                if protocol is not None:
                    protocol.close()
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                checks["processCleanup"] = process.poll() is not None
    checks["temporaryStoreCleanup"] = not Path(temporary_path).exists()
    if not all(checks.values()):
        raise SystemExit(f"local smoke checks failed: {checks}")
    report = {
        "schemaVersion": 1,
        "classification": "bounded-local-x64-l0c-smoke-not-production-qualification",
        "hostArchitecture": "x86_64",
        "server": {"version": observed_version, "binarySha256": observed_digest},
        "network": "loopback-only-dynamic-ports",
        "credentials": "none",
        "checks": checks,
        "notTested": [
            "ARM64", "JWT/NKeys/accounts/permissions", "TLS/mTLS/routes/gateways",
            "R3/peer-loss/snapshot-restore", "KV CAS/watch", "Object Store",
            "durable-consumer-redelivery/backoff", "N/N-1 mixed versions",
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
