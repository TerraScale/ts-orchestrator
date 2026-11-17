import base64
import hashlib
import hmac
import os
import socket
import ssl
import struct


class Rejected(ConnectionError):
    def __init__(self, code):
        super().__init__("Postgres admission refused")
        self.code = code


def exact(stream, count):
    data = bytearray()
    while len(data) < count:
        part = stream.recv(count - len(data))
        if not part:
            raise ConnectionError("Postgres closed before ReadyForQuery")
        data.extend(part)
    return bytes(data)


def packet(stream):
    tag = exact(stream, 1)
    size = struct.unpack("!I", exact(stream, 4))[0]
    if size < 4 or size > 1 << 20:
        raise ConnectionError("invalid Postgres message length")
    return tag, exact(stream, size - 4)


def send(stream, tag, body):
    stream.sendall(tag + struct.pack("!I", len(body) + 4) + body)


def connect(host, address, password, timeout, source):
    raw = socket.create_connection((address, 5432), timeout, (source, 0))
    try:
        raw.sendall(struct.pack("!II", 8, 80877103))
        if exact(raw, 1) != b"S":
            raise ConnectionError("Postgres TLS negotiation refused")
        stream = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise
    try:
        body = struct.pack("!I", 196608) + b"user\0postgres\0database\0postgres\0\0"
        stream.sendall(struct.pack("!I", len(body) + 4) + body)
        nonce = base64.b64encode(os.urandom(18)).decode()
        first = "n=postgres,r=" + nonce
        expected = None
        verified = False
        while True:
            tag, data = packet(stream)
            if tag == b"E":
                fields = {part[:1]: part[1:] for part in data.split(b"\0") if part}
                raise Rejected(fields.get(b"C", b"").decode())
            if tag == b"R":
                kind = struct.unpack("!I", data[:4])[0]
                if kind == 10:
                    if b"SCRAM-SHA-256\0" not in data[4:]:
                        raise ConnectionError("Postgres SCRAM-SHA-256 unavailable")
                    initial = ("n,," + first).encode()
                    send(stream, b"p", b"SCRAM-SHA-256\0" + struct.pack("!I", len(initial)) + initial)
                elif kind == 11:
                    server = data[4:].decode()
                    fields = dict(item.split("=", 1) for item in server.split(","))
                    if not fields["r"].startswith(nonce) or fields["r"] == nonce:
                        raise ConnectionError("invalid Postgres SCRAM nonce")
                    iterations = int(fields["i"])
                    if not 1 <= iterations <= 1000000:
                        raise ConnectionError("invalid Postgres SCRAM iteration count")
                    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(fields["s"]), iterations)
                    key = hmac.digest(salted, b"Client Key", "sha256")
                    final = "c=biws,r=" + fields["r"]
                    message = (first + "," + server + "," + final).encode()
                    signature = hmac.digest(hashlib.sha256(key).digest(), message, "sha256")
                    proof = bytes(a ^ b for a, b in zip(key, signature, strict=True))
                    expected = hmac.digest(hmac.digest(salted, b"Server Key", "sha256"), message, "sha256")
                    send(stream, b"p", (final + ",p=" + base64.b64encode(proof).decode()).encode())
                elif kind == 12:
                    fields = dict(item.split("=", 1) for item in data[4:].decode().split(","))
                    if expected is None or "v" not in fields or not hmac.compare_digest(base64.b64decode(fields["v"]), expected):
                        raise ConnectionError("Postgres server SCRAM signature invalid")
                    verified = True
                elif kind != 0:
                    raise ConnectionError("unexpected Postgres authentication method")
            if tag == b"Z":
                if not verified:
                    raise ConnectionError("Postgres session did not authenticate with SCRAM")
                return stream
    except BaseException:
        stream.close()
        raise
