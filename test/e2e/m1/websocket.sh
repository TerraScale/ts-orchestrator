#!/usr/bin/env bash
source "$(dirname "$0")/setup.sh"

begin "websocket upgrade through the edge"
python3 - "$work/ca.pem" whoami.e2e.test <<'EOF'
import base64, hashlib, os, socket, ssl, sys
ca, host = sys.argv[1:3]
key = base64.b64encode(os.urandom(16)).decode()
tls = ssl.create_default_context(cafile=ca).wrap_socket(socket.create_connection(("127.0.0.1", 443), timeout=5), server_hostname=host)
tls.sendall(f"GET /echo HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: websocket, foo\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n".encode())
stream = tls.makefile("rb")
status = stream.readline()
headers = {name.strip().lower(): value.strip() for name, value in (line.decode().split(":", 1) for line in iter(stream.readline, b"\r\n"))}
accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
if status.split()[1] != b"101" or headers.get("sec-websocket-accept") != accept:
	sys.exit(f"websocket upgrade refused: {status!r} {headers}")
mask, payload = os.urandom(4), b"ts-e2e websocket"
tls.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
echo = stream.read(2 + len(payload))
if echo != bytes([0x81, len(payload)]) + payload:
	sys.exit(f"websocket echo missing: {echo!r}")
print(status.decode().strip(), "and echo", echo[2:].decode())
EOF
end "upgrade -> whoami /echo echoed one frame through the edge"
