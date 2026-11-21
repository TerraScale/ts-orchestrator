import http.server
import json
import os
import socket
import ssl
import threading
import time
from pathlib import Path

root = Path('/opt/host-image')
case = Path('/etc/host-image-case').read_text().strip()
baked = Path('/usr/local/lib/ts-orch/image-release.sha256').read_text().strip()
launch = (root / 'launch.sha256').read_text().strip()
unbound_since = None
binding = threading.Lock()
volume = {
    'terrascale-data-volume': 'ocid1.volume.oc1.phx.c2t',
    'terrascale-data-may-format': 'true',
}
static = {
    'ssh_authorized_keys': (root / 'ssh-key.pub').read_text(),
    'terrascale-release-url': 'https://localhost:8443/release',
    'terrascale-release-sha256': (
        '0' * 64 if case == 'wrong-sha256' else launch if case == 'launch-release' else baked
    ),
}


def current(path):
    global unbound_since
    if case != 'late-bind':
        return static | volume
    with binding:
        if unbound_since is not None and time.monotonic() - unbound_since >= 15:
            return static | volume
        if unbound_since is None and path in (
            '/opc/v2/instance/metadata/terrascale-data-volume',
            '/opc/v2/instance/metadata/',
            '/opc/v2/instance/metadata',
            '/opc/v2/instance/',
        ):
            unbound_since = time.monotonic()
        return static


class Metadata(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer Oracle':
            self.send_error(401)
            return
        prefix = '/opc/v2/instance/metadata/'
        metadata = current(self.path)
        if self.path == '/opc/v2/instance/':
            body = json.dumps({'id': 'ocid1.instance.oc1.phx.c2t', 'metadata': metadata})
        elif self.path == prefix:
            body = json.dumps(metadata)
        elif self.path.startswith(prefix) and self.path[len(prefix):] in metadata:
            body = metadata[self.path[len(prefix):]]
        elif self.path == '/opc/v2/instance/metadata':
            body = json.dumps(metadata)
        else:
            self.send_error(404)
            return
        content = body.encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)


class Release(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/release':
            self.send_error(404)
            return
        with (root / 'downloads').open('a') as output:
            output.write(case + '\n')
        path = root / 'release'
        self.send_response(200)
        self.send_header('Content-Length', str(path.stat().st_size))
        self.end_headers()
        with path.open('rb') as source:
            while chunk := source.read(1024 * 1024):
                self.wfile.write(chunk)


imds = http.server.ThreadingHTTPServer(('169.254.169.254', 80), Metadata)
release = http.server.ThreadingHTTPServer(('127.0.0.1', 8443), Release)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root / 'localhost.crt', root / 'localhost.key')
release.socket = context.wrap_socket(release.socket, server_side=True)
threading.Thread(target=imds.serve_forever, daemon=True).start()
threading.Thread(target=release.serve_forever, daemon=True).start()
notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
notify.connect(os.environ['NOTIFY_SOCKET'])
notify.sendall(b'READY=1')
threading.Event().wait()
