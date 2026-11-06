#!/usr/bin/env python3
"""Three measured dev-only backup/transport repeats on existing authorized hosts."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import tempfile
import time
from types import SimpleNamespace
import cold

os.umask(0o077)
host = socket.gethostname().split('.')[0]
cold.require(host in ('delta', 'beta', 'mariogk-dev'), 'dev host required')
peer = 'mariogk-dev' if host != 'mariogk-dev' else 'beta'
rows = []
for repeat in range(1, 4):
    with tempfile.TemporaryDirectory(prefix='zdt-backup-proof-') as tmp:
        root = Path(tmp)
        data = root / 'data'; data.mkdir()
        with (data / 'retained.db').open('wb') as f:
            chunk = bytes(range(256)) * 4096
            for _ in range(64): f.write(chunk)
        (data / 'retained.db-wal').write_bytes(b'wal')
        (data / 'r10-holds').mkdir(); (data / 'r10-holds/hold').write_bytes(b'acked')
        roots = root / 'roots'; roots.write_text(json.dumps([str(data)]))
        password = root / 'fixture-password'; password.write_text('qualification-only-not-a-production-secret')
        cold.backup(SimpleNamespace(roots=str(roots), destination=str(root / 'copy'), password=str(password)))
        m = json.loads((root / 'copy/manifest.json').read_text())
        dest = cold.command(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', peer,
                             'mktemp -d /tmp/zdt-backup-transport.XXXXXXXX'], timeout=10).decode().strip()
        cold.require(dest.startswith('/tmp/zdt-backup-transport.') and '\n' not in dest, 'unexpected dev destination')
        try:
            started = time.monotonic()
            cold.command(['scp', '-q', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                          str(root / 'copy/data.tar.enc'), str(root / 'copy/manifest.json'), peer + ':' + dest + '/'], timeout=60)
            remote = 'python3 -c ' + shlex.quote('import hashlib,json,pathlib; p=pathlib.Path(' + repr(dest) + '); f=p/"data.tar.enc"; print(json.dumps({"size":f.stat().st_size,"sha256":hashlib.file_digest(f.open("rb"),"sha256").hexdigest()}))')
            readback = json.loads(cold.command(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', peer, remote], timeout=20))
            elapsed = time.monotonic() - started
            cold.require(readback == {'size': m['encryptedBytes'], 'sha256': m['encryptedSha256']}, 'off-host encrypted archive readback mismatch')
            rows.append({'repeat': repeat, 'sourceHost': host, 'destinationHost': peer, 'sourceBytes': m['bytes'],
                         'archiveBytes': m['encryptedBytes'], 'coldCopyEncryptReadbackSeconds': m['elapsedSeconds'],
                         'transferReadbackSeconds': elapsed, 'sha256': m['encryptedSha256'], 'exactReadback': True})
        finally:
            cold.command(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', peer,
                          'rm -r -- ' + shlex.quote(dest)], timeout=10)
print('BACKUP_TRANSPORT_RESULT=' + json.dumps(rows, sort_keys=True))
