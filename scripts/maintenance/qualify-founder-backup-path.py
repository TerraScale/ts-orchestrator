#!/usr/bin/env python3
"""Read-only founder sizing and equivalent-byte transport, dev host only.

No serving data is copied or changed. This deliberately does not qualify workers
or all data mounts. Pin the measured destination before using the transport proof.
"""
import hashlib
import json
import math
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
destination = socket.gethostname().split('.')[0]
assert destination in ('delta', 'beta', 'mariogk-dev')
ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'Compression=no']
measure = '''import os,json,time
root='/var/lib/ts-data/terrabase';sizes=[];started=time.time()
for parent,dirs,files in os.walk(root,followlinks=False):
 for name in dirs+files:
  p=os.path.join(parent,name)
  if os.path.islink(p):raise RuntimeError('unexpected link')
 for name in files:sizes.append(os.stat(os.path.join(parent,name)).st_size)
print(json.dumps({'root':root,'fileBytes':sum(sizes),'fileSizes':sizes,'at':started}))
'''
rows = []
for region in ('gru', 'sjc', 'fra'):
    host = 'ts-' + region + '-1'
    size = json.loads(subprocess.check_output([*ssh, host, 'sudo python3 -c ' + shlex.quote(measure)], timeout=20))
    assert size['fileBytes'] > 0 and len(size['fileSizes']) < 10000
    repeats = []
    for repeat in range(1, 4):
        with tempfile.TemporaryDirectory(prefix='zdt-equivalent-backup-') as tmp:
            root = Path(tmp); data = root / 'synthetic'; data.mkdir()
            for i, count in enumerate(size['fileSizes']):
                with (data / str(i)).open('wb') as f:
                    while count:
                        n = min(count, 1024 * 1024); f.write(os.urandom(n)); count -= n
            roots = root / 'roots'; roots.write_text(json.dumps([str(data)]))
            password = root / 'fixture-pass'; password.write_text('dev-fixture-only')
            cold.backup(SimpleNamespace(roots=str(roots), destination=str(root / 'copy'), password=str(password)))
            manifest = json.loads((root / 'copy/manifest.json').read_text())
            count = manifest['encryptedBytes']
            # This is the same root-SSH stdout/readback route as sudo cat of the
            # eventual encrypted cold archive; production only generates bytes.
            generate = 'import os,sys,hashlib; h=hashlib.sha256(); remaining=' + str(count) + '\nwhile remaining:\n n=min(remaining,1048576);chunk=os.urandom(n);sys.stdout.buffer.write(chunk);h.update(chunk);remaining-=n\nsys.stdout.buffer.flush();sys.stderr.write(h.hexdigest())'
            started = time.monotonic()
            with (root / 'received-equivalent.enc').open('wb') as out:
                transfer_result = subprocess.run([*ssh, host, 'sudo python3 -c ' + shlex.quote(generate)], stdout=out, stderr=subprocess.PIPE, check=True, timeout=45)
            archive = root / 'received-equivalent.enc'
            assert archive.stat().st_size == count
            with archive.open('rb') as stream: actual = hashlib.file_digest(stream, 'sha256').hexdigest()
            assert transfer_result.stderr.decode().strip() == actual
            transfer = time.monotonic() - started
            total = manifest['elapsedSeconds'] + transfer
            repeats.append({'repeat':repeat, 'equivalentArchiveBytes':count, 'localCopyEncryptReadbackSeconds':manifest['elapsedSeconds'],
                            'sourceSSHTransferReadbackSeconds':transfer, 'totalSeconds':total,
                            'budgetSeconds':math.ceil(total * 1.5), 'receivedSha256':actual})
    rows.append({'node':host,'region':region,'source':{'root':size['root'],'fileBytes':size['fileBytes'],'fileCount':len(size['fileSizes']),'at':size['at']},
                 'destinationHost':destination,'path':'source sudo stdout -> SSH(no compression) -> dev private file -> full readback',
                 'repeats':repeats,'budgetSeconds':max(r['budgetSeconds'] for r in repeats)})
print('FOUNDER_BACKUP_PATH_RESULT=' + json.dumps({'productionMutation':False,'scope':'principal TerraBase root on founders only; workers and other mounts NOT QUALIFIED','nodes':rows},sort_keys=True))
