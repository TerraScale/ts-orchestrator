#!/usr/bin/env python3
"""Read-only founder backup timing with the real live TerraBase bytes.

Runs on the pinned off-host destination (mariogk-dev). Each founder streams a
tar of its only mounted TerraBase root over root SSH stdout (compression off).
The destination hashes and counts the stream and discards it: no customer
bytes are stored anywhere and nothing on the founder is written or changed.
The live files may change while being read, so these hashes only prove the
stream arrived intact (source == destination); they are not a cold backup.
"""
import hashlib, json, math, shlex, socket, subprocess, time

assert socket.gethostname().split('.')[0] == 'mariogk-dev'
ROOT = '/var/lib/ts-data/terrabase'
ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'Compression=no']
# Source side: tar to stdout, hash what was sent, report bytes/hash/seconds on stderr.
SEND = r'''import hashlib,subprocess,sys,time,json
t=time.monotonic();h=hashlib.sha256();n=0
p=subprocess.Popen(['nice','-n','10','tar','--warning=no-file-changed','-C','/var/lib/ts-data','-cf','-','terrabase'],stdout=subprocess.PIPE)
for c in iter(lambda:p.stdout.read(1<<20),b''):h.update(c);n+=len(c);sys.stdout.buffer.write(c)
sys.stdout.buffer.flush();rc=p.wait()
sys.stderr.write(json.dumps({'rc':rc,'bytes':n,'sha256':h.hexdigest(),'seconds':time.monotonic()-t}))'''
# Local proxy for copy+readback: archive and hash on the founder, read-only.
LOCAL = r'''import hashlib,subprocess,time,json
t=time.monotonic();h=hashlib.sha256();n=0
p=subprocess.Popen(['nice','-n','10','tar','--warning=no-file-changed','-C','/var/lib/ts-data','-cf','-','terrabase'],stdout=subprocess.PIPE)
for c in iter(lambda:p.stdout.read(1<<20),b''):h.update(c);n+=len(c)
rc=p.wait();print(json.dumps({'rc':rc,'bytes':n,'seconds':time.monotonic()-t}))'''
SIZE = r'''import os,json
s=[];
for d,_,f in os.walk('/var/lib/ts-data/terrabase'):
 for x in f:s.append(os.lstat(os.path.join(d,x)).st_size)
print(json.dumps({'fileBytes':sum(s),'fileCount':len(s)}))'''

def remote(host, code, **kw):
    return subprocess.run([*ssh, host, 'sudo python3 -c ' + shlex.quote(code)], **kw)

rows = []
for region in ('gru', 'sjc', 'fra'):
    host = f'ts-{region}-1'
    size = json.loads(remote(host, SIZE, capture_output=True, check=True, timeout=30).stdout)
    repeats = []
    for i in range(1, 4):
        local = json.loads(remote(host, LOCAL, capture_output=True, check=True, timeout=60).stdout)
        assert local['rc'] in (0, 1), local
        started = time.monotonic(); h = hashlib.sha256(); n = 0
        p = subprocess.Popen([*ssh, host, 'sudo python3 -c ' + shlex.quote(SEND)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for c in iter(lambda: p.stdout.read(1 << 20), b''):
            h.update(c); n += len(c)
        err = p.stderr.read().decode(); assert p.wait(timeout=90) == 0, err
        transfer = time.monotonic() - started
        src = json.loads(err)
        assert src['rc'] in (0, 1) and src['bytes'] == n and src['sha256'] == h.hexdigest(), (src, n)
        # Budget: local copy + local readback (2x read-only archive) + transfer/readback.
        total = 2 * local['seconds'] + transfer
        repeats.append({'repeat': i, 'archiveBytes': n, 'sha256Match': True, 'tarRc': src['rc'],
                        'founderArchiveHashSeconds': local['seconds'], 'sshTransferSeconds': transfer,
                        'totalSeconds': total, 'budgetSeconds': math.ceil(total * 1.5)})
    rows.append({'node': host, 'region': region, 'root': ROOT, **size, 'repeats': repeats,
                 'budgetSeconds': max(r['budgetSeconds'] for r in repeats)})
print('FOUNDER_BACKUP_REAL_RESULT=' + json.dumps({
    'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'destination': 'mariogk-dev (hash+discard)',
    'productionMutation': False, 'scope': 'live mounted TerraBase root on 3 founders; real bytes; workers excluded by plan v3',
    'nodes': rows}, sort_keys=True))
