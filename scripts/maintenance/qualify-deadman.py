#!/usr/bin/env python3
"""Dev-host fixture rehearsal of the dead-man switch, with kill -9 of the operator.

Runs the real deadman.py / deadman_workers.py against fake host commands
(systemctl, nft, mountpoint, umount, KV tool, orchestrator binary, oci) in a
private temp tree. A fake operator writes the heartbeat until it is SIGKILLed;
a fake timer runs the switch every 0.5 s. Per phase it asserts: no action while
the heartbeat is fresh, then exactly the expected restore actions, once.
Usage: qualify-deadman.py REPEATS
"""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
LIMIT = '3'

FAKE = {
'systemctl': '#!/bin/sh\necho "systemctl $*" >> "$ZDT_FIX/calls.log"\n',
'nft': '#!/bin/sh\nif [ "$1 $2" = "list tables" ] && [ -e "$ZDT_FIX/gate" ]; then echo "table inet ts_zdt_20261105"; fi\n',
'mountpoint': '#!/bin/sh\n[ -e "$2.mounted" ]\n',
'umount': '#!/bin/sh\nrm -f "$1.mounted"; echo "umount $1" >> "$ZDT_FIX/calls.log"\n',
}
COLD = r'''#!/usr/bin/env python3
import os, sys
fix = os.environ['ZDT_FIX']; a = sys.argv[1:]
open(fix + '/calls.log', 'a').write('cold ' + ' '.join(a[:2]) + '\n')
live = os.path.exists(fix + '/keys-live')
if a[:2] == ['kv', 'dry-run']: sys.exit(0 if live else 1)
if a[:2] == ['kv', 'delete']:
    if live: os.remove(fix + '/keys-live')
    sys.exit(0)
if a[:1] == ['kv-tombstoned']: sys.exit(1 if live else 0)
if a[:2] == ['gate', 'open']:
    os.remove(fix + '/gate'); sys.exit(0)
sys.exit(2)
'''
ORCH = r'''#!/usr/bin/env python3
import json, os, sys
fix = os.environ['ZDT_FIX']; a = sys.argv[1:]
open(fix + '/calls.log', 'a').write('orch ' + ' '.join(a[:2]) + '\n')
job = json.load(open(fix + '/job.json'))
if a[1] == 'status': print(json.dumps(job))
elif a[1] == 'owner': sys.exit(0 if os.path.exists(fix + '/owner-ready') else 1)
elif a[1] == 'replace':
    job['phase'] = 'verified'; json.dump(job, open(fix + '/job.json', 'w'))
'''
OCI = r'''#!/usr/bin/env python3
import json, os, sys
fix = os.environ['ZDT_FIX']; a = sys.argv[3:]
open(fix + '/calls.log', 'a').write('oci ' + ' '.join(a[:3]) + '\n')
st = json.load(open(fix + '/oci.json'))
def out(d): print(json.dumps({'data': d}))
if a[:3] == ['compute', 'volume-attachment', 'get']: out({'lifecycle-state': st['founderAttach']})
elif a[:3] == ['compute', 'volume-attachment', 'detach']: st['founderAttach'] = 'DETACHED'
elif a[:3] == ['compute', 'boot-volume-attachment', 'list']:
    out([{'lifecycle-state': 'ATTACHED', 'boot-volume-id': st['boot']}] if st['boot'] else [])
elif a[:3] == ['compute', 'boot-volume-attachment', 'attach']: st['boot'] = a[a.index('--boot-volume-id') + 1]
elif a[:3] == ['compute', 'instance', 'get']: out({'lifecycle-state': st['worker']})
elif a[:3] == ['compute', 'instance', 'action']: st['worker'] = 'RUNNING'
json.dump(st, open(fix + '/oci.json', 'w'))
'''

EXPECT = {
    'stopped': ['umount', 'cold kv dry-run', 'cold kv delete', 'cold kv-tombstoned --token', 'systemctl start containerd', 'systemctl start ts-orch', 'cold gate open'],
    'installed': ['umount', 'cold kv dry-run', 'cold kv-tombstoned --token', 'systemctl stop ts-orch', 'systemctl start containerd', 'systemctl start ts-orch', 'cold gate open'],
    'engines': ['orch bootstrap-maintenance status', 'orch bootstrap-maintenance owner', 'orch bootstrap-maintenance replace', 'orch bootstrap-maintenance status', 'cold gate open'],
}


def scenario(phase, repeat):
    with tempfile.TemporaryDirectory(prefix='zdt-deadman-') as tmp:
        root = Path(tmp)
        fix, state, bins, mnt = root / 'fix', root / 'state', root / 'bin', root / 'mnt'
        for d in (fix, state, bins, mnt):
            d.mkdir()
        for name, body in FAKE.items():
            (bins / name).write_text(body); (bins / name).chmod(0o755)
        (bins / 'cold.py').write_text(COLD); (bins / 'cold.py').chmod(0o755)
        (bins / 'orch').write_text(ORCH); (bins / 'orch').chmod(0o755)
        (bins / 'orch.zdt-b443').write_text(ORCH + '# old\n'); (bins / 'orch.zdt-b443').chmod(0o755)
        (bins / 'oci').write_text(OCI); (bins / 'oci').chmod(0o755)
        (fix / 'gate').write_text('closed')
        if phase == 'stopped':
            (fix / 'keys-live').write_text('1')
        (mnt / 'zdt-ts-gru-2').mkdir(); (mnt / 'zdt-ts-gru-2.mounted').write_text('1')
        (fix / 'job.json').write_text(json.dumps({'id': 'zdt-x', 'member': 'ts-fra-1', 'owner': 'ts-fra-2', 'epoch': 7, 'phase': 'held'}))
        (fix / 'owner-ready').write_text('1')
        for f in ('nats.token', 'stale-key-audit.json'):
            (state / f).write_text('{}')
        (state / 'phase').write_text(phase); (state / 'armed').write_text('')
        # Worker half state (delta): clone attached to founder, original detached, worker stopped.
        (fix / 'oci.json').write_text(json.dumps({'founderAttach': 'ATTACHED', 'boot': '', 'worker': 'STOPPED'}))
        wstate = root / 'wstate'; wstate.mkdir()
        (wstate / 'armed').write_text(''); (wstate / 'phase').write_text(phase); (wstate / 'attach-gru.id').write_text('att')
        (wstate / 'targets.json').write_text(json.dumps({'gru': {'ociRegion': 'r', 'worker': 'w', 'workerBootVolume': 'orig', 'ad': 'ad', 'compartment': 'c'}}))
        env = dict(os.environ, PATH=f'{bins}:{os.environ["PATH"]}', ZDT_FIX=str(fix), ZDT_STATE=str(state), ZDT_COLD=str(bins / 'cold.py'),
                   ZDT_BIN=str(bins / 'orch'), ZDT_LIMIT=LIMIT, ZDT_MNT=str(mnt), ZDT_OCI=str(bins / 'oci'))
        operator = subprocess.Popen([sys.executable, '-c', 'import pathlib,sys,time\nwhile True:\n [pathlib.Path(p).touch() for p in sys.argv[1:]]; time.sleep(0.5)',
                                     str(state / 'heartbeat'), str(wstate / 'heartbeat')])
        timer_runs = 0
        def tick():
            nonlocal timer_runs
            timer_runs += 1
            subprocess.run([sys.executable, '-I', str(HERE / 'deadman.py')], env=env, capture_output=True, timeout=60)
            subprocess.run([sys.executable, '-I', str(HERE / 'deadman_workers.py'), 'check', str(wstate)], env=env, capture_output=True, timeout=60)
        try:
            time.sleep(0.6)
            for _ in range(8):  # 4 s with a live operator: nothing may happen
                tick(); time.sleep(0.5)
            calls = (fix / 'calls.log').read_text() if (fix / 'calls.log').exists() else ''
            assert calls == '', f'acted with a fresh heartbeat: {calls}'
            os.kill(operator.pid, signal.SIGKILL)
            killed = time.monotonic()
            while not ((state / 'deadman-done').exists() and (wstate / 'deadman-done').exists()):
                assert time.monotonic() - killed < 30, 'dead-man did not complete within 30 s of the kill'
                tick(); time.sleep(0.5)
            fired = time.monotonic() - killed
            tick(); tick()  # one-shot: later timer runs change nothing
        finally:
            operator.kill(); operator.wait()
        calls = [l for l in (fix / 'calls.log').read_text().splitlines()]
        founder = [c for c in calls if not c.startswith('oci')]
        got = [c for c in founder if any(c.startswith(e) for e in ('umount', 'cold', 'systemctl', 'orch'))]
        norm = ['umount' if c.startswith('umount') else c for c in got]
        assert norm == EXPECT[phase], f'{phase}: {norm}'
        assert not (fix / 'gate').exists(), 'ingress not reopened'
        if phase == 'installed':
            assert (bins / 'orch').read_text().endswith('# old\n'), 'b443-era binary not restored'
        if phase == 'stopped':
            assert not (fix / 'keys-live').exists(), 'stale keys not deleted'
        if phase == 'engines':
            assert json.loads((fix / 'job.json').read_text())['phase'] == 'verified'
        oci = json.loads((fix / 'oci.json').read_text())
        if phase in ('stopped', 'installed'):
            assert oci == {'founderAttach': 'DETACHED', 'boot': 'orig', 'worker': 'RUNNING'}, oci
        else:
            assert oci == {'founderAttach': 'ATTACHED', 'boot': '', 'worker': 'STOPPED'}, oci
        return {'repeat': repeat, 'phase': phase, 'firedAfterKillSeconds': round(fired, 2), 'founderActions': norm,
                'worker': oci, 'timerRuns': timer_runs}


rows = []
for repeat in range(1, int(sys.argv[1]) + 1):
    for phase in ('stopped', 'installed', 'engines'):
        rows.append(scenario(phase, repeat))
        print(json.dumps(rows[-1]), flush=True)
print(json.dumps({'pass': True, 'scenarios': len(rows)}))
