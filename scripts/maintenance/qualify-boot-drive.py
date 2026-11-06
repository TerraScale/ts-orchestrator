#!/usr/bin/env python3
"""Local qualification of cold.py boot-drive ordering with a fake executor CLI.

Runs the real boot_drive function in a private temp root with its fixed paths
redirected, process/runtime observations stubbed to "no engine", the watch
shortened, and a fake `bootstrap-maintenance` that records every call.
Proves: the owner replaces after stage; a follower replaces only after its
owner is ready; a follower whose owner never becomes ready never calls replace;
and a second boot never re-drives. No root, no network, no real executor.
"""
import importlib.util
import json
import os
import socket
import stat
import sys
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location('cold', Path(__file__).with_name('cold.py'))
cold = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cold)
REAL_SLEEP = cold.time.sleep

FAKE = r'''#!/usr/bin/env python3
import json, os, sys
state = os.environ['FAKE_STATE']
log = os.path.join(state, 'calls.log')
action = sys.argv[2]
open(log, 'a').write(action + '\n')
job = json.load(open(os.path.join(state, 'job.json')))
if action == 'status':
    print(json.dumps(job)); sys.exit(0)
if action == 'owner':
    ready = os.path.join(state, 'owner-ready')
    n = len([l for l in open(log) if l.strip() == 'owner'])
    sys.exit(0 if os.path.exists(ready) and n >= int(open(ready).read() or 1) else 1)
if action == 'replace':
    job['phase'] = 'verified'; json.dump(job, open(os.path.join(state, 'job.json'), 'w'))
sys.exit(0)
'''


def scenario(name, member, owner, owner_ready_after):
    root = Path(tempfile.mkdtemp(prefix='zdt-boot-drive-'))
    os.chmod(root, 0o700)
    state = root / 'state'
    (state / 'terrabase-bootstrap').mkdir(parents=True)
    (state / 'terrabase-bootstrap' / 'control.sock').write_text('')
    drive = root / 'drive'
    drive.mkdir(mode=0o700)
    host = socket.gethostname()
    cold.save(drive / 'drive.json', {'id': 'zdt-' + name, 'member': host, 'instance': 'ocid1.instance.oc1.test.' + ('owner' if name == 'wrong-instance' else name)})
    (state / 'job.json').write_text(json.dumps({'id': 'zdt-' + name, 'phase': 'held', 'member': member, 'owner': owner}))
    if owner_ready_after is not None:
        (state / 'owner-ready').write_text(str(owner_ready_after))
    fake = root / 'bin' / 'terrascale-orchestrator'
    fake.parent.mkdir()
    fake.write_text(FAKE)
    fake.chmod(stat.S_IRWXU)
    os.environ['FAKE_STATE'] = str(state)
    cold.os.geteuid = lambda: 0  # the private-file owner check is qualified elsewhere
    cold.private = Path
    cold.imds_instance_id = lambda: 'ocid1.instance.oc1.test.' + name
    cold.STATE, cold.DRIVE_DIR, cold.BINARY = str(state), str(drive).lstrip('/'), str(fake).lstrip('/')
    cold.WATCH_SECONDS, cold.OWNER_WAIT_SECONDS, cold.STAGE_WAIT_SECONDS, cold.PREPULL_WAIT_SECONDS = 1, 3, 1, 1
    cold.engine_processes, cold.runtime_tasks = (lambda: []), (lambda: {})
    cold.time.sleep = lambda s: REAL_SLEEP(min(s, 0.05))
    error = None
    try:
        cold.boot_drive(None)
    except Exception as e:
        error = type(e).__name__ + ': ' + str(e)
    calls = (state / 'calls.log').read_text().split() if (state / 'calls.log').exists() else []
    rerun = None
    try:
        cold.boot_drive(None)
    except FileExistsError:
        rerun = 'refused'
    except RuntimeError:
        rerun = 'refused-identity'
    return {'scenario': name, 'error': error, 'calls': [c for c in calls if c != 'status'], 'secondBoot': rerun}


rows = [scenario('owner', 'ts-fra-2', 'ts-fra-2', None),
        scenario('follower', 'ts-gru-2', 'ts-gru-1', 3),
        scenario('follower-owner-never-ready', 'ts-sjc-2', 'ts-sjc-1', None),
        scenario('wrong-instance', 'ts-fra-2', 'ts-fra-2', None)]
checks = {
    'owner replaces after stage': rows[0]['error'] is None and rows[0]['calls'] == ['stage', 'prepull', 'replace'],
    'follower waits for its owner': rows[1]['error'] is None and rows[1]['calls'] == ['stage', 'prepull', 'owner', 'owner', 'owner', 'replace'],
    'clone booted on another instance never drives': rows[3]['error'] is not None and rows[3]['calls'] == [],
    'never-ready owner: no replace': rows[2]['error'] is not None and 'replace' not in rows[2]['calls'],
    'second boot never re-drives': all(r['secondBoot'] == 'refused' for r in rows[:3]),
}
print(json.dumps({'pass': all(checks.values()), 'checks': checks, 'rows': rows}, indent=2))
sys.exit(0 if all(checks.values()) else 1)
