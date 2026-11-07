#!/usr/bin/env python3
"""Worker half of the cold-maintenance dead-man switch (runs on delta).

`deadman_workers.py check STATE_DIR` acts only while STATE_DIR/armed exists and
STATE_DIR/heartbeat is older than LIMIT seconds. In phases stopped/installed it
restores each worker to its original boot volume and starts it:
  1. detach the worker clone from its founder (the founder half unmounts first),
  2. make the original boot volume the attached boot volume (never a clone),
  3. OCI START the worker.
In phase engines it only logs: workers then belong to the v2 forward path.
Idempotent; each timer run retries what is still missing.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

LIMIT = float(os.environ.get('ZDT_LIMIT', '300'))
OCI = os.environ.get('ZDT_OCI', 'oci')


def main(state):
    state = Path(state)

    def log(msg):
        line = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()) + ' deadman-workers ' + msg
        print(line, flush=True)
        with open(state / 'deadman.log', 'a') as f:
            f.write(line + '\n')

    def oci(region, *args, check=True):
        p = subprocess.run([OCI, '--region', region, *args], capture_output=True, text=True, timeout=900)
        if check and p.returncode:
            raise RuntimeError(f'oci {args[:3]}: {p.stderr[-300:]}')
        return json.loads(p.stdout or '{}') if p.stdout.strip() else {}

    if not (state / 'armed').exists() or (state / 'deadman-done').exists():
        return
    hb = state / 'heartbeat'
    age = time.time() - hb.stat().st_mtime if hb.exists() else float('inf')
    if age <= LIMIT:
        return
    phase = (state / 'phase').read_text().strip() if (state / 'phase').exists() else 'gate'
    if phase not in ('stopped', 'installed'):
        log(f'heartbeat {age:.0f}s old in phase {phase}: no worker action')
        (state / 'deadman-done').write_text(phase + '\n')
        return
    log(f'heartbeat {age:.0f}s old; restoring workers from phase {phase}')
    targets = json.loads((state / 'targets.json').read_text())
    pending = []
    for r, t in targets.items():
        reg, worker, original = t['ociRegion'], t['worker'], t['workerBootVolume']
        attach_file = state / f'attach-{r}.id'
        if attach_file.exists():
            aid = attach_file.read_text().strip()
            a = oci(reg, 'compute', 'volume-attachment', 'get', '--volume-attachment-id', aid, check=False).get('data', {})
            if a.get('lifecycle-state') == 'ATTACHED':
                p = subprocess.run([OCI, '--region', reg, 'compute', 'volume-attachment', 'detach', '--volume-attachment-id', aid,
                                    '--force', '--wait-for-state', 'SUCCEEDED', '--max-wait-seconds', '300'], capture_output=True, text=True, timeout=400)
                if p.returncode:
                    pending.append(f'{r}: clone still attached to founder')
                    continue
                log(f'{r}: worker clone detached from founder')
        bvas = oci(reg, 'compute', 'boot-volume-attachment', 'list', '--availability-domain', t['ad'],
                   '--compartment-id', t['compartment'], '--instance-id', worker).get('data', [])
        live = [b for b in bvas if b['lifecycle-state'] in ('ATTACHED', 'ATTACHING')]
        if live and live[0]['boot-volume-id'] != original:
            pending.append(f'{r}: a non-original boot volume is attached; manual')
            continue
        if not live:
            oci(reg, 'compute', 'boot-volume-attachment', 'attach', '--boot-volume-id', original, '--instance-id', worker,
                '--wait-for-state', 'ATTACHED', '--max-wait-seconds', '600')
            log(f'{r}: original boot volume reattached')
        st = oci(reg, 'compute', 'instance', 'get', '--instance-id', worker)['data']['lifecycle-state']
        if st == 'STOPPED':
            oci(reg, 'compute', 'instance', 'action', '--instance-id', worker, '--action', 'START',
                '--wait-for-state', 'RUNNING', '--max-wait-seconds', '600')
            log(f'{r}: worker started on its original boot volume')
        elif st != 'RUNNING':
            pending.append(f'{r}: worker {st}')
    if pending:
        log('retrying later: ' + '; '.join(pending))
        return
    (state / 'deadman-done').write_text(phase + '\n')
    log('workers restored')


if __name__ == '__main__':
    os.umask(0o077)
    try:
        main(sys.argv[2] if sys.argv[1:2] == ['check'] else sys.argv[1])
    except Exception as error:
        print(f'deadman-workers FAILED {type(error).__name__}: {str(error)[:300]}', flush=True)
        sys.exit(1)
