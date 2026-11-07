#!/usr/bin/env python3
"""Founder dead-man switch for the cold maintenance window.

A root systemd timer runs `deadman.py check` every 30 s. It acts only while the
window is armed and the operator heartbeat is older than LIMIT seconds. Actions
depend on the phase the operator recorded, and restore the old service:

  gate      reopen ingress
  stopped   unmount worker clones, make sure both stale keys are tombstoned,
            start containerd (the old ts-orch recreates b443), reopen ingress
  installed as stopped, after restoring the retained b443-era ts-orch binary
  engines   finish this founder's pinned replacement (owner now; follower once
            its owner serves and released ingress), then reopen ingress. b443
            must never return once a v2 writer may exist.

Each action is idempotent and logged; a later run retries failed actions.
Workers are restarted by the delta half (deadman_workers.py) through OCI.
"""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

STATE = Path(os.environ.get('ZDT_STATE', '/root/zdt-txn'))
COLD = os.environ.get('ZDT_COLD', '/var/tmp/zdt-offline/cold.py')
BIN = os.environ.get('ZDT_BIN', '/usr/local/bin/terrascale-orchestrator')
LIMIT = float(os.environ.get('ZDT_LIMIT', '300'))
PHASES = ('gate', 'stopped', 'installed', 'engines')


def log(msg):
    line = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()) + ' deadman ' + msg
    print(line, flush=True)
    with open(STATE / 'deadman.log', 'a') as f:
        f.write(line + '\n')


def run(*args, timeout=120, check=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(f'{args[0]} {args[1:3]} exit {p.returncode}: {p.stderr[-300:]}')
    return p


def unmount_clones():
    for m in sorted(Path('/mnt').glob('zdt-*')) if not os.environ.get('ZDT_MNT') else sorted(Path(os.environ['ZDT_MNT']).glob('zdt-*')):
        if run('mountpoint', '-q', str(m), check=False).returncode == 0:
            run('umount', str(m))
            log(f'unmounted {m}')


def keys_deleted():
    # Tombstone check through the existing local NATS; delete conditionally if
    # still live (the audited revisions make a racing second delete refuse).
    p = run(sys.executable, '-I', COLD, 'kv', 'dry-run', '--token', str(STATE / 'nats.token'),
            '--audit', str(STATE / 'stale-key-audit.json'), '--receipt', str(STATE / f'deadman-kv-dry-{int(time.time())}.jsonl'), check=False)
    if p.returncode == 0:
        run(sys.executable, '-I', COLD, 'kv', 'delete', '--token', str(STATE / 'nats.token'),
            '--audit', str(STATE / 'stale-key-audit.json'), '--receipt', str(STATE / f'deadman-kv-delete-{int(time.time())}.jsonl'), check=False)
    # Either way, both keys must now read back as tombstones.
    p = run(sys.executable, '-I', COLD, 'kv-tombstoned', '--token', str(STATE / 'nats.token'), check=False)
    if p.returncode:
        raise RuntimeError('stale keys are not tombstoned; old engines stay stopped')
    log('stale keys tombstoned')


def restore_binary():
    old = Path(BIN + '.zdt-b443')
    if not old.exists():
        log('no retained b443-era binary; current binary kept')
        return
    if run('cmp', '-s', str(old), BIN, check=False).returncode == 0:
        return
    run('systemctl', 'stop', 'ts-orch')
    tmp = Path(BIN + '.zdt-restore')
    run('cp', '-p', str(old), str(tmp))
    os.replace(tmp, BIN)
    log('restored the retained b443-era ts-orch binary')


def start_old_engines():
    run('systemctl', 'start', 'containerd')
    run('systemctl', 'start', 'ts-orch', timeout=300)
    log('containerd and ts-orch started; the old executor recreates its engine')


def open_gate():
    p = run('nft', 'list', 'tables', check=False)
    if 'ts_zdt_20261105' in p.stdout:
        run(sys.executable, '-I', COLD, 'gate', 'open', '--operator', '0.0.0.0')
        log('maintenance gate removed (ingress reopened)')


def check():
    if not (STATE / 'armed').exists():
        return
    heartbeat = STATE / 'heartbeat'
    age = time.time() - heartbeat.stat().st_mtime if heartbeat.exists() else float('inf')
    if age <= LIMIT:
        return
    phase = (STATE / 'phase').read_text().strip() if (STATE / 'phase').exists() else 'gate'
    if phase not in PHASES:
        phase = 'gate'
    if (STATE / 'deadman-done').exists():
        return
    log(f'operator heartbeat {age:.0f}s old; restoring from phase {phase}')
    if phase == 'engines':
        job = json.loads(run(BIN, 'bootstrap-maintenance', 'status', '--state', '/var/lib/ts-orch').stdout)
        if job['phase'] != 'verified':
            if job['member'] != job['owner']:
                run(BIN, 'bootstrap-maintenance', 'owner', '--state', '/var/lib/ts-orch', '--id', job['id'], timeout=80)
            run(BIN, 'bootstrap-maintenance', 'replace', '--state', '/var/lib/ts-orch', '--id', job['id'], timeout=80)
            job = json.loads(run(BIN, 'bootstrap-maintenance', 'status', '--state', '/var/lib/ts-orch').stdout)
            if job['phase'] != 'verified':
                raise RuntimeError('pinned replacement not verified')
            log(f'finished pinned replacement {job["id"]} at {job["owner"]}/{job["epoch"]}')
    if phase in ('stopped', 'installed'):
        unmount_clones()
        keys_deleted()
        if phase == 'installed':
            restore_binary()
        start_old_engines()
    open_gate()
    (STATE / 'deadman-done').write_text(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()) + ' ' + phase + '\n')
    log(f'restore actions complete for phase {phase}')


if __name__ == '__main__':
    os.umask(0o077)
    try:
        check()
    except Exception as error:  # retried by the next timer run
        log(f'FAILED {type(error).__name__}: {str(error)[:300]}')
        sys.exit(1)
