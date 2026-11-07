#!/usr/bin/env python3
"""Rehearse the v3 offline worker install on boot-volume CLONES, never originals.

Per region and repeat: clone the worker's boot volume, attach the clone
read-write to the region's founder, mount it, capture pins, run cold.py
offline-install (new binary, arm-offline, agent DB aside, drive unit),
unmount and detach; reattach read-only, offline-verify, detach and delete the
clone. Production worker volumes and instances are only read. Founders only
gain and lose one attachment; their own disks and mounts are checked after.
Usage: qualify-offline-worker.py TARGETS.json BINARY OLD_SHA256 REPEATS OUT.json
"""
import concurrent.futures
import hashlib
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

TARGETS, BINARY, OLD_SHA, REPEATS, OUT = sys.argv[1:6]
RESEED = set(sys.argv[6].split(',')) if len(sys.argv) > 6 else set()
REPEATS = int(REPEATS)
HERE = Path(__file__).resolve().parent
COLD = HERE / 'cold.py'
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'Compression=no']
OWNERS = {'gru': ('ts-gru-1', 9), 'sjc': ('ts-sjc-1', 5), 'fra': ('ts-fra-2', 7)}  # rehearsal: expected owners/epochs
TARGET_IMAGE = 'ghcr.io/terrascale/terrabase@sha256:' + hashlib.sha256(b'zdt-rehearsal-target').hexdigest()
ZERO = '0001-01-01T00:00:00Z'
STAGE = '/var/tmp/zdt-rehearsal'  # never the production staging dir
BIN_SHA = hashlib.file_digest(open(BINARY, 'rb'), 'sha256').hexdigest()


# Mark a stale follower: keep its data aside, leave a fresh empty data dir with
# the original owner/mode so the new engine starts it as a fresh follower.
RESEED_SH = '''sudo bash -c 'set -euo pipefail; d={root}/var/lib/ts-data/terrabase; s=$d.stale-zdt-20261107
test -d $d; test ! -e $s; o=$(stat -c %u:%g $d); m=$(stat -c %a $d); n=$(find $d -type f | wc -l); b=$(du -sb $d | cut -f1)
mv $d $s; install -d -o ${{o%:*}} -g ${{o#*:}} -m $m $d; sync -f $d
test -z "$(ls -A $d)"; test "$(stat -c "%u:%g %a" $d)" = "$o $m"; echo "moved files=$n bytes=$b owner=$o mode=$m"' '''


def run(args, timeout, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True, timeout=timeout).stdout


def oci(t, *args, timeout=900):
    return json.loads(run(['oci', '--region', t['ociRegion'], *args], timeout) or b'{}')


def remote(host, script, timeout=120):
    return run([*SSH, host, 'bash -s'], timeout, ('set -euo pipefail\n' + script).encode()).decode()


def timed(rows, name, fn):
    started = time.monotonic()
    value = fn()
    rows[name] = round(time.monotonic() - started, 3)
    return value


def founder_safe(host):
    # A founder boots root=LABEL=cloudimg-rootfs: it must never reboot while a
    # worker clone (same labels) is attached. Refuse when a reboot is scheduled.
    out = remote(host, '''test ! -e /run/systemd/shutdown/scheduled
! grep -Eqs '^[^/]*Automatic-Reboot "true"' /etc/apt/apt.conf.d/*
for m in / /boot /boot/efi; do findmnt -n -o SOURCE $m; done | tr '\\n' ' '
readlink -f /dev/disk/by-label/cloudimg-rootfs /dev/disk/by-label/BOOT /dev/disk/by-label/UEFI | tr '\\n' ' '
''')
    require(out.split() == ['/dev/sda1', '/dev/sda16', '/dev/sda15'] * 2, 'founder root/boot mounts or labels are not on sda: ' + out)


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def attach(t, volume, read_only, name):
    data = oci(t, 'compute', 'volume-attachment', 'attach', '--type', 'paravirtualized', '--instance-id', t['founder'], '--volume-id', volume,
               '--is-read-only', 'true' if read_only else 'false', '--display-name', name, '--wait-for-state', 'ATTACHED', '--max-wait-seconds', '600')
    return data['data']['id']


def detach(t, attachment):
    oci(t, 'compute', 'volume-attachment', 'detach', '--volume-attachment-id', attachment, '--force', '--wait-for-state', 'SUCCEEDED', '--max-wait-seconds', '600')


def mount(host, worker, options, before):
    # The new disk is the one sd* absent before attach whose partition 1 is the
    # cloud root; cold.py then requires its /etc/hostname to be the worker.
    return remote(host, f'''for i in $(seq 1 120); do
  new=$(lsblk -dn -o NAME | grep '^sd' | grep -vxF -f <(printf '%s\\n' {' '.join(before)}) || true)
  [ -n "$new" ] && [ -b /dev/${{new}}1 ] && break; sleep 0.5; done
[ "$(echo "$new" | wc -w)" = 1 ] && [ -b /dev/${{new}}1 ]
sudo udevadm settle -t 10
[ "$(sudo blkid -o value -s LABEL /dev/${{new}}1)" = cloudimg-rootfs ]
sudo mkdir -p /mnt/zdt-{worker}
sudo mount -o {options} /dev/${{new}}1 /mnt/zdt-{worker}
[ "$(cat /mnt/zdt-{worker}/etc/hostname)" = {worker} ]
echo $new''').strip()


def umount(host, worker):
    remote(host, f'sudo umount /mnt/zdt-{worker} && sudo rmdir /mnt/zdt-{worker}')


def disks(host):
    return remote(host, "lsblk -dn -o NAME | grep '^sd'").split()


def stage(host):
    remote(host, f'sudo install -d -m 0700 -o root -g root {STAGE}; mkdir -p -m 700 /dev/shm/zdt-stage-$USER')
    run(['scp', '-q', '-o', 'BatchMode=yes', BINARY, str(COLD), f'{host}:/dev/shm/zdt-stage-$USER/'.replace('$USER', remote(host, 'echo $USER').strip())], 600)
    remote(host, f'''u=/dev/shm/zdt-stage-$USER
sudo install -m 0755 -o root -g root $u/{Path(BINARY).name} {STAGE}/terrascale-orchestrator
sudo install -m 0700 -o root -g root $u/cold.py {STAGE}/cold.py
rm -rf $u
[ "$(sudo sha256sum {STAGE}/terrascale-orchestrator | cut -d' ' -f1)" = {BIN_SHA} ]''', 600)


def manifest(region, worker, pins, founder_task, rep):
    owner, epoch = OWNERS[region]
    def job(member, job_id, source):
        return {'member': member, 'id': job_id, 'source': source, 'target': {'node': source['node'], 'service': source['service'], 'task': '', 'fingerprint': '', 'image': TARGET_IMAGE},
                'process': {'pid': 1 << 22, 'start': 1}, 'owner': owner, 'epoch': epoch, 'phase': 'held', 'deadline': ZERO}
    local = job(worker, f'zdt-rehearsal-{worker}-r{rep}', pins)
    if owner == worker:
        return {'local': local, 'owner': local}
    # Rehearsal only: the founder owner's job feeds just the clone's ingress hold.
    founder_pin = dict(pins, node='rehearsalfoundernode', task=founder_task, fingerprint=hashlib.sha256(b'rehearsal-founder-pin').hexdigest())
    founder = job(owner, f'zdt-rehearsal-{owner}', founder_pin)
    founder['process'] = {'pid': 100, 'start': 100}
    return {'local': local, 'owner': founder}


def manager_tasks(host):
    out = remote(host, 'sudo timeout 15 /usr/local/bin/terrascale-orchestrator service ps terrabase')
    rows = [line.split() for line in out.splitlines()[1:]]
    return {row[1]: row[0] for row in rows if row[2] == 'running' and row[3] == 'running'}


def repeat(region, t, rep):
    worker, founder = f'ts-{region}-2', f'ts-{region}-1'
    rows = {'region': region, 'repeat': rep}
    clone = attachment = None
    try:
        founder_safe(founder)
        clone = timed(rows, 'cloneSeconds', lambda: oci(t, 'bv', 'boot-volume', 'create', '--source-boot-volume-id', t['workerBootVolume'], '--availability-domain', t['ad'],
                                                         '--compartment-id', t['compartment'], '--display-name', f'zdt-rehearsal-{worker}-r{rep}',
                                                         '--freeform-tags', '{"zdt":"rehearsal-20261106","delete":"same-day"}', '--wait-for-state', 'AVAILABLE', '--max-wait-seconds', '900')['data']['id'])
        rows['clone'] = clone
        before = disks(founder)
        attachment = timed(rows, 'attachRwSeconds', lambda: attach(t, clone, False, f'zdt-rehearsal-{worker}-r{rep}'))
        rows['device'] = timed(rows, 'mountRwSeconds', lambda: mount(founder, worker, 'rw,nodev,nosuid', before))
        def capture():
            pins = json.loads(remote(founder, f'sudo {STAGE}/terrascale-orchestrator bootstrap-maintenance pins-offline --root /mnt/zdt-{worker} --state /var/lib/ts-orch'))
            tasks = manager_tasks(founder)
            # The clone is crash-consistent from the live worker: its agent task is the manager's running task.
            require(tasks.get(worker) == pins['task'], 'offline pin differs from the manager running task')
            return pins, tasks.get('single-host', 'rehearsalfoundertask')
        pins, founder_task = timed(rows, 'captureSeconds', capture)
        rows['pins'] = pins
        doc = json.dumps(manifest(region, worker, pins, founder_task, rep))
        name = f'r{rep}'
        remote(founder, f'sudo install -m 0600 -o root -g root /dev/stdin {STAGE}/manifest-{name}.json <<\'EOF\'\n{doc}\nEOF')
        def install():
            remote(founder, f'sudo python3 -I {STAGE}/cold.py offline-install --root /mnt/zdt-{worker} --manifest {STAGE}/manifest-{name}.json '
                            f'--binary {STAGE}/terrascale-orchestrator --binary-sha256 {BIN_SHA} --old-sha256 {OLD_SHA} --instance-id {t["worker"]} --receipt {STAGE}/install-{name}.json')
        timed(rows, 'installSeconds', install)
        rows['install'] = json.loads(remote(founder, f'sudo cat {STAGE}/install-{name}.json'))
        if region in RESEED:
            rows['reseed'] = timed(rows, 'reseedSeconds', lambda: remote(founder, RESEED_SH.format(root=f'/mnt/zdt-{worker}')).strip())
        # Production gate: verify on the rw mount before unmount/detach/boot attach.
        timed(rows, 'verifyRwSeconds', lambda: remote(founder, f'sudo python3 -I {STAGE}/cold.py offline-verify --root /mnt/zdt-{worker} '
                                                          f'--install-receipt {STAGE}/install-{name}.json --receipt {STAGE}/verify-rw-{name}.json'))
        timed(rows, 'umountSeconds', lambda: umount(founder, worker))
        timed(rows, 'detachSeconds', lambda: detach(t, attachment))
        attachment = None
        founder_safe(founder)
        before = disks(founder)
        attachment = timed(rows, 'attachRoSeconds', lambda: attach(t, clone, True, f'zdt-rehearsal-{worker}-r{rep}-verify'))
        timed(rows, 'mountRoSeconds', lambda: mount(founder, worker, 'ro,noload,nodev,nosuid,noexec', before))
        def verify():
            if region in RESEED:
                remote(founder, f'sudo test -d /mnt/zdt-{worker}/var/lib/ts-data/terrabase.stale-zdt-20261107 && sudo test -z "$(sudo ls -A /mnt/zdt-{worker}/var/lib/ts-data/terrabase)"')
            remote(founder, f'sudo python3 -I {STAGE}/cold.py offline-verify --root /mnt/zdt-{worker} --install-receipt {STAGE}/install-{name}.json --receipt {STAGE}/verify-{name}.json')
            return json.loads(remote(founder, f'sudo cat {STAGE}/verify-{name}.json'))
        rows['verify'] = timed(rows, 'verifySeconds', verify)
        umount(founder, worker)
        timed(rows, 'detachRoSeconds', lambda: detach(t, attachment))
        attachment = None
        founder_safe(founder)
        rows['result'] = 'pass'
    except Exception as error:
        rows['result'] = 'fail'
        rows['error'] = f'{type(error).__name__}: {getattr(error, "stderr", b"") or error}'[:600]
    finally:
        # Always leave the founder clean and delete the clone the same run.
        try:
            remote(founder, f'mountpoint -q /mnt/zdt-{worker} && sudo umount /mnt/zdt-{worker} || true; sudo rmdir /mnt/zdt-{worker} 2>/dev/null || true')
        except Exception as error:
            rows['cleanupMountError'] = str(error)[:200]
        if attachment:
            try:
                detach(t, attachment)
            except Exception as error:
                rows['cleanupDetachError'] = str(error)[:200]
        if clone:
            try:
                timed(rows, 'deleteSeconds', lambda: oci(t, 'bv', 'boot-volume', 'delete', '--boot-volume-id', clone, '--force', '--wait-for-state', 'TERMINATED', '--max-wait-seconds', '900'))
            except Exception as error:
                rows['cleanupDeleteError'] = str(error)[:200]
        try:
            founder_safe(founder)
            rows['founderClean'] = True
        except Exception as error:
            rows['founderClean'] = False
            rows['founderError'] = str(error)[:200]
    return rows


def region_run(region, t):
    founder = f'ts-{region}-1'
    stage(founder)
    try:
        return [repeat(region, t, rep) for rep in range(1, REPEATS + 1)]
    finally:
        remote(founder, f'sudo rm -rf {STAGE}')


targets = json.load(open(TARGETS))
started = time.time()
with concurrent.futures.ThreadPoolExecutor(3) as pool:
    futures = {region: pool.submit(region_run, region, t) for region, t in targets.items()}
    results = {region: f.result() for region, f in futures.items()}
summary = {'startedAt': started, 'finishedAt': time.time(), 'binarySha256': BIN_SHA, 'oldBinarySha256': OLD_SHA, 'repeats': REPEATS,
           'productionMutation': 'none: clones only; each founder gained and lost one attachment', 'results': results,
           'pass': all(r['result'] == 'pass' and r.get('founderClean') for rows in results.values() for r in rows)}
Path(OUT).write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps({'pass': summary['pass'], **{k: [r['result'] for r in v] for k, v in results.items()}}))
