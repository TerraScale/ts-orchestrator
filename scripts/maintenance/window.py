#!/usr/bin/env python3
"""Cold maintenance window driver (plan v4 / option 2). One subcommand per step.
Every step gates; any exception aborts that step. Logs one UTC line per action."""
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import time
from pathlib import Path

X = Path(os.environ['HOME']) / 'zdt-txn-20261107'
T = json.loads((X / 'targets.json').read_text())
REGIONS = ('gru', 'sjc', 'fra')
TARGET = 'ghcr.io/terrascale/terrabase@sha256:0046773223695fdc4c26043f8fa843d89a394465c8a84c1bc6e0e9fb1b05c001'
OLD_ORCH = '214b1e2791692bca33e9b6d9b554aab9346aaabba034285606e865d6703c4146'
NEW_ORCH = '27b17d84026fca3153969bed61fd25cfef68990978488199fc1672308215a3c2'
OWNER = {'gru': ('ts-gru-1', 9), 'sjc': ('ts-sjc-1', 5), 'fra': ('ts-fra-2', 7)}
OPERATOR = '179.124.206.245'
PUBLIC = {'gru': '163.176.124.12', 'sjc': '163.192.54.17', 'fra': '130.162.238.198'}
S = '/var/tmp/zdt-offline'
R = '/root/zdt-txn'
SSH = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', '-o', 'Compression=no']
os.umask(0o077)


def log(step, msg):
    line = f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} {step} {msg}"
    print(line, flush=True)
    with open(X / 'window.log', 'a') as f:
        f.write(line + '\n')


def sh(host, script, timeout=120):
    p = subprocess.run([*SSH, host, 'sudo bash -s'], input=('set -euo pipefail\n' + script).encode(),
                       capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f'{host}: exit {p.returncode}: {p.stderr.decode()[-600:]} {p.stdout.decode()[-300:]}')
    return p.stdout.decode()


def oci(r, *args, timeout=900):
    p = subprocess.run(['oci', '--region', T[r]['ociRegion'], *args], capture_output=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f'oci {r} {args[:3]}: {p.stderr.decode()[-400:]}')
    return json.loads(p.stdout or b'{}')


def par(fn, items):
    with cf.ThreadPoolExecutor(len(items)) as pool:
        futures = {i: pool.submit(fn, i) for i in items}
        errors = {}
        results = {}
        for i, f in futures.items():
            try:
                results[i] = f.result()
            except Exception as e:  # collect all, then fail
                errors[i] = e
        if errors:
            raise RuntimeError('; '.join(f'{k}: {v}' for k, v in errors.items()))
        return results


def F(r):
    return f'ts-{r}-1'


def W(r):
    return f'ts-{r}-2'


def fetch(host, path, local):
    data = subprocess.run([*SSH, host, f'sudo cat {path}'], capture_output=True, check=True, timeout=60).stdout
    Path(local).write_bytes(data)
    os.chmod(local, 0o600)
    return data


def push(host, local, path, mode='0600'):
    subprocess.run([*SSH, host, f'sudo install -m {mode} -o root -g root /dev/stdin {path}'],
                   input=Path(local).read_bytes(), check=True, timeout=60)



# ---------------- dead-man, heartbeat, phases, rollback ----------------
DELTA_STATE = 'zdt-deadman'


def dsh(script, timeout=60):
    # delta's login shell is fish: always run bash explicitly, script on stdin.
    p = subprocess.run([*SSH, 'delta', 'bash -s'], input='set -euo pipefail\n' + script, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f'delta: exit {p.returncode}: {p.stderr[-300:]}')
    return p.stdout


def on_all(founder_cmd, delta_cmd):
    with cf.ThreadPoolExecutor(4) as pool:
        fs = [pool.submit(sh, F(r), founder_cmd, 30) for r in REGIONS]
        fs.append(pool.submit(dsh, delta_cmd, 30))
        for f in fs:
            f.result()


def beat():
    on_all(f'touch {R}/heartbeat', f'touch {DELTA_STATE}/heartbeat')


def mark(phase):
    on_all(f'echo {phase} > {R}/phase; touch {R}/heartbeat', f'echo {phase} > {DELTA_STATE}/phase; touch {DELTA_STATE}/heartbeat')
    log('phase', phase)


class Heart:
    def __init__(self):
        import threading
        self.stop = threading.Event()
        self.t = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.wait(30):
            try:
                beat()
            except Exception as e:
                log('heartbeat', f'failed {type(e).__name__}')


UNIT_SVC = """[Unit]
Description=TerraScale cold-maintenance dead-man switch
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I /var/tmp/zdt-offline/deadman.py
"""
UNIT_TMR = """[Unit]
Description=TerraScale cold-maintenance dead-man switch (30 s)
[Timer]
OnBootSec=60
OnUnitActiveSec=30
AccuracySec=5
[Install]
WantedBy=timers.target
"""


def steparm():
    for r in REGIONS:
        for f in ('cold.py', 'deadman.py'):
            push(F(r), X / f, f'{S}/{f}', '0700')
    audit = X / 'stale-key-audit.json'
    fetch('ts-sjc-1', f'{R}/stale-key-audit.json', audit)
    for r in REGIONS:
        push(F(r), audit, f'{R}/stale-key-audit.json')
        sh(F(r), f"""cat > /etc/systemd/system/ts-zdt-deadman.service <<'EOF'
{UNIT_SVC}EOF
cat > /etc/systemd/system/ts-zdt-deadman.timer <<'EOF'
{UNIT_TMR}EOF
rm -f {R}/deadman-done; echo gate > {R}/phase; touch {R}/heartbeat; touch {R}/armed
systemctl daemon-reload; systemctl enable --now ts-zdt-deadman.timer; systemctl is-active ts-zdt-deadman.timer""")
    py = dsh('command -v python3; command -v oci').split()
    dsh(f'mkdir -p -m 700 {DELTA_STATE} .config/systemd/user')
    for f in ('deadman_workers.py', 'targets.json'):
        subprocess.run(['scp', '-q', '-o', 'BatchMode=yes', str(X / f), f'delta:{DELTA_STATE}/{f}'], check=True)
    dsh(f'rm -f {DELTA_STATE}/attach-gru.id {DELTA_STATE}/attach-sjc.id {DELTA_STATE}/attach-fra.id')
    svc = f"""[Unit]
Description=TerraScale cold-maintenance worker dead-man switch
[Service]
Type=oneshot
Environment=ZDT_OCI={py[1]}
ExecStart={py[0]} -I %h/{DELTA_STATE}/deadman_workers.py check %h/{DELTA_STATE}
"""
    tmr = UNIT_TMR.replace('dead-man switch (30 s)', 'worker dead-man switch (30 s)').replace('timers.target', 'timers.target')
    dsh(f"""cat > .config/systemd/user/zdt-deadman-workers.service <<'EOF'
{svc}EOF
cat > .config/systemd/user/zdt-deadman-workers.timer <<'EOF'
{tmr}EOF
rm -f {DELTA_STATE}/deadman-done; echo gate > {DELTA_STATE}/phase; touch {DELTA_STATE}/heartbeat {DELTA_STATE}/armed
systemctl --user daemon-reload; systemctl --user enable --now zdt-deadman-workers.timer; systemctl --user is-active zdt-deadman-workers.timer""")
    log('arm', 'dead-man timers armed on 3 founders (root, 30 s) and delta (worker OCI restore, 30 s); phase gate; heartbeat fresh')


def stepdisarm():
    on_all(f'rm -f {R}/armed; systemctl disable --now ts-zdt-deadman.timer >/dev/null 2>&1 || true',
           f'rm -f {DELTA_STATE}/armed; systemctl --user disable --now zdt-deadman-workers.timer >/dev/null 2>&1 || true')
    log('disarm', 'dead-man timers disarmed and stopped')


def rollback(reason):
    log('rollback', f'automatic rollback: {reason[:300]}')
    on_all(f'touch -d @0 {R}/heartbeat', f'touch -d @0 {DELTA_STATE}/heartbeat')
    def founder(r):
        return sh(F(r), f'rm -f {R}/deadman-done; ZDT_LIMIT=-1 python3 -I {S}/deadman.py; tail -3 {R}/deadman.log', 900)
    res = par(founder, REGIONS)
    for r, o in res.items():
        log('rollback', f'{F(r)}: {o.strip().splitlines()[-1][:200] if o.strip() else "ok"}')
    out = dsh(f'rm -f {DELTA_STATE}/deadman-done; ZDT_LIMIT=-1 ZDT_OCI=$(command -v oci) python3 -I {DELTA_STATE}/deadman_workers.py check {DELTA_STATE} || true; tail -3 {DELTA_STATE}/deadman.log', 2400)
    log('rollback', f'workers: {out.strip().splitlines()[-1][:200] if out.strip() else "no output"}')


# ---------------- step 1: gate, cutoff, logical baseline ----------------
def step1():
    def close(r):
        return sh(F(r), f'''python3 -I {S}/cold.py gate close --operator {OPERATOR} >/dev/null
nft -j list table inet ts_zdt_20261105 > {R}/gate-readback.json; echo ok''')
    par(close, REGIONS)
    log('1', 'gate closed on 3 founders (nft table ts_zdt_20261105 read back)')
    # Negative: a founder's public NAT source to another founder's 443 must be reset.
    for a, b in (('gru', 'sjc'), ('sjc', 'fra'), ('fra', 'gru')):
        out = sh(F(a), f"timeout 5 bash -c 'echo > /dev/tcp/{PUBLIC[b]}/443' && echo OPEN || echo CLOSED")
        if 'CLOSED' not in out:
            raise RuntimeError(f'negative probe {a}->{b} reached 443')
    # Positive: operator reaches every region's API.
    for r in REGIONS:
        p = subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-m', '10', f'https://{r}.api.terrascale.tech/'],
                           capture_output=True, timeout=15)
        if not p.stdout or p.stdout == b'000':
            raise RuntimeError(f'positive operator probe {r} failed')
    log('1', 'negative probes reset (3 cross-founder), positive operator probes answered (3 regions)')
    time.sleep(20)
    log('1', 'admitted work settled 20 s')
    par(lambda r: sh(F(r), f'rm -f {R}/watch-baseline-t0.json; python3 -I {S}/cold.py watch-baseline --receipt {R}/watch-baseline-t0.json; echo ok'), REGIONS)
    rowhash('before')
    log('1', 'fresh task baselines captured; logical baseline recorded (all-before.json on 3 founders)')


NODEIP = {'gru': ('10.200.165.148', '10.200.101.28'), 'sjc': ('10.200.109.193', '10.200.72.235'), 'fra': ('10.200.40.238', '10.200.95.5')}


def logical(path):
    d = json.loads(Path(path).read_text())
    core = ('homeRegion', 'organizationId', 'projectId', 'databaseId')
    # Range hashes are incarnation-specific (they differ between a region's two
    # nodes for identical rows); keep table, rowid bounds, rows and bytes.
    return {k: {'core': {c: v['catalog'].get(c) for c in core}, 'counts': v['counts'],
                'ranges': [{f: x[f] for f in x if f != 'hash'} for x in v['ranges']]}
            for k, v in d['databases'].items()}


def rowhash(tag):
    # Each region's home catalog (the complete distinct inventory) on both of its
    # nodes; cross-region replicas are not served by the checksum API (404).
    def node(r):
        for attempt in range(4):
            try:
                return node_once(r)
            except RuntimeError as e:
                if 'differ' not in str(e) or attempt == 3:
                    raise
                time.sleep(15)

    def node_once(r):
        out = {}
        # GRU's follower is stale (issue #1141) and is re-seeded in-window: before
        # the stop its gate is the owner only; afterwards both nodes must agree.
        roles = ('founder',) if (tag == 'before' and r == 'gru') else ('founder', 'worker')
        for role, ip in zip(roles, NODEIP[r]):
            sh(F(r), f'rm -f {R}/home-{tag}-{role}.json; python3 -I {S}/cold.py row-hash --address {ip} --region {r} --credential {R}/peer.credential --receipt {R}/home-{tag}-{role}.json', 120)
            fetch(F(r), f'{R}/home-{tag}-{role}.json', X / f'home-{tag}-{r}-{role}.json')
            out[role] = logical(X / f'home-{tag}-{r}-{role}.json')
        if 'worker' in out and out['founder'] != out['worker']:
            raise RuntimeError(f'{r} founder and worker logical inventories differ')
        return len(out['founder']), sum(sum(v['counts'].values()) for v in out['founder'].values())
    counts = par(node, REGIONS)
    log('rowhash', f'{tag}: home DBs/rows per region (founder == worker) {counts}')
    if tag == 'after':
        for r in REGIONS:
            if logical(X / f'home-before-{r}-founder.json') != logical(X / f'home-after-{r}-founder.json'):
                raise RuntimeError(f'{r} logical inventory changed across maintenance')
        log('rowhash', 'after == before for all 3 regions (counts, checksum ranges, catalog identity)')


# ---------------- step 2: stop everything ----------------
def step2():
    mark('stopped')
    t0 = time.monotonic()
    par(lambda r: sh(F(r), '''systemctl stop containerd
python3 - <<'PY'
import socket,errno
s=socket.socket(socket.AF_UNIX); s.settimeout(0.5); c=s.connect_ex('/run/containerd/containerd.sock')
assert c in (errno.ENOENT, errno.ECONNREFUSED), c
PY
systemctl is-active ts-orch; systemctl show containerd -p ActiveState'''), REGIONS)
    log('2a', 'containerd stopped on 3 founders; runtime API refused; old ts-orch still active')
    for r in REGIONS:
        oci(r, 'compute', 'instance', 'action', '--instance-id', T[r]['worker'], '--action', 'SOFTSTOP')
    log('2b', 'OCI SOFTSTOP issued to ts-gru-2, ts-sjc-2, ts-fra-2')
    hard = set()
    def state(r):
        return oci(r, 'compute', 'instance', 'get', '--instance-id', T[r]['worker'])['data']['lifecycle-state']
    while True:
        states = {r: state(r) for r in REGIONS}
        if all(s == 'STOPPED' for s in states.values()):
            break
        el = time.monotonic() - t0
        if el > 90:
            for r, s in states.items():
                if s != 'STOPPED' and r not in hard:
                    try:
                        oci(r, 'compute', 'instance', 'action', '--instance-id', T[r]['worker'], '--action', 'STOP')
                        log('2b', f'{W(r)} not STOPPED after 90 s; hard STOP accepted')
                    except RuntimeError as e:
                        log('2b', f'{W(r)} hard STOP refused while {s}: {str(e)[:120]}; waiting')
                    hard.add(r)
        if el > 150:
            raise RuntimeError(f'workers not STOPPED within 150 s: {states}')
        time.sleep(5)
    log('2b', f'all 3 workers STOPPED (OCI readback) at +{time.monotonic()-t0:.0f}s')
    par(lambda r: sh(F(r), f'rm -f {R}/stop.json; python3 -I {S}/cold.py stop --identity {R}/identity.json --receipt {R}/stop.json; echo ok', 60), REGIONS)
    log('2c', 'founder engine PIDs TERM→exit proven (pidfd, start ticks) on 3 founders')
    par(lambda r: sh(F(r), f'rm -f {R}/watch-stopped.json {R}/watch-stopped.json.pending; python3 -I {S}/cold.py watch --baseline {R}/watch-baseline-t0.json --receipt {R}/watch-stopped.json --barrier stopped --runtime-down; echo ok', 120), REGIONS)
    recs = []
    for r in REGIONS:
        fetch(F(r), f'{R}/watch-stopped.json', X / f'watch-stopped-{r}.json'); recs.append(str(X / f'watch-stopped-{r}.json'))
        p = X / f'oci-stopped-{r}.json'
        if p.exists():
            p.unlink()
        subprocess.run(['python3', '-I', str(X / 'cold.py'), 'oci-stopped', '--host', W(r), '--region', T[r]['ociRegion'], '--instance-id', T[r]['worker'], '--receipt', str(p)], check=True, timeout=60)
        recs.append(str(p))
    out = subprocess.run(['python3', '-I', str(X / 'cold.py'), 'watch-check', '--barrier', 'stopped', '--receipts', *recs], capture_output=True, check=True, timeout=30).stdout.decode().strip()
    log('2', f'stopped barrier PASS: 3 founder 60 s watches + 3 OCI STOPPED receipts {out}')


# ---------------- step 3: backups (founders) + worker offline install ----------------
def backup(r):
    sh(F(r), f'''rm -rf {R}/backup; python3 -I {S}/cold.py backup --roots {R}/roots.json --destination {R}/backup --password {R}/backup.pass >/dev/null
sha256sum {R}/backup/data.tar.enc | cut -d' ' -f1 > {R}/backup/enc.sha256; echo ok''', 200)
    sha = sh(F(r), f'cat {R}/backup/enc.sha256').strip()
    dest = f'zdt-backup-20261107/{F(r)}'
    subprocess.run([*SSH, 'mariogk-dev', f'mkdir -p -m 700 {dest}'], check=True, timeout=30)
    c1 = subprocess.Popen([*SSH, F(r), f'sudo cat {R}/backup/data.tar.enc'], stdout=subprocess.PIPE)
    subprocess.run([*SSH, 'mariogk-dev', f'cat > {dest}/data.tar.enc && sha256sum {dest}/data.tar.enc'], stdin=c1.stdout, check=True, timeout=180, capture_output=True)
    c1.wait(60)
    remote = subprocess.run([*SSH, 'mariogk-dev', f'sha256sum {dest}/data.tar.enc'], capture_output=True, check=True, timeout=60).stdout.decode().split()[0]
    if remote != sha:
        raise RuntimeError(f'{r} off-host backup readback mismatch')
    return sha[:16]


def worker_install(r):
    t = T[r]
    wk = W(r)
    st = {}
    clone = oci(r, 'bv', 'boot-volume', 'create', '--source-boot-volume-id', t['workerBootVolume'], '--availability-domain', t['ad'],
                '--compartment-id', t['compartment'], '--display-name', f'{wk}-zdt-20261107',
                '--freeform-tags', '{"zdt":"20261107","role":"v2-boot"}', '--wait-for-state', 'AVAILABLE', '--max-wait-seconds', '900')['data']['id']
    st['clone'] = clone
    (X / f'clone-{r}.id').write_text(clone)
    log('3w', f'{wk} boot volume cloned ({clone[-12:]}); original {t["workerBootVolume"][-12:]} kept untouched')
    out = sh(F(r), '''test ! -e /run/systemd/shutdown/scheduled
for m in / /boot /boot/efi; do findmnt -n -o SOURCE $m; done | tr '\\n' ' '; readlink -f /dev/disk/by-label/cloudimg-rootfs; lsblk -dn -o NAME | grep '^sd' | tr '\\n' ' ' ''')
    parts = out.split()
    if parts[:4] != ['/dev/sda1', '/dev/sda16', '/dev/sda15', '/dev/sda1']:
        raise RuntimeError(f'{F(r)} reboot/label gate: {out}')
    before = parts[4:]
    att = oci(r, 'compute', 'volume-attachment', 'attach', '--type', 'paravirtualized', '--instance-id', t['founder'], '--volume-id', clone,
              '--is-read-only', 'false', '--display-name', f'{wk}-zdt-install', '--wait-for-state', 'ATTACHED', '--max-wait-seconds', '600')['data']['id']
    (X / f'attach-{r}.id').write_text(att)
    dsh(f'echo {att} > {DELTA_STATE}/attach-{r}.id')
    dev = sh(F(r), f'''for i in $(seq 1 120); do new=$(lsblk -dn -o NAME | grep '^sd' | grep -vxF -f <(printf '%s\\n' {' '.join(before)}) || true); [ -n "$new" ] && [ -b /dev/${{new}}1 ] && break; sleep 0.5; done
[ "$(echo $new | wc -w)" = 1 ]; udevadm settle -t 10
[ "$(blkid -o value -s LABEL /dev/${{new}}1)" = cloudimg-rootfs ]
mkdir -p /mnt/zdt-{wk}; mount -o rw,nodev,nosuid /dev/${{new}}1 /mnt/zdt-{wk}
[ "$(cat /mnt/zdt-{wk}/etc/hostname)" = {wk} ]; echo $new''').strip()
    pins = json.loads(sh(F(r), f'{S}/terrascale-orchestrator bootstrap-maintenance pins-offline --root /mnt/zdt-{wk} --state /var/lib/ts-orch'))
    expected = [l.split()[2] for l in (X / 'manager-running-pre.txt').read_text().splitlines() if l.split()[0] == r and l.split()[1] == wk][0]
    if pins['task'] != expected:
        raise RuntimeError(f'{wk} offline pin {pins["task"]} != pre-window manager task {expected}')
    owner, epoch = OWNER[r]
    local = {'member': wk, 'id': f'zdt-20261107-{wk}', 'source': pins,
             'target': {'node': pins['node'], 'service': pins['service'], 'task': '', 'fingerprint': '', 'image': TARGET},
             'process': {'pid': 1 << 22, 'start': 1}, 'owner': owner, 'epoch': epoch, 'phase': 'held', 'deadline': '0001-01-01T00:00:00Z'}
    if owner == wk:
        manifest = {'local': local, 'owner': local}
    else:
        founder_job = json.loads(sh(F(r), f'cat {R}/local-job.json'))
        manifest = {'local': local, 'owner': founder_job}
    (X / f'manifest-{wk}.json').write_text(json.dumps(manifest))
    push(F(r), X / f'manifest-{wk}.json', f'{R}/manifest-{wk}.json')
    sh(F(r), f'''rm -f {R}/install-{wk}.json {R}/verify-{wk}.json
python3 -I {S}/cold.py offline-install --root /mnt/zdt-{wk} --manifest {R}/manifest-{wk}.json --binary {S}/terrascale-orchestrator --binary-sha256 {NEW_ORCH} --old-sha256 {OLD_ORCH} --instance-id {t["worker"]} --receipt {R}/install-{wk}.json
python3 -I {S}/cold.py offline-verify --root /mnt/zdt-{wk} --install-receipt {R}/install-{wk}.json --receipt {R}/verify-{wk}.json
umount /mnt/zdt-{wk}; rmdir /mnt/zdt-{wk}; echo ok''', 120)
    log('3w', f'{wk} offline-install + verify PASS on its founder (fence {local["id"]}, owner {owner}/{epoch}, agent DB moved aside, drive unit enabled)')
    if r == 'gru':
        out = sh(F(r), f'''d=/mnt/zdt-{wk}/var/lib/ts-data/terrabase; s=$d.stale-zdt-20261107
mkdir -p /mnt/zdt-{wk}; mount -o rw,nodev,nosuid /dev/{dev}1 /mnt/zdt-{wk}; [ "$(cat /mnt/zdt-{wk}/etc/hostname)" = {wk} ]
test -d $d; test ! -e $s; o=$(stat -c %u:%g $d); m=$(stat -c %a $d); n=$(find $d -type f | wc -l); b=$(du -sb $d | cut -f1)
mv $d $s; install -d -o ${{o%:*}} -g ${{o#*:}} -m $m $d; sync -f $d
test -z "$(ls -A $d)"; test "$(stat -c "%u:%g %a" $d)" = "$o $m"
python3 -I {S}/cold.py offline-verify --root /mnt/zdt-{wk} --install-receipt {R}/install-{wk}.json --receipt {R}/verify-reseed-{wk}.json >/dev/null
umount /mnt/zdt-{wk}; rmdir /mnt/zdt-{wk}; echo "moved files=$n bytes=$b owner=$o mode=$m"''', 120).strip()
        log('3w', f'{wk} marked stale (#1141): data dir moved aside and kept, fresh empty data dir ({out}); re-verified')
    oci(r, 'compute', 'volume-attachment', 'detach', '--volume-attachment-id', att, '--force', '--wait-for-state', 'SUCCEEDED', '--max-wait-seconds', '600')
    lab = sh(F(r), 'readlink -f /dev/disk/by-label/cloudimg-rootfs /dev/disk/by-label/BOOT /dev/disk/by-label/UEFI | tr "\\n" " "')
    if lab.split() != ['/dev/sda1', '/dev/sda16', '/dev/sda15']:
        raise RuntimeError(f'{F(r)} labels not back on sda: {lab}')
    oci(r, 'compute', 'boot-volume-attachment', 'detach', '--boot-volume-attachment-id', t['workerBootAttachment'], '--force', '--wait-for-state', 'DETACHED', '--max-wait-seconds', '600')
    log('3w', f'{wk} clone detached from founder (labels back on sda); original boot volume detached from {wk} and retained')
    if r == 'fra':
        # FRA founder is the follower: its owner job is fra-2's exact job.
        fra1 = json.loads(sh(F(r), f'cat {R}/local-job.json'))
        (X / 'manifest-ts-fra-1.json').write_text(json.dumps({'local': fra1, 'owner': local}))
        push(F(r), X / 'manifest-ts-fra-1.json', f'{R}/manifest.json')
        log('3w', 'ts-fra-1 manifest completed with ts-fra-2 owner job')
    return clone


def step3():
    with cf.ThreadPoolExecutor(6) as pool:
        b = {r: pool.submit(backup, r) for r in REGIONS}
        w = {r: pool.submit(worker_install, r) for r in REGIONS}
        errs = []
        for r in REGIONS:
            try:
                log('3', f'{F(r)} cold backup local+encrypted, off-host mariogk-dev readback sha256 {b[r].result()}…')
            except Exception as e:
                errs.append(f'backup {r}: {e}')
        for r in REGIONS:
            try:
                w[r].result()
            except Exception as e:
                errs.append(f'worker {r}: {e}')
        if errs:
            raise RuntimeError('; '.join(errs))
    log('3', 'backups 3/3 and worker offline installs 3/3 PASS')


# ---------------- step 4: stale keys ----------------
def step4():
    # The two stale keys were tombstoned (conditional DEL) during the 2026-11-07
    # 05:49Z restore; re-read both tombstones through the still-running old NATS.
    out = sh('ts-sjc-1', f'python3 -I {S}/cold.py kv-tombstoned --token {R}/nats.token')
    log('4', f'both stale keys read back as DEL tombstones {out.strip()[-60:]}')


# ---------------- step 5: founders arm, install, restart ----------------
def founder5(r):
    sh(F(r), f'''test -f {R}/manifest.json
{S}/terrascale-orchestrator bootstrap-maintenance arm-stopped --state /var/lib/ts-orch --manifest {R}/manifest.json
python3 -c "import json;j=json.load(open('/var/lib/ts-orch/terrabase-bootstrap/job.json'));m=json.load(open('{R}/manifest.json'));assert j==m['local'],(j,m['local'])"
test -f /var/lib/ts-orch/terrabase-bootstrap/ingress.json
systemctl stop ts-orch; ! systemctl is-active -q ts-orch
test ! -e /var/lib/ts-orch/nats/release-trial
rm -f {R}/controller-pre.tar; tar -C / --exclude='*.sock' --exclude='*.lock' -cpf {R}/controller-pre.tar var/lib/ts-orch usr/local/bin/terrascale-orchestrator etc/systemd/system/ts-orch.service etc/systemd/system/containerd.service.d 2>/dev/null || [ $? = 1 ]
[ "$(sha256sum /usr/local/bin/terrascale-orchestrator | cut -d' ' -f1)" = {OLD_ORCH} ]
ln -f /usr/local/bin/terrascale-orchestrator /usr/local/bin/terrascale-orchestrator.zdt-b443
install -m 0755 -o root -g root {S}/terrascale-orchestrator /usr/local/bin/.terrascale-orchestrator.zdt-new
mv -f /usr/local/bin/.terrascale-orchestrator.zdt-new /usr/local/bin/terrascale-orchestrator; sync
[ "$(sha256sum /usr/local/bin/terrascale-orchestrator | cut -d' ' -f1)" = {NEW_ORCH} ]
systemctl start containerd
timeout 240 systemctl start ts-orch; systemctl is-active ts-orch; echo ok''', 360)
    return 'ok'


def step5():
    mark('installed')
    par(founder5, REGIONS)
    log('5', 'founders: fences armed (job+ingress read back), controller state archived, ts-orch 09381c30 installed, containerd+ts-orch restarted')
    par(lambda r: sh(F(r), f'rm -f {R}/watch-restarted.json {R}/watch-restarted.json.pending; python3 -I {S}/cold.py watch --baseline {R}/watch-baseline-t0.json --receipt {R}/watch-restarted.json --barrier restarted; echo ok', 120), REGIONS)
    recs = []
    for r in REGIONS:
        fetch(F(r), f'{R}/watch-restarted.json', X / f'watch-restarted-{r}.json'); recs.append(str(X / f'watch-restarted-{r}.json'))
    out = subprocess.run(['python3', '-I', str(X / 'cold.py'), 'watch-check', '--barrier', 'restarted', '--receipts', *recs], capture_output=True, check=True, timeout=30).stdout.decode().strip()
    log('5', f'restarted barrier PASS on 3 founders (60 s, no engine, no new task) {out}')


# ---------------- step 5b: release-only to the fenced founders ----------------
def step5b():
    repo = 'TerraScale/terrascale'
    subprocess.run(['gh', 'workflow', 'enable', '381575024', '--repo', repo], check=True, timeout=60)
    try:
        subprocess.run(['gh', 'workflow', 'run', '381575024', '--repo', repo, '--ref', 'main', '-f', 'publication=release-only',
                        '-f', 'terrabase_arm64=' + TARGET.split('@')[1]], check=True, timeout=60)
    finally:
        subprocess.run(['gh', 'workflow', 'disable', '381575024', '--repo', repo], check=True, timeout=60)
    time.sleep(8)
    run = subprocess.run(['gh', 'run', 'list', '--repo', repo, '--workflow', '381575024', '--limit', '1', '--json', 'databaseId', '--jq', '.[0].databaseId'],
                         capture_output=True, check=True, timeout=60).stdout.decode().strip()
    log('5b', f'release-only dispatched (run {run}); CI workflow disabled again')
    subprocess.run(['gh', 'run', 'watch', run, '--repo', repo, '--exit-status'], capture_output=True, timeout=1200)
    jobs = subprocess.run(['gh', 'run', 'view', run, '--repo', repo, '--json', 'jobs', '--jq', '.jobs[]|select(.name=="release-only")|.conclusion'],
                          capture_output=True, check=True, timeout=60).stdout.decode().strip()
    cands = par(lambda r: sh(F(r), 'cat /var/lib/ts-orch/terrabase-bootstrap/candidate.json'), REGIONS)
    ok = {r: json.loads(c)['image'] == TARGET for r, c in cands.items()}
    log('5b', f'release-only job {jobs}; candidate retained on founders {ok}')
    if not all(ok.values()):
        raise RuntimeError('candidate not retained on every founder')


# ---------------- step 6: engines at the same owners/epochs ----------------
def boot_worker(r):
    t = T[r]
    clone = (X / f'clone-{r}.id').read_text().strip()
    oci(r, 'compute', 'boot-volume-attachment', 'attach', '--boot-volume-id', clone, '--instance-id', t['worker'],
        '--display-name', f'{W(r)}-v2-boot', '--wait-for-state', 'ATTACHED', '--max-wait-seconds', '600')
    log('6', f'{W(r)} clone attached as boot volume')
    oci(r, 'compute', 'instance', 'action', '--instance-id', t['worker'], '--action', 'START', '--wait-for-state', 'RUNNING', '--max-wait-seconds', '600')
    log('6', f'{W(r)} OCI START → RUNNING')


def bm(host, action, job, timeout=80):
    return sh(host, f'{"/usr/local/bin/terrascale-orchestrator"} bootstrap-maintenance {action} --state /var/lib/ts-orch --id {job}', timeout)


def wait(fn, seconds, what):
    end = time.monotonic() + seconds
    last = None
    while time.monotonic() < end:
        try:
            return fn()
        except Exception as e:
            last = e
            time.sleep(5)
    raise RuntimeError(f'{what} not reached in {seconds}s: {str(last)[:300]}')


def status(host):
    return json.loads(sh(host, '/usr/local/bin/terrascale-orchestrator bootstrap-maintenance status --state /var/lib/ts-orch'))


def worker_verified(r):
    out = sh(F(r), 'timeout 15 /usr/local/bin/terrascale-orchestrator service ps terrabase; timeout 15 /usr/local/bin/terrascale-orchestrator service inspect terrabase | python3 -c "import json,sys;print(json.load(sys.stdin)[\'spec\'][\'image\'])"')
    lines = out.splitlines()
    image = lines[-1].strip()
    run = [l.split() for l in lines[1:-1] if len(l.split()) > 3 and l.split()[1] == W(r) and l.split()[2] == 'running']
    old = [l.split()[2] for l in (X / 'manager-running-pre.txt').read_text().splitlines() if l.split()[1] == W(r)][0]
    if image != TARGET or not run or run[0][0] == old:
        raise RuntimeError(f'{W(r)} not yet on candidate: image={image[-12:]} running={run}')
    return run[0][0]


def region6(r):
    fj, owner = f'zdt-20261107-{F(r)}', OWNER[r][0]
    boot_worker(r)
    wait(lambda: bm(F(r), 'stage', fj), 420, f'{r} stage (worker fenced+joined)')
    log('6', f'{r} stage PASS: both regional executors fenced; candidate staged (Parallelism 0)')
    if owner == F(r):
        bm(F(r), 'replace', fj, 90)
        if status(F(r))['phase'] != 'verified':
            raise RuntimeError(f'{F(r)} owner replace not verified')
        log('6', f'{F(r)} owner replaced in place at {owner}/{OWNER[r][1]} (verified)')
        task = wait(lambda: worker_verified(r), 960, f'{W(r)} follower self-drive')
        log('6', f'{W(r)} follower replaced by its boot drive (task {task})')
    else:
        task = wait(lambda: worker_verified(r), 600, f'{W(r)} owner self-drive')
        log('6', f'{W(r)} owner replaced by its boot drive at {owner}/{OWNER[r][1]} (task {task})')
        wait(lambda: bm(F(r), 'owner', fj, 80), 600, f'{r} owner ready + ingress released')
        bm(F(r), 'replace', fj, 90)
        if status(F(r))['phase'] != 'verified':
            raise RuntimeError(f'{F(r)} follower replace not verified')
        log('6', f'{F(r)} follower replaced (verified, primed to owner)')


def step6():
    mark('engines')
    region6('sjc')  # canary: a worker follower's swap and first boot first
    log('6', 'SJC canary complete; proceeding with GRU and FRA')
    par(region6, ('gru', 'fra'))
    log('6', 'all 6 engines on the candidate at original owners/epochs')


def step7():
    rowhash('after')


def step7open():
    par(lambda r: sh(F(r), f'python3 -I {S}/cold.py gate open --operator {OPERATOR}'), REGIONS)
    log('7', 'maintenance gate removed on 3 founders')


def engines_ready(timeout=600):
    out = sh('ts-sjc-1', f'''python3 -I - <<'PY'
import subprocess, json, time
cred=open('{R}/peer.credential').read().strip()
ips={{'ts-gru-1':'10.200.165.148','ts-gru-2':'10.200.101.28','ts-sjc-1':'10.200.109.193','ts-sjc-2':'10.200.72.235','ts-fra-1':'10.200.40.238','ts-fra-2':'10.200.95.5'}}
def st(ip):
    cfg=f'url = "http://{{ip}}:8081/v1/rollout/status"\\nheader = "X-TerraBase-Peer-Credential: {{cred}}"\\n'
    p=subprocess.run(['curl','-s','--max-time','4','--http2-prior-knowledge','--config','-'],input=cfg.encode(),capture_output=True)
    try: return json.loads(p.stdout)
    except Exception: return None
end=time.time()+{timeout}
while True:
    s={{n:st(ip) for n,ip in ips.items()}}
    w={{n for n,v in s.items() if v and v.get('writer') and v.get('ready')}}
    if (w>={{'ts-gru-1','ts-sjc-1','ts-fra-2'}} and all(v and v.get('ready') for v in s.values())) or time.time()>end: break
    time.sleep(10)
print(json.dumps(s))
PY''', timeout + 60)
    s = json.loads(out.strip().splitlines()[-1])
    ok = all(v and v.get('ready') for v in s.values()) and {n for n, v in s.items() if v and v.get('writer')} >= {'ts-gru-1', 'ts-sjc-1', 'ts-fra-2'}
    return ok, {n: (v or {}).get('owner') for n, v in s.items()}


def canary():
    p = subprocess.run(['python3', '-I', str(X / 'canary.py'), '/home/mariogk/.local/state/ts-throwaway-account/zdt20261107.key', str(X / 'canary-state.json'), 'probe'],
                       capture_output=True, text=True, timeout=300)
    return p.returncode == 0, (p.stdout.strip().splitlines() or [''])[-1][:300]


def status_operational(seconds=900):
    end = time.monotonic() + seconds
    s = None
    while time.monotonic() < end:
        p = subprocess.run(['curl', '-s', '-m', '8', 'https://status.terrascale.tech/api/v1/status'], capture_output=True, text=True)
        try:
            s = json.loads(p.stdout)['status']
        except Exception:
            s = None
        if s == 'operational':
            return s
        time.sleep(20)
    return s


def stepall():
    heart = Heart()
    heart.t.start()
    phase = 'gate'
    try:
        mark('gate')
        for name in ('1', '2', '3', '4', '5', '5b', '6', '7'):
            globals()['step' + name]()
        step7open()
        ok, owners = engines_ready(300)
        c_ok, c = canary()
        log('7', f'six engines ready {ok} owners {owners}; canary {c_ok} {c}')
        if not (ok and c_ok):
            raise RuntimeError('post-window readiness or canary failed')
        log('7', f'status {status_operational()}')
        stepdisarm()
        log('DONE', 'window complete')
    except BaseException as e:
        log('ABORT', f'{type(e).__name__}: {str(e)[:600]}')
        try:
            rollback(str(e))
            ok, owners = engines_ready(900)
            c_ok, c = canary()
            log('rollback', f'six engines ready {ok} owners {owners}; canary {c_ok} {c}; status {status_operational()}')
        except BaseException as e2:
            log('rollback', f'FAILED {type(e2).__name__}: {str(e2)[:400]}; dead-man timers stay armed')
            raise
        stepdisarm()
        log('RESTORED', 'rolled back to the old engines; ingress open')
    finally:
        heart.stop.set()


if __name__ == '__main__':
    step = sys.argv[1]
    try:
        globals()['step' + step]()
    except Exception as e:
        log(step, f'GATE FAILED: {type(e).__name__}: {str(e)[:900]}')
        sys.exit(1)
