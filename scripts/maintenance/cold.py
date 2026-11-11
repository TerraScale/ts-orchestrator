#!/usr/bin/env python3
"""Bounded, explicit operator steps for the six-node cold maintenance.

No fleet loop and no deployment: each command emits a private receipt. Review the
six receipts before advancing the next fleet barrier. See README.md.
"""
import argparse
import base64
import collections
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse

TABLE = 'ts_zdt_20261105'
PEERS = ('10.200.165.148', '10.200.101.28', '10.200.109.193',
         '10.200.72.235', '10.200.40.238', '10.200.95.5')
# Booting workers reach NetBird management on their founder's 443 before they
# own an overlay address: VCN and public sources of ts-gru-2, ts-sjc-2, ts-fra-2.
WORKER_SOURCES = ('10.251.0.115', '10.252.0.90', '10.253.0.35', '147.15.5.65', '163.192.24.49', '152.70.187.12')
KEYS = ('home.00000000000000000000000003', 'home.00000000000000000000000004')
TASK_ROOT = Path('/run/containerd/io.containerd.runtime.v2.task')
RUNTIME_SOCKET = '/run/containerd/containerd.sock'
WATCH_SECONDS = 60


def require(value, message):
    if not value:
        raise RuntimeError(message)


def private(path):
    p = Path(path)
    s = p.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and s.st_mode & 0o077 == 0,
            'input must be an owned private regular file')
    return p


def save(path, value):
    p = Path(path)
    with open(p, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as f:
        json.dump(value, f, sort_keys=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())


def command(args, timeout=15, data=None):
    return subprocess.run(args, input=data, capture_output=True, check=True, timeout=timeout).stdout


def digest(path, deadline):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        while chunk := f.read(1024 * 1024):
            require(time.monotonic() < deadline, 'hash deadline exceeded')
            h.update(chunk)
    return h.hexdigest()


def gate_rules(operator):
    addr = ipaddress.ip_address(operator)
    family = 'ip' if addr.version == 4 else 'ip6'
    return f'''table inet {TABLE} {{
 comment "zdt-20261105-owned-maintenance"
 chain ingress {{
  type filter hook input priority -20; policy accept;
  {family} saddr {addr} tcp dport {{ 80, 443, 5432, 8081 }} accept
  ip saddr {{ {', '.join(PEERS)} }} tcp dport 8081 accept
  ip saddr {{ {', '.join(WORKER_SOURCES)} }} tcp dport 443 accept
  tcp dport {{ 80, 443, 5432, 8081 }} reject with tcp reset
 }}
}}
'''


def gate(args):
    rules = gate_rules(args.operator)
    if args.action == 'render':
        print(rules, end='')
        return
    require(os.geteuid() == 0, 'gate requires root')
    if args.action == 'close':
        command(['nft', '--check', '-f', '-'], data=rules.encode())
        command(['nft', '-f', '-'], data=rules.encode())
    else:
        state = json.loads(command(['nft', '-j', 'list', 'table', 'inet', TABLE]))
        tables = [x['table'] for x in state['nftables'] if 'table' in x]
        require(len(tables) == 1 and tables[0].get('comment') == 'zdt-20261105-owned-maintenance',
                'refusing to remove a table without our ownership comment')
        command(['nft', 'delete', 'table', 'inet', TABLE])
    print(json.dumps({'action': args.action, 'table': TABLE, 'rulesSha256': hashlib.sha256(rules.encode()).hexdigest()}))


def runtime_labels(args):
    namespaces = command(['ctr', 'namespaces', 'list', '-q']).decode().split()
    rows = []
    for ns in namespaces:
        for container in command(['ctr', '-n', ns, 'containers', 'list', '-q']).decode().split():
            data = json.loads(command(['ctr', '-n', ns, 'containers', 'info', container]))
            labels = data.get('Labels', {}) or {}
            policy = labels.get('containerd.io/restart.policy', '')
            require(policy in ('', 'no', 'never'), 'restart policy can recreate a stopped task')
            rows.append({'namespace': ns, 'container': container, 'labels': labels})
    save(args.receipt, {'namespaces': namespaces, 'containers': rows, 'at': time.time()})


def identity(pid):
    try:
        text = Path(f'/proc/{pid}/stat').read_text()
        fields = text[text.rindex(')') + 2:].split()
        if fields[0] == 'Z':
            return None
        return {'pid': pid, 'start': fields[19], 'exe': os.readlink(f'/proc/{pid}/exe')}
    except (FileNotFoundError, ProcessLookupError):
        return None


def engine_args(args):
    # Inspect executable/managed entrypoint identities, never arbitrary operator
    # arguments which may mention TerraBase in a receipt or script pathname.
    if not args:
        return False
    name = Path(args[0]).name.lower().removesuffix(' (deleted)')
    if name in ('terrabase', 'tb-server', 'terrabase.dll'):
        return True
    return name == 'dotnet' and any(Path(x).name.lower() == 'terrabase.dll' for x in args[1:])


def engine_processes():
    rows = []
    for p in Path('/proc').iterdir():
        if not p.name.isdecimal():
            continue
        try:
            found = identity(int(p.name))
            if found is None:
                continue
            args = (p / 'cmdline').read_bytes().decode(errors='replace').split('\0')
            if engine_args([found['exe']]) or engine_args(args):
                rows.append(found)
        except (FileNotFoundError, ProcessLookupError):
            continue  # A process exiting during enumeration is absent.
        # Permission errors and malformed proc data are failures, not absence.
    return rows


def task_directories():
    require(TASK_ROOT.is_dir() and not TASK_ROOT.is_symlink(), 'runtime task directory unavailable')
    rows = {}
    for namespace in TASK_ROOT.iterdir():
        require(namespace.is_dir() and not namespace.is_symlink(), 'unexpected runtime namespace')
        for task in namespace.iterdir():
            require(task.is_dir() and not task.is_symlink(), 'unexpected runtime task directory')
            s = task.stat()
            rows[namespace.name + '/' + task.name] = [s.st_dev, s.st_ino, s.st_ctime_ns]
    return rows


def runtime_tasks():
    rows = {}
    for ns in command(['ctr', 'namespaces', 'list', '-q'], timeout=2).decode().split():
        lines = command(['ctr', '-n', ns, 'tasks', 'list'], timeout=2).decode().splitlines()
        require(lines and lines[0].split() == ['TASK', 'PID', 'STATUS'], 'unexpected task table')
        for line in lines[1:]:
            columns = line.split()
            require(len(columns) == 3 and columns[1].isdecimal(), 'malformed task table')
            task, pid, status = columns
            data = json.loads(command(['ctr', '-n', ns, 'containers', 'info', task], timeout=2))
            args = data.get('Spec', {}).get('value', {}).get('process', {}).get('args', [])
            image = data.get('Image', '').split('@')[0].split(':')[0]
            engine = image.endswith('/terrabase') or engine_args(args)
            rows[ns + '/' + task] = {'pid': int(pid), 'identity': identity(int(pid)) if int(pid) else None,
                                     'status': status, 'engine': engine}
    return rows


def watch_baseline(args):
    require(os.geteuid() == 0, 'watch baseline requires root')
    save(args.receipt, {'host': socket.gethostname(), 'at': time.time(),
                        'tasks': runtime_tasks(), 'directories': task_directories()})


def no_reappearance(args):
    require(os.geteuid() == 0, 'process watch requires root')
    baseline_path = private(args.baseline)
    baseline_bytes = baseline_path.read_bytes()
    baseline = json.loads(baseline_bytes)
    require(baseline['host'] == socket.gethostname(), 'watch baseline belongs to another host')
    # Create the abort receipt before taking observations. An interrupted driver
    # leaves abort=true, never a missing receipt which could be mistaken for pass.
    receipt = Path(args.receipt)
    record = {'host': socket.gethostname(), 'abort': True, 'startedAt': time.time(),
              'baselineSha256': hashlib.sha256(baseline_bytes).hexdigest(),
              'barrier': args.barrier, 'runtimeDown': args.runtime_down,
              'requiredSeconds': WATCH_SECONDS, 'samples': 0}
    save(receipt, record)
    def update():
        pending = receipt.with_name(receipt.name + '.pending')
        save(pending, record)
        os.replace(pending, receipt)
        fd = os.open(receipt.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    start = time.monotonic()
    try:
        while True:
            processes = engine_processes()
            require(not processes, 'engine process reappeared')
            directories = task_directories()
            engine_dirs = {k for k, task in baseline['tasks'].items() if task['engine']}
            for k, v in directories.items():
                old = baseline['directories'].get(k)
                # A stopped engine's shim records the exit in its own bundle
                # directory (ctime moves). Same device/inode only; any new or
                # recreated directory, and any other change, still fails.
                same = old is not None and (old[:2] == v[:2] if k in engine_dirs else old == v)
                require(same, 'new or recreated containerd task directory')
            if args.runtime_down:
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.settimeout(0.2)
                    code = probe.connect_ex(RUNTIME_SOCKET)
                require(code in (errno.ENOENT, errno.ECONNREFUSED), 'runtime API reappeared or unreadable')
                # With the daemon down, direct host proc identities plus the
                # shim task directories remain observable independently of RPC.
                for task in baseline['tasks'].values():
                    if task['engine'] and task['identity'] is not None:
                        require(identity(task['pid']) != task['identity'], 'captured engine still alive')
            else:
                tasks = runtime_tasks()
                for key, task in tasks.items():
                    require(key in baseline['tasks'], 'new containerd task')
                    old = baseline['tasks'][key]
                    require(not task['engine'] or task['status'] == 'STOPPED' and task['identity'] is None,
                            'live engine containerd task')
                    require(task['identity'] is None or task['identity'] == old['identity'],
                            'restarted containerd task')
            record['samples'] += 1
            record['elapsedSeconds'] = time.monotonic() - start
            require(record['elapsedSeconds'] < WATCH_SECONDS + 10, 'watch sample deadline exceeded')
            update()
            if record['elapsedSeconds'] >= WATCH_SECONDS:
                record.update(abort=False, completedAt=time.time())
                update()
                return
            time.sleep(min(0.25, WATCH_SECONDS - record['elapsedSeconds']))
    except BaseException as error:
        record.update(abort=True, failure=type(error).__name__, elapsedSeconds=time.monotonic() - start)
        update()
        raise


def check_watches(args):
    # stopped: three founder 60 s watches plus three worker OCI STOPPED receipts.
    # restarted: the three founders; each worker gates itself in boot-drive.
    founders = {f'ts-{region}-1' for region in ('gru', 'sjc', 'fra')}
    workers = {f'ts-{region}-2' for region in ('gru', 'sjc', 'fra')}
    expected = founders | workers if args.barrier == 'stopped' else founders
    rows = [json.loads(private(path).read_text()) for path in args.receipts]
    require(len(rows) == len(expected) and {row['host'] for row in rows} == expected, 'one receipt per expected host required')
    for row in rows:
        if row.get('kind') == 'oci-stopped':
            require(args.barrier == 'stopped' and row['host'] in workers and row['abort'] is False, 'OCI receipt is only a worker stop proof')
            continue
        require(row['host'] in founders and row['abort'] is False and row['barrier'] == args.barrier
                and row['requiredSeconds'] == WATCH_SECONDS and row['elapsedSeconds'] >= WATCH_SECONDS
                and row['samples'] >= 2 and row['completedAt'] >= row['startedAt'] + WATCH_SECONDS,
                'missing, incomplete, failed or wrong-barrier process watch')
    print(json.dumps({'barrier': args.barrier, 'abort': False, 'hosts': sorted(expected)}))


def stop(args):
    require(os.geteuid() == 0, 'physical stop requires root')
    expected = json.loads(private(args.identity).read_text())
    pid = int(expected['pid'])
    require(pid > 1, 'unsafe PID')
    for sig, wait in ((signal.SIGTERM, 20), (signal.SIGKILL, 5)):
        now = identity(pid)
        if now is None:
            break
        require(now == expected, 'PID/start/executable identity changed; do not signal')
        # A pidfd pins the exact task across exit/PID reuse between check and signal.
        fd = os.pidfd_open(pid)
        try:
            require(identity(pid) == expected, 'PID identity changed while opening pidfd')
            signal.pidfd_send_signal(fd, sig)
        finally:
            os.close(fd)
        end = time.monotonic() + wait
        while identity(pid) == expected and time.monotonic() < end:
            time.sleep(0.05)
    require(identity(pid) is None, 'physical exit not established in 25 seconds')
    save(args.receipt, {'expected': expected, 'physicallyExitedAt': time.time(), 'boundSeconds': 25})


def inventory(roots, deadline):
    result = {}
    for root in roots:
        root = Path(root)
        require(root.is_absolute() and root.is_dir() and not root.is_symlink(), 'root must be an absolute real directory')
        for p in sorted([root, *root.rglob('*')]):
            require(time.monotonic() < deadline, 'inventory deadline exceeded')
            st = p.lstat()
            require(stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode), 'unexpected symlink/device/socket in data tree')
            name = str(p).lstrip('/')
            require(name not in result, 'overlapping data roots')
            result[name] = {'size': st.st_size if p.is_file() else 0, 'mode': stat.S_IMODE(st.st_mode),
                            'uid': st.st_uid, 'gid': st.st_gid,
                            'sha256': digest(p, deadline) if p.is_file() else None}
    return result


def backup(args):
    start = time.monotonic()
    end = start + 150
    roots = json.loads(private(args.roots).read_text())
    require(isinstance(roots, list) and roots, 'nonempty data root inventory required')
    out = Path(args.destination)
    out.mkdir(mode=0o700)  # Never overwrite an earlier backup.
    require(not any(str(out.resolve()).startswith(str(Path(r).resolve()) + '/') for r in roots), 'backup must be outside data roots')
    before = inventory(roots, end)
    for root in roots:
        target = out / 'data' / root.lstrip('/')
        shutil.copytree(root, target, copy_function=shutil.copy2)
    # copy2 preserves modes; explicitly preserve ownership of the cold copy.
    for name, item in before.items():
        p = out / 'data' / name
        os.chown(p, item['uid'], item['gid'])
        os.chmod(p, item['mode'])
        if item['sha256']:
            require(digest(p, end) == item['sha256'], 'local backup readback mismatch')
    require(inventory(roots, end) == before, 'source changed during cold copy')
    password = private(args.password)
    archive = out / 'data.tar'
    remaining = lambda: max(0.1, end - time.monotonic())
    command(['tar', '-C', str(out / 'data'), '-cpf', str(archive), '--', *[r.lstrip('/') for r in roots]], timeout=remaining())
    encrypted = out / 'data.tar.enc'
    command(['openssl', 'enc', '-aes-256-cbc', '-pbkdf2', '-salt', '-pass', 'file:' + str(password),
             '-in', str(archive), '-out', str(encrypted)], timeout=remaining())
    archive.unlink()
    # Full decryption + per-entry readback, rather than trusting openssl's exit alone.
    with tempfile.TemporaryFile() as f:
        p = subprocess.run(['openssl', 'enc', '-d', '-aes-256-cbc', '-pbkdf2', '-pass', 'file:' + str(password),
                            '-in', str(encrypted)], stdout=f, stderr=subprocess.PIPE, timeout=remaining(), check=True)
        f.seek(0)
        seen = set()
        with tarfile.open(fileobj=f, mode='r:') as tar:
            for member in tar:
                name = member.name.rstrip('/')
                require(name in before and name not in seen, 'unexpected archive member')
                seen.add(name)
                row = before[name]
                require((member.uid, member.gid, member.mode) == (row['uid'], row['gid'], row['mode']), 'archive metadata mismatch')
                if member.isfile():
                    h = hashlib.sha256()
                    stream = tar.extractfile(member)
                    while chunk := stream.read(1024 * 1024):
                        require(time.monotonic() < end, 'archive readback deadline')
                        h.update(chunk)
                    require(h.hexdigest() == row['sha256'] and member.size == row['size'], 'archive file mismatch')
                else:
                    require(member.isdir() and row['sha256'] is None, 'archive type mismatch')
        require(seen == set(before), 'archive omitted data')
    save(out / 'manifest.json', {'files': before, 'bytes': sum(x['size'] for x in before.values()),
                                'encryptedBytes': encrypted.stat().st_size, 'encryptedSha256': digest(encrypted, end),
                                'elapsedSeconds': time.monotonic() - start, 'at': time.time()})
    print(str(out / 'manifest.json'))


def curl_json(address, path, credential):
    # Credential lives only in stdin, never the process arguments or error text.
    ipaddress.ip_address(address)
    require('\n' not in credential and '\r' not in credential and '"' not in credential and '\\' not in credential, 'invalid credential encoding')
    config = f'url = "http://{address}:8081{path}"\nheader = "X-TerraBase-Peer-Credential: {credential}"\n'
    return json.loads(command(['curl', '--fail', '--silent', '--show-error', '--max-time', '8',
                              '--http2-prior-knowledge', '--config', '-'], timeout=10, data=config.encode()))


def checksum_database(get, path):
    revision = get(path + '?revision=ts1:00000000000000000000000001:1:0')['revision']
    cursor, ranges, seen, schema = {}, [], set(), None
    for _ in range(4096):
        page = get(path + '?' + urllib.parse.urlencode({'revision': revision, **cursor}))
        require(page['revision'] == revision and page['moved'] is False, 'database moved during checksums')
        for row in page['ranges']:
            if row['table'] == '':
                require(schema is None or schema == row, 'schema changed between checksum pages')
                schema = row
            else:
                ranges.append(row)
        cursor = page.get('next')
        if cursor is None:
            break
        key = json.dumps(cursor, sort_keys=True)
        require(key not in seen, 'repeating checksum cursor')
        seen.add(key)
    else:
        raise RuntimeError('checksum page bound exceeded')
    require(schema is not None, 'schema checksum missing')
    ranges.insert(0, schema)
    counts = collections.Counter()
    for row in ranges:
        if row['table']:
            counts[row['table']] += row['rows']
    # Native checksum ranges include schema, type/null/blob encoding and rowids.
    return {'revision': revision, 'counts': dict(counts), 'ranges': ranges}


def row_hash(args):
    credential = private(args.credential).read_text().strip()
    get = lambda path: curl_json(args.address, path, credential)
    require(args.region in ('gru', 'sjc', 'fra'), 'unknown region')
    databases, cursor, seen = [], None, set()
    for _ in range(4096):
        query = '?' + urllib.parse.urlencode({'after': cursor}) if cursor else ''
        page = get('/v1/sync/regions/' + args.region + '/databases' + query)
        databases.extend(page['databases'])
        cursor = page.get('next')
        if cursor is None:
            break
        require(cursor not in seen, 'repeating catalog cursor')
        seen.add(cursor)
    else:
        raise RuntimeError('catalog page bound exceeded')
    # Union each home catalog for foreign replicas. Region-only builtins with
    # the same IDs remain scoped to their home, rather than overwriting one another.
    for source in args.catalogs or []:
        databases.extend(row['catalog'] for row in json.loads(private(source).read_text())['databases'].values())
    selected = {}
    for db in databases:
        home = db['homeRegion']
        if home != args.region and not (db.get('allRegions') or args.region in db.get('replicaRegions', [])):
            continue
        key = home + ':' + '/'.join(db[k] for k in ('organizationId', 'projectId', 'databaseId'))
        require(key not in selected or selected[key] == db, 'catalog placement disagreement')
        selected[key] = db
    result = {}
    for key, db in sorted(selected.items()):
        parts = [urllib.parse.quote(db[k], safe='') for k in ('organizationId', 'projectId', 'databaseId')]
        path = '/v1/sync/organizations/{}/projects/{}/databases/{}/checksums'.format(*parts)
        result[key] = {'catalog': db, **checksum_database(get, path)}
    save(args.receipt, {'address': args.address, 'region': args.region, 'at': time.time(), 'databases': result})


def logical_compare(args):
    before = json.loads(private(args.before).read_text())
    after = json.loads(private(args.after).read_text())
    require(before['region'] == after['region'] and before['address'] == after['address'], 'node identity differs')
    def logical(receipt):
        return {key: {field: row[field] for field in ('catalog', 'counts', 'ranges')}
                for key, row in receipt['databases'].items()}
    require(logical(before) == logical(after), 'logical inventory differs')
    print(json.dumps({'equal': True, 'databases': len(before['databases']), 'address': before['address']}))


class Nats:
    def __init__(self, token, port=4223):
        self.s = socket.create_connection(('127.0.0.1', port), timeout=5)
        self.r = self.s.makefile('rb')
        require(self.r.readline().startswith(b'INFO '), 'NATS greeting unavailable')
        self.s.sendall(b'CONNECT ' + json.dumps({'auth_token': token, 'headers': True, 'verbose': False}).encode() + b'\r\nPING\r\n')
        while True:
            line = self.r.readline().strip()
            if line == b'PONG':
                break
            require(line and not line.startswith(b'-ERR'), 'NATS authentication refused')

    def request(self, subject, data, headers=None):
        box = '_INBOX.zdt' + secrets.token_hex(10)
        self.s.sendall(f'SUB {box} 1\r\nUNSUB 1 1\r\n'.encode())
        if headers:
            h = ('NATS/1.0\r\n' + ''.join(k + ': ' + str(v) + '\r\n' for k, v in headers.items()) + '\r\n').encode()
            self.s.sendall(f'HPUB {subject} {box} {len(h)} {len(h)+len(data)}\r\n'.encode() + h + data + b'\r\n')
        else:
            self.s.sendall(f'PUB {subject} {box} {len(data)}\r\n'.encode() + data + b'\r\n')
        while True:
            line = self.r.readline().strip()
            if line == b'PING':
                self.s.sendall(b'PONG\r\n')
                continue
            require(line and not line.startswith(b'-ERR'), 'NATS request failed')
            if line.startswith(b'MSG '):
                n = int(line.split()[-1])
                require(n <= 1024 * 1024, 'oversized NATS reply')
                body = self.r.read(n)
                require(self.r.read(2) == b'\r\n', 'invalid NATS frame')
                return json.loads(body)
            if line.startswith(b'HMSG '):
                raise RuntimeError('NATS returned status instead of data')

    def read(self, key):
        reply = self.request('$JS.API.STREAM.MSG.GET.KV_terrabase-homes', json.dumps({'last_by_subj': '$KV.terrabase-homes.' + key}).encode())
        require('error' not in reply, 'KV read failed')
        return reply['message']


def delete_keys(client, approved, apply, record=lambda key, value: None):
    require(set(approved) == set(KEYS), 'exact two-key allowlist required')
    # Verify both before any write. Each conditional publish still checks revision.
    for key in KEYS:
        m = client.read(key)
        data = base64.b64decode(m.get('data', ''))
        require(m['seq'] == approved[key]['revision'] and hashlib.sha256(data).hexdigest() == approved[key]['sha256'], 'KV changed since approved audit')
        require('KV-Operation: DEL' not in base64.b64decode(m.get('hdrs', '')).decode(), 'key already deleted; use retained receipt')
    receipts = {}
    for key in KEYS:
        if not apply:
            receipts[key] = {'dryRun': True, **approved[key]}
            record(key, receipts[key])
            continue
        reply = client.request('$KV.terrabase-homes.' + key, b'',
                               {'KV-Operation': 'DEL', 'Nats-Expected-Last-Subject-Sequence': approved[key]['revision']})
        require('error' not in reply and isinstance(reply.get('seq'), int), 'conditional KV delete refused; retain partial receipt')
        m = client.read(key)
        require(m['seq'] == reply['seq'] and 'KV-Operation: DEL' in base64.b64decode(m.get('hdrs', '')).decode(), 'KV tombstone not read back')
        receipts[key] = {'revision': reply['seq'], 'deleted': True}
        record(key, receipts[key])
        # Emit and flush each outcome even if the second conditional publish fails.
        print(json.dumps({'key': key, **receipts[key]}), flush=True)
    return receipts


def kv_tombstoned(args):
    # Read-only: both stale keys must read back as DEL tombstones.
    client = Nats(private(args.token).read_text().strip())
    try:
        for key in KEYS:
            m = client.read(key)
            require('KV-Operation: DEL' in base64.b64decode(m.get('hdrs', '')).decode(), 'stale key is not tombstoned: ' + key[-2:])
    finally:
        client.r.close()
        client.s.close()
    print(json.dumps({'tombstoned': list(KEYS)}))


def kv(args):
    client = Nats(private(args.token).read_text().strip())
    try:
        approved = json.loads(private(args.audit).read_text())
        with open(args.receipt, 'x', opener=lambda name, flags: os.open(name, flags, 0o600)) as receipt:
            def record(key, value):
                receipt.write(json.dumps({'key': key, **value}) + '\n')
                receipt.flush()
                os.fsync(receipt.fileno())
            delete_keys(client, approved, args.action == 'delete', record)
    finally:
        client.r.close()
        client.s.close()


# --- Offline worker install (v3): founder-side on a mounted worker boot volume ---
# The worker is STOPPED and its (cloned) boot volume is attached to its region's
# founder. Nothing here touches the founder's own root or a live worker.
STATE = '/var/lib/ts-orch'
BINARY = 'usr/local/bin/terrascale-orchestrator'
DRIVE_DIR = 'var/lib/ts-orch/zdt-drive'
DRIVE_UNIT = 'ts-orch-cold-drive.service'
DRIVE_SCRIPT = 'usr/local/lib/ts-zdt/cold.py'
OWNER_WAIT_SECONDS = 900
STAGE_WAIT_SECONDS = 300
PREPULL_WAIT_SECONDS = 300
IMDS = 'http://169.254.169.254/opc/v2/instance/id'


def imds_instance_id():
    import urllib.request
    request = urllib.request.Request(IMDS, headers={'Authorization': 'Bearer Oracle'})
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.read().decode().strip()
UNIT_TEXT = '''[Unit]
Description=TerraScale cold maintenance drive for one pinned TerraBase transaction
After=ts-orch.service
Requires=ts-orch.service
ConditionPathExists=/var/lib/ts-orch/zdt-drive/drive.json
ConditionPathExists=!/var/lib/ts-orch/zdt-drive/attempted

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I /usr/local/lib/ts-zdt/cold.py boot-drive
TimeoutStartSec=2100
UMask=0077

[Install]
WantedBy=multi-user.target
'''


def sha256_file(path):
    with open(path, 'rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def offline_root(root, member):
    root = Path(root)
    require(root.is_absolute() and str(root) != '/' and os.path.ismount(root), 'offline root must be a mounted path other than /')
    require(root.stat().st_dev != Path('/').stat().st_dev, 'offline root is the live root filesystem')
    require((root / 'etc/hostname').read_text().strip() == member != socket.gethostname(), 'mounted volume is not the named stopped worker')
    return root


def write_private(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name('.' + path.name + '.zdt-new')
    with open(temporary, 'wb', opener=lambda name, flags: os.open(name, flags | os.O_TRUNC, mode)) as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(temporary, mode)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def offline_manifest(root, job_id):
    # Every path this transaction owns, with hash/mode/owner, for verify after detach.
    paths = [BINARY, BINARY + '.zdt-b443', DRIVE_SCRIPT, 'etc/systemd/system/' + DRIVE_UNIT, DRIVE_DIR + '/drive.json',
             'var/lib/ts-orch/terrabase-bootstrap/job.json', 'var/lib/ts-orch/terrabase-bootstrap/ingress.json',
             'var/lib/ts-orch/zdt-retained/tasks.db.' + job_id]
    rows = {}
    for name in paths:
        st = (root / name).lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0, 'offline file is not a root-owned regular file: ' + name)
        rows[name] = {'sha256': sha256_file(root / name), 'mode': stat.S_IMODE(st.st_mode), 'size': st.st_size}
    link = root / 'etc/systemd/system/multi-user.target.wants' / DRIVE_UNIT
    rows['enabled'] = os.readlink(link)
    rows['agentDatabasePresent'] = (root / 'var/lib/ts-orch/swarm/worker/tasks.db').exists()
    rows['releaseTrialPresent'] = (root / 'var/lib/ts-orch/nats/release-trial').exists()
    return rows


def offline_install(args):
    require(os.geteuid() == 0, 'offline install requires root')
    started = time.monotonic()
    manifest = json.loads(private(args.manifest).read_text())
    local = manifest['local']
    member, job_id = local['member'], local['id']
    root = offline_root(args.root, member)
    require(not (root / 'var/lib/ts-orch/nats/release-trial').exists(), 'pending release probation could restore .prev')
    require(sha256_file(args.binary) == args.binary_sha256, 'staged binary differs from the qualified digest')
    current = root / BINARY
    require(sha256_file(current) == args.old_sha256, 'worker binary differs from the captured b443-era executable')
    tool = [args.binary, 'bootstrap-maintenance']
    pins = json.loads(command([*tool, 'pins-offline', '--root', str(root), '--state', STATE], timeout=20))
    require(pins == local['source'], 'worker agent task differs from the manifest source pin')
    # Fence first: if anything below fails, the volume is discarded, never booted.
    command([*tool, 'arm-offline', '--root', str(root), '--state', STATE, '--manifest', str(args.manifest)], timeout=20)
    retained = root / (BINARY + '.zdt-b443')
    if not retained.exists():
        os.link(current, retained)
    write_private(root / (BINARY + '.zdt-stage'), Path(args.binary).read_bytes(), 0o755)
    os.replace(root / (BINARY + '.zdt-stage'), current)
    write_private(root / DRIVE_SCRIPT, Path(__file__).read_bytes(), 0o700)
    write_private(root / 'etc/systemd/system' / DRIVE_UNIT, UNIT_TEXT.encode(), 0o644)
    require(args.instance_id.startswith('ocid1.instance.'), 'worker instance OCID required')
    write_private(root / DRIVE_DIR / 'drive.json', json.dumps({'id': job_id, 'member': member, 'instance': args.instance_id}).encode())
    link = root / 'etc/systemd/system/multi-user.target.wants' / DRIVE_UNIT
    if not link.is_symlink():
        os.symlink('/etc/systemd/system/' + DRIVE_UNIT, link)
    for d in (root / 'usr/local/bin', link.parent):
        fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    os.sync()
    files = offline_manifest(root, job_id)
    require(files[BINARY]['sha256'] == args.binary_sha256 and files[BINARY + '.zdt-b443']['sha256'] == args.old_sha256
            and not files['agentDatabasePresent'] and not files['releaseTrialPresent'], 'offline install readback failed')
    job = json.loads((root / 'var/lib/ts-orch/terrabase-bootstrap/job.json').read_text())
    require(job == local, 'retained worker fence differs from the manifest')
    save(args.receipt, {'member': member, 'id': job_id, 'files': files, 'pins': pins,
                        'seconds': time.monotonic() - started, 'at': time.time()})


def offline_verify(args):
    # Read-only mount after detach/reattach: the same bytes must be there.
    expected = json.loads(private(args.install_receipt).read_text())
    root = offline_root(args.root, expected['member'])
    require(offline_manifest(root, expected['id']) == expected['files'], 'offline volume differs from the install receipt')
    save(args.receipt, {'member': expected['member'], 'id': expected['id'], 'verified': True, 'at': time.time()})


# --- Worker boot drive: runs once on the worker, from the offline-installed unit ---
def rebooted_watch(receipt_path):
    # After a reboot every task is new: non-engine services may restart, but no
    # engine process and no live engine containerd task may appear for 60 s.
    receipt = Path(receipt_path)
    record = {'host': socket.gethostname(), 'abort': True, 'startedAt': time.time(), 'barrier': 'rebooted',
              'requiredSeconds': WATCH_SECONDS, 'samples': 0}
    save(receipt, record)
    start = time.monotonic()
    try:
        while True:
            require(not engine_processes(), 'engine process appeared after reboot')
            for task in runtime_tasks().values():
                require(not task['engine'] or (task['identity'] is None and task['status'] != 'RUNNING'), 'live engine task after reboot')
            record['samples'] += 1
            record['elapsedSeconds'] = time.monotonic() - start
            require(record['elapsedSeconds'] < WATCH_SECONDS + 10, 'watch sample deadline exceeded')
            if record['elapsedSeconds'] >= WATCH_SECONDS:
                record.update(abort=False, completedAt=time.time())
                break
            time.sleep(min(0.25, WATCH_SECONDS - record['elapsedSeconds']))
    finally:
        pending = receipt.with_name(receipt.name + '.pending')
        save(pending, record)
        os.replace(pending, receipt)


def boot_drive(args):
    require(os.geteuid() == 0, 'boot drive requires root')
    base = Path('/' + DRIVE_DIR)
    config = json.loads(private(base / 'drive.json').read_text())
    require(config['member'] == socket.gethostname(), 'drive belongs to another host')
    # The hostname comes from the volume; only the instance identity proves this
    # is the worker (a founder booting a same-label clone root must never drive).
    require(imds_instance_id() == config['instance'], 'drive volume booted on another instance')
    # Attempt once: a later reboot never re-drives; the fence keeps holding.
    save(base / 'attempted', {'at': time.time()})
    result = {'id': config['id'], 'host': config['member'], 'startedAt': time.time(), 'steps': []}
    def step(name, run):
        t = time.monotonic()
        run()
        result['steps'].append({'step': name, 'seconds': time.monotonic() - t})
        save(base / ('result-' + name + '.json'), result)
    tool = ['/' + BINARY, 'bootstrap-maintenance']
    def ready():
        end = time.monotonic() + 180
        while not Path(STATE + '/terrabase-bootstrap/control.sock').exists():
            require(time.monotonic() < end, 'executor control socket did not appear')
            time.sleep(0.5)
        job = json.loads(command([*tool, 'status', '--state', STATE], timeout=10))
        require(job['id'] == config['id'] and job['phase'] == 'held', 'fence is not the held offline transaction')
    step('ready', ready)
    step('watch', lambda: rebooted_watch(base / 'watch-rebooted.json'))
    def retry(name, seconds, required=True):
        # Budget-free, idempotent calls: stage waits for the mesh join; prepull
        # is best effort (Prepare still pulls inside the replace budget).
        end = time.monotonic() + seconds
        while True:
            try:
                command([*tool, name, '--state', STATE, '--id', config['id']], timeout=70)
                return True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                if time.monotonic() >= end:
                    require(not required, name + ' did not succeed in time')
                    return False
                time.sleep(5)
    step('stage', lambda: retry('stage', STAGE_WAIT_SECONDS))
    step('prepull', lambda: result.update(prepulled=retry('prepull', PREPULL_WAIT_SECONDS, required=False)))
    def owner_ready():
        # A follower's driver budget starts at replace: never spend it before its
        # pinned owner serves as writer. A timeout leaves the fence and budget intact.
        job = json.loads(command([*tool, 'status', '--state', STATE], timeout=10))
        if job['member'] == job['owner']:
            return
        end = time.monotonic() + OWNER_WAIT_SECONDS
        while True:
            try:
                command([*tool, 'owner', '--state', STATE, '--id', config['id']], timeout=70)
                return
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                require(time.monotonic() < end, 'pinned owner did not become the ready writer')
                time.sleep(5)
    step('owner', owner_ready)
    step('replace', lambda: command([*tool, 'replace', '--state', STATE, '--id', config['id']], timeout=70))
    def verified():
        job = json.loads(command([*tool, 'status', '--state', STATE], timeout=10))
        require(job['id'] == config['id'] and job['phase'] == 'verified', 'replacement not verified')
    step('verified', verified)


def oci_stopped(args):
    # Workers: OCI STOPPED is the physical exit receipt (no worker shell exists).
    data = json.loads(command(['oci', '--region', args.region, 'compute', 'instance', 'get', '--instance-id', args.instance_id], timeout=30))
    instance = data['data']
    require(instance['display-name'] == args.host and instance['lifecycle-state'] == 'STOPPED', 'worker is not STOPPED')
    save(args.receipt, {'host': args.host, 'kind': 'oci-stopped', 'abort': False, 'barrier': 'stopped',
                        'instance': args.instance_id, 'etag': data.get('etag'), 'at': time.time()})


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='cmd', required=True)
    p = sub.add_parser('gate'); p.add_argument('action', choices=['render', 'close', 'open']); p.add_argument('--operator', required=True); p.set_defaults(run=gate)
    p = sub.add_parser('runtime-labels'); p.add_argument('--receipt', required=True); p.set_defaults(run=runtime_labels)
    p = sub.add_parser('watch-baseline'); p.add_argument('--receipt', required=True); p.set_defaults(run=watch_baseline)
    p = sub.add_parser('watch'); p.add_argument('--baseline', required=True); p.add_argument('--receipt', required=True); p.add_argument('--barrier', required=True, choices=['stopped', 'restarted']); p.add_argument('--runtime-down', action='store_true'); p.set_defaults(run=no_reappearance)
    p = sub.add_parser('watch-check'); p.add_argument('--barrier', required=True, choices=['stopped', 'restarted']); p.add_argument('--receipts', required=True, nargs='+'); p.set_defaults(run=check_watches)
    p = sub.add_parser('stop'); p.add_argument('--identity', required=True); p.add_argument('--receipt', required=True); p.set_defaults(run=stop)
    p = sub.add_parser('backup'); p.add_argument('--roots', required=True); p.add_argument('--destination', required=True); p.add_argument('--password', required=True); p.set_defaults(run=backup)
    p = sub.add_parser('row-hash'); p.add_argument('--address', required=True); p.add_argument('--region', required=True); p.add_argument('--catalogs', nargs='+'); p.add_argument('--credential', required=True); p.add_argument('--receipt', required=True); p.set_defaults(run=row_hash)
    p = sub.add_parser('compare'); p.add_argument('--before', required=True); p.add_argument('--after', required=True); p.set_defaults(run=logical_compare)
    p = sub.add_parser('kv'); p.add_argument('action', choices=['dry-run', 'delete']); p.add_argument('--token', required=True); p.add_argument('--audit', required=True); p.add_argument('--receipt', required=True); p.set_defaults(run=kv)
    p = sub.add_parser('kv-tombstoned'); p.add_argument('--token', required=True); p.set_defaults(run=kv_tombstoned)
    p = sub.add_parser('oci-stopped'); p.add_argument('--host', required=True); p.add_argument('--region', required=True); p.add_argument('--instance-id', required=True); p.add_argument('--receipt', required=True); p.set_defaults(run=oci_stopped)
    p = sub.add_parser('offline-install'); p.add_argument('--root', required=True); p.add_argument('--manifest', required=True); p.add_argument('--binary', required=True); p.add_argument('--binary-sha256', required=True); p.add_argument('--old-sha256', required=True); p.add_argument('--instance-id', required=True); p.add_argument('--receipt', required=True); p.set_defaults(run=offline_install)
    p = sub.add_parser('offline-verify'); p.add_argument('--root', required=True); p.add_argument('--install-receipt', required=True); p.add_argument('--receipt', required=True); p.set_defaults(run=offline_verify)
    p = sub.add_parser('boot-drive'); p.set_defaults(run=boot_drive)
    args = parser.parse_args()
    def expired(signum, frame):
        raise TimeoutError('step hard deadline exceeded')
    signal.signal(signal.SIGALRM, expired)
    signal.alarm({'backup': 150, 'row-hash': 120, 'runtime-labels': 30, 'watch-baseline': 30,
                  'watch': 72, 'watch-check': 15, 'kv-tombstoned': 20, 'oci-stopped': 40, 'offline-install': 60, 'offline-verify': 30, 'boot-drive': 2050, 'kv': 20, 'stop': 28, 'gate': 15, 'compare': 15}[args.cmd])
    try:
        args.run(args)
    except Exception as error:
        # Never echo subprocess output/arguments: they may contain session material.
        raise SystemExit(type(error).__name__ + ': operation failed; retain receipts and hold maintenance') from None


if __name__ == '__main__':
    main()
