import fcntl, hashlib, json, os, pathlib, signal, stat, subprocess, sys, time

OUT = pathlib.Path(__file__).parent
REQUEST = OUT/'request.json'
request = json.loads(REQUEST.read_text())
ROOT = pathlib.Path(request['cwd'])
GO = request['go']
BIN = '/run/current-system/sw/bin/'
ENV = request['env']
HEAD, TREE = request['head'], request['tree']
assert request['packages'] == ['./internal/swarmruntime', './internal/app']
assert request['tags'] == ['fixturetest'] and request['no_execution']
active = None
lock_file = None
spawning = False
pending_signal = None
SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)

def digest(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def git(*args):
    return subprocess.check_output([BIN+'git', *args], cwd=ROOT).decode().strip()

def source():
    assert git('rev-parse', 'HEAD') == HEAD
    assert git('rev-parse', 'HEAD^{tree}') == TREE
    assert not git('status', '--porcelain')
    names = subprocess.check_output([BIN+'git', 'ls-files', '-z'], cwd=ROOT).split(b'\0')
    h = hashlib.sha256()
    for name in names:
        if not name:
            continue
        path = ROOT / os.fsdecode(name)
        h.update(name+b'\0')
        h.update(path.read_bytes() if not path.is_symlink() else os.fsencode(os.readlink(path)))
        h.update(b'\0')
    return h.hexdigest()

def resources():
    memory = dict(line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    available = int(memory['MemAvailable'].split()[0])*1024
    load = os.getloadavg()[0]
    compilers = []
    for path in pathlib.Path('/proc').glob('[0-9]*/comm'):
        try:
            if path.read_text().strip() == 'compile':
                compilers.append(int(path.parent.name))
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            pass
    record = {'available_bytes': available, 'load1': load, 'compiler_pids': compilers}
    assert available >= 16*1024**3 and load < 12 and len(compilers) <= 4, record
    return record


def owned_group(proc):
    members = []
    for path in pathlib.Path('/proc').glob('[0-9]*/stat'):
        try:
            wire = path.read_text()
            fields = wire[wire.rfind(')')+2:].split()
            if int(fields[2]) == proc.pid or int(path.parent.name) == proc.pid:
                members.append(int(path.parent.name))
        except (OSError, ValueError, IndexError):
            pass
    return members

def reap_group(proc):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        proc.poll()
        if not owned_group(proc):
            break
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            pass
        until = time.monotonic()+5
        while time.monotonic() < until:
            proc.poll()
            if not owned_group(proc):
                break
            time.sleep(.05)
    proc.poll()
    return owned_group(proc)

def save():
    (OUT/'results.json').write_text(json.dumps(results, indent=2)+'\n')

def interrupted(signum, frame):
    global pending_signal
    if spawning:
        pending_signal = signum
        return
    raise RuntimeError('runner interrupted by signal '+str(signum))

def cleanup_active():
    global active
    if active is None:
        return
    for sig in SIGNALS:
        signal.signal(sig, signal.SIG_IGN)
    try:
        remaining = reap_group(active)
    except BaseException as error:
        results['state'] = 'FAILED'
        results['cleanup_error'] = repr(error)
        remaining = owned_group(active)
    if remaining:
        results['state'] = 'FAILED_CLEANUP_PENDING'
        results['cleanup_pending'] = {'remaining_group_processes': remaining, 'lock_held': True}
        try:
            save()
        except BaseException:
            pass
        try:
            print(json.dumps({'state': 'FAILED_CLEANUP_PENDING', 'remaining_group_processes': remaining, 'lock_held': True}), flush=True)
        except BaseException:
            pass
        while remaining:
            active.poll()
            time.sleep(.05)
            remaining = owned_group(active)
        results['state'] = 'FAILED'
    active.poll()
    try:
        os.killpg(active.pid, 0)
    except ProcessLookupError:
        pass
    else:
        results['state'] = 'FAILED_CLEANUP_PENDING'
        try:
            save()
        except BaseException:
            pass
        try:
            print(json.dumps({'state': 'FAILED_CLEANUP_PENDING', 'group': active.pid, 'lock_held': True}), flush=True)
        except BaseException:
            pass
        while True:
            try:
                os.killpg(active.pid, 0)
            except ProcessLookupError:
                break
            time.sleep(.05)
        results['state'] = 'FAILED'
    results['runs'][-1]['process_group_after_terminal'] = 'ABSENT'
    active = None
    for sig in SIGNALS:
        signal.signal(sig, interrupted)

results = {'state': 'STARTING', 'request_sha256': digest(REQUEST), 'runner_sha256': digest(__file__), 'runs': []}
old_handlers = {sig: signal.signal(sig, interrupted) for sig in SIGNALS}
try:
    results['tool_sha256'] = {path: digest(path) for path in [GO, str(pathlib.Path(GO).parent.parent/'pkg/tool/linux_amd64/compile'), BIN+'nice', BIN+'timeout', sys.executable]}
    results['source_pre'] = source()
    lock_file = open(request['lock'], 'a+')
    fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    results['state'] = 'RUNNING'
    save()
    print(json.dumps({'launch': results}), flush=True)
    for package in request['packages']:
        name = package.rsplit('/', 1)[1]
        output = OUT/(name+'.test')
        output.touch(mode=0o600, exist_ok=False)
        os.chmod(output, 0o600)
        command = [BIN+'nice', '-n', '19', BIN+'timeout', '--signal=TERM', '--kill-after=5s', '240s', GO, 'test', '-c', '-tags=fixturetest', '-p=1', '-mod=readonly', '-o', str(output), package]
        record = {'package': package, 'command': command, 'resources_pre': resources(), 'source_pre': source(), 'artifact_path': str(output)}
        results['runs'].append(record)
        save()
        started = time.monotonic()
        try:
            with (OUT/(name+'.stdout')).open('wb') as stdout, (OUT/(name+'.stderr')).open('wb') as stderr:
                spawning = True
                try:
                    active = subprocess.Popen(command, cwd=ROOT, env=ENV, stdout=stdout, stderr=stderr, start_new_session=True)
                finally:
                    spawning = False
                record['pid'] = active.pid
                save()
                print(json.dumps({'started': package, 'pid': active.pid}), flush=True)
                if pending_signal is not None:
                    raise RuntimeError('runner interrupted during spawn by signal '+str(pending_signal))
                record['exit_code'] = active.wait()
        finally:
            cleanup_active()
            os.chmod(output, 0o600)
            record['wall_seconds'] = time.monotonic()-started
            record['artifact'] = {'path': str(output), 'mode': oct(stat.S_IMODE(output.stat().st_mode)), 'bytes': output.stat().st_size, 'sha256': digest(output), 'executed': False}
            save()
        record['source_post'] = source()
        record['source_unchanged'] = record['source_pre'] == record['source_post'] == results['source_pre']
        record['artifact'] = {'path': str(output), 'mode': oct(stat.S_IMODE(output.stat().st_mode)), 'bytes': output.stat().st_size, 'sha256': digest(output), 'executed': False}
        save()
        print(json.dumps({'finished': record}), flush=True)
        if record['exit_code'] or not record['source_unchanged'] or results['state'] != 'RUNNING':
            raise RuntimeError('compile or source/cleanup check failed: '+package)
    results['state'] = 'PASS'
except BaseException as error:
    results['state'] = 'FAILED'
    results['error'] = repr(error)
finally:
    for sig in SIGNALS:
        signal.signal(sig, signal.SIG_IGN)
    cleanup_active()
    for sig in SIGNALS:
        signal.signal(sig, signal.SIG_IGN)
    try:
        results['source_post'] = source()
        results['runner_sha256_post'] = digest(__file__)
        results['tool_sha256_post'] = {path: digest(path) for path in results.get('tool_sha256', {})}
        if results.get('source_pre') != results['source_post'] or results['runner_sha256'] != results['runner_sha256_post'] or results.get('tool_sha256') != results['tool_sha256_post']:
            raise RuntimeError('post-run source/runner/tool pins changed')
    except BaseException as error:
        results['state'] = 'FAILED'
        results['post_pin_error'] = repr(error)
    if lock_file is not None:
        fcntl.flock(lock_file, fcntl.LOCK_UN)
        lock_file.close()
    results['lock_released'] = True
    results['cleanup'] = 'Owned groups absent before source/tool postpins and SHORTA release; no test binary executed.'
    save()
    for sig, handler in old_handlers.items():
        signal.signal(sig, handler)
print(json.dumps({'complete': str(OUT/'results.json'), 'state': results['state']}), flush=True)
sys.exit(0 if results['state'] == 'PASS' else 1)
