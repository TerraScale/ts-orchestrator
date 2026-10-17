import collections, datetime, fcntl, hashlib, json, math, os, pathlib, resource, signal, subprocess, time

OUT = pathlib.Path(__file__).parent
RAW = (OUT / 'request.json').read_bytes()
assert hashlib.sha256(RAW).hexdigest() == '7457cd90d757c336a92a2a0e9315345d707612c649e37e4530bd9d4c583bf546'

def object_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key: ' + key)
        result[key] = value
    return result

def strict_json(raw):
    return json.loads(raw, object_pairs_hook=object_without_duplicates,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('non-finite JSON: ' + value)))

R = strict_json(RAW)
W = pathlib.Path(R['worktree'])
ENV = R['environment']
assert dict(os.environ) == ENV

def write(name, data):
    with (OUT / name).open('x') as file:
        json.dump(data, file, indent=2, sort_keys=True, allow_nan=False)
        file.write('\n')

def git(*args):
    return subprocess.check_output(['/run/current-system/sw/bin/git', '-C', str(W), *args], env=ENV).decode()

def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()

def seal():
    assert git('rev-parse', 'HEAD').strip() == R['commit']
    assert git('rev-parse', 'HEAD^{tree}').strip() == R['tree']
    assert not git('status', '--porcelain=v1', '--untracked-files=all')
    actual_paths = {os.fsdecode(path) for path in subprocess.check_output(
        ['/run/current-system/sw/bin/git', '-C', str(W), 'ls-files', '-z'], env=ENV).split(b'\0') if path}
    assert actual_paths == {entry['path'] for entry in R['source']}
    for entry in R['source']:
        path = W / entry['path']
        data = os.readlink(path).encode() if entry['mode'] == '120000' else path.read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry['sha256'], entry['path']
    for entry in R['tools']:
        path = pathlib.Path(entry['path'])
        assert str(path.resolve()) == entry['resolved'] and sha(path) == entry['sha256'], entry['path']
    return {'commit': R['commit'], 'tree': R['tree'], 'clean': True,
            'source_files': len(R['source']), 'tool_count': len(R['tools'])}

def processes():
    result = []
    for path in pathlib.Path('/proc').glob('[0-9]*'):
        try:
            stat = (path / 'stat').read_text()
            tail = stat[stat.rfind(')') + 2:].split()
            result.append({'pid': int(path.name), 'ppid': int(tail[1]),
                           'pgrp': int(tail[2]), 'comm': (path / 'comm').read_text().strip()})
        except (OSError, ValueError, IndexError):
            pass
    return result

def owned_group(child):
    return [proc for proc in processes() if proc['pgrp'] == child.pid or proc['pid'] == child.pid]

def cleanup(child):
    actions = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        child.poll()
        if not owned_group(child):
            break
        try:
            os.killpg(child.pid, sig)
            actions.append(signal.Signals(sig).name)
        except ProcessLookupError:
            pass
        until = time.monotonic() + 5
        while time.monotonic() < until:
            child.poll()
            if not owned_group(child):
                break
            time.sleep(.05)
    child.poll()
    return actions, owned_group(child)

def interrupted(signum, frame):
    raise RuntimeError('runner interrupted by signal ' + str(signum))

def event(raw, expected):
    value = strict_json(raw)
    if not isinstance(value, dict) or not isinstance(value.get('Action'), str):
        raise ValueError('test event must be an object with an Action string')
    action = value['Action']
    if action in {'build-output', 'build-fail'}:
        required = {'Action', 'ImportPath'} | ({'Output'} if action == 'build-output' else set())
        if set(value) != required or any(not isinstance(value[key], str) or not value[key] for key in required):
            raise ValueError('invalid build event schema')
        return value
    required = {'Action', 'Package', 'Time'}
    allowed = set(required)
    if action in {'run', 'pause', 'cont'}:
        required.add('Test')
        allowed.add('Test')
    elif action in {'pass', 'fail', 'skip'}:
        required.add('Elapsed')
        allowed.update({'Elapsed', 'Test'})
        if action == 'fail':
            allowed.add('FailedBuild')
    elif action == 'output':
        required.add('Output')
        allowed.update({'Output', 'OutputType', 'Test'})
    elif action != 'start':
        raise ValueError('unknown test event action: ' + action)
    if not required <= set(value) or not set(value) <= allowed:
        raise ValueError('missing or unexpected test event fields')
    if value['Package'] not in R['expected_packages']:
        raise ValueError('unexpected test package')
    if not isinstance(value['Time'], str) or datetime.datetime.fromisoformat(value['Time']).utcoffset() is None:
        raise ValueError('invalid event timestamp')
    for key in {'Test', 'Output', 'OutputType', 'FailedBuild'} & set(value):
        if not isinstance(value[key], str) or key != 'Output' and not value[key]:
            raise ValueError('invalid string field: ' + key)
    if 'Test' in value and (value['Package'], value['Test']) not in expected:
        raise ValueError('unexpected test outcome')
    if 'Elapsed' in value and (type(value['Elapsed']) not in (int, float) or not math.isfinite(value['Elapsed']) or value['Elapsed'] < 0):
        raise ValueError('invalid elapsed value')
    return value

class Lifecycle:
    def __init__(self, expected):
        self.expected = set(expected)
        self.packages = {}
        self.tests = {}

    def feed(self, value):
        action = value['Action']
        if action in {'build-output', 'build-fail'}:
            return
        package = value['Package']
        test = value.get('Test')
        if action == 'start':
            if package in self.packages:
                raise ValueError('duplicate package start')
            self.packages[package] = 'running'
            return
        if self.packages.get(package) != 'running':
            raise ValueError('event outside active package lifecycle')
        if test is None:
            if action == 'output':
                return
            if action not in {'pass', 'fail', 'skip'}:
                raise ValueError('invalid package transition')
            if any(state != 'terminal' for (pkg, _), state in self.tests.items() if pkg == package):
                raise ValueError('package terminal while test remains active')
            if action == 'pass' and any(self.tests.get(key) != 'terminal' for key in self.expected if key[0] == package):
                raise ValueError('package passed before expected tests completed')
            self.packages[package] = 'terminal'
            return
        key = package, test
        state = self.tests.get(key)
        if action == 'run':
            if state is not None:
                raise ValueError('duplicate test run')
            if '/' in test and self.tests.get((package, test.rsplit('/', 1)[0])) != 'running':
                raise ValueError('subtest started outside running parent')
            self.tests[key] = 'running'
        elif action == 'pause':
            if state != 'running':
                raise ValueError('pause outside running test')
            self.tests[key] = 'paused'
        elif action == 'cont':
            if state != 'paused':
                raise ValueError('continue outside paused test')
            self.tests[key] = 'running'
        elif action == 'output':
            if state not in {'running', 'paused'}:
                raise ValueError('output outside active test')
        elif action in {'pass', 'fail', 'skip'}:
            if state != 'running':
                raise ValueError('test terminal outside running test')
            if any(pkg == package and name.startswith(test + '/') and child != 'terminal'
                   for (pkg, name), child in self.tests.items()):
                raise ValueError('parent terminal while subtest remains active')
            self.tests[key] = 'terminal'
        else:
            raise ValueError('invalid test transition')


assert not (OUT / 'started.json').exists() and not (OUT / 'receipt.json').exists()
with open(R['lock'], 'a') as gate:
    try:
        fcntl.flock(gate, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        write('receipt.json', {'state': 'LOCK_BUSY_NOT_LAUNCHED'})
        raise SystemExit(75)
    pre = post = child = code = None
    cleanup_attempted = False
    errors, remaining, cleanup_actions, events, malformed, bad = [], [], [], [], [], []
    run, passed, packages, starts = (collections.Counter() for _ in range(4))
    expected = collections.Counter((package, name) for package, names in R['expected_packages'].items() for name in names)
    started = time.monotonic()
    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        pre = seal()
        memory = {key: int(value.split()[0]) * 1024 for key, value in
                  (line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())}
        load = os.getloadavg()[0]
        compilers = [proc for proc in processes() if proc['comm'] == 'compile']
        write('preflight.json', {'source': pre, 'mem_available': memory['MemAvailable'],
                                'load1': load, 'compilers': compilers, 'argv': R['argv'], 'environment': ENV})
        assert memory['MemAvailable'] >= 16 * 1024 ** 3 and load < 12 and len(compilers) <= 4, 'resource gate'
        with (OUT / 'stdout.jsonl').open('xb') as stdout, (OUT / 'stderr.log').open('xb') as stderr:
            child = subprocess.Popen(R['argv'], cwd=W, env=ENV, start_new_session=True, stdout=stdout, stderr=stderr)
            write('started.json', {'pid': child.pid, 'pgrp': child.pid, 'argv': R['argv'], 'runner_pid': os.getpid()})
            print(json.dumps({'state': 'STARTED', 'pid': child.pid, 'packet': str(OUT)}), flush=True)
            code = child.wait()
        cleanup_attempted = True
        cleanup_actions, remaining = cleanup(child)
        if remaining:
            raise RuntimeError('post validation withheld while owned group remains')
        post = seal()
        lifecycle = Lifecycle(expected)
        for index, line in enumerate((OUT / 'stdout.jsonl').read_text().splitlines(), 1):
            try:
                value = event(line, expected)
                lifecycle.feed(value)
                events.append(value)
            except (ValueError, TypeError, KeyError, OverflowError) as exc:
                malformed.append({'line': index, 'error': str(exc)})
        run = collections.Counter((item['Package'], item['Test']) for item in events if item['Action'] == 'run')
        passed = collections.Counter((item['Package'], item['Test']) for item in events if item['Action'] == 'pass' and item.get('Test'))
        packages = collections.Counter(item['Package'] for item in events if item['Action'] == 'pass' and not item.get('Test'))
        starts = collections.Counter(item['Package'] for item in events if item['Action'] == 'start')
        bad = [item for item in events if item['Action'] in {'fail', 'skip', 'build-fail', 'build-output'}]
    except BaseException as exc:
        errors.append({'stage': 'launch_or_postrun_validation', 'error': repr(exc)})
    finally:
        for sig in old_handlers:
            signal.signal(sig, signal.SIG_IGN)
        if child is not None:
            try:
                if not cleanup_attempted:
                    cleanup_actions, remaining = cleanup(child)
                remaining = owned_group(child)
            except BaseException as exc:
                errors.append({'stage': 'child_cleanup', 'error': repr(exc)})
                remaining = owned_group(child)
            if code is None:
                code = child.poll()
        cleanup_facts = {'pid': child.pid if child else None, 'actions': cleanup_actions,
                         'remaining_group_processes': remaining, 'gate_held': True}
        try:
            write('cleanup.json', cleanup_facts)
        except BaseException as exc:
            errors.append({'stage': 'cleanup_evidence_write', 'error': repr(exc)})
        if remaining:
            errors.append({'stage': 'cleanup', 'error': 'owned group remains after bounded TERM/KILL; gate retained until actual absence'})
            pending = {'state': 'FAILED_CLEANUP_PENDING', 'errors': errors, 'cleanup': cleanup_facts}
            try:
                write('receipt-cleanup-pending.json', pending)
            except BaseException:
                pass
            print(json.dumps(pending), flush=True)
            # Never release the execution lease while an owned child remains.
            # Signals stay ignored; the completed test operation is never retried.
            while remaining:
                child.poll()
                time.sleep(.05)
                remaining = owned_group(child)
        if child is not None:
            remaining = owned_group(child)
        logs = {}
        for name in ('stdout.jsonl', 'stderr.log'):
            try:
                logs[name] = sha(OUT / name)
            except BaseException as exc:
                errors.append({'stage': 'log_hash', 'path': name, 'error': repr(exc)})
        success = code == 0 and not errors and pre is not None and pre == post and not remaining and not malformed and not bad and run == passed == expected and starts == packages == collections.Counter(R['expected_packages'].keys())
        receipt = {'state': 'PASS' if success else 'NOT_QUALIFIED', 'exit_code': code, 'errors': errors,
                   'wall_seconds': time.monotonic() - started, 'source_pre': pre, 'source_post': post,
                   'expected_outcomes': sum(expected.values()), 'run_count': sum(run.values()), 'pass_count': sum(passed.values()),
                   'package_passes': dict(packages), 'package_starts': dict(starts), 'bad': bad, 'malformed': malformed,
                   'remaining_group_processes': remaining, 'cleanup_actions': cleanup_actions, 'gate_held_at_receipt': True,
                   'logs': logs, 'max_child_rss_kib': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}
        try:
            write('receipt.json', receipt)
        except BaseException as exc:
            success = False
            receipt['state'] = 'NOT_QUALIFIED'
            receipt['errors'].append({'stage': 'receipt_write', 'error': repr(exc)})
            try:
                write('receipt-write-failure.json', receipt)
            except BaseException:
                pass
        print(json.dumps(receipt), flush=True)
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
raise SystemExit(0 if success else 1)
