import collections
import fcntl
import hashlib
import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import time

OUT = pathlib.Path(__file__).parent
REQUEST = json.loads((OUT / 'request.json').read_text())
SOURCE = pathlib.Path(REQUEST['worktree'])
GO = '/home/mariogk/.local/share/mise/installs/go/1.27.1/bin/go'
GOFMT = '/home/mariogk/.local/share/mise/installs/go/1.27.1/bin/gofmt'
GIT = '/run/current-system/sw/bin/git'
ENV = REQUEST['environment']
LOCK = '/tmp/ts-orch-refactor-short-check-a.lock'
PACKAGE = 'github.com/TerraScale/ts-orchestrator/internal/ociclient'
sha = lambda value: hashlib.sha256(value).hexdigest()
result = {'head': REQUEST['head'], 'tree': REQUEST['tree'], 'source': str(SOURCE), 'env': ENV, 'uid': os.getuid(), 'lock': LOCK, 'steps': [], 'runtime_executed': False, 'request_sha256': sha((OUT / 'request.json').read_bytes()), 'runner_sha256': sha(pathlib.Path(__file__).read_bytes())}
lock_fd = None
lock_held = False
with (OUT / 'attempt.json').open('x') as attempt:
    json.dump({'runner_pid': os.getpid(), 'head': REQUEST['head'], 'time_unix': time.time()}, attempt)

def git(*args):
    return subprocess.check_output([GIT, '-C', str(SOURCE), *args], env=ENV)

def source_state():
    assert git('rev-parse', 'HEAD').decode().strip() == REQUEST['head']
    assert git('rev-parse', 'HEAD^{tree}').decode().strip() == REQUEST['tree']
    assert git('status', '--porcelain=v1') == b''
    assert sha((SOURCE / REQUEST['file_claim']).read_bytes()) == REQUEST['source_sha256']
    seal = hashlib.sha256()
    paths = git('ls-files', '-z').split(b'\0')[:-1]
    for raw in paths:
        path = SOURCE / os.fsdecode(raw)
        mode = stat.S_IMODE(path.lstat().st_mode)
        data = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        seal.update(raw + b'\0' + str(mode).encode() + b'\0' + sha(data).encode() + b'\n')
    return {'head': REQUEST['head'], 'tree': REQUEST['tree'], 'status': '', 'tracked_paths': len(paths), 'all_tracked_path_mode_sha256_seal': seal.hexdigest(), 'new_file_sha256': REQUEST['source_sha256']}

def group_alive(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False

def stage(name, argv):
    log = OUT / (name + '.log')
    started = time.monotonic()
    print(json.dumps({'stage': name, 'argv': argv, 'log': str(log)}), flush=True)
    with log.open('xb') as stream:
        process = subprocess.Popen(argv, cwd=SOURCE, env=ENV, stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        code = process.wait()
    remaining_group = group_alive(process.pid)
    if remaining_group:
        os.killpg(process.pid, signal.SIGTERM)
        deadline = time.monotonic() + 5
        while group_alive(process.pid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if group_alive(process.pid):
            os.killpg(process.pid, signal.SIGKILL)
    clean = not group_alive(process.pid)
    row = {'name': name, 'argv': argv, 'pid': process.pid, 'exit_code': code, 'elapsed_seconds': time.monotonic() - started, 'log': str(log), 'log_sha256': sha(log.read_bytes()), 'process_group_absent': clean, 'unexpected_descendants_observed': remaining_group}
    result['steps'].append(row)
    print(json.dumps(row), flush=True)
    assert code == 0 and clean and not remaining_group, row
    return log

try:
    assert os.getuid() == 1000
    assert set(ENV) == {'HOME', 'PATH', 'LANG', 'GOMAXPROCS', 'GOFLAGS', 'GOTOOLCHAIN'}
    assert ENV['GOMAXPROCS'] == '2' and ENV['GOFLAGS'] == '-p=2' and ENV['GOTOOLCHAIN'] == 'local'
    lock_fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    lock_held = True
    memory = dict(line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    available = int(memory['MemAvailable'].split()[0]) * 1024
    load1 = os.getloadavg()[0]
    active = []
    for path in pathlib.Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            executable = (path / 'exe').resolve(strict=True)
            args = (path / 'cmdline').read_bytes().split(b'\0')
            if executable.name in {'compile', 'link'} or (str(executable) == GO and len(args) > 1 and args[1] in {b'test', b'build', b'install'}):
                active.append({'pid': int(path.name), 'tool': executable.name})
        except (OSError, PermissionError):
            pass
    result['admission'] = {'available_bytes': available, 'load1': load1, 'existing_compiler_processes': active, 'ram_minimum_bytes': 16 * 1024**3, 'load1_maximum_exclusive': 12, 'compiler_cap': 4}
    assert available >= 16 * 1024**3 and load1 < 12 and len(active) < 4
    result['source_before'] = source_state()
    print(json.dumps({'admitted': result['admission'], 'source_before': result['source_before'], 'runner_pid': os.getpid()}), flush=True)
    fmt_log = stage('gofmt', ['nice', '-n', '19', GOFMT, '-d', REQUEST['file_claim']])
    assert fmt_log.read_bytes() == b''
    binary = OUT / 'ociclient.test'
    stage('compile', ['nice', '-n', '19', 'timeout', '--signal=TERM', '--kill-after=5s', '240s', GO, 'test', '-c', '-mod=readonly', '-p=1', '-o', str(binary), './internal/ociclient'])
    binary.chmod(0o600)
    assert binary.is_file() and not binary.is_symlink() and binary.read_bytes().startswith(b'\x7fELF')
    result['binary'] = {'path': str(binary), 'mode': '0600', 'bytes': binary.stat().st_size, 'sha256': sha(binary.read_bytes()), 'never_executed': True}
    result['source_after_compile'] = source_state()
    assert result['source_after_compile'] == result['source_before']
    runtime_argv = ['nice', '-n', '19', 'timeout', '--signal=TERM', '--kill-after=5s', '120s', GO, *REQUEST['runtime']['argv'][1:]]
    result['runtime_executed'] = True
    runtime_log = stage('runtime', runtime_argv)
    events = [json.loads(line) for line in runtime_log.read_text().splitlines() if line.strip()]
    expected = set(REQUEST['runtime']['expected_named_pass'])
    passed = [row['Test'] for row in events if row.get('Action') == 'pass' and row.get('Test')]
    runs = [row['Test'] for row in events if row.get('Action') == 'run']
    package_passes = [row for row in events if row.get('Action') == 'pass' and not row.get('Test')]
    assert len(expected) == len(passed) == len(runs) == 12
    assert set(passed) == set(runs) == expected
    assert len(package_passes) == 1 and package_passes[0]['Package'] == PACKAGE
    assert all(row.get('Package') == PACKAGE and (not row.get('Test') or row['Test'] in expected) for row in events)
    assert not any(row.get('Action') in {'fail', 'skip'} for row in events)
    result['runtime'] = {'named_pass': passed, 'package_pass': package_passes[0], 'fail': 0, 'skip': 0, 'extra_missing_duplicate_test_identities': 0, 'raw_events': len(events), 'scope': REQUEST['runtime']['scope'], 'signature_presence_only': True, 'direct_Factory_HomeRegion_invocation': False}
    result['source_after'] = source_state()
    assert result['source_after'] == result['source_before']
    result['state'] = 'PASS_EXACT_FA44_FORMAT_DEFAULT_VET_TRUECOMPILE_AND_THREE_SELECTED_TLS_BOUNDARY_ROOTS'
except BaseException as error:
    result['state'] = 'FAILED_OR_NOT_ADMITTED_NO_RETRY'
    result['error'] = repr(error)
    try:
        result['source_after'] = source_state()
    except BaseException as source_error:
        result['source_after_error'] = repr(source_error)
finally:
    if lock_held:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    if lock_fd is not None:
        os.close(lock_fd)
    result['lock_released'] = lock_held
    with (OUT / 'result.json').open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'result': str(OUT / 'result.json'), 'state': result['state'], 'lock_released': result['lock_released']}), flush=True)
sys.exit(0 if result['state'].startswith('PASS_') else 1)
