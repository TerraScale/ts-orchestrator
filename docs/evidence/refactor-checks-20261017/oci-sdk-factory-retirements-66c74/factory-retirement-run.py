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
ENV = REQUEST['environment']
GO = '/home/mariogk/.local/share/mise/installs/go/1.27.1/bin/go'
GIT = '/run/current-system/sw/bin/git'
sha = lambda data: hashlib.sha256(data).hexdigest()
result = {'head': REQUEST['head'], 'tree': REQUEST['tree'], 'source': str(SOURCE), 'env': ENV, 'uid': os.getuid(), 'lock': REQUEST['lock'], 'request_sha256': sha((OUT / 'request.json').read_bytes()), 'runner_sha256': sha(pathlib.Path(__file__).read_bytes()), 'runtime_executed': False}
with (OUT / 'attempt.json').open('x') as target:
    json.dump({'runner_pid': os.getpid(), 'head': REQUEST['head'], 'time_unix': time.time()}, target)
lock_fd = None
locked = False

def git(*args):
    return subprocess.check_output([GIT, '-C', str(SOURCE), *args], env=ENV)

def source_state():
    assert git('rev-parse', 'HEAD').decode().strip() == REQUEST['head']
    assert git('rev-parse', 'HEAD^{tree}').decode().strip() == REQUEST['tree']
    assert git('status', '--porcelain=v1') == b''
    assert sha(pathlib.Path(REQUEST['source_proof']).read_bytes()) == REQUEST['source_proof_sha256']
    paths = git('ls-files', '-z').split(b'\0')[:-1]
    digest = hashlib.sha256()
    for raw in paths:
        path = SOURCE / os.fsdecode(raw)
        mode = stat.S_IMODE(path.lstat().st_mode)
        data = os.fsencode(os.readlink(path)) if path.is_symlink() else path.read_bytes()
        digest.update(raw + b'\0' + str(mode).encode() + b'\0' + sha(data).encode() + b'\n')
    return {'head': REQUEST['head'], 'tree': REQUEST['tree'], 'status': '', 'tracked_paths': len(paths), 'all_tracked_path_mode_sha256_seal': digest.hexdigest(), 'source_proof_sha256': REQUEST['source_proof_sha256']}

def group_alive(pid):
    try:
        os.killpg(pid, 0)
        return True
    except ProcessLookupError:
        return False

try:
    assert REQUEST['head'] == 'c0a7945b717771b953e6392a4afe2cc9d699d343'
    assert REQUEST['tree'] == '5f6566d5347525dedce8408b34e9232458421ed4'
    assert os.getuid() == 1000
    assert set(ENV) == {'HOME', 'PATH', 'LANG', 'GOMAXPROCS', 'GOFLAGS', 'GOTOOLCHAIN'}
    assert ENV['GOMAXPROCS'] == '2' and ENV['GOFLAGS'] == '-p=2' and ENV['GOTOOLCHAIN'] == 'local'
    assert REQUEST['lock'] == '/tmp/ts-orch-refactor-capacity-check.lock'
    lock_fd = os.open(REQUEST['lock'], os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    locked = True
    memory = dict(line.split(':', 1) for line in pathlib.Path('/proc/meminfo').read_text().splitlines())
    available = int(memory['MemAvailable'].split()[0]) * 1024
    load1 = os.getloadavg()[0]
    drivers, compiler_tools = [], []
    for path in pathlib.Path('/proc').iterdir():
        if not path.name.isdecimal():
            continue
        try:
            executable = (path / 'exe').resolve(strict=True)
            args = (path / 'cmdline').read_bytes().split(b'\0')
            if executable.name in {'compile', 'link'}:
                compiler_tools.append({'pid': int(path.name), 'tool': executable.name})
            if str(executable) == GO and len(args) > 1 and args[1] in {b'test', b'build', b'install'}:
                drivers.append(int(path.name))
        except OSError:
            pass
    result['admission'] = {'available_bytes': available, 'load1': load1, 'existing_go_compiler_flows': drivers, 'existing_compiler_tools': compiler_tools, 'ram_minimum_bytes': 16 * 1024**3, 'load1_maximum_exclusive': 12, 'maximum_compiler_flows_including_this': 4}
    assert available >= 16 * 1024**3 and load1 < 12 and len(drivers) < 4
    result['source_before'] = source_state()
    print(json.dumps({'runner_pid': os.getpid(), 'admission': result['admission'], 'source_before': result['source_before']}), flush=True)
    binary = OUT / 'ociclient.test'
    log = OUT / 'compile.log'
    argv = ['nice', '-n', '19', 'timeout', '--signal=TERM', '--kill-after=5s', '240s', GO, 'test', '-c', '-mod=readonly', '-p=1', '-o', str(binary), './internal/ociclient']
    started = time.monotonic()
    print(json.dumps({'stage': 'truecompile_only', 'argv': argv, 'log': str(log)}), flush=True)
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
    result['compile'] = {'argv': argv, 'pid': process.pid, 'exit_code': code, 'elapsed_seconds': time.monotonic() - started, 'log': str(log), 'log_sha256': sha(log.read_bytes()), 'process_group_absent': not group_alive(process.pid), 'unexpected_descendants_observed': remaining_group, 'default_vet': True, 'default_tags': True}
    if binary.exists():
        binary.chmod(0o600)
    assert code == 0 and not group_alive(process.pid) and not remaining_group
    assert binary.is_file() and not binary.is_symlink() and binary.read_bytes().startswith(b'\x7fELF')
    assert stat.S_IMODE(binary.stat().st_mode) == 0o600
    result['binary'] = {'path': str(binary), 'mode': '0600', 'bytes': binary.stat().st_size, 'sha256': sha(binary.read_bytes()), 'never_executed': True}
    result['source_after'] = source_state()
    assert result['source_after'] == result['source_before']
    result['state'] = 'PASS_EXACT_C0A_DEFAULT_VET_DEFAULT_TAG_TRUECOMPILE_ONLY'
except BaseException as error:
    result['state'] = 'FAILED_OR_NOT_ADMITTED_NO_RETRY'
    result['error'] = repr(error)
    try:
        result['source_after'] = source_state()
    except BaseException as source_error:
        result['source_after_error'] = repr(source_error)
finally:
    if locked:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
    if lock_fd is not None:
        os.close(lock_fd)
    result['lock_released'] = locked
    with (OUT / 'result.json').open('x') as stream:
        json.dump(result, stream, indent=2)
        stream.write('\n')
    print(json.dumps({'result': str(OUT / 'result.json'), 'state': result['state'], 'lock_released': result['lock_released']}), flush=True)
sys.exit(0 if result['state'].startswith('PASS_') else 1)
