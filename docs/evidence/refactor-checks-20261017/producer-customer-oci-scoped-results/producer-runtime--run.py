import collections
import fcntl
import hashlib
import json
import os
import pathlib
import resource
import subprocess
import time

OUT = pathlib.Path(__file__).resolve().parent
REQUEST = pathlib.Path('/tmp/ts-foundation-producer-8f3-clean-source-t755eark/request.json')
EXPECTED_REQUEST_SHA = 'c9bbb1e119927330391b0443573428d5578a4d976e5281cc1b2363052e02a5e2'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def write(name, value):
    with (OUT / name).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')

raw = REQUEST.read_bytes()
assert sha(raw) == EXPECTED_REQUEST_SHA, 'request changed'
request = json.loads(raw)
ENV = request['request']['environment']
assert dict(os.environ) == ENV and len(ENV) == 6, 'wrapper requires exact six-key clean environment'
w = pathlib.Path(request['worktree'])

def git(*args):
    return subprocess.check_output([request['tools']['git']['path'], '-C', str(w), *args], env=ENV)

def snapshot():
    tracked = git('ls-files', '-z').decode().split('\0')[:-1]
    manifest = []
    for rel in tracked:
        path = w / rel
        manifest.append({'path': rel, 'mode': oct(path.lstat().st_mode & 0o177777),
                         'kind': 'symlink' if path.is_symlink() else 'file',
                         'sha256': sha(path.readlink().as_posix().encode() if path.is_symlink() else path.read_bytes())})
    manifest_raw = (json.dumps(manifest, indent=2) + '\n').encode()
    return {'head': git('rev-parse', 'HEAD').decode().strip(),
            'tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
            'status': git('status', '--porcelain=v1', '--untracked-files=all').decode(),
            'tracked_count': len(manifest), 'tracked_source_manifest_sha256': sha(manifest_raw),
            'request_sha256': sha(REQUEST.read_bytes()), 'wrapper_sha256': sha(pathlib.Path(__file__).read_bytes()),
            'tools': {name: {'path': item['path'], 'realpath': str(pathlib.Path(item['path']).resolve()),
                             'sha256': sha(pathlib.Path(item['path']).read_bytes())}
                      for name, item in request['tools'].items()},
            'audit_sha256': {path: sha(pathlib.Path(path).read_bytes()) for path in request['audit_files']}}, manifest

def validate(snapshot):
    assert snapshot['head'] == request['commit'] and snapshot['tree'] == request['tree'], 'commit/tree changed'
    assert not snapshot['status'], 'worktree not clean'
    assert snapshot['tracked_count'] == request['tracked_count'], 'tracked set changed'
    assert snapshot['tracked_source_manifest_sha256'] == request['tracked_source_manifest_sha256'], 'tracked source changed'
    assert snapshot['request_sha256'] == EXPECTED_REQUEST_SHA, 'request changed'
    assert snapshot['tools'] == request['tools'], 'executable identity changed'
    assert snapshot['audit_sha256'] == request['audit_files'], 'audit changed'
    assert sha(pathlib.Path(request['tracked_source_manifest']).read_bytes()) == request['tracked_source_manifest_sha256'], 'pinned manifest changed'

def seal():
    with (OUT / 'SHA256SUMS').open('x') as stream:
        for path in sorted(OUT.iterdir()):
            if path.is_file() and path.name != 'SHA256SUMS':
                stream.write(sha(path.read_bytes()) + '  ' + path.name + '\n')

pre, pre_manifest = snapshot()
validate(pre)
write('preflight.json', {'source': pre, 'argv': request['request']['argv'], 'cwd': str(w),
                         'effective_child_environment': ENV, 'GOROOT_present': False,
                         'lease_requirement': 'Parent must have explicit QA grant before launching this wrapper.'})
write('tracked-source-pre.json', pre_manifest)
with open(request['request']['shared_lock'], 'a') as gate:
    try:
        fcntl.flock(gate, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        write('receipt.json', {'state': 'LOCK_BUSY_NOT_LAUNCHED', 'source': pre, 'attempts': 0})
        seal()
        raise SystemExit(75)
    # Repeat verification while holding the gate, immediately before the only launch.
    locked, _ = snapshot()
    validate(locked)
    assert pre == locked, 'source changed before launch'
    started = time.time()
    clock = time.monotonic()
    with (OUT / 'stdout.jsonl').open('xb') as stdout, (OUT / 'stderr.log').open('xb') as stderr:
        proc = subprocess.Popen(request['request']['argv'], cwd=w, env=ENV, stdout=stdout,
                                stderr=stderr, start_new_session=True)
        write('started.json', {'pid': proc.pid, 'epoch': started, 'argv': request['request']['argv']})
        print(json.dumps({'state': 'STARTED', 'pid': proc.pid, 'output': str(OUT)}), flush=True)
        returncode = proc.wait()
    elapsed = time.monotonic() - clock
    post, post_manifest = snapshot()
    write('tracked-source-post.json', post_manifest)
    actions, packages, malformed = [], [], []
    for number, line in enumerate((OUT / 'stdout.jsonl').read_text().splitlines(), 1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            malformed.append({'line': number, 'text': line})
            continue
        if event.get('Action') in ('pass', 'fail', 'skip'):
            if event.get('Test'):
                actions.append({key: event[key] for key in ('Package', 'Test', 'Action', 'Elapsed') if key in event})
            else:
                packages.append(event)
    counts = collections.Counter(item['Test'] for item in actions if item['Action'] == 'pass')
    expected = request['expected_pass_tests']
    success = (returncode == 0 and pre == post and not malformed and len(actions) == 17
               and counts == collections.Counter(expected) and all(item['Action'] == 'pass' for item in actions)
               and all(item['Package'] == request['expected_package'] for item in actions)
               and len(packages) == 1 and packages[0].get('Action') == 'pass'
               and packages[0].get('Package') == request['expected_package'])
    receipt = {'state': 'PASS' if success else 'NOT_QUALIFIED', 'exit_code': returncode, 'attempts': 1,
               'wall_seconds': elapsed, 'max_child_rss_kib': resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
               'source_pre': pre, 'source_post': post, 'expected_tests': expected, 'test_outcomes': actions,
               'package_outcomes': packages, 'malformed_output': malformed,
               'stdout_sha256': sha((OUT / 'stdout.jsonl').read_bytes()),
               'stderr_sha256': sha((OUT / 'stderr.log').read_bytes()),
               'scope': 'One default-vet/default-tag three-root attempt; no retirement/global/live provisioning credit.'}
    write('receipt.json', receipt)
    seal()
    print(json.dumps(receipt), flush=True)
    fcntl.flock(gate, fcntl.LOCK_UN)
raise SystemExit(0 if success else 1)
