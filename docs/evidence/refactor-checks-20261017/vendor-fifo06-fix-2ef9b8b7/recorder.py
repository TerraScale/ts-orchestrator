"""Metadata validation and receipt recording; never starts Go."""
import argparse
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate JSON key: ' + key)
        result[key] = value
    return result


def invalid(value):
    raise ValueError('Nonfinite JSON value: ' + value)


def finite(value):
    result = float(value)
    require(math.isfinite(result), 'Nonfinite JSON number')
    return result


def parse(value):
    return json.loads(value, object_pairs_hook=unique, parse_constant=invalid, parse_float=finite)


def read(path):
    return parse(Path(path).read_text())


def write_once(path, value):
    with Path(path).open('x') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def inventory(root):
    result = {}
    for path in sorted(Path(root).rglob('*')):
        kind = 'symlink:' + os.readlink(path) if path.is_symlink() else 'directory' if path.is_dir() else 'file'
        result[str(path.relative_to(root))] = kind
    return result


def load(path, sha):
    require(digest(path) == sha, 'Dispatch hash changed')
    plan = read(path)
    require(Path(path) == Path(plan['root']) / 'dispatch.json', 'Unexpected dispatch location')
    require(plan['stop_after_terminal'] and not plan['automatic_advance'], 'Stop policy changed')
    require(digest(plan['request']) == plan['request_sha256'], 'Request hash changed')
    request = read(plan['request'])
    for key in ('revision', 'tree', 'worktree', 'cwd', 'argv', 'environment'):
        require(plan[key] == request[key], 'Request binding changed: ' + key)
    require(len(plan['expected_tests']) == 9 and len(set(plan['expected_tests'])) == 9,
            'Expected identity set changed')
    return plan


def snapshot(plan, sha, expected_cmdline):
    errors = []
    def hashed(bindings):
        actual = {}
        for path, expected in bindings.items():
            try:
                actual[path] = digest(path)
            except OSError as error:
                actual[path] = {'error': str(error)}
            if actual[path] != expected:
                errors.append('Hash changed: ' + path)
        return actual
    state = {}
    for key, args in [('revision', ['rev-parse', 'HEAD']), ('tree', ['rev-parse', 'HEAD^{tree}']),
                      ('status', ['status', '--porcelain=v1', '--untracked-files=all'])]:
        try:
            state[key] = subprocess.check_output([plan['git'], '--no-optional-locks', '-c', 'core.fsmonitor=false', '-C',
                        plan['worktree'], *args], env=plan['environment'], text=True,
                        stderr=subprocess.PIPE, timeout=15).strip()
        except (OSError, subprocess.SubprocessError) as error:
            state[key] = {'error': str(error)}
    if state != {'revision': plan['revision'], 'tree': plan['tree'], 'status': ''}:
        errors.append('Source identity/clean status changed')
    trees = {}
    for root, expected in plan['tree_inventories'].items():
        try:
            trees[root] = inventory(root)
        except OSError as error:
            trees[root] = {'error': str(error)}
        if trees[root] != expected:
            errors.append('Input tree membership/type/symlink changed: ' + root)
    source = {'git': state, 'trees': trees, 'bindings': hashed(plan['bindings']), 'scripts': hashed(plan['scripts']),
              'dispatch': hashed({str(Path(plan['root']) / 'dispatch.json'): sha})}
    environment_ok = dict(os.environ) == plan['environment']
    context = {'cwd': os.getcwd(),
               'environment': dict(os.environ) if environment_ok else {'error': 'Unexpected environment'},
               'cmdline': Path('/proc/self/cmdline').read_bytes().rstrip(b'\0').decode().split('\0'),
               'interpreter': str(Path('/proc/self/exe').resolve()),
               'niceness': os.getpriority(os.PRIO_PROCESS, 0)}
    if not environment_ok:
        errors.append('Complete environment allowlist differs')
    for key, expected in [('cwd', plan['cwd']), ('cmdline', expected_cmdline),
                          ('interpreter', plan['python']), ('niceness', 19)]:
        if context[key] != expected:
            errors.append('Context differs: ' + key)
    return {'source': source, 'context': context, 'errors': errors}


def summarize(plan):
    events, errors = [], []
    try:
        raw = Path(plan['outputs']['raw']).read_bytes()
        require(raw and raw.endswith(b'\n'), 'Raw JSONL empty or truncated')
        for number, line in enumerate(raw.decode().splitlines(), 1):
            try:
                event = parse(line)
                require(isinstance(event, dict), 'Event is not an object')
                events.append(event)
            except ValueError as error:
                errors.append(f'Line {number}: {error}')
    except (OSError, UnicodeError, ValueError) as error:
        errors.append(str(error))
    expected, runs, terminals = set(plan['expected_tests']), {}, {}
    starts, package_terminal, outputs = 0, [], []
    for number, event in enumerate(events, 1):
        action, test = event.get('Action'), event.get('Test')
        if event.get('Package') != plan['package']:
            errors.append(f'Event {number}: unexpected package')
        if test is not None and test not in expected:
            errors.append(f'Event {number}: unexpected test {test!r}')
        if action not in ('start', 'run', 'output', 'pass', 'fail'):
            errors.append(f'Event {number}: forbidden action {action!r}')
        if package_terminal:
            errors.append(f'Event {number}: event after package terminal')
        if action == 'start':
            starts += 1
            if number != 1 or test is not None:
                errors.append('Invalid package start')
        elif starts != 1:
            errors.append('Missing/duplicate package start')
        if action == 'run':
            runs[test] = runs.get(test, 0) + 1
            if test in terminals or test not in expected:
                errors.append('Invalid test run')
        if action == 'output':
            if not isinstance(event.get('Output'), str):
                errors.append('Invalid output')
            else:
                outputs.append(event['Output'])
            if test is not None and (runs.get(test) != 1 or test in terminals):
                errors.append('Test output outside its execution')
        if action in ('pass', 'fail'):
            elapsed = event.get('Elapsed')
            if type(elapsed) not in (int, float) or elapsed < 0:
                errors.append('Invalid elapsed')
            if test is None:
                package_terminal.append(action)
            else:
                if test in terminals or runs.get(test) != 1:
                    errors.append('Invalid test terminal')
                terminals[test] = action
    if starts != 1 or runs != {name: 1 for name in expected} or set(terminals) != expected:
        errors.append('Expected exactly nine test identities, each once')
    if len(package_terminal) != 1:
        errors.append('Expected exactly one package terminal')
    passed = not errors and all(value == 'pass' for value in terminals.values()) and package_terminal == ['pass']
    if not errors and not passed and package_terminal != ['fail']:
        errors.append('Package/test outcome disagreement')
    return {'scope_ok': not errors, 'passed': passed, 'runs': runs, 'terminals': terminals,
            'package_terminal': package_terminal, 'event_count': len(events),
            'race_report': any('WARNING: DATA RACE' in value for value in outputs), 'errors': errors}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dispatch', required=True)
    parser.add_argument('--dispatch-sha256', required=True)
    parser.add_argument('--session', required=True, type=int)
    parser.add_argument('--exit-code', required=True, type=int)
    args = parser.parse_args()
    plan = load(args.dispatch, args.dispatch_sha256)
    out = plan['outputs']
    expected_cmdline = [plan['python'], '-I', '-B', str(Path(plan['root']) / 'recorder.py'),
                        '--dispatch', args.dispatch, '--dispatch-sha256', args.dispatch_sha256,
                        '--session', str(args.session), '--exit-code', str(args.exit_code)]
    after = snapshot(plan, args.dispatch_sha256, expected_cmdline)
    before, launch, terminal = [read(out[key]) for key in ('before', 'launch', 'terminal')]
    errors = after['errors'] + before['errors'] + terminal['errors']
    if before['source'] != after['source'] or before != terminal['after']:
        errors.append('Pre/post source or wrapper bindings differ')
    expected_launch = {'argv': plan['argv'], 'environment': plan['environment'], 'cwd': plan['cwd'],
                       'dispatch_sha256': args.dispatch_sha256, 'before_sha256': digest(out['before'])}
    if launch != expected_launch:
        errors.append('Actual launch differs')
    for key in ('before', 'launch', 'raw'):
        if terminal.get(key + '_sha256') != digest(out[key]):
            errors.append('Terminal hash mismatch: ' + key)
    if terminal['child_returncode'] != args.exit_code or terminal['wrapper_exit'] != args.exit_code:
        errors.append('Broker/child/wrapper exit mismatch')
    result = summarize(plan)
    if result != terminal['result']:
        errors.append('Parsed raw result changed')
    released = False
    try:
        with Path(plan['lock']).open('r') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            released = True
            fcntl.flock(lock, fcntl.LOCK_UN)
    except OSError as error:
        errors.append('Lane release unverified: ' + str(error))
    receipt = {'revision': plan['revision'], 'tree': plan['tree'], 'dispatch': args.dispatch,
               'dispatch_sha256': args.dispatch_sha256, 'session': args.session, 'exit': args.exit_code,
               'after': after, 'result': result, 'errors': errors, 'released': released,
               'scoped_pass': args.exit_code == 0 and not errors and result['passed'],
               'evidence': {key: {'path': out[key], 'sha256': digest(out[key])}
                            for key in ('before', 'launch', 'raw', 'terminal')},
               'original_failure': 'RETAINED_FAIL_OPEN', 'closed_rows': 0,
               'automatic_advance': False, 'stop_required': True,
               'qualification': plan['qualification']}
    write_once(out['receipt'], receipt)
    print(json.dumps({key: receipt[key] for key in ('session', 'exit', 'scoped_pass', 'released', 'errors')}))


if __name__ == '__main__':
    main()
