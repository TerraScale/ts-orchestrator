"""One authorized invocation; preserve all output and stop after its terminal."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import hashlib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dispatch', required=True)
    parser.add_argument('--dispatch-sha256', required=True)
    args = parser.parse_args()
    dispatch = Path(args.dispatch)
    if hashlib.sha256(dispatch.read_bytes()).hexdigest() != args.dispatch_sha256:
        raise ValueError('Dispatch hash differs')
    plan = json.loads(dispatch.read_text())
    recorder = Path(plan['root']) / 'recorder.py'
    if hashlib.sha256(recorder.read_bytes()).hexdigest() != plan['scripts'][str(recorder)]:
        raise ValueError('Recorder source differs')
    spec = importlib.util.spec_from_file_location('fifo06_recorder', recorder)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    plan = module.load(args.dispatch, args.dispatch_sha256)
    out = plan['outputs']
    module.require(not any(Path(path).exists() or Path(path).is_symlink() for path in out.values()),
                   'Existing output: preserve it; never repeat this dispatch')
    cmdline = [plan['python'], '-I', '-B', str(Path(plan['root']) / 'run-once.py'),
               '--dispatch', args.dispatch, '--dispatch-sha256', args.dispatch_sha256]
    before = module.snapshot(plan, args.dispatch_sha256, cmdline)
    module.require(not before['errors'], '\n'.join(before['errors']))
    module.write_once(out['before'], before)
    launch = {'argv': plan['argv'], 'environment': plan['environment'], 'cwd': plan['cwd'],
              'dispatch_sha256': args.dispatch_sha256, 'before_sha256': module.digest(out['before'])}
    child_returncode, child_pid, wrapper_exit, errors = None, None, 125, []
    started = time.monotonic()
    try:
        with Path(out['raw']).open('xb') as raw:
            module.write_once(out['launch'], launch)
            child = subprocess.Popen(launch['argv'], cwd=launch['cwd'], env=launch['environment'],
                                     stdout=raw, stderr=subprocess.STDOUT, start_new_session=True)
            child_pid = child.pid
            child_returncode = child.wait()
            wrapper_exit = child_returncode if child_returncode >= 0 else 128 - child_returncode
            raw.flush()
            os.fsync(raw.fileno())
    except OSError as error:
        errors.append('Child launch/capture error: ' + str(error))
    after = module.snapshot(plan, args.dispatch_sha256, cmdline)
    errors.extend(after['errors'])
    if before != after:
        errors.append('Wrapper pre/post bindings differ')
    result = module.summarize(plan)
    errors.extend(result['errors'])
    if errors:
        wrapper_exit = 125
    terminal = {'dispatch_sha256': args.dispatch_sha256, 'child_pid': child_pid,
                'child_returncode': child_returncode, 'wrapper_exit': wrapper_exit,
                'elapsed_seconds': time.monotonic() - started, 'after': after,
                'result': result, 'errors': errors,
                **{key + '_sha256': module.digest(out[key]) if Path(out[key]).is_file() else None
                   for key in ('before', 'launch', 'raw')}}
    module.write_once(out['terminal'], terminal)
    print(json.dumps({key: terminal[key] for key in ('child_pid', 'child_returncode', 'wrapper_exit',
                                                   'elapsed_seconds', 'errors')}), flush=True)
    return wrapper_exit


if __name__ == '__main__':
    sys.exit(main())
