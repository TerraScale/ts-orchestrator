#!/usr/bin/env python3
"""Slow only: five real 60-second watches at both cold-maintenance barriers.

Run via ts-heavy-any. Private PID/mount namespaces isolate real proc scans; task
filesystem observations are real, runtime API replies use contract fixtures.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch
import cold


def child(phase):
    os.umask(0o077)
    assert os.geteuid() == 0
    signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("qualification hard bound")))
    signal.alarm(72)
    with tempfile.TemporaryDirectory(prefix='zdt-watch-') as tmp:
        root = Path(tmp)
        tasks = root / 'tasks'; tasks.mkdir(); (tasks / 'namespace').mkdir()
        engine_dir = tasks / 'namespace/engine-task'; engine_dir.mkdir()
        baseline = root / 'baseline.json'
        stopped_engine = {'namespace/engine-task': {'pid': 0, 'identity': None, 'status': 'STOPPED', 'engine': True}}
        with patch.object(cold, 'TASK_ROOT', tasks), patch.object(cold, 'RUNTIME_SOCKET', str(root / 'missing.sock')), patch.object(cold, 'runtime_tasks', return_value=stopped_engine):
            cold.watch_baseline(SimpleNamespace(receipt=str(baseline)))
            args = SimpleNamespace(baseline=str(baseline), receipt=str(root / 'watch.json'), barrier=phase, runtime_down=phase == 'stopped')
            assert cold.engine_args(['/app/terrabase'])
            assert cold.engine_args(['dotnet', '/app/TerraBase.dll'])
            assert not cold.engine_args(['python3', '/tmp/terrabase', 'terrabase'])
            assert not cold.engine_args(['/bin/sh', '-c', 'echo terrabase'])
            # A new real host process appears after the first successful sample.
            launched = []
            def appear():
                launched.append(subprocess.Popen(['terrabase', '-c', 'import time; time.sleep(30)'], executable=sys.executable))
            timer = threading.Timer(0.3, appear); timer.start()
            args.receipt = str(root / 'engine-appeared.json')
            try:
                try: cold.no_reappearance(args)
                except RuntimeError: pass
                else: raise AssertionError('new engine was accepted')
                assert json.loads(Path(args.receipt).read_text())['abort'] is True
            finally:
                timer.join()
                for proc in launched:
                    proc.kill(); proc.wait(timeout=2)
            # A newly created runtime task directory aborts even with RPC down.
            timer = threading.Timer(0.3, lambda: (tasks / 'namespace/new-task').mkdir()); timer.start()
            args.receipt = str(root / 'task-appeared.json')
            try:
                try: cold.no_reappearance(args)
                except RuntimeError: pass
                else: raise AssertionError('new task was accepted')
                assert json.loads(Path(args.receipt).read_text())['abort'] is True
            finally:
                timer.join(); (tasks / 'namespace/new-task').rmdir()
            # A recreated engine bundle directory (new inode) aborts.
            def recreate():
                engine_dir.rmdir(); engine_dir.mkdir()
            timer = threading.Timer(0.3, recreate); timer.start()
            args.receipt = str(root / 'engine-dir-recreated.json')
            try:
                try: cold.no_reappearance(args)
                except RuntimeError: pass
                else: raise AssertionError('recreated engine task directory was accepted')
                assert json.loads(Path(args.receipt).read_text())['abort'] is True
            finally:
                timer.join()
            cold.watch_baseline(SimpleNamespace(receipt=str(baseline) + '.2')); baseline.unlink(); Path(str(baseline) + '.2').rename(baseline)
            # Read failure is not evidence of zero tasks.
            args.runtime_down = False; args.receipt = str(root / 'unreadable.json')
            with patch.object(cold, 'runtime_tasks', side_effect=RuntimeError('fixture unavailable')):
                try: cold.no_reappearance(args)
                except RuntimeError: pass
                else: raise AssertionError('unreadable runtime was accepted')
            assert json.loads(Path(args.receipt).read_text())['abort'] is True
            # Run the full positive interval only after failure fixtures work.
            args.runtime_down = phase == 'stopped'; args.receipt = str(root / 'watch.json')
            # The stopped engine's shim writes into its own bundle (ctime moves): accepted.
            timer = threading.Timer(0.5, lambda: (engine_dir / 'exit-status').write_text('0')); timer.start()
            before = time.monotonic(); cold.no_reappearance(args); elapsed = time.monotonic() - before
            timer.join()
            receipt = json.loads(Path(args.receipt).read_text())
            assert 60 <= elapsed < 72 and receipt['abort'] is False and receipt['samples'] >= 2
            assert receipt['elapsedSeconds'] >= 60 and receipt['barrier'] == phase
            print(json.dumps({'barrier': phase, 'elapsedSeconds': elapsed, 'samples': receipt['samples'], 'abort': False}), flush=True)
            good = receipt.copy()
            # Both fleet barriers consume receipt abort/phase, not CLI success.
            paths = []
            for region in ('gru', 'sjc', 'fra'):
                p = root / f'{region}-1.json'; cold.save(p, {**good, 'host': f'ts-{region}-1'}); paths.append(str(p))
                if phase == 'stopped':  # workers prove exit by OCI STOPPED receipts
                    p = root / f'{region}-2.json'; cold.save(p, {'host': f'ts-{region}-2', 'kind': 'oci-stopped', 'abort': False, 'barrier': 'stopped'}); paths.append(str(p))
            check = SimpleNamespace(receipts=paths, barrier=phase)
            with contextlib.redirect_stdout(io.StringIO()): cold.check_watches(check)
            for bad in ({'abort': True}, {'elapsedSeconds': 59.99}, {'barrier': 'restarted' if phase == 'stopped' else 'stopped'}):
                Path(paths[0]).write_text(json.dumps({**good, 'host': 'ts-gru-1', **bad}))
                try: cold.check_watches(check)
                except RuntimeError: pass
                else: raise AssertionError('bad fleet watch receipt was accepted')
            print('NEGATIVES_PASS=' + phase, flush=True)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == 'child':
        child(sys.argv[2]); return
    assert socket.gethostname().split('.')[0] in ('delta', 'beta', 'mariogk-dev')
    results = []
    for repeat in range(1, 6):
        children = [(phase, subprocess.Popen(['sudo', '-n', 'unshare', '--pid', '--fork', '--kill-child=KILL', '--mount-proc',
                     sys.executable, str(Path(__file__).resolve()), 'child', phase], stdout=subprocess.PIPE, stderr=subprocess.PIPE))
                    for phase in ('stopped', 'restarted')]
        for phase, proc in children:
            try:
                out, error = proc.communicate(timeout=78)
            except subprocess.TimeoutExpired as error:
                for _, running in children: running.kill()
                raise AssertionError((repeat, phase, error.stdout, error.stderr)) from error
            if proc.returncode != 0:
                for _, running in children:
                    if running.poll() is None: running.kill()
                raise AssertionError((repeat, phase, error.decode(), out.decode()))
            lines = out.decode().splitlines(); value = json.loads(lines[0]); assert lines[1] == 'NEGATIVES_PASS=' + phase
            results.append({'repeat': repeat, **value}); print('WATCH_PROOF=' + json.dumps(results[-1]), flush=True)
    print('WATCH_RESULT=' + json.dumps(results, sort_keys=True))


if __name__ == '__main__':
    main()
