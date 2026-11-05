#!/usr/bin/env python3
"""Retry immutable release downloads on server errors; leave admission to callers."""

import re
import subprocess
import sys
import time


def download(*args, runner=None):
    if args[:3] != ('gh', 'release', 'download'):
        raise ValueError('Expected gh release download')
    if '--clobber' not in args:
        args = (*args, '--clobber')
    if runner is None:
        def runner(*command, **kwargs):
            return subprocess.check_output(command, timeout=180, **kwargs)
    for attempt in range(3):
        try:
            return runner(*args, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as error:
            diagnostic = error.stderr or b''
            if isinstance(diagnostic, bytes):
                diagnostic = diagnostic.decode(errors='replace')
            safe = re.sub(r'(https?://[^?\s)]+)\?[^\s)]+', r'\1?[redacted]', diagnostic)
            print(safe, file=sys.stderr, end='')
            if attempt == 2 or not re.search(r'(?i)(?:HTTP\s+|status(?: code)?[:= ]+|returned error: )5[0-9]{2}\b', diagnostic):
                raise
            print(f'Transient release download failure; retry {attempt + 1}/2 in {2 ** attempt}s', file=sys.stderr)
            time.sleep(2 ** attempt)


if __name__ == '__main__':
    try:
        sys.stdout.buffer.write(download(*sys.argv[1:]))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        sys.exit(f'Pinned release download failed: {type(error).__name__}')
