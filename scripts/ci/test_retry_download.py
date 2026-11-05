#!/usr/bin/env python3
"""Check transient recovery and fail-closed bounds without external downloads."""
import contextlib
import io
import subprocess
import unittest
from unittest.mock import Mock, call, patch

import retry_download


class DownloadRetry(unittest.TestCase):
    def test_transient_recovery_five_times_with_backoff_and_partial_replacement(self):
        for _ in range(5):
            attempts = [subprocess.CalledProcessError(1, 'gh', stderr=f'HTTP {code}: unavailable'.encode()) for code in (504, 502)]
            runner = Mock(side_effect=[*attempts, b'original pinned bytes'])
            with patch.object(retry_download.time, 'sleep') as pause, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(retry_download.download('gh', 'release', 'download', 'pinned-tag', runner=runner), b'original pinned bytes')
                self.assertEqual(runner.call_count, 3)
                self.assertEqual(pause.call_args_list, [call(1), call(2)])
                self.assertEqual(runner.call_args.args[-1], '--clobber')

    def test_persistent_server_failure_is_bounded_and_4xx_is_not_retried(self):
        for code, attempts in ((503, 3), (404, 1), (403, 1)):
            runner = Mock(side_effect=subprocess.CalledProcessError(1, 'gh', stderr=f'HTTP {code}: unavailable'))
            with patch.object(retry_download.time, 'sleep'), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(subprocess.CalledProcessError):
                    retry_download.download('gh', 'release', 'download', 'pinned-tag', runner=runner)
            self.assertEqual(runner.call_count, attempts)
        with self.assertRaises(ValueError):
            retry_download.download('gh', 'release', 'create', 'must-not-retry-writes')
