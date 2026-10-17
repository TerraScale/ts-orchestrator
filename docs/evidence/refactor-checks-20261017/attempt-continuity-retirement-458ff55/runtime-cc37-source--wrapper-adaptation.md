# ShortB wrapper adaptation

Only REQUEST and EXPECTED_REQUEST_SHA constant assignments differ from the immutable predecessor. Normalized wrapper text is byte-identical; ast.parse confirms exactly those two AST assignments differ. The wrapper was not imported, compiled or executed. It retains pinned Python3.15 -I -B checks, one-shot exclusive artifact creation, nonblocking exclusive flock, one Popen/wait and no retry, raw stdout/stderr, full pre/post HEAD/tree/untracked-inclusive status/source/original/modules/request/runner/executable hashes, exact one root actual run/pass and package pass, no child leaves/skips, exit0 and unchanged snapshots.

Go argv and six-key environment are byte-for-byte preserved. Lock is ShortB; test30s and outerTERM180s/KILL5s remain unchanged. No execution lease is included; no current grant is implied.
