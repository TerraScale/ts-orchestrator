# Wrapper adaptation

Pattern copied from the last approved NetBird wrapper named in the parent task. New wrapper code has been parsed with Python ast.parse only and never executed.

Retains nonblocking shared flock, exclusive output creation, exact argv/cwd recording, raw JSON/stderr, one Popen/wait and no retry. Adds pinned interpreter/isolated/no-bytecode checks; Go/Python/git/nice/timeout/env executable pre/post hashes; module and runner hashes; full untracked-inclusive git status; a one-shot attempt marker; and stricter exact actual root/run/pass/package evidence with no child leaves or malformed JSON.

The packet contains no lease. Only QA may authorize and execute its recorded direct pinned Python3.15 -I -B invocation. No Go command or prepared runner ran during packet creation.
