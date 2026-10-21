# Attempt cc37 ShortB successor: prepared and unexecuted

Use request.json, delta-proof.json and preservation-proof.json for independent review. The immutable predecessor request and runner are unused and retained in full under predecessor/. The independent source review and the complete sealed initializer supplement are copied byte-identically.

The only runtime control change is the nonblocking shared lock: /tmp/ts-orch-refactor-short-check-b.lock. Go argv, environment, selected root, source and original test bodies, module/executable pins, one attempt/no retry, test30s and outerTERM180s/KILL5s are unchanged. Runtime disclosure now includes local proc/cgroup/sysfs/executable/entropy reads, metric reader and authority goroutines, recurring NATS timers and possible stderr. Under one second is not guaranteed; RSS/cache/time figures are unmeasured estimates without hard RSS/cache caps.

No Go command, test, package discovery, prepared wrapper invocation, lock acquisition or lease request occurred. A later QA review and explicit grant are required before execution; this packet itself grants nothing. The runner directory is private mode0700 and contains only read-only run.py; no execution artifacts exist.
