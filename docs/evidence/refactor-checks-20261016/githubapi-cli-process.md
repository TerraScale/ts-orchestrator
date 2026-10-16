# GitHub workflow-detail process integration

Source: original `760d500531fdf85147c0074818e53182022be262`, integrated as `79fb2e8e` on the published `847b55fc` baseline. Only `internal/githubapi/run_test.go` changes.

All 21 original table cases and their assertions remain. Each case now reads temporary JSON through a real bounded child process and OS stdout pipe; exact NUL-delimited command arguments are checked after execution. Accepted provenance and normalized output, rejected source/run identity, rejected attempt/status/workflow and rejected pagination/size retain their original checks.

The delegated Short-B check ran against the exact clean original commit:

```sh
timeout 180s flock /tmp/ts-orch-refactor-short-check-b.lock env GOMAXPROCS=2 GOFLAGS=-p=2 nice -n 19 go test ./internal/githubapi -count=1 -timeout=60s
```

Result: PASS, 0.335 seconds, exit 0. The lane was released and no repeat was run. The checked test file and integrated test file are byte-identical.

Limits: actual local process/filesystem/argv/pipe behavior; no live GitHub API, installed `gh`, race or whole-repository qualification.

Raw log: `githubapi-cli-process.log`.

Log SHA-256: `7c408db4413cea3652b1af00ef4e568594882d82bfb18b91cc4c283c5184cda0`.
