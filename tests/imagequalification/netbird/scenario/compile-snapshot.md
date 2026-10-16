This isolated source snapshot exists for compiler and test-binary metadata checks.
It does not merge production main, authorize native hosts, or establish native
Linux/arm64 image qualification. The current x86_64 builder can execute only its
own compiler-check binary; that artifact must not receive fixed-NET approval.

The QA integrator approved these exact upstream copies:

- `9904b8f306e7da99d1cb9f5f41217a3234aac1d7`: the 13-line `NewFencedAPI` addition
  in `internal/netbird/manager/api.go` and complete `baseline.go`, using the
  `0e439cec..9904b8f3` patch limited to those two paths. No rewritten helper or
  stub is present. Patch SHA-256:
  `c1fff17b93eb80f1532d6dfc9c4cd06af56de3ee2b78862753c1e2b5e30d18da`.
- `a7520a5c`: exact committed canonical module-union `go.mod` and `go.sum`,
  obtained with `git show`, including the qualified containerd dependencies.
  No dirty CORE module files were copied.

Copied content SHA-256:

| File | SHA-256 |
| --- | --- |
| `internal/netbird/manager/baseline.go` | `71927a96c9e60a6d2faeae9ea8ca1184cd740eb0862f4822585c570bff869344` |
| `go.mod` | `3dcc9ecb65641323ccb85a6383ad370d328ccc3ef47545227abb38e7b8474d4f` |
| `go.sum` | `8b66a5397e2d3eddd6f553f081eb34365352c104503b72a813bc21a4ebf3dca3` |

The narrow check compiles `./internal/netbird/foundation` with `go test -c`
without running its hardware scenarios. An unstamped binary must reject both
`build-identity` and `serve` before host metadata or fixture construction. A
second build stamped with the clean snapshot's full Git SHA must report that
exact revision and its actual executable SHA-256 through `build-identity`.
Retain the exact clean source SHA, commands, compiler/platform settings, binaries,
and process outputs. Run all local build/check commands with `nice -n 19` under
the assigned bounded QA lane. No native acceptance or provider durability claim
can be derived from this compiler check.
