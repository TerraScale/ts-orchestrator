# Static initializer review: cc37fe13

No Go package discovery or package execution was performed. Static traversal includes all 615 files in 79 first-party packages reachable from internal/attempt production and test imports, conservatively including platform variants. Exact file hashes and all five initializer locations are in static-import-closure.json; complete initializer source files accompany it.

There is no TestMain or init function in internal/attempt production or test source. Dependency test functions are not run. Existing attempt tests have no package-level network/process initializer.

1. authority/runtime.go:36 starts one in-memory diagnostic queue goroutine. With no enqueued events it blocks on the channel; this test never enqueues work. No network or subprocess call occurs.
2. ociregion/sdkcli/inventory.go:15 registers handler closures. listIn returns a closure; the service factory and SDK requests execute only when that handler is invoked, not while registered.
3. ociregion/publicapi/sdk_peer.go:15 assigns function values and flag lists to registration maps. It does not invoke creators or OCI clients.
4. host/native_exec.go:38 activates only for exactly two os.Args entries and the private --terrascale-internal-native-workload-helper argument. The proposed Go test command contains ordinary test flags and never supplies this private argument.
5. host/runtime_probe.go:32 likewise requires exactly two os.Args entries and one of two private probe arguments. Neither appears in the command, and env-i removes probe nonce/UID/GID variables. It does not start a helper under this invocation.

First-party package-level calls observed are local regex/error/metrics/map/channel/semaphore setup and protocol subject construction. OCI provider symbols are stored as function values; factories, credential reads, metadata requests, SDK requests, process starts and broker starts occur in uncalled functions. The import scan is conservative static evidence, not an external-library initializer audit or a sandbox claim.

The selected test calls attempt.Run with --config <real temp file> continuity. Run reads its flags, New reads and decodes that config, validates its nonempty paths/prefix and canonical ULID, creates a private work directory, resolves os.Executable, copies environment values and installs uncalled closures. Phase rejects continuity through its default branch, and Run writes exactly the resulting error and newline. No cloud(), Runner, Sleep, Cell, or other phase executes.
