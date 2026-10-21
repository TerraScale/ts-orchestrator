# Static external initializer supplement for cc37fe13

Read this with the immutable source packet at `/tmp/ts-attempt-phase-dispatch-cc37-source-kh0o533k`. It adds dependency initializer evidence; it changes no source, request, runner, original test, or earlier packet. No Go package discovery, Go execution, build, test, runner invocation, lease request or runtime result occurred.

## Material correction to the request

The selected test body still reaches the retired-phase error without calling cloud/Runner/Sleep/broker operations. Its imports have effects before that body runs. The sealed request's `runtime_resources` description understates these total-process effects and its under-one-second estimate is not guaranteed. The original bytes remain unchanged; this explicit correction must accompany any later execution decision.

| Import initializer | Effects from reviewed source |
| --- | --- |
| Local NATS `server/pse` | Reads `/proc/<pid>/stat`, calls `Sysinfo` and `Getpagesize`, and starts recurring one-second `AfterFunc` sampling while reads succeed. No broker or listener is created. |
| VictoriaMetrics | Immediately reads `/proc/self/cgroup`; a goroutine reads `/proc/self/mountinfo` with a one-second timeout, then resolved cgroup v2 CPU/IO/memory pressure files may be read. A blocked reader can survive the timeout. Error paths may log to stderr. Runtime metric metadata is read. |
| Wazero and protobuf | Wazero reads `/sys/kernel/mm/hugepages/`; protobuf opens/stats/samples its own executable for a local seed. Wazero perf-map file creation is behind a false `PerfMapEnabled` constant for the stated no-`perfmap` build. |
| NUID, CPU and loggers | NUID obtains kernel entropy and initializes random state. CPU/page-size/clock/build metadata and absent library environment variables are read. OCI/gRPC logger setup uses local stderr/discard loggers; OCI file-output and file-based EC mode are not selected by the sealed six-key environment. |
| First-party and registries | The existing authority diagnostic goroutine waits on an in-memory channel. Other reviewed registrations are local descriptors, tables, metrics, codecs, resolvers and callbacks. x/net/trace adds default HTTP handlers without starting a listener. Host subprocess helper guards do not match the sealed test arguments. |

No reviewed initializer path under the stated source selection initiates an OCI credential provider, IMDS request, cloud SDK request, DNS lookup, network connection/listener, broker, host mutation, or child process. Stored closures containing those operations are distinguished from immediate calls. This is a qualified static assessment, not a sandbox or complete interprocedural proof. Descriptor corruption/duplicate-registration paths can fail initialization; no runtime pass is implied.

## Coverage and artifacts

1. `closure.json`: explicit root `go.mod` require/replace resolution into existing local module cache, plus the local NATS replacement; 428 package entries including the standard-library boundary, 4,394 enumerated Go files, 117 init declarations and 687 package-var call candidates. Root attempt tests are included; dependency tests are excluded. No root TestMain was found.
2. `classifications.json` and `.tsv`: every declaration has its source location, declaration hash, ownership, source-selection status, effect family and rationale. Ownership totals are 256 repository declarations, one cached first-party SDK declaration, 77 local third-party declarations and 470 cached third-party declarations.
3. `support-index.json` and named `.txt` excerpts: inspected callee and build-constraint evidence, with complete original-file and excerpt hashes. `scan.py` and `classify.py` preserve the static method and assertion checks.
4. `module-metadata-hashes.json`: metadata for all 37 reached modules, including root/source `go.mod` and `go.sum` where present plus cached `.mod` and `.ziphash` file hashes. Legacy NUID has no extracted-source `go.mod`; its cached synthesized `.mod` exists. No reached package/module source directory or download metadata is missing. Cache authenticity/zip contents were not independently verified.
5. `bindings-and-limits.json`: full commit/tree/parent, source/original/module/request/runner/executable hashes, counts and limits. Every enumerated source and every earlier-packet manifest entry was rehashed unchanged. Runner directory still contains only `run.py`.

## Source-selection limits

The stated static target is Linux/amd64/gc/Go 1.27, nonrace, no extra user tags. There are 3,932 selected files, 311 filename exclusions, 147 modern build-constraint exclusions and four conservatively retained legacy-tag files. No lexical errors or unresolved module-prefix mappings were found. No Go discovery, type checking or minimum-version selection computation confirms this closure.

The four `github.com/gogo/protobuf@v1.3.2/proto/pointer_{reflect,reflect_gogo,unsafe,unsafe_gogo}.go` files use only legacy `+build` lines. The scanner explicitly retains the ambiguity. Manual interpretation selects the unsafe variants for the stated target (`!purego,!appengine,!js`) and excludes reflect variants (`purego appengine js`); this is not toolchain-observed selection. No cgo/goexperiment ambiguity was encountered in this reached source set.

Persisted Go environment configuration under HOME was not inspected. `env -i` alone does not prove all actual compiler target/default settings. Standard-library/runtime, compiler/linker/test-harness initialization, assembly, embedded payload contents, full transitive call/alias analysis and actual resource usage remain outside this audit. The static classification distinguishes likely local construction and deferred callbacks but does not replace those missing proofs.

Execution remains unperformed. This supplement does not grant a lease or authorize a runner invocation.
