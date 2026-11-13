# Single-host CI lanes

The ARM journeys run as independent matrix jobs. Every lane runs for every pull request and every push to main, including changes limited to documentation. This conservative path condition includes the command, all internal packages, deployment assets, shared journey scripts, module files and the workflow. No lane currently skips by path. A future path filter must select all lanes on main and may skip a pull-request lane only when neither its own inputs nor any shared input changed.

| Lane | What it proves | Timeout | Path condition |
|---|---|---|---|
| core | Install, serving, DNS, service status, removal and persistent data | 8 minutes | All paths |
| websocket | HTTP/1.1 upgrade and echo through the installed edge | 8 minutes | All paths |
| regional | Second edge, REST, both WebSocket protocols, drain, half-close upload and request counters | 3 minutes | All paths |
| nodelist | Signed inventory, real-daemon release admission and identity preservation/refusals | 8 minutes | All paths |
| restarts | Agent and task restart, private/public key preservation and persistent data | 8 minutes | All paths |
| rollback | Never-ready update rolls back while the previous task serves | 8 minutes | All paths |
| host-logs | Journal settings applied once from current host state, unsupported hosts left untouched, syslog handling | 12 minutes | All paths |
| monitoring | Alert rule sets, relay delivery, and task metrics that keep the recorded service identity across restart and adoption | 8 minutes | All paths |
| boot-order | Management and peer cold boots, old declarations, dependency gates and running tasks | 8 minutes | All paths |
| rollout | Regional bake windows, local holds, signed replacement and nonce admission across three isolated regions | 10 minutes | All paths |
| rollout-install | First installs, lost receipts, new regions, release identity validation, interruption budgets and host sampling | 10 minutes | All paths |
| operator | Fleet routing contracts and startup metadata recovery/outage/cancellation | 8 minutes | All paths |
| data-volume | Volume lifecycle and zero-write refusals, format once, adoption, mount reporting and dependent-unit stop/recovery | 8 minutes | All paths |

Each lane restores the shared ARM Go cache and builds the static agent and its selected Go journey entry points with the same build.sh. Independent warm-cache builds avoid the artifact producer/upload/download dependency on the longest lane. The node-list journey additionally compiles distinct embedded-inventory variants as part of its assertions. Startup deliberately observes a five-minute metadata window; it runs alongside the other lanes. Boot-order installs the pinned runtime without running the agent installer. Regional and node-list create their own isolated environments. Core, WebSocket, restarts, rollback, host-logs, monitoring and data-volume source the same installer/serving setup. Only data-volume runs the volume bootstrap before installation: it creates the mount requirements as service drop-ins, while the installer itself does not require a data mount. Its privileged volume drills run in private mount and network namespaces. The install fixture grows the verified 3 GiB filesystem to 32 GiB for the installed services’ disk reservations and adopts it without format permission, then the lane uses the shared setup’s per-command sudo. Only core saves the Go cache on main, avoiding concurrent uploads of the same cache key.

Fail-fast is disabled so the other lanes finish after a failure. Per-lane concurrency cancels obsolete work on the same ref. The aggregate check retains the name e2e-m1 and requires the complete matrix, including each lane's build, to succeed. A failed, cancelled or unexpectedly skipped matrix cannot pass the aggregate. No skips are currently intended; a future filtered matrix must represent intentional exclusions as successful jobs while still rejecting unexpected skips. Both all-green and the existing release gate continue to depend on the aggregate. Release concurrency and publication logic are unchanged.

The caller-key lifecycle and recovery journey runs in eight parallel x86 shards with fail-fast disabled and a five-minute limit per job. A separate build job compiles the overlay command and journey once and distributes those exact binaries. Cases have stable names and zero-based indices; case i belongs to shard i modulo eight. Every shard rejects an empty selection, and partition validation requires the sorted union to equal the unsharded list with no duplicates. Mutation-boundary families are split by operation, original interruption boundary and failure mode; all boundary cases still execute. Each shard records its execution time in the job summary. Locally, run `bash test/e2e/m1/callerkey/build.sh /tmp/caller-key-bin`, then `/tmp/caller-key-bin/callerkey run /tmp/caller-key-bin/terrascale-orchestrator` for all cases, or append `0 8` for shard zero; `callerkey list [i n]` lists the selected cases.

Selection uses `go list -deps -json` for the journey and the command with the journey's actual store overlay, for both the source and base revisions. Any change under a repository-local dependency directory, including local replacements under third_party, selects the journey. Embedded files, local module manifests and sums, the journey's complete directory, caller-keys.md, this document, ci.yml and the Go action are also inputs. Checking both graphs catches removed dependencies and files; directory matching includes newly added sources and package assets such as the region catalog. Graph errors fail the detector rather than skipping qualification. Detector logs list the computed inputs and matched changes. The journey also runs daily.

Both all-green and the release gate require a successful detector. A true changed output requires the entire shard matrix to succeed; a false output permits a successful or skipped matrix. Detector failure or cancellation, an absent or invalid output, and any failed, cancelled or unexpectedly skipped required shard block both gates. All-green also rejects failure or cancellation in every other dependency. Scheduled runs qualify the journey but cannot publish binaries or release: the publication build runs only on push, and release-push additionally requires main, successful host lanes and publication marked required.

To add a lane, create its entry script under test/e2e/m1/, source setup.sh if it needs the installed services, then add exactly one matrix entry in .github/workflows/ci.yml:

~~~yaml
          - {lane: example, entry: example.sh, timeout: 10}
~~~

Its binary argument is the lane's agent; sibling helper binaries are in the same directory. A lane with Go helpers lists their package paths in the same matrix entry, for example packages: "./test/e2e/m1/example". Helper directory basenames must be unique. Record its proof, timeout and path condition in the table. Do not append it to run.sh.

For a disposable local host, build with:

~~~sh
test/e2e/m1/build.sh /tmp/m1-bin
bash test/e2e/m1/run.sh /tmp/m1-bin/terrascale-orchestrator
~~~

Substitute the selected entry script. Install-based lanes require passwordless sudo and modify the disposable host.

## Publication on main

A successful main push releases only when the build emits publication=required, e2e-m1 succeeds, and the caller-key detector and shard gate described above pass. The release-input comparison includes the executable dependency graph for both architectures (source, native files and embedded assets), module manifests, Makefile, .github/workflows/ci.yml, .github/actions/go/action.yml, and the release qualification/audit scripts listed in scripts/ci/release-inputs-changed.py.

A change limited to .github/ can therefore release: the CI workflow and Go action are explicit executable inputs. Other workflow files, docs/ and test/ alone do not require publication when a complete, admissible retained main ancestor proves those executable inputs unchanged. An absent, invalid or unreadable retained baseline requires publication even for documentation-only or journey-only changes. The comparison is against retained qualification, rather than just the previous commit.
