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
| monitoring | Alert rule sets, relay delivery, and task metrics that keep the recorded service identity across restart and adoption | 8 minutes | All paths |
| boot-order | Management and peer cold boots, old declarations, dependency gates and running tasks | 8 minutes | All paths |
| updater-preflight | Candidate preflight before the binary swap, the single commit point under injected write failures, host and integrity refusals across regions, probation, and the alert relay runtime files | 12 minutes | All paths |
| host-credentials | Prepared-file relay startup, missing/malformed/protection health checks and activation preparation gate | 5 minutes | All paths |
| release-contracts | Revision admission/refusals, retained Vault policy narrowing, installer metadata preservation and platform preflight | 5 minutes | All paths |
| metadata-upgrade | Real installer upgrade preserves metadata exceptions and local rules through a systemd unit restart | 8 minutes | All paths |
| operator | Fleet routing contracts and startup metadata recovery/outage/cancellation | 8 minutes | All paths |

Each lane restores the shared ARM Go cache and builds the static agent and its selected Go journey entry points with the same build.sh. Independent warm-cache builds avoid the artifact producer/upload/download dependency on the longest lane. The node-list journey additionally compiles distinct embedded-inventory variants as part of its assertions. Startup deliberately observes a five-minute metadata window; it runs alongside the other lanes. Boot-order installs the pinned runtime without running the agent installer. Regional and node-list create their own isolated environments. Core, WebSocket, restarts and rollback source the same installer/serving setup. Only core saves the Go cache on main, avoiding concurrent uploads of the same cache key.

Fail-fast is disabled so the other lanes finish after a failure. Per-lane concurrency cancels obsolete work on the same ref. The aggregate check retains the name e2e-m1 and requires the complete matrix, including each lane's build, to succeed. A failed, cancelled or unexpectedly skipped matrix cannot pass the aggregate. No skips are currently intended; a future filtered matrix must represent intentional exclusions as successful jobs while still rejecting unexpected skips. Both all-green and the existing release gate continue to depend on the aggregate. Release concurrency and publication logic are unchanged.

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

## Credential isolation

The host-credentials lane uses mount and network namespaces with an actual tmpfs and disables swap on its disposable runner. The updater-preflight lane runs the alert-preparation assertions with the same memory protection. Together they cover every assertion in the local credential-vm harness without requiring KVM or QEMU in CI. That harness remains available for local machines whose active swap must stay untouched; it adds no VM-only assertions. The monitoring lane also disables swap and prepares protected disposable credential files before starting the real relay. Its malformed journey-state assertions continue to exercise alert acceptance independently of journey observations.

Release-contracts runs its short namespace/API journeys together. Metadata-upgrade sources setup.sh to exercise the real installed systemd unit. Core run.sh and operator startup.sh remain identical to the merged base.

## Publication on main

A successful main push releases only when the build emits publication=required and e2e-m1 succeeds. The release-input comparison includes the executable dependency graph for both architectures (source, native files and embedded assets), module manifests, Makefile, .github/workflows/ci.yml, .github/actions/go/action.yml, and the release qualification/audit scripts listed in scripts/ci/release-inputs-changed.py.

A change limited to .github/ can therefore release: the CI workflow and Go action are explicit executable inputs. Other workflow files, docs/ and test/ alone do not require publication when a complete, admissible retained main ancestor proves those executable inputs unchanged. An absent, invalid or unreadable retained baseline requires publication even for documentation-only or journey-only changes. The comparison is against retained qualification, rather than just the previous commit.
