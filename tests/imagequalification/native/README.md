This directory is **test infrastructure**, not an admission authority or a live
execution authorization. `Run` requires four different disposable OCI
Compute instances (three managers and a separate container agent), one exact imported image, private IPv4 addresses, trusted SSH
host-key pins, and an owner-only ephemeral SSH key. The parent must authenticate
actual OCI confinement and host ownership before calling it. A `/run` marker is
an additional accident guard, not cloud authorization.

Build `./tests/imagequalification/native/cmd/native-worker` from the exact source
candidate for the target architecture. The parent supplies its SHA256, the image
component hashes, the immutable architecture-specific smoke image child manifest,
and a pinned OCI archive of that workload. The runner transfers only the worker
and archive over pinned SSH. Driver continuity probes use direct-tcpip forwarding through
the same pinned SSH connection to host loopback port 18080; the runner needs
SSH ingress only. Manager-to-worker readiness probes use the exact peer-only
ports 18080, 18081, 18082 and 18083. The archive is imported and unpacked locally; CORE's
cached exact-image execution path requires no registry access. NetBird and
production units must be inactive. No production secrets or NetBird membership
are installed. The launch bootstrap must create `/run/ts-native-disposable` with
the exact run ID. All test state lives under `/run/ts-native-<run-id>`.

The scenarios use real CORE managers/agents and containerd tasks on distinct
hosts, real HTTP, actual iptables manager-IP-only partitions that preserve the separate worker Dispatcher connection, durable node restart,
cross-host container identity/PID checks, real readiness failure and upstream
rollback. Evidence includes exact component and IMDS instance/boot-image identity,
per-scenario transcripts and hashes. The parent independently maps the observed
image ID to its QCOW2 digest and retains CI/source qualification and policy proof.
Join tokens and SSH private keys are excluded from reports.

Required scenario names are `manager-loss`, `manager-partition`, `agent-restart`
(`runtime-ha`), `unavailable-agent-replacement` (also `runtime-ha`), and `readiness-rejection`, `rollback`, `container-isolation`
(`workload-safety`). Formation and cleanup have their own additional transcripts.
`container-isolation` measures the actual platform container process contract:
non-root identity, readonly root filesystem, no privileges/capabilities and
seccomp. CORE currently uses host networking. This does not establish hostile
customer/tenant network isolation, signed production workload admission, database
fencing, production release qualification, or regional availability. The fixture
integration tests exercise local filesystem/process/SSH/HTTP boundaries only.
Their success never establishes native image acceptance.

Cleanup heals partitions and removes services across the available quorum, then
verifies no matching runtime containers remain on any host. Cleanup errors fail
the run. The parent's independently authorized cleanup still owns terminating
the disposable hosts and deleting their cloud resources. A failed process or
unreachable host must never be considered cleaned up by a successful local call.
