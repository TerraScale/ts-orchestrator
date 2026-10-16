# Runtime admission through containerd metadata — 2026-10-16

`TestContainerdRuntimeSpecMetadataIntegration` passed on clean source
`812d936ae7cb00206d49979775c950154c81a63e`: scenario 0.21 seconds, package 0.249
seconds, all nine drift subtests passed without skips. Log:
`/tmp/ts-data-runtime-metadata-812d936a.log`. QA granted the capacity lane; the
command used its lock, GOMAXPROCS=2, GOFLAGS=-p=2, nice -n 19 and the existing
containerd executable from `/tmp/ts-runtime-tools/bin` on PATH.

## Actual boundary

The fixture starts its own unprivileged containerd process with a fresh temporary
root, state directory and Unix socket. It inherits the local test command's nice
19 priority; CI retains its normal priority. It uses the actual SDK
to create metadata, read the stored OCI spec and update that spec. It does not
use a shared daemon, fetch an image, create a workload or require production
credentials. Cleanup closes the SDK client and terminates only its owned daemon
process before temporary-directory removal. Missing containerd on PATH is an
explicit failure, never a silent skip.

The valid spec round-trips through real containerd unchanged. The production
`RuntimeObserver.Observe` accepts its metadata admission checks and reaches the
absent-task boundary. Each mutated spec must instead produce `ErrUnsafe` before
the task lookup. Restoring the original spec must restore the absent-task result;
this also checks that test mutations did not change the retained pins.

## Direct-test replacement map

`TestRuntimeSpecRefusesAdmissionDrift` is replaced by the same nine scenarios
after actual containerd SDK updates: writable root, changed process, memory,
mount or cgroup, host PID namespace, host mount namespace, added user namespace
and added private network namespace. Exact OCI spec readback replaces its direct
positive helper call. The final restored-spec observation retains its assertion
that mutations do not corrupt admitted process pins.

`TestRuntimeObserverRequiresConcreteClient` is folded into this same scenario:
both nil context and actual namespaced context must return `ErrUnsafe` with no
runtime client, beside the real-client metadata observations. The existing real
host-network kernel namespace scenario remains unchanged.

This evidence qualifies runtime metadata/spec admission only. No running writer,
actual retained container mount or Source → host issue → runtime positive chain
is established. CORE's separate emergency-stop scenario and actual kernel mount,
namespace and member-process scenarios retain their own scope and evidence.
