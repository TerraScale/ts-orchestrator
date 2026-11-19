# Production dashboard capacity with auth confined to gru

An image release copies the persisted service spec and changes only its image.
It retains placement, CPU/memory reservations, credentials, environment,
routes, ports, mounts and replica count. Editing a checked-in declaration or
shipping a new orchestrator binary does not apply those configuration changes
to an existing service. A repeated signed receipt resumes its original
generation and bake. The existing hold and failed-bake rules still apply;
rollback restores the entire previous spec and retains the signed release floor.

The production dashboard declaration omits `regions`, so an explicit apply
targets all regions in the production mesh, including future admitted regions.
Production auth retains `regions: ["gru"]`; do not expand it without qualifying
regional auth startup and write safety.

## Apply a deliberate configuration change

Commit the intended env, secret references, reservations or placement change
to the appropriate declaration. Coordinate new variables with the application
release that supports them. For an existing service, a matching operator must
then explicitly apply that declaration with the service's **current image**;
the checked-in image can be older and must not replace the active release.
The production root auth/dashboard declarations require an explicit apply.
Only app-canary has automatic first apply.

Run as root on a production manager with its mesh running and
the reviewed declaration available. This example changes dashboard
configuration without changing its image:

```sh
(
  set -eu
  umask 077
  prepared_spec=$(mktemp)
  trap 'rm -f "$prepared_spec"' EXIT
  current_image=$(ts-orch service inspect ts-dashboard | jq -er '.spec.image')
  jq --arg image "$current_image" '.image = $image' deploy/m1/services/ts-dashboard.json > "$prepared_spec"
  ts-orch service apply -f "$prepared_spec"
  ts-orch service inspect ts-dashboard
)
```

Verify the resulting spec, placement and readiness. Image releases preserve the
applied configuration.

Provision every newly referenced secret and its read permission before shipping
the binary that embeds it. Secret preflight checks the whole region's applicable
declarations; one missing reference refuses that region's orchestrator
binary release. An individual app-pull failure does not stop the updater from
trying the other services. A failed first apply can roll back to absence and
retain its signed floor: fixing the secret alone does not admit that same signed
run again. Repair the cause and publish a strictly newer signed run or attempt.

## Capacity

Dashboard reserves **200m CPU and 2048 MiB memory**. Auth retains its existing
**500m CPU and 2048 MiB memory**, exclusively in gru. Stateless
TaskPort services have a CPU limit of **2 CPUs**, or their reservation if larger,
and reserve **2 GiB disk**. Their update order remains start-first. Memory limits
remain equal to reservations. The executor applies CPU limits as CFS quota with
a 100 ms period and leaves every task at the default scheduler weight, the one
TerraBase runs at (a reservation-sized weight starved the dashboard's startup on
2-CPU hosts under load). Packing uses reservations, so unused CPU
can serve bursts without imposing a 200m execution cap. This does not change
TerraBase's current 1-CPU limit.

For a sjc/fra node advertising 1750m CPU and approximately 11.4 GiB memory,
using the supplied existing-host inventory and conservatively counting each
probe at 50m/64 MiB:

- Steady CPU: 1000 + 200 + 2×50 = **1300m**.
- One app update overlap: 1300 + 200 = **1500m**, leaving **250m** allocatable
  beyond the executor's separate 250m host CPU reserve.
- Steady memory: 4096 + 2048 + 2×64 = **6272 MiB**.
- One app update overlap: 6272 + 2048 = **8320 MiB** (8.125 GiB), leaving
  approximately **3.275 GiB** of the stated allocatable memory.
- Dashboard plus one overlap: 2 + 2 = **4 GiB** of
  additional scheduler budget against the reported approximately 12–13 GiB
  free. Existing held task budgets are added to the scheduler offer and then
  subtracted by SwarmKit; they are not charged against free space twice.

No app RSS measurements were found in `deploy/observability` or the supplied
repair evidence. Retaining the existing 2048 MiB hard cap avoids an unsupported
memory reduction. These are packing calculations from the supplied inventory,
not live capacity or load qualification; no production hosts were accessed.

The disk budget accounts for retained compressed image blobs, unpacked image
layers and bounded rotating logs. The root filesystem is read-only, and `/tmp`
is tmpfs charged to memory, so stateless tasks do not need the mounted-service
10 GiB allowance. `diskAvailable` still requires physical headroom for the whole
budget, and `prepareDisk` refuses an image whose retained bytes plus logs exceed
2 GiB. The existing free-space/inode policy, image accounting and log bounds
are unchanged. Exact next-release image sizes have not been measured here;
oversize artifacts fail admission rather than bypassing storage checks.

## Why this binary change does not restart TerraBase

Mesh startup/periodic sync **does re-render persisted desired state**:
`Node.sync` calls `Node.reconcile`, then `swarmApplier.Apply` calls
`swarmruntime.ApplyServiceSpec`. The latter compares the full current service
with the rendered service using `proto.Equal` and returns without a write when
they match. A global renderer change would therefore be unsafe.

The new resource rendering applies only to services using TaskPort without
mounts. Valid TaskPort services also require readiness and forbid a PostgreSQL
listener. TerraBase has mounted data, fixed ports and no TaskPort;
its render and update policy remain unchanged, including 1000m/4096 MiB and
10 GiB disk. Image releases do not reapply its declaration's configuration.
The executor's equal-budget OCI CPU options also remain unchanged.

`TestTerraBaseRenderUnchanged` pins the **full** declaration render to a SHA-256
captured from main `784000657` before the renderer change, including task,
endpoint and update policy. It also replays the persisted generation and region
through the actual `ApplyServiceSpec` path for gru, sjc and fra and asserts zero
service writes. The OCI test verifies every task receives only its CFS quota and
period, never a scheduler weight. The existing executor reconnect path loads
`ts-<taskID>` and validates its unchanged task fingerprint; `Executor.Close`
closes its client and controller `Close` releases bookkeeping without killing
the process. The existing containerd integration test
`TestContainerdLifecycleAgentRecovery` checks process PID reuse across agent restarts
(CI runtime qualification; not exercised locally without its containerd fixture).
`Node.Stop` cancels the agent before upstream Stop so it suspends without
leaving the swarm or clearing assignments; its explicit contract preserves
workloads across orchestrator restarts.
This proves this change introduces no TerraBase task-template update or restart;
it does not claim a production rollout was performed.

## GeoDNS scope

`ts-orch region apply gru dns` reconciles the fleet document's five global
names in `edge.terrascale.tech`: dash, auth, api, mcp and platform. One shared
HTTP monitor probes each region's owned NLB reserved address at :80/readyz
every 10 seconds. The document's continent assignments determine the first
choice, with healthy failover to the next nearest region. Public Cloudflare
names move to DNS-only CNAMEs only after the end-to-end gate passes for every
hostname and NLB. See [DNS ownership](../oci-reconcile.md#fleet-dns-pass) and
[the cutover procedure](../network/geodns.md).
