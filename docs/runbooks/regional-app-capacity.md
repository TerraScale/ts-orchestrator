# Regional dashboard capacity with auth confined to gru

New signed releases of an unheld app with an embedded all-region declaration
adopt that declaration's placement and CPU/memory reservations. Dashboard omits
`regions`, so it follows all admitted regions, including future regions. Auth keeps its explicit `regions: ["gru"]` and its signed releases
preserve placement: current terrascale main rejects startup outside TS_REGION=gru
(App.cs:177), and regional auth writes are not linearizable. Regional auth startup
and write safety must be resolved before its placement can expand. Releases
retain the persisted spec's credentials, environment, routes,
ports, mounts and replica count. They do not apply the declaration's image.
Held services retain their placement, budgets and hold. Identical signed
receipt retries resume the original generation and bake, including a receipt
accepted before this placement change. Unsigned releases and unrelated services
retain their placement. Rollback restores the entire previous spec and retains
the signed release floor.

Dashboard reserves **200m CPU and 2048 MiB memory**. Auth retains its existing
**500m CPU and 2048 MiB memory**, exclusively in gru. Stateless
TaskPort services have a CPU limit of **2 CPUs**, or their reservation if larger,
and reserve **2 GiB disk**. Their update order remains start-first. Memory limits
remain equal to reservations. The executor applies CPU limits as CFS quota with
a 100 ms period; when CPU budgets differ it sets proportional shares from the
reservation (200m becomes 204 shares). Packing uses reservations, so unused CPU
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
mounts. Valid TaskPort services also require readiness and forbid PostgreSQL
and wire listeners. TerraBase has mounted data, fixed ports and no TaskPort;
its render and update policy remain unchanged, including 1000m/4096 MiB and
10 GiB disk. Its declaration is not embedded in the signed-app placement policy.
The executor's equal-budget OCI CPU options also remain unchanged.

`TestTerraBaseRenderUnchanged` pins the **full** declaration render to a SHA-256
captured from main `784000657` before the renderer change, including task,
endpoint and update policy. It also replays the persisted generation and region
through the actual `ApplyServiceSpec` path for gru, sjc and fra and asserts zero
service writes. The OCI test verifies equal-budget tasks receive their original
CFS options without adding shares. The existing executor reconnect path loads
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

`ts-orch edge geodns [--plan]` steers the hostnames of every embedded
first-party declaration that names no regions (`geodns.Hosts`): today
`dash.terrascale.tech`, `mcp.terrascale.tech` and `platform.terrascale.tech`.
`auth.terrascale.tech` stays a gru record while ts-auth is confined to gru, and
`api.terrascale.tech` keeps its TerraBase routing. Switch a hostname's
Cloudflare record to its `<label>.edge.terrascale.tech` CNAME only after every
region serves it.
