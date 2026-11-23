import type { MetricsPoint10s, MetricsPoint1m, NodeInfo, PlacementInfo, RegionConfig, ServiceSpec } from "./protocol";
import { DATA_VOLUME_PATH, allocatableCpuMilli, allocatableMemMiB, type UnschedulableEntry } from "./scheduler";

export interface AutoscaleInput {
  regions: RegionConfig[];
  nodes: NodeInfo[];
  services: ServiceSpec[];
  placements: PlacementInfo[];
  unschedulable: UnschedulableEntry[];
  metrics10s: MetricsPoint10s[];
  metrics1m: MetricsPoint1m[];
  cooldowns: Map<string, number>;
  nowMs: number;
  poolIds?: Map<string, string>;
}

export type AutoscaleAction =
  | { kind: "scale_replicas"; serviceName: string; region: string; desiredReplicas: number; reason: string }
  | {
      kind: "scale_pool_up";
      region: string;
      ociRegion: string;
      compartmentId: string;
      poolId: string;
      newSize: number;
      reason: string;
    }
  | { kind: "drain_for_scale_down"; region: string; nodeId: string; reason: string }
  | {
      kind: "terminate_drained_worker";
      region: string;
      ociRegion: string;
      nodeId: string;
      instanceId: string;
      poolId: string;
      reason: string;
    }
  | {
      kind: "grow_volume";
      region: string;
      ociRegion: string;
      nodeId: string;
      volumeId: string;
      mountPath: string;
      newSizeGiB: number;
      reason: string;
    };

export const REPLICA_UP_COOLDOWN_MS = 120_000;
export const REPLICA_DOWN_COOLDOWN_MS = 600_000;
export const REPLICA_SIGNAL_WINDOW_MS = 60_000;
export const POOL_UP_SUSTAIN_MS = 180_000;
export const POOL_UP_COOLDOWN_MS = 600_000;
export const POOL_DOWN_WINDOW_MS = 900_000;
export const POOL_DOWN_COOLDOWN_MS = 900_000;
export const POOL_DOWN_MARGIN = 0.3;
export const VOLUME_USAGE_THRESHOLD_PCT = 75;
export const VOLUME_SUSTAIN_MS = 300_000;
export const VOLUME_GROW_GIB = 50;
export const VOLUME_COOLDOWN_MS = 1_800_000;
export const HOT_CPU_PCT = 80;
export const HOT_PSI = 25;
export const HOT_MEM_RATIO = 0.85;
export const POOL_ID_LABEL = "oci.instance-pool-id";
export const INSTANCE_ID_LABEL = "oci.instance-id";
export const DATA_VOLUME_ID_LABEL = "oci.data-volume-id";

const MINUTE_MS = 60_000;
const INACTIVE_STATES: ReadonlySet<string> = new Set(["stopped", "failed", "unschedulable"]);

interface ReplicaSignals {
  cpuPct: number;
  memRatio: number;
  psi: number;
  p95Ms: number | null;
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function poolScaleUpCooldownKey(region: string): string {
  return `pool-up:${region}`;
}

export function poolScaleDownCooldownKey(region: string): string {
  return `pool-down:${region}`;
}

export function volumeGrowCooldownKey(nodeId: string): string {
  return `volume:${nodeId}`;
}

function cooled(cooldowns: Map<string, number>, key: string, nowMs: number, windowMs: number): boolean {
  const last = cooldowns.get(key);
  return last === undefined || last + windowMs <= nowMs;
}

function average(values: number[]): number {
  return values.length === 0 ? 0 : values.reduce((sum, value) => sum + value, 0) / values.length;
}

function replicaSignals(
  service: ServiceSpec,
  region: string,
  placements: PlacementInfo[],
  metrics10s: MetricsPoint10s[],
  nowMs: number,
): ReplicaSignals | null {
  const placementIds = new Set<string>();
  const nodeIds = new Set<string>();
  for (const placement of placements) {
    if (placement.serviceName !== service.name || placement.region !== region || placement.state !== "ready") continue;
    placementIds.add(placement.id);
    if (placement.nodeId !== undefined) nodeIds.add(placement.nodeId);
  }
  if (placementIds.size === 0) return null;
  const cpu: number[] = [];
  const mem: number[] = [];
  const psi: number[] = [];
  let p95: number | null = null;
  for (const point of metrics10s) {
    if (point.ts < nowMs - REPLICA_SIGNAL_WINDOW_MS || !nodeIds.has(point.nodeId)) continue;
    psi.push(Math.max(point.cpuPsi10, point.memPsi10));
    for (const container of point.containers) {
      if (!placementIds.has(container.placementId)) continue;
      cpu.push(container.cpuPct);
      if (container.memLimitMiB > 0) mem.push(container.memUsedMiB / container.memLimitMiB);
    }
    const edge = point.edge?.services.find((entry) => entry.serviceName === service.name);
    if (edge !== undefined && edge.requests > 0) p95 = Math.max(p95 ?? 0, edge.p95Ms);
  }
  if (cpu.length === 0) return null;
  return { cpuPct: average(cpu), memRatio: average(mem), psi: average(psi), p95Ms: p95 };
}

function evaluateReplicas(input: AutoscaleInput, regionLabels: Set<string>, cooldowns: Map<string, number>): AutoscaleAction[] {
  const actions: AutoscaleAction[] = [];
  const services = [...input.services].sort((a, b) => compareText(a.name, b.name));
  for (const service of services) {
    if (service.mode !== "replicated") continue;
    const min = Math.max(0, service.minReplicas);
    const max = Math.max(min, service.maxReplicas);
    for (const region of [...service.regions].sort(compareText)) {
      if (!regionLabels.has(region)) continue;
      const current = service.replicas;
      const upKey = `replica-up:${service.name}:${region}`;
      const lastKey = `replica-last:${service.name}:${region}`;
      const emit = (desiredReplicas: number, reason: string): void => {
        actions.push({ kind: "scale_replicas", serviceName: service.name, region, desiredReplicas, reason });
        cooldowns.set(lastKey, input.nowMs);
        if (desiredReplicas > current) cooldowns.set(upKey, input.nowMs);
      };
      if (current < min) {
        emit(min, "below_min_replicas");
        continue;
      }
      if (current > max) {
        emit(max, "above_max_replicas");
        continue;
      }
      const spec = service.autoscale;
      if (spec === undefined) continue;
      const signals = replicaSignals(service, region, input.placements, input.metrics10s, input.nowMs);
      if (signals === null) continue;
      const upMs = spec.scaleUpCooldownSeconds > 0 ? spec.scaleUpCooldownSeconds * 1000 : REPLICA_UP_COOLDOWN_MS;
      const downMs = spec.scaleDownCooldownSeconds > 0 ? spec.scaleDownCooldownSeconds * 1000 : REPLICA_DOWN_COOLDOWN_MS;
      const cpuHot = spec.targetCpuPct > 0 && signals.cpuPct > spec.targetCpuPct;
      const p95Hot = spec.targetP95Ms > 0 && signals.p95Ms !== null && signals.p95Ms > spec.targetP95Ms;
      const memHot = signals.memRatio > HOT_MEM_RATIO;
      const psiHot = signals.psi > HOT_PSI;
      if (cpuHot || p95Hot || memHot || psiHot) {
        if (current < max && cooled(cooldowns, upKey, input.nowMs, upMs)) {
          const byCpu = cpuHot ? Math.ceil((current * signals.cpuPct) / spec.targetCpuPct) : current + 1;
          const desiredReplicas = Math.min(max, Math.max(current + 1, byCpu));
          const reasons = [cpuHot ? "cpu" : "", p95Hot ? "p95" : "", memHot ? "memory" : "", psiHot ? "psi" : ""].filter(
            (reason) => reason.length > 0,
          );
          emit(desiredReplicas, `high_${reasons.join("_")}`);
        }
        continue;
      }
      const cold =
        (spec.targetCpuPct <= 0 || signals.cpuPct < spec.targetCpuPct * 0.5) &&
        signals.memRatio < 0.5 &&
        signals.psi < 5 &&
        (signals.p95Ms === null || spec.targetP95Ms <= 0 || signals.p95Ms < spec.targetP95Ms * 0.5);
      if (cold && current > min && cooled(cooldowns, lastKey, input.nowMs, downMs)) emit(current - 1, "low_utilization");
    }
  }
  return actions;
}

function minuteBuckets(points: MetricsPoint1m[]): Map<number, MetricsPoint1m[]> {
  const buckets = new Map<number, MetricsPoint1m[]>();
  for (const point of points) {
    const bucket = Math.floor(point.ts / MINUTE_MS);
    const list = buckets.get(bucket);
    if (list === undefined) buckets.set(bucket, [point]);
    else list.push(point);
  }
  return buckets;
}

function sustainedHot(nodes: NodeInfo[], metrics1m: MetricsPoint1m[], nowMs: number): boolean {
  const byId = new Map(nodes.map((node) => [node.id, node]));
  const points = metrics1m.filter((point) => point.ts > nowMs - POOL_UP_SUSTAIN_MS - MINUTE_MS && byId.has(point.nodeId));
  const buckets = minuteBuckets(points);
  if (buckets.size < POOL_UP_SUSTAIN_MS / MINUTE_MS) return false;
  for (const bucket of buckets.values()) {
    let memUsed = 0;
    let memTotal = 0;
    for (const point of bucket) {
      memUsed += point.memAvgMiB;
      memTotal += byId.get(point.nodeId)?.memTotalMiB ?? 0;
    }
    const cpu = average(bucket.map((point) => point.cpuAvg));
    const psi = average(bucket.map((point) => point.cpuPsiAvg));
    const mem = memTotal > 0 ? memUsed / memTotal : 0;
    if (!(cpu > HOT_CPU_PCT || psi > HOT_PSI || mem > HOT_MEM_RATIO)) return false;
  }
  return true;
}

function activePlacementCount(nodeId: string, placements: PlacementInfo[]): number {
  return placements.filter((p) => p.nodeId === nodeId && !INACTIVE_STATES.has(p.state)).length;
}

function poolIdFor(input: AutoscaleInput, region: string, workers: NodeInfo[]): string | undefined {
  const configured = input.poolIds?.get(region);
  if (configured !== undefined && configured.length > 0) return configured;
  for (const worker of workers) {
    const label = worker.labels[POOL_ID_LABEL];
    if (label !== undefined && label.length > 0) return label;
  }
  return undefined;
}

function fitsWithout(
  input: AutoscaleInput,
  region: string,
  candidate: NodeInfo,
  regionNodes: NodeInfo[],
  servicesByName: Map<string, ServiceSpec>,
): boolean {
  const remaining = regionNodes.filter(
    (node) => node.id !== candidate.id && node.status === "active" && !node.drainRequested,
  );
  if (remaining.length === 0) return false;
  const capCpu = remaining.reduce((sum, node) => sum + allocatableCpuMilli(node), 0);
  const capMem = remaining.reduce((sum, node) => sum + allocatableMemMiB(node), 0);
  let reqCpu = 0;
  let reqMem = 0;
  for (const placement of input.placements) {
    if (placement.region !== region || placement.nodeId === undefined || INACTIVE_STATES.has(placement.state)) continue;
    const service = servicesByName.get(placement.serviceName);
    if (service === undefined) continue;
    reqCpu += service.cpuRequestMilli;
    reqMem += service.memRequestMiB;
  }
  const nodesById = new Map(regionNodes.map((node) => [node.id, node]));
  const points = input.metrics1m.filter(
    (point) => point.ts > input.nowMs - POOL_DOWN_WINDOW_MS && nodesById.has(point.nodeId),
  );
  const buckets = minuteBuckets(points);
  if (buckets.size < POOL_DOWN_WINDOW_MS / MINUTE_MS) return false;
  let peakCpu = 0;
  let peakMem = 0;
  for (const bucket of buckets.values()) {
    let cpu = 0;
    let mem = 0;
    for (const point of bucket) {
      const node = nodesById.get(point.nodeId);
      if (node === undefined) continue;
      cpu += (point.cpuP95 / 100) * node.cpuTotalMilli;
      mem += point.memAvgMiB;
    }
    peakCpu = Math.max(peakCpu, cpu);
    peakMem = Math.max(peakMem, mem);
  }
  const demandCpu = Math.max(reqCpu, peakCpu);
  const demandMem = Math.max(reqMem, peakMem);
  return demandCpu <= capCpu * (1 - POOL_DOWN_MARGIN) && demandMem <= capMem * (1 - POOL_DOWN_MARGIN);
}

function evaluatePools(input: AutoscaleInput, cooldowns: Map<string, number>): AutoscaleAction[] {
  const actions: AutoscaleAction[] = [];
  const servicesByName = new Map(input.services.map((service) => [service.name, service]));
  const regions = [...input.regions].sort((a, b) => compareText(a.label, b.label));
  for (const region of regions) {
    const regionNodes = input.nodes.filter((node) => node.region === region.label);
    const workers = regionNodes
      .filter((node) => node.poolKind === "worker")
      .sort((a, b) => compareText(a.id, b.id));
    const live = workers.filter((node) => node.status !== "down" && node.status !== "drained");
    const poolId = poolIdFor(input, region.label, workers);
    const upKey = poolScaleUpCooldownKey(region.label);
    const downKey = poolScaleDownCooldownKey(region.label);
    const unschedulable = input.unschedulable.filter((entry) => entry.region === region.label && entry.missing > 0);
    const activeNodes = regionNodes.filter((node) => node.status === "active" && !node.drainRequested);
    const hot = sustainedHot(activeNodes, input.metrics1m, input.nowMs);

    if (unschedulable.length > 0 || hot) {
      if (
        poolId !== undefined &&
        live.length < region.pools.worker.max &&
        cooled(cooldowns, upKey, input.nowMs, POOL_UP_COOLDOWN_MS)
      ) {
        const reason =
          unschedulable.length > 0
            ? `unschedulable:${unschedulable.map((entry) => `${entry.serviceName}x${entry.missing}`).join(",")}`
            : "sustained_high_utilization";
        actions.push({
          kind: "scale_pool_up",
          region: region.label,
          ociRegion: region.ociRegion,
          compartmentId: region.compartmentId,
          poolId,
          newSize: live.length + 1,
          reason,
        });
      }
      continue;
    }

    let terminating = false;
    for (const worker of workers) {
      if (!worker.drainRequested) continue;
      if (worker.status !== "drained" && worker.status !== "down") continue;
      if (activePlacementCount(worker.id, input.placements) > 0) continue;
      const instanceId = worker.labels[INSTANCE_ID_LABEL];
      if (instanceId === undefined || instanceId.length === 0 || poolId === undefined) continue;
      actions.push({
        kind: "terminate_drained_worker",
        region: region.label,
        ociRegion: region.ociRegion,
        nodeId: worker.id,
        instanceId,
        poolId,
        reason: "drained_for_scale_down",
      });
      terminating = true;
    }
    if (terminating || workers.some((worker) => worker.drainRequested && worker.status !== "down")) continue;

    const activeWorkers = workers.filter((worker) => worker.status === "active" && !worker.drainRequested);
    if (activeWorkers.length <= Math.max(0, region.pools.worker.min)) continue;
    if (!cooled(cooldowns, downKey, input.nowMs, POOL_DOWN_COOLDOWN_MS)) continue;
    if (!cooled(cooldowns, upKey, input.nowMs, POOL_DOWN_WINDOW_MS)) continue;
    const requestOf = (node: NodeInfo): number =>
      input.placements
        .filter((p) => p.nodeId === node.id && !INACTIVE_STATES.has(p.state))
        .reduce((sum, p) => sum + (servicesByName.get(p.serviceName)?.cpuRequestMilli ?? 0), 0);
    const candidate = [...activeWorkers].sort(
      (a, b) =>
        activePlacementCount(a.id, input.placements) - activePlacementCount(b.id, input.placements) ||
        requestOf(a) - requestOf(b) ||
        compareText(a.id, b.id),
    )[0];
    if (candidate === undefined) continue;
    if (!fitsWithout(input, region.label, candidate, regionNodes, servicesByName)) continue;
    actions.push({
      kind: "drain_for_scale_down",
      region: region.label,
      nodeId: candidate.id,
      reason: `headroom_fits_${activeWorkers.length - 1}_workers`,
    });
  }
  return actions;
}

function sustainedDisk(node: NodeInfo, usedPct: number, input: AutoscaleInput): boolean {
  if (usedPct <= VOLUME_USAGE_THRESHOLD_PCT) return false;
  const since = input.nowMs - VOLUME_SUSTAIN_MS;
  const fine = input.metrics10s.filter((point) => point.nodeId === node.id && point.ts >= since - 10_000);
  if (fine.length > 0) {
    const earliest = Math.min(...fine.map((point) => point.ts));
    if (earliest <= since && fine.every((point) => point.diskUsedPct > VOLUME_USAGE_THRESHOLD_PCT)) return true;
  }
  const coarse = input.metrics1m.filter((point) => point.nodeId === node.id && point.ts > since - MINUTE_MS);
  return (
    minuteBuckets(coarse).size >= VOLUME_SUSTAIN_MS / MINUTE_MS &&
    coarse.every((point) => point.diskPct > VOLUME_USAGE_THRESHOLD_PCT)
  );
}

function evaluateVolumes(input: AutoscaleInput, cooldowns: Map<string, number>): AutoscaleAction[] {
  const actions: AutoscaleAction[] = [];
  const regionsByLabel = new Map(input.regions.map((region) => [region.label, region]));
  const nodes = input.nodes
    .filter((node) => node.poolKind === "stateful" && node.status !== "down")
    .sort((a, b) => compareText(a.id, b.id));
  for (const node of nodes) {
    const region = regionsByLabel.get(node.region);
    const volume = node.volumes.find((entry) => entry.mountPath === DATA_VOLUME_PATH);
    const volumeId = node.labels[DATA_VOLUME_ID_LABEL];
    if (region === undefined || volume === undefined || volumeId === undefined || volumeId.length === 0) continue;
    const key = volumeGrowCooldownKey(node.id);
    if (!cooled(cooldowns, key, input.nowMs, VOLUME_COOLDOWN_MS)) continue;
    if (!sustainedDisk(node, volume.usedPct, input)) continue;
    actions.push({
      kind: "grow_volume",
      region: region.label,
      ociRegion: region.ociRegion,
      nodeId: node.id,
      volumeId,
      mountPath: DATA_VOLUME_PATH,
      newSizeGiB: volume.sizeGiB + VOLUME_GROW_GIB,
      reason: `disk_usage_${Math.round(volume.usedPct)}pct`,
    });
  }
  return actions;
}

export function evaluateAutoscale(input: AutoscaleInput): {
  actions: AutoscaleAction[];
  updatedCooldowns: Map<string, number>;
} {
  const cooldowns = new Map(input.cooldowns);
  const regionLabels = new Set(input.regions.map((region) => region.label));
  const actions = [
    ...evaluateReplicas(input, regionLabels, cooldowns),
    ...evaluatePools(input, cooldowns),
    ...evaluateVolumes(input, cooldowns),
  ];
  return { actions, updatedCooldowns: cooldowns };
}
