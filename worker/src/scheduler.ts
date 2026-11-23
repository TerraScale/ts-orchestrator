import type {
  HttpRouteEntry,
  HttpUpstream,
  NodeInfo,
  PlacementInfo,
  PlacementMode,
  PostgresRouteEntry,
  PostgresUpstream,
  PriorityTier,
  RegionConfig,
  ServiceSpec,
} from "./protocol";

export interface ScheduleInput {
  regions: RegionConfig[];
  nodes: NodeInfo[];
  services: ServiceSpec[];
  currentPlacements: PlacementInfo[];
  nowMs: number;
  heartbeatTimeoutMs?: number;
}

export interface DesiredPlacement {
  id: string;
  serviceName: string;
  region: string;
  nodeId: string;
  slot: number;
  desiredImage: string;
  hostPort: number;
}

export interface UnschedulableEntry {
  serviceName: string;
  region: string;
  missing: number;
  reason: string;
}

export interface ScheduleResult {
  desired: DesiredPlacement[];
  unschedulable: UnschedulableEntry[];
  removedIds: string[];
  failedOverNodeIds: string[];
}

export const DEFAULT_HEARTBEAT_TIMEOUT_MS = 25_000;
export const HOST_PORT_MIN = 20_000;
export const HOST_PORT_MAX = 29_999;
export const DATA_VOLUME_PATH = "/var/lib/ts-data";
export const CPU_RESERVE_FRACTION = 0.15;
export const MEM_RESERVE_FRACTION = 0.1;
export const MEM_RESERVE_MIN_MIB = 1024;

const PRIORITY_ORDER: Record<PriorityTier, number> = { high: 0, normal: 1, low: 2 };
const MODE_ORDER: Record<PlacementMode, number> = { stateful: 0, daemon: 1, replicated: 2 };

interface NodeLoad {
  node: NodeInfo;
  allocCpu: number;
  allocMem: number;
  cpuFree: number;
  memFree: number;
  ports: Set<number>;
  services: Map<string, number>;
}

export function reservedCpuMilli(node: NodeInfo): number {
  return Math.ceil(node.cpuTotalMilli * CPU_RESERVE_FRACTION);
}

export function reservedMemMiB(node: NodeInfo): number {
  return Math.max(Math.ceil(node.memTotalMiB * MEM_RESERVE_FRACTION), MEM_RESERVE_MIN_MIB);
}

export function allocatableCpuMilli(node: NodeInfo): number {
  return Math.max(0, node.cpuTotalMilli - reservedCpuMilli(node));
}

export function allocatableMemMiB(node: NodeInfo): number {
  return Math.max(0, node.memTotalMiB - reservedMemMiB(node));
}

export function nodeAlive(node: NodeInfo, nowMs: number, timeoutMs = DEFAULT_HEARTBEAT_TIMEOUT_MS): boolean {
  return node.status === "active" && nowMs - node.lastSeenAt <= timeoutMs;
}

export function nodeSchedulable(node: NodeInfo, nowMs: number, timeoutMs = DEFAULT_HEARTBEAT_TIMEOUT_MS): boolean {
  return nodeAlive(node, nowMs, timeoutMs) && !node.drainRequested;
}

export function hasDataVolume(node: NodeInfo): boolean {
  return node.volumes.some((volume) => volume.mountPath === DATA_VOLUME_PATH);
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareServices(a: ServiceSpec, b: ServiceSpec): number {
  return (
    PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority] ||
    MODE_ORDER[a.mode] - MODE_ORDER[b.mode] ||
    compareText(a.name, b.name)
  );
}

function newLoad(node: NodeInfo): NodeLoad {
  const allocCpu = allocatableCpuMilli(node);
  const allocMem = allocatableMemMiB(node);
  return { node, allocCpu, allocMem, cpuFree: allocCpu, memFree: allocMem, ports: new Set(), services: new Map() };
}

function fits(load: NodeLoad, service: ServiceSpec): boolean {
  return load.cpuFree >= service.cpuRequestMilli && load.memFree >= service.memRequestMiB;
}

function reserve(load: NodeLoad, service: ServiceSpec): void {
  load.cpuFree -= service.cpuRequestMilli;
  load.memFree -= service.memRequestMiB;
  load.services.set(service.name, (load.services.get(service.name) ?? 0) + 1);
}

function headroom(load: NodeLoad): number {
  const cpu = load.allocCpu > 0 ? load.cpuFree / load.allocCpu : 0;
  const mem = load.allocMem > 0 ? load.memFree / load.allocMem : 0;
  return cpu + mem;
}

function allocatePort(load: NodeLoad): number | undefined {
  for (let port = HOST_PORT_MIN; port <= HOST_PORT_MAX; port++) {
    if (!load.ports.has(port)) {
      load.ports.add(port);
      return port;
    }
  }
  return undefined;
}

function placementId(serviceName: string, region: string, slot: number, nodeId: string): string {
  return `${serviceName}.${region}.${slot}.${nodeId}`;
}

function slotKey(serviceName: string, region: string, slot: number): string {
  return `${serviceName}|${region}|${slot}`;
}

function daemonKey(serviceName: string, region: string, nodeId: string): string {
  return `${serviceName}|${region}|node:${nodeId}`;
}

export function computeSchedule(input: ScheduleInput): ScheduleResult {
  const timeout = input.heartbeatTimeoutMs ?? DEFAULT_HEARTBEAT_TIMEOUT_MS;
  const regionLabels = new Set(input.regions.map((region) => region.label));
  const nodesById = new Map(input.nodes.map((node) => [node.id, node]));
  const loads = new Map<string, NodeLoad>();
  for (const node of input.nodes) loads.set(node.id, newLoad(node));
  const servicesByName = new Map(input.services.map((service) => [service.name, service]));
  const desired: DesiredPlacement[] = [];
  const removed = new Set<string>();
  const failedOver = new Set<string>();
  const keptKeys = new Set<string>();
  const needsPort: { placement: DesiredPlacement; load: NodeLoad }[] = [];
  const sorted = [...input.currentPlacements].sort((a, b) => compareText(a.id, b.id));

  for (const placement of sorted) {
    const service = servicesByName.get(placement.serviceName);
    if (service === undefined || !regionLabels.has(placement.region) || !service.regions.includes(placement.region)) {
      removed.add(placement.id);
      continue;
    }
    if (placement.nodeId === undefined) {
      removed.add(placement.id);
      continue;
    }
    const node = nodesById.get(placement.nodeId);
    const load = loads.get(placement.nodeId);
    if (node === undefined || load === undefined || node.region !== placement.region) {
      removed.add(placement.id);
      if (service.mode !== "stateful") failedOver.add(placement.nodeId);
      continue;
    }
    let key: string;
    if (service.mode === "stateful") {
      key = slotKey(service.name, placement.region, placement.slot);
      if (placement.slot >= service.replicas || node.poolKind !== "stateful" || keptKeys.has(key)) {
        removed.add(placement.id);
        continue;
      }
    } else if (service.mode === "replicated") {
      key = slotKey(service.name, placement.region, placement.slot);
      if (placement.slot >= service.replicas || keptKeys.has(key)) {
        removed.add(placement.id);
        continue;
      }
      if (!nodeSchedulable(node, input.nowMs, timeout)) {
        removed.add(placement.id);
        failedOver.add(node.id);
        continue;
      }
    } else {
      key = daemonKey(service.name, placement.region, node.id);
      if (keptKeys.has(key)) {
        removed.add(placement.id);
        continue;
      }
      if (!nodeSchedulable(node, input.nowMs, timeout)) {
        removed.add(placement.id);
        failedOver.add(node.id);
        continue;
      }
    }
    keptKeys.add(key);
    reserve(load, service);
    const kept: DesiredPlacement = {
      id: placement.id,
      serviceName: service.name,
      region: placement.region,
      nodeId: node.id,
      slot: placement.slot,
      desiredImage: placement.desiredImage,
      hostPort: 0,
    };
    if (placement.hostPort !== undefined && !load.ports.has(placement.hostPort)) {
      load.ports.add(placement.hostPort);
      kept.hostPort = placement.hostPort;
    } else {
      needsPort.push({ placement: kept, load });
    }
    desired.push(kept);
  }

  const unschedulable = new Map<string, UnschedulableEntry>();
  const markMissing = (service: ServiceSpec, region: string, reason: string): void => {
    const key = `${service.name}|${region}`;
    const entry = unschedulable.get(key);
    if (entry === undefined) unschedulable.set(key, { serviceName: service.name, region, missing: 1, reason });
    else entry.missing += 1;
  };

  for (const item of needsPort) {
    const port = allocatePort(item.load);
    if (port === undefined) {
      const index = desired.indexOf(item.placement);
      if (index >= 0) desired.splice(index, 1);
      removed.add(item.placement.id);
      const service = servicesByName.get(item.placement.serviceName);
      if (service !== undefined) markMissing(service, item.placement.region, "host_ports_exhausted");
      continue;
    }
    item.placement.hostPort = port;
  }

  const regions = [...input.regions].sort((a, b) => compareText(a.label, b.label));
  const services = [...input.services].sort(compareServices);

  for (const region of regions) {
    const regionLoads = [...loads.values()]
      .filter((load) => load.node.region === region.label)
      .sort((a, b) => compareText(a.node.id, b.node.id));
    for (const service of services) {
      if (!service.regions.includes(region.label)) continue;
      const create = (load: NodeLoad, slot: number): boolean => {
        const port = allocatePort(load);
        if (port === undefined) return false;
        reserve(load, service);
        desired.push({
          id: placementId(service.name, region.label, slot, load.node.id),
          serviceName: service.name,
          region: region.label,
          nodeId: load.node.id,
          slot,
          desiredImage: service.image,
          hostPort: port,
        });
        return true;
      };

      if (service.mode === "daemon") {
        const usedSlots = new Set(
          desired.filter((p) => p.serviceName === service.name && p.region === region.label).map((p) => p.slot),
        );
        let nextSlot = 0;
        for (const load of regionLoads) {
          if (!nodeSchedulable(load.node, input.nowMs, timeout)) continue;
          if (keptKeys.has(daemonKey(service.name, region.label, load.node.id))) continue;
          if (!fits(load, service)) {
            markMissing(service, region.label, "insufficient_capacity");
            continue;
          }
          while (usedSlots.has(nextSlot)) nextSlot++;
          if (!create(load, nextSlot)) {
            markMissing(service, region.label, "host_ports_exhausted");
            continue;
          }
          usedSlots.add(nextSlot);
          keptKeys.add(daemonKey(service.name, region.label, load.node.id));
        }
        continue;
      }

      const domainCounts = new Map<string, number>();
      for (const placement of desired) {
        if (placement.serviceName !== service.name || placement.region !== region.label) continue;
        const node = nodesById.get(placement.nodeId);
        if (node !== undefined) domainCounts.set(node.faultDomain, (domainCounts.get(node.faultDomain) ?? 0) + 1);
      }

      for (let slot = 0; slot < service.replicas; slot++) {
        if (keptKeys.has(slotKey(service.name, region.label, slot))) continue;
        let candidates: NodeLoad[];
        let reason: string;
        if (service.mode === "stateful") {
          reason = "no_stateful_node_with_data_volume";
          candidates = regionLoads
            .filter(
              (load) =>
                load.node.poolKind === "stateful" &&
                nodeSchedulable(load.node, input.nowMs, timeout) &&
                hasDataVolume(load.node) &&
                (load.services.get(service.name) ?? 0) === 0 &&
                fits(load, service),
            )
            .sort((a, b) => headroom(b) - headroom(a) || compareText(a.node.id, b.node.id));
        } else {
          reason = regionLoads.some((load) => nodeSchedulable(load.node, input.nowMs, timeout))
            ? "insufficient_capacity"
            : "no_schedulable_nodes";
          candidates = regionLoads
            .filter((load) => nodeSchedulable(load.node, input.nowMs, timeout) && fits(load, service))
            .sort(
              (a, b) =>
                (domainCounts.get(a.node.faultDomain) ?? 0) - (domainCounts.get(b.node.faultDomain) ?? 0) ||
                (a.services.get(service.name) ?? 0) - (b.services.get(service.name) ?? 0) ||
                headroom(b) - headroom(a) ||
                compareText(a.node.id, b.node.id),
            );
        }
        const target = candidates.find((load) => load.ports.size <= HOST_PORT_MAX - HOST_PORT_MIN);
        if (target === undefined || !create(target, slot)) {
          markMissing(service, region.label, reason);
          continue;
        }
        keptKeys.add(slotKey(service.name, region.label, slot));
        domainCounts.set(target.node.faultDomain, (domainCounts.get(target.node.faultDomain) ?? 0) + 1);
      }
    }
  }

  const desiredIds = new Set(desired.map((placement) => placement.id));
  return {
    desired: desired.sort(
      (a, b) =>
        compareText(a.region, b.region) ||
        compareText(a.serviceName, b.serviceName) ||
        a.slot - b.slot ||
        compareText(a.id, b.id),
    ),
    unschedulable: [...unschedulable.values()].sort(
      (a, b) => compareText(a.region, b.region) || compareText(a.serviceName, b.serviceName),
    ),
    removedIds: [...removed].filter((id) => !desiredIds.has(id)).sort(compareText),
    failedOverNodeIds: [...failedOver].sort(compareText),
  };
}

export function expandRegionTemplate(value: string, region: string): string {
  return value.replaceAll("{region}", region);
}

export function computeRoutes(
  region: string,
  services: ServiceSpec[],
  placements: PlacementInfo[],
  nodes: NodeInfo[],
  localNodeId?: string,
): { httpRoutes: HttpRouteEntry[]; postgresRoutes: PostgresRouteEntry[] } {
  const nodesById = new Map(nodes.map((node) => [node.id, node]));
  const httpRoutes: HttpRouteEntry[] = [];
  const postgresRoutes: PostgresRouteEntry[] = [];
  const sortedServices = [...services].filter((s) => s.regions.includes(region)).sort((a, b) => compareText(a.name, b.name));
  for (const service of sortedServices) {
    const upstreams: HttpUpstream[] = [];
    for (const placement of placements) {
      if (placement.serviceName !== service.name || placement.region !== region || placement.state !== "ready") continue;
      if (placement.nodeId === undefined || placement.hostPort === undefined) continue;
      const node = nodesById.get(placement.nodeId);
      if (node === undefined || node.status !== "active" || node.drainRequested) continue;
      upstreams.push({
        placementId: placement.id,
        nodeId: node.id,
        address: node.vcnIp,
        port: placement.hostPort,
        local: node.id === localNodeId,
      });
    }
    upstreams.sort((a, b) => compareText(a.placementId, b.placementId));
    const hostnames = [...new Set(service.hostnames.map((hostname) => expandRegionTemplate(hostname, region)))];
    if (hostnames.length > 0) {
      httpRoutes.push({ serviceName: service.name, hostnames, upstreams: upstreams.map((u) => ({ ...u })) });
    }
    if (service.postgres !== undefined) {
      const pgHostnames = [
        ...new Set(service.postgres.hostnames.map((hostname) => expandRegionTemplate(hostname, region))),
      ];
      const pgUpstreams: PostgresUpstream[] = upstreams.map((u) => ({ ...u }));
      postgresRoutes.push({
        serviceName: service.name,
        hostnames: pgHostnames,
        listenPort: service.postgres.port,
        upstreams: pgUpstreams,
      });
    }
  }
  return { httpRoutes, postgresRoutes };
}
