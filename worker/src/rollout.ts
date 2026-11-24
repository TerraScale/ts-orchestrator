import type { EdgeServiceMetrics, EventKind, NodeInfo, PlacementInfo, RolloutInfo, RolloutPhase, ServiceSpec } from "./protocol";

export interface NodeEdgeMetrics {
  ts: number;
  windowSeconds: number;
  services: EdgeServiceMetrics[];
}

export interface RolloutContext {
  rollout: RolloutInfo;
  service: ServiceSpec;
  placements: PlacementInfo[];
  nodes: NodeInfo[];
  rolloutOrder: string[];
  latestMetricsByNode: Map<string, NodeEdgeMetrics>;
  nowMs: number;
  canaryBakeMs?: number;
}

export interface RolloutStep {
  rollout: RolloutInfo;
  imageUpdates: { placementId: string; targetImage: string }[];
  events: { kind: string; region?: string; subject: string; detail: Record<string, unknown> }[];
}

export interface CanaryBreach {
  metric: "5xx" | "p95";
  value: number;
  threshold: number;
}

export const DEFAULT_CANARY_BAKE_MS = 15_000;
export const WAVE_FRACTION = 0.25;
export const CANARY_READY_GRACE_MS = 120_000;
export const MIN_CANARY_REQUESTS = 20;

type RolloutEvent = RolloutStep["events"][number];

const TERMINAL: ReadonlySet<RolloutPhase> = new Set(["succeeded", "rolled_back", "failed"]);

function event(kind: EventKind, subject: string, detail: Record<string, unknown>, region?: string): RolloutEvent {
  return region === undefined ? { kind, subject, detail } : { kind, region, subject, detail };
}

function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export function orderRegions(regions: string[], rolloutOrder: string[]): string[] {
  const scope = [...new Set(regions)];
  const ordered = rolloutOrder.filter((region) => scope.includes(region));
  const rest = scope.filter((region) => !rolloutOrder.includes(region)).sort(compareText);
  return [...new Set([...ordered, ...rest])];
}

function regionSequence(rollout: RolloutInfo, service: ServiceSpec, rolloutOrder: string[]): string[] {
  return orderRegions(rollout.region !== undefined ? [rollout.region] : service.regions, rolloutOrder);
}

export function canaryThresholds(rollout: RolloutInfo): { max5xxPct: number; maxP95Ms: number } {
  return {
    max5xxPct: Math.max(1, (rollout.baseline5xxPct ?? 0) * 2),
    maxP95Ms: Math.max(250, (rollout.baselineP95Ms ?? 0) * 2),
  };
}

export function canaryBreach(metrics: EdgeServiceMetrics | undefined, rollout: RolloutInfo): CanaryBreach | null {
  if (metrics === undefined) return null;
  if (metrics.requests < MIN_CANARY_REQUESTS) return null;
  const { max5xxPct, maxP95Ms } = canaryThresholds(rollout);
  if (metrics.errorRate5xxPct > max5xxPct) return { metric: "5xx", value: metrics.errorRate5xxPct, threshold: max5xxPct };
  if (metrics.p95Ms > maxP95Ms) return { metric: "p95", value: metrics.p95Ms, threshold: maxP95Ms };
  return null;
}

function runningTarget(placement: PlacementInfo, target: string): boolean {
  return placement.state === "ready" && placement.activeImage === target;
}

function candidateFailed(placement: PlacementInfo, target: string): boolean {
  return placement.candidateImage === target && placement.candidateError !== undefined && placement.candidateError.length > 0;
}

function targetFailed(placement: PlacementInfo, target: string): boolean {
  return (placement.state === "failed" && placement.activeImage === target) || candidateFailed(placement, target);
}

export function createRollout(
  service: ServiceSpec,
  targetImage: string,
  regions: string[],
  rolloutOrder: string[],
  baselineP95Ms: number,
  baseline5xxPct: number,
  nowMs: number,
): RolloutInfo {
  const ordered = orderRegions(regions.length > 0 ? regions : service.regions, rolloutOrder);
  const rollout: RolloutInfo = {
    id: `${service.name}-${nowMs.toString(36)}`,
    serviceName: service.name,
    targetImage,
    previousImage: service.image,
    phase: "pending",
    currentWave: 0,
    totalWaves: ordered.length,
    baselineP95Ms,
    baseline5xxPct,
    startedAt: nowMs,
  };
  const first = ordered[0];
  if (first !== undefined) rollout.currentRegion = first;
  if (regions.length === 1 && first !== undefined) rollout.region = first;
  return rollout;
}

class Stepper {
  readonly updates: RolloutStep["imageUpdates"] = [];
  readonly events: RolloutEvent[] = [];
  state: RolloutInfo;
  readonly sequence: string[];
  readonly nodesById: Map<string, NodeInfo>;

  constructor(readonly ctx: RolloutContext) {
    this.state = { ...ctx.rollout };
    this.sequence = regionSequence(ctx.rollout, ctx.service, ctx.rolloutOrder);
    this.nodesById = new Map(ctx.nodes.map((node) => [node.id, node]));
  }

  regionPlacements(region: string): PlacementInfo[] {
    return this.ctx.placements
      .filter((placement) => {
        if (placement.serviceName !== this.state.serviceName || placement.region !== region) return false;
        if (placement.nodeId === undefined || placement.state === "stopped") return false;
        const node = this.nodesById.get(placement.nodeId);
        return node !== undefined && node.status !== "down";
      })
      .sort((a, b) => a.slot - b.slot || compareText(a.id, b.id));
  }

  setImage(placement: PlacementInfo, image: string): void {
    if (placement.desiredImage !== image) this.updates.push({ placementId: placement.id, targetImage: image });
  }

  startRegion(index: number): void {
    const region = this.sequence[index];
    if (region === undefined) {
      this.succeed();
      return;
    }
    this.state.currentRegion = region;
    this.state.currentWave = index;
    const placements = this.regionPlacements(region);
    if (placements.length === 0) {
      this.startRegion(index + 1);
      return;
    }
    const canary = placements.find((p) => p.desiredImage !== this.state.targetImage) ?? placements[0];
    if (canary === undefined) {
      this.startRegion(index + 1);
      return;
    }
    this.setImage(canary, this.state.targetImage);
    this.state.phase = "canary";
    this.state.canaryStartedAt = this.ctx.nowMs;
    delete this.state.waveStartedAt;
    this.events.push(
      event(
        "canary_started",
        this.state.serviceName,
        { rolloutId: this.state.id, placementId: canary.id, nodeId: canary.nodeId, image: this.state.targetImage },
        region,
      ),
    );
  }

  succeed(): void {
    this.state.phase = "succeeded";
    this.state.finishedAt = this.ctx.nowMs;
    delete this.state.waveStartedAt;
    this.events.push(
      event("rollout_succeeded", this.state.serviceName, { rolloutId: this.state.id, image: this.state.targetImage }),
    );
  }

  abort(region: string, reason: string, detail: Record<string, unknown>): void {
    const previous = this.state.previousImage;
    if (previous !== undefined) {
      for (const placement of this.ctx.placements) {
        if (placement.serviceName !== this.state.serviceName) continue;
        if (this.state.region !== undefined && placement.region !== this.state.region) continue;
        if (placement.desiredImage === this.state.targetImage) this.setImage(placement, previous);
      }
    }
    this.state.phase = previous === undefined ? "failed" : "rolled_back";
    this.state.finishedAt = this.ctx.nowMs;
    delete this.state.waveStartedAt;
    this.state.error = reason;
    this.events.push(
      event(
        previous === undefined ? "rollout_failed" : "rollback",
        this.state.serviceName,
        { rolloutId: this.state.id, reason, targetImage: this.state.targetImage, previousImage: previous, ...detail },
        region,
      ),
    );
  }

  canaryOf(placements: PlacementInfo[]): PlacementInfo | undefined {
    return placements.find((p) => p.desiredImage === this.state.targetImage);
  }

  metricsFor(nodeId: string | undefined, sinceMs?: number): EdgeServiceMetrics | undefined {
    if (nodeId === undefined) return undefined;
    const sample = this.ctx.latestMetricsByNode.get(nodeId);
    if (sample === undefined) return undefined;
    const windowStartMs = sample.ts - sample.windowSeconds * 1000;
    if (sinceMs !== undefined && windowStartMs < sinceMs) return undefined;
    return sample.services.find((m) => m.serviceName === this.state.serviceName);
  }

  run(): void {
    if (this.state.phase === "pending") {
      this.events.push(
        event("deploy_started", this.state.serviceName, {
          rolloutId: this.state.id,
          image: this.state.targetImage,
          regions: this.sequence,
        }),
      );
      this.startRegion(0);
      return;
    }
    const region = this.state.currentRegion ?? this.sequence[0];
    if (region === undefined) {
      this.succeed();
      return;
    }
    const index = Math.max(0, this.sequence.indexOf(region));
    const placements = this.regionPlacements(region);
    const target = this.state.targetImage;

    if (this.state.phase === "canary") {
      const canary = this.canaryOf(placements);
      if (canary === undefined) {
        this.startRegion(index);
        return;
      }
      if (targetFailed(canary, target)) {
        const detail: Record<string, unknown> = { placementId: canary.id };
        if (candidateFailed(canary, target)) detail.error = canary.candidateError;
        this.abort(region, "canary_failed", detail);
        return;
      }
      if (runningTarget(canary, target)) {
        this.state.phase = "baking";
        this.state.canaryStartedAt = this.ctx.nowMs;
        return;
      }
      const startedAt = this.state.canaryStartedAt ?? this.ctx.nowMs;
      const limit = this.ctx.service.readyTimeoutSeconds * 1000 + CANARY_READY_GRACE_MS;
      if (this.ctx.nowMs - startedAt > limit) this.abort(region, "canary_not_ready", { placementId: canary.id });
      return;
    }

    if (this.state.phase === "baking") {
      const canary = this.canaryOf(placements);
      if (canary === undefined || targetFailed(canary, target)) {
        const detail: Record<string, unknown> = canary === undefined ? {} : { placementId: canary.id };
        if (canary !== undefined && candidateFailed(canary, target)) detail.error = canary.candidateError;
        this.abort(region, "canary_failed", detail);
        return;
      }
      const breach = canaryBreach(this.metricsFor(canary.nodeId, this.state.canaryStartedAt), this.state);
      if (breach !== null) {
        this.abort(region, `canary_${breach.metric}_breach`, {
          placementId: canary.id,
          metric: breach.metric,
          value: breach.value,
          threshold: breach.threshold,
        });
        return;
      }
      const bake = this.ctx.canaryBakeMs ?? DEFAULT_CANARY_BAKE_MS;
      if (this.ctx.nowMs - (this.state.canaryStartedAt ?? this.ctx.nowMs) < bake) return;
      this.state.phase = "waves";
      delete this.state.waveStartedAt;
      this.events.push(
        event("canary_passed", this.state.serviceName, { rolloutId: this.state.id, placementId: canary.id }, region),
      );
    }

    if (this.state.phase === "waves") {
      const inflight = placements.filter((p) => p.desiredImage === target && !runningTarget(p, target));
      const failed = inflight.find((p) => targetFailed(p, target));
      if (failed !== undefined) {
        const detail: Record<string, unknown> = { placementId: failed.id };
        if (candidateFailed(failed, target)) detail.error = failed.candidateError;
        this.abort(region, "wave_failed", detail);
        return;
      }
      if (inflight.length > 0) {
        const waveStartedAt = this.state.waveStartedAt ?? this.ctx.nowMs;
        this.state.waveStartedAt = waveStartedAt;
        const limit = this.ctx.service.readyTimeoutSeconds * 1000 + CANARY_READY_GRACE_MS;
        if (this.ctx.nowMs - waveStartedAt > limit) {
          this.abort(region, "wave_not_ready", { placementIds: inflight.map((p) => p.id) });
        }
        return;
      }
      delete this.state.waveStartedAt;
      const pending = placements.filter((p) => p.desiredImage !== target);
      if (pending.length === 0) {
        this.startRegion(index + 1);
        return;
      }
      const size = Math.max(1, Math.ceil(placements.length * WAVE_FRACTION));
      for (const placement of pending.slice(0, size)) this.setImage(placement, target);
      this.state.waveStartedAt = this.ctx.nowMs;
    }
  }
}

export function advanceRollout(ctx: RolloutContext): RolloutStep {
  if (TERMINAL.has(ctx.rollout.phase)) return { rollout: ctx.rollout, imageUpdates: [], events: [] };
  const stepper = new Stepper(ctx);
  stepper.run();
  return { rollout: stepper.state, imageUpdates: stepper.updates, events: stepper.events };
}

export function rollbackRollout(rollout: RolloutInfo, placements: PlacementInfo[], nowMs: number): RolloutStep {
  const state: RolloutInfo = { ...rollout, finishedAt: nowMs };
  const previous = rollout.previousImage;
  if (previous === undefined) {
    state.phase = "failed";
    state.error = "no_previous_image";
    return {
      rollout: state,
      imageUpdates: [],
      events: [event("rollout_failed", rollout.serviceName, { rolloutId: rollout.id, reason: "no_previous_image" })],
    };
  }
  const imageUpdates = placements
    .filter(
      (p) =>
        p.serviceName === rollout.serviceName &&
        (rollout.region === undefined || p.region === rollout.region) &&
        p.desiredImage === rollout.targetImage &&
        p.desiredImage !== previous,
    )
    .sort((a, b) => compareText(a.id, b.id))
    .map((p) => ({ placementId: p.id, targetImage: previous }));
  state.phase = "rolled_back";
  state.error = "manual_rollback";
  return {
    rollout: state,
    imageUpdates,
    events: [
      event(
        "rollback",
        rollout.serviceName,
        { rolloutId: rollout.id, reason: "manual_rollback", targetImage: rollout.targetImage, previousImage: previous },
        rollout.region,
      ),
    ],
  };
}
