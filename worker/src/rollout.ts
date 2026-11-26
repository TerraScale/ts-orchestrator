import type {
  EdgeServiceMetrics,
  EventKind,
  NodeInfo,
  PlacementInfo,
  RolloutInfo,
  RolloutPhase,
  RolloutRegionPhase,
  RolloutRegionProgress,
  ServiceSpec,
} from "./protocol";

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
export const MAX_CANARY_BAKE_MS = 30_000;
export const WAVE_FRACTION = 0.25;
export const CANARY_READY_GRACE_MS = 120_000;
const MAX_WAVE_READY_MS = 30 * 60_000;
export const MIN_CANARY_REQUESTS = 20;

type RolloutEvent = RolloutStep["events"][number];

const TERMINAL: ReadonlySet<RolloutPhase> = new Set(["succeeded", "rolled_back", "failed"]);

type ActiveRegionPhase = "canary" | "baking" | "waves";

function activeRegionPhase(phase: RolloutRegionPhase | RolloutPhase): ActiveRegionPhase | undefined {
  switch (phase) {
    case "canary":
    case "baking":
    case "waves":
      return phase;
    case "pending":
    case "succeeded":
    case "skipped":
    case "rolled_back":
    case "failed":
      return undefined;
  }
}

function regionDone(entry: RolloutRegionProgress | undefined): boolean {
  return entry !== undefined && activeRegionPhase(entry.phase) === undefined;
}

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

export function rolloutSequence(rollout: RolloutInfo, service: ServiceSpec, rolloutOrder: string[]): string[] {
  if (rollout.regionOrder !== undefined) return rollout.regionOrder;
  return orderRegions(rollout.region !== undefined ? [rollout.region] : service.regions, rolloutOrder);
}

export function rolloutStages(sequence: string[]): string[][] {
  const [first, ...rest] = sequence;
  if (first === undefined) return [];
  return rest.length === 0 ? [[first]] : [[first], rest];
}

function progressEntry(
  region: string,
  phase: RolloutRegionPhase,
  canaryStartedAt: number | undefined,
  waveStartedAt: number | undefined,
): RolloutRegionProgress {
  const entry: RolloutRegionProgress = { region, phase };
  if (canaryStartedAt !== undefined) entry.canaryStartedAt = canaryStartedAt;
  if (waveStartedAt !== undefined) entry.waveStartedAt = waveStartedAt;
  return entry;
}

export interface StageProgress {
  stage: number;
  regions: RolloutRegionProgress[];
}

export function stageProgress(rollout: RolloutInfo, sequence: string[]): StageProgress {
  if (rollout.regionProgress !== undefined) return { stage: rollout.currentWave, regions: rollout.regionProgress };
  const current = rollout.currentRegion;
  const phase = activeRegionPhase(rollout.phase);
  const index = current === undefined || phase === undefined ? -1 : sequence.indexOf(current);
  if (current === undefined || phase === undefined || index < 0) return { stage: 0, regions: [] };
  const active = progressEntry(current, phase, rollout.canaryStartedAt, rollout.waveStartedAt);
  if (index === 0) return { stage: 0, regions: [active] };
  const completed = sequence.slice(0, index).map((region) => progressEntry(region, "succeeded", undefined, undefined));
  return { stage: 1, regions: [...completed, active] };
}

export function regionRunsTarget(rollout: RolloutInfo, sequence: string[], region: string): boolean {
  const { regions } = stageProgress(rollout, sequence);
  const phase = regions.find((entry) => entry.region === region)?.phase;
  return phase === "waves" || phase === "succeeded";
}

export function bakingStartTimes(rollout: RolloutInfo): number[] {
  if (rollout.regionProgress === undefined) {
    return rollout.phase === "baking" && rollout.canaryStartedAt !== undefined ? [rollout.canaryStartedAt] : [];
  }
  return rollout.regionProgress.flatMap((entry) =>
    entry.phase === "baking" && entry.canaryStartedAt !== undefined ? [entry.canaryStartedAt] : []
  );
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
  const stages = rolloutStages(ordered);
  const rollout: RolloutInfo = {
    id: `${service.name}-${nowMs.toString(36)}`,
    serviceName: service.name,
    targetImage,
    previousImage: service.image,
    phase: "pending",
    currentWave: 0,
    totalWaves: stages.length,
    baselineP95Ms,
    baseline5xxPct,
    startedAt: nowMs,
    regionOrder: ordered,
    activeRegions: stages[0] ?? [],
    regionProgress: [],
  };
  const first = ordered[0];
  if (first !== undefined) rollout.currentRegion = first;
  if (regions.length === 1 && first !== undefined) rollout.region = first;
  return rollout;
}

const ACTIVE_REGION_RANK: Readonly<Record<ActiveRegionPhase, number>> = {
  canary: 0,
  baking: 1,
  waves: 2,
};

class Stepper {
  updates: RolloutStep["imageUpdates"] = [];
  readonly events: RolloutEvent[] = [];
  state: RolloutInfo;
  readonly sequence: string[];
  readonly stages: string[][];
  readonly nodesById: Map<string, NodeInfo>;
  stage: number;
  progress: Map<string, RolloutRegionProgress>;

  constructor(readonly ctx: RolloutContext) {
    this.state = { ...ctx.rollout };
    this.sequence = rolloutSequence(ctx.rollout, ctx.service, ctx.rolloutOrder);
    this.stages = rolloutStages(this.sequence);
    this.nodesById = new Map(ctx.nodes.map((node) => [node.id, node]));
    const { stage, regions } = stageProgress(ctx.rollout, this.sequence);
    this.stage = stage;
    this.progress = new Map(regions.map((entry) => [entry.region, { ...entry }]));
  }

  finished(): boolean {
    return TERMINAL.has(this.state.phase);
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

  startRegion(region: string): void {
    const placements = this.regionPlacements(region);
    const canary = placements.find((p) => p.desiredImage !== this.state.targetImage) ?? placements[0];
    if (canary === undefined) {
      this.progress.set(region, progressEntry(region, "skipped", undefined, undefined));
      return;
    }
    this.setImage(canary, this.state.targetImage);
    this.progress.set(region, progressEntry(region, "canary", this.ctx.nowMs, undefined));
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
    this.events.push(
      event("rollout_succeeded", this.state.serviceName, { rolloutId: this.state.id, image: this.state.targetImage }),
    );
  }

  abort(region: string, reason: string, detail: Record<string, unknown>): void {
    const previous = this.state.previousImage;
    const target = this.state.targetImage;
    this.updates = this.updates.filter((update) => update.targetImage !== target);
    if (previous !== undefined) {
      for (const placement of this.ctx.placements) {
        if (placement.serviceName !== this.state.serviceName) continue;
        if (this.state.region !== undefined && placement.region !== this.state.region) continue;
        if (placement.desiredImage === target) this.setImage(placement, previous);
      }
    }
    this.state.phase = previous === undefined ? "failed" : "rolled_back";
    this.state.finishedAt = this.ctx.nowMs;
    this.state.currentRegion = region;
    this.state.error = reason;
    this.events.push(
      event(
        previous === undefined ? "rollout_failed" : "rollback",
        this.state.serviceName,
        { rolloutId: this.state.id, reason, targetImage: target, previousImage: previous, ...detail },
        region,
      ),
    );
  }

  canaryOf(placements: PlacementInfo[]): PlacementInfo | undefined {
    return placements.find((p) => p.desiredImage === this.state.targetImage);
  }

  run(): void {
    if (this.state.phase === "pending") {
      this.events.push(
        event("deploy_started", this.state.serviceName, {
          rolloutId: this.state.id,
          image: this.state.targetImage,
          regions: this.sequence,
          stages: this.stages,
        }),
      );
    }
    this.advance();
    this.publish();
  }

  advance(): void {
    for (;;) {
      const scope = this.stages[this.stage];
      if (scope === undefined) {
        this.succeed();
        return;
      }
      for (const region of scope) {
        const entry = this.progress.get(region);
        if (entry === undefined) this.startRegion(region);
        else if (!regionDone(entry)) this.stepRegion(entry);
        if (this.finished()) return;
      }
      if (!scope.every((region) => regionDone(this.progress.get(region)))) return;
      if (this.stage + 1 >= this.stages.length) {
        this.succeed();
        return;
      }
      this.stage += 1;
    }
  }

  publish(): void {
    const entries = this.sequence.flatMap((region) => {
      const entry = this.progress.get(region);
      return entry === undefined ? [] : [progressEntry(region, entry.phase, entry.canaryStartedAt, entry.waveStartedAt)];
    });
    this.state.regionOrder = this.sequence;
    this.state.currentWave = this.state.phase === "succeeded" ? this.stages.length : this.stage;
    this.state.totalWaves = this.stages.length;
    this.state.regionProgress = entries;
    if (this.finished()) {
      delete this.state.activeRegions;
      delete this.state.waveStartedAt;
      return;
    }
    const active = entries.flatMap((entry) => {
      const phase = activeRegionPhase(entry.phase);
      return phase === undefined ? [] : [{ entry, phase }];
    });
    this.state.activeRegions = active.map(({ entry }) => entry.region);
    const lead = active.reduce<(typeof active)[number] | undefined>(
      (best, item) => (best === undefined || ACTIVE_REGION_RANK[item.phase] < ACTIVE_REGION_RANK[best.phase] ? item : best),
      undefined,
    );
    if (lead === undefined) return;
    this.state.phase = lead.phase;
    this.state.currentRegion = lead.entry.region;
    if (lead.entry.canaryStartedAt === undefined) delete this.state.canaryStartedAt;
    else this.state.canaryStartedAt = lead.entry.canaryStartedAt;
    if (lead.entry.waveStartedAt === undefined) delete this.state.waveStartedAt;
    else this.state.waveStartedAt = lead.entry.waveStartedAt;
  }

  stepRegion(entry: RolloutRegionProgress): void {
    const region = entry.region;
    const placements = this.regionPlacements(region);
    const target = this.state.targetImage;

    if (entry.phase === "canary") {
      const canary = this.canaryOf(placements);
      if (canary === undefined) {
        this.startRegion(region);
        return;
      }
      if (targetFailed(canary, target)) {
        const detail: Record<string, unknown> = { placementId: canary.id };
        if (candidateFailed(canary, target)) detail.error = canary.candidateError;
        this.abort(region, "canary_failed", detail);
        return;
      }
      if (runningTarget(canary, target)) {
        entry.phase = "baking";
        entry.canaryStartedAt = this.ctx.nowMs;
        return;
      }
      const startedAt = entry.canaryStartedAt ?? this.ctx.nowMs;
      const limit = this.ctx.service.readyTimeoutSeconds * 1000 + CANARY_READY_GRACE_MS;
      if (this.ctx.nowMs - startedAt > limit) this.abort(region, "canary_not_ready", { placementId: canary.id });
      return;
    }

    if (entry.phase === "baking") {
      const canary = this.canaryOf(placements);
      if (canary === undefined || targetFailed(canary, target)) {
        const detail: Record<string, unknown> = canary === undefined ? {} : { placementId: canary.id };
        if (canary !== undefined && candidateFailed(canary, target)) detail.error = canary.candidateError;
        this.abort(region, "canary_failed", detail);
        return;
      }
      if (!runningTarget(canary, target)) {
        this.abort(region, "canary_lost_readiness", { placementId: canary.id });
        return;
      }
      entry.canaryStartedAt ??= this.ctx.nowMs;
      const sample = canary.nodeId === undefined ? undefined : this.ctx.latestMetricsByNode.get(canary.nodeId);
      const serviceMetrics = sample?.services.find((metrics) => metrics.serviceName === this.state.serviceName);
      const metrics = sample !== undefined && sample.ts - sample.windowSeconds * 1000 >= entry.canaryStartedAt
        ? serviceMetrics
        : undefined;
      const breach = canaryBreach(metrics, this.state);
      if (breach !== null) {
        this.abort(region, `canary_${breach.metric}_breach`, {
          placementId: canary.id,
          metric: breach.metric,
          value: breach.value,
          threshold: breach.threshold,
        });
        return;
      }
      const elapsed = this.ctx.nowMs - entry.canaryStartedAt;
      if (elapsed < (this.ctx.canaryBakeMs ?? DEFAULT_CANARY_BAKE_MS)) return;
      const evaluatedTraffic = (metrics?.requests ?? 0) >= MIN_CANARY_REQUESTS;
      const expectsTrafficMetrics = serviceMetrics !== undefined ||
        this.ctx.service.hostnames.length > 0 || this.ctx.service.internalPort !== undefined;
      if (!evaluatedTraffic && expectsTrafficMetrics && elapsed < MAX_CANARY_BAKE_MS) return;
      entry.phase = "waves";
      delete entry.waveStartedAt;
      this.events.push(
        event("canary_passed", this.state.serviceName, {
          rolloutId: this.state.id,
          placementId: canary.id,
          requests: metrics?.requests ?? 0,
          evaluatedTraffic,
        }, region),
      );
    }

    if (entry.phase === "waves") {
      const inflight = placements.filter((p) => p.desiredImage === target && !runningTarget(p, target));
      const failed = inflight.find((p) => targetFailed(p, target));
      if (failed !== undefined) {
        const detail: Record<string, unknown> = { placementId: failed.id };
        if (candidateFailed(failed, target)) detail.error = failed.candidateError;
        this.abort(region, "wave_failed", detail);
        return;
      }
      if (inflight.length > 0) {
        entry.waveStartedAt ??= entry.canaryStartedAt ?? this.state.startedAt;
        const limit = Math.min(this.ctx.service.readyTimeoutSeconds * 1000 + CANARY_READY_GRACE_MS, MAX_WAVE_READY_MS);
        if (this.ctx.nowMs - entry.waveStartedAt >= limit) {
          this.abort(region, "wave_not_ready", { placementIds: inflight.map((p) => p.id) });
        }
        return;
      }
      delete entry.waveStartedAt;
      const pending = placements.filter((p) => p.desiredImage !== target);
      if (pending.length === 0) {
        entry.phase = "succeeded";
        return;
      }
      const size = Math.max(1, Math.ceil(placements.length * WAVE_FRACTION));
      for (const placement of pending.slice(0, size)) this.setImage(placement, target);
      entry.waveStartedAt = this.ctx.nowMs;
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
  delete state.activeRegions;
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
