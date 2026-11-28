import { DurableObject } from "cloudflare:workers";
import { atlasStub } from "./atlas-do";
import { ATLAS_REQUIRED_SERVICES, b64urlDecode, b64urlEncode, validateAtlasPlacement, validateAtlasTopology } from "./atlas-pin";
import {
  checkEnrollSecret,
  decodePrincipal,
  hashNodeToken,
  localDevAllowed,
  mintSshSession,
  newNodeToken,
  nodeBearer,
  parseAllowedSshKeys,
  PRINCIPAL_HEADER,
  randomToken,
  sessionSecret,
  sha256Hex,
  SSH_CHALLENGE_TTL_MS,
  SSH_NAMESPACE,
  verifyNodeToken,
  verifySshLogin,
  type Principal,
} from "./auth";
import {
  actionBackedOff,
  activePlacementCount,
  actionFailureExpired,
  autoscaleActionKey,
  DATA_VOLUME_ID_LABEL,
  evaluateAutoscale,
  hasVolumeGrowthBudget,
  INSTANCE_ID_LABEL,
  INSTANCE_POOL_ID_LABEL,
  cooled,
  oldestUnjoinedMember,
  planPoolScaleUp,
  PENDING_HELLO_GRACE_MS,
  POOL_ENROLLMENT_FAILURE_BACKOFF_MS,
  POOL_ENROLLMENT_GRACE_MS,
  POOL_UP_COOLDOWN_MS,
  REAPED_INSTANCE_TOMBSTONE_MS,
  poolEnrollmentFailureKey,
  poolScaleDownCooldownKey,
  poolScaleUpCooldownKey,
  VOLUME_GROW_GIB,
  VOLUME_MAX_GIB,
  VOLUME_SUSTAIN_MS,
  VOLUME_USAGE_THRESHOLD_PCT,
  hasStableVolumeIdentity,
  isOciInstanceId,
  nextActionFailure,
  poolListFailureKey,
  reapUnjoinedFailureKey,
  restoresWorkerFloor,
  sustainedDataDisk,
  terminateWorkerFailureKey,
  volumeGrowCooldownKey,
  volumeGrowTarget,
  volumeReachedTarget,
  WORKER_POOL_MAX,
  workerPoolBoundsOf,
  type ActionFailure,
  type AutoscaleAction,
  type DataDiskPoint,
  type VolumeGrowTarget,
} from "./autoscaler";
import type { Env } from "./env";
import { isOciRegion, OciError, ociVolumeReady, OciRestClient, type OciDataVolume, type PoolInstance } from "./oci-client";
import type {
  AgentMessage,
  AtlasPlacement,
  AtlasRegion,
  AtlasTopology,
  BackplaneMessage,
  ChaosRequest,
  ConfigFileSpec,
  ContainerMetrics,
  CpuArch,
  DeployRequest,
  DesiredPlacement,
  DiffItem,
  EdgeMetricsSnapshot,
  EdgeServiceMetrics,
  ErrorCode,
  ErrorResponse,
  EventKind,
  EventRecord,
  ExecRequest,
  ExecResponse,
  FleetConfig,
  HealthState,
  HeartbeatMessage,
  HelloMessage,
  HttpRouteRule,
  MetricsPoint10s,
  MetricsPoint1m,
  NetBirdConfig,
  NodeEnrollRequest,
  NodeEnrollResponse,
  NodeInfo,
  NodeStatus,
  PlacementInfo,
  PlacementMode,
  PlacementReport,
  PlacementState,
  PoolKind,
  PriorityTier,
  RegionConfig,
  RegionSummary,
  RollbackRequest,
  RolloutInfo,
  RolloutPhase,
  RolloutRegionProgress,
  ServiceSpec,
  ServiceSummary,
  SshChallengeRequest,
  SshChallengeResponse,
  SshVerifyRequest,
  SshVerifyResponse,
  StatusResponse,
  TlsBundle,
  TopResponse,
  VolumeInfo,
} from "./protocol";
import {
  advanceRollout,
  bakingStartTimes,
  createRollout,
  DEFAULT_CANARY_BAKE_MS,
  MAX_CANARY_BAKE_MS,
  orderRegions,
  rollbackRollout,
  type NodeEdgeMetrics,
  type RolloutStep,
} from "./rollout";
import {
  allocatableCpuMilli,
  allocatableMemMiB,
  computeClusterPeers,
  computeRoutes,
  computeSchedule,
  DATA_VOLUME_PATH,
  DEFAULT_HEARTBEAT_TIMEOUT_MS,
  expandRegionTemplate,
  nodeAlive,
  type ScheduleResult,
  type UnschedulableEntry,
} from "./scheduler";
import { ensureCertificate, LETS_ENCRYPT_DIRECTORY, type AcmeAccountState, type TlsManagerConfig } from "./tls-manager";

export const FLEET_DO_NAME = "fleet";

export function fleetStub(env: Env): DurableObjectStub {
  return env.FLEET_DO.get(env.FLEET_DO.idFromName(FLEET_DO_NAME), { locationHint: env.FLEET_DO_LOCATION_HINT });
}

const ALARM_INTERVAL_MS = 10_000;
const IDLE_ALARM_INTERVAL_MS = 30_000;
const METRICS_10S_RETENTION_MS = 3600_000;
const METRICS_1M_RETENTION_MS = 48 * 3600_000;
const MINUTE_MS = 60_000;
const PRUNE_INTERVAL_MS = MINUTE_MS;
const EVENTS_KEEP = 2000;
const ROLLOUT_HISTORY_KEEP = 200;
const SERVICE_ROLLBACK_HISTORY_KEEP = 20;
const TOPOLOGY_REFRESH_MS = 20_000;
const AUTOSCALE_INTERVAL_MS = 30_000;
const EDGE_FRESH_MS = 30_000;
const BASELINE_WINDOW_MS = 300_000;
const EXEC_MAX_SECONDS = 120;
const LOG_IDLE_MS = 2_000;
const LOG_FIRST_MS = 5_000;
const LOG_MAX_MS = 30_000;
const STREAM_MAX_MS = 3600_000;
const KEEPALIVE_MS = 15_000;
const MAX_JSON_BYTES = 1024 * 1024;
const MAX_NODE_FRAME_BYTES = 64 * 1024;
const MAX_EXEC_RESULT_FRAME_BYTES = 16 * 1024 * 1024;
const MIN_HEARTBEAT_INTERVAL_MS = 5000;
const MAX_CHALLENGES = 1000;
const MAX_CHALLENGES_PER_IP = 5;
const VOLUME_GROW_RETRY_MS = 15_000;
const VOLUME_GROW_MAX_MS = 30 * 60_000;

function volumeGrowExpired(at: number, now: number): boolean {
  return now - at > VOLUME_GROW_MAX_MS;
}
const GROW_VOLUME_ID_CAPABILITY = "grow_volume_id";
const VOLUME_ATTACH_SKEW_MS = 60_000;
const VOLUME_RECONCILE_PROBE_MS = 30_000;
const VOLUME_RECONCILE_RETRY_MS = 600_000;
const VOLUME_RECONCILE_PERIODIC_MS = 15 * 60 * 1000;
const MAX_VOLUME_OPS = 2;
const MAX_BACKGROUND_RECONCILES = 1;
const TLS_RETRY_BACKOFF_MS = 60_000;
const DEFAULT_PROD_TLS_DOMAINS = [
  "*.terrascale.tech",
  "*.api.terrascale.tech",
  "*.pg.terrascale.tech",
  "*.auth.terrascale.tech",
];
const TERMINAL_PHASES: ReadonlySet<RolloutPhase> = new Set(["succeeded", "rolled_back", "failed"]);
const INACTIVE_PLACEMENT_STATES: ReadonlySet<PlacementState> = new Set(["stopped", "failed", "unschedulable"]);
const EVENT_KINDS: ReadonlySet<string> = new Set<EventKind>([
  "deploy_started",
  "canary_started",
  "canary_passed",
  "rollback",
  "rollout_succeeded",
  "rollout_failed",
  "replica_scale_up",
  "replica_scale_down",
  "pool_scale_up",
  "pool_scale_down",
  "pool_worker_replaced",
  "pool_scale_blocked",
  "node_enrolled",
  "node_connected",
  "node_lost",
  "node_drained",
  "failover",
  "oom_kill",
  "volume_grown",
  "container_exec",
  "secret_rotated",
  "tls_renewed",
  "chaos",
]);
const PLACEMENT_STATES: ReadonlySet<string> = new Set<PlacementState>([
  "pending",
  "unschedulable",
  "pulling",
  "starting",
  "ready",
  "draining",
  "stopped",
  "failed",
]);
const MODES: ReadonlySet<string> = new Set<PlacementMode>(["daemon", "replicated", "stateful"]);
const PRIORITIES: ReadonlySet<string> = new Set<PriorityTier>(["high", "normal", "low"]);
const NAME_RE = /^[a-z][a-z0-9-]{0,62}$/;
const REGION_RE = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

type NodeRow = {
  id: string;
  region: string;
  pool_kind: string;
  vcn_ip: string;
  netbird_ip: string | null;
  arch: string;
  shape: string;
  fault_domain: string;
  cpu_total_m: number;
  mem_total_mib: number;
  disk_total_gib: number;
  labels_json: string;
  volumes_json: string;
  volumes_verified: number;
  volumes_verified_at: number;
  token_hash: string | null;
  status: string;
  drain_requested: number;
  drain_reason: string | null;
  last_seen_at: number;
  last_heartbeat_at: number;
  agent_version: string;
  enrolled_at: number;
};

type PlacementRow = {
  id: string;
  service_name: string;
  region: string;
  node_id: string | null;
  slot: number;
  desired_image: string;
  desired_config_hash: string | null;
  active_image: string | null;
  active_config_hash: string | null;
  host_port: number | null;
  postgres_host_port: number | null;
  internal_host_port: number | null;
  candidate_image: string | null;
  candidate_error: string | null;
  state: string;
  error: string | null;
  updated_at: number;
};

type ServiceRow = {
  name: string;
  mode: string;
  priority: string;
  image: string;
  spec_json: string;
  config_version: number;
  updated_at: number;
};

type RegionRow = {
  label: string;
  oci_region: string;
  compartment_id: string;
  instance_pool_id: string | null;
  min_workers: number;
  max_workers: number;
  rollout_order: number;
  config_json: string;
  updated_at: number;
};

type RolloutRow = {
  id: string;
  service_name: string;
  target_image: string;
  previous_image: string | null;
  state: string;
  current_region: string | null;
  wave_json: string;
  baseline_p95_ms: number | null;
  baseline_5xx_pct: number | null;
  canary_started_at: number | null;
  started_at: number;
  finished_at: number | null;
  error: string | null;
};

type Metrics10Row = {
  node_id: string;
  ts: number;
  cpu_pct: number;
  cpu_psi_10: number;
  mem_used_mib: number;
  mem_psi_10: number;
  disk_used_pct: number;
  net_rx_bps: number;
  net_tx_bps: number;
  containers_json: string;
  edge_json: string | null;
};

type Metrics1mRow = {
  node_id: string;
  ts: number;
  cpu_avg: number;
  cpu_p95: number;
  cpu_psi_avg: number;
  mem_avg_mib: number;
  disk_pct: number;
  edge_rps: number;
  edge_5xx: number;
  edge_p95_ms: number;
};

type EventRow = {
  id: number;
  ts: number;
  kind: string;
  region: string | null;
  subject: string;
  detail_json: string;
};

type TlsRow = {
  id: string;
  domains_json: string;
  cert_pem: string;
  key_pem_enc: string;
  not_after: number;
  renewed_at: number;
};

type ChallengeRow = { id: string; fingerprint: string; nonce: string; expires_at: number };
type StateRow = { value: string };
type CountRow = { count: number };

interface Attachment {
  nodeId: string;
  region: string;
  poolKind: PoolKind;
  sessionId: string;
  volumesVerified: boolean;
  growVolumeId: boolean;
  lastVolumeSeq: number;
  volumeReconcileScheduled: boolean;
}

type SessionVolumeState = Pick<Attachment, "volumesVerified" | "growVolumeId" | "lastVolumeSeq" | "volumeReconcileScheduled">;

function sessionVerified(ws: WebSocket): boolean {
  const attachment = ws.deserializeAttachment() as Attachment | null;
  return ws.readyState === WebSocket.OPEN && attachment?.volumesVerified === true && attachment.growVolumeId === true;
}

function updateSessionVolumes(ws: WebSocket, attachment: Attachment, change: Partial<SessionVolumeState>): void {
  const current = ws.deserializeAttachment() as Attachment | null;
  Object.assign(attachment, change);
  if (current !== null) ws.serializeAttachment({ ...current, ...change });
}

function markSessionVolumes(ws: WebSocket, attachment: Attachment, verified: boolean): void {
  if ((ws.deserializeAttachment() as Attachment | null)?.volumesVerified === verified) return;
  updateSessionVolumes(ws, attachment, { volumesVerified: verified });
}

function acceptVolumeSeq(ws: WebSocket, attachment: Attachment, volumeSeq: unknown): boolean {
  const current = ws.deserializeAttachment() as Attachment | null;
  if (current === null) return false;
  if (volumeSeq === undefined && !current.growVolumeId) return true;
  if (typeof volumeSeq !== "number" || !Number.isSafeInteger(volumeSeq) || volumeSeq <= current.lastVolumeSeq) return false;
  updateSessionVolumes(ws, attachment, { lastVolumeSeq: volumeSeq });
  return true;
}

interface ChaosState {
  fiveXx: Record<string, { ratePct: number; until: number }>;
  cpu: Record<string, { cpuPct: number; until: number }>;
  disk: Record<string, { usedPct: number }>;
}

interface AtlasPlacementChaos {
  kind: "atlas_placement";
  project: string;
  database: string;
  region: string | null;
}

interface AtlasRoundtripChaos {
  kind: "atlas_roundtrip";
  project?: string;
  database?: string;
  region?: string;
}

type DevChaosRequest = ChaosRequest | AtlasPlacementChaos | AtlasRoundtripChaos;

interface LogRequest {
  streamId: string;
  nodeId: string;
  placementId: string;
}

interface LogStream {
  writer: WritableStreamDefaultWriter<Uint8Array>;
  sse: boolean;
  follow: boolean;
  requests: Set<string>;
  idleTimer: ReturnType<typeof setTimeout> | undefined;
  maxTimer: ReturnType<typeof setTimeout> | undefined;
  keepAlive: ReturnType<typeof setInterval> | undefined;
  closed: boolean;
}

interface ExecWaiter {
  nodeId: string;
  resolve: (result: ExecResponse | null) => void;
}

interface EventSubscriber {
  region: string | null;
  push: (event: EventRecord) => void;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    message: string,
    readonly fix?: string,
  ) {
    super(message);
  }
}

const encoder = new TextEncoder();

function json(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function errorJson(status: number, code: ErrorCode, message: string, fix?: string): Response {
  const body: ErrorResponse = { error: fix === undefined ? { code, message } : { code, message, fix } };
  return json(body, status);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseLabels(raw: string | null): Record<string, string> {
  const parsed = parseJson<unknown>(raw, null);
  if (!isRecord(parsed)) return {};
  return Object.fromEntries(Object.entries(parsed).filter((entry): entry is [string, string] => typeof entry[1] === "string"));
}

function parseJson<T>(text: string | null, fallback: T): T {
  if (text === null || text.length === 0) return fallback;
  try {
    return JSON.parse(text) as T;
  } catch {
    return fallback;
  }
}

function finite(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function positiveInt(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : fallback;
}

function stringArray(value: unknown): string[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return null;
  return value as string[];
}

function stringRecord(value: unknown): Record<string, string> | null {
  if (value === undefined) return {};
  if (!isRecord(value)) return null;
  const out: Record<string, string> = {};
  for (const [key, item] of Object.entries(value)) {
    if (typeof item !== "string") return null;
    out[key] = item;
  }
  return out;
}

function average(values: number[]): number {
  return values.length === 0 ? 0 : values.reduce((sum, value) => sum + value, 0) / values.length;
}

function percentile(values: number[], pct: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.max(0, Math.ceil((pct / 100) * sorted.length) - 1))] ?? 0;
}

function round(value: number, digits = 1): number {
  const factor = 10 ** digits;
  return Math.round(value * factor) / factor;
}

function tcpPort(value: unknown): number | null {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= 65535 ? value : null;
}

const SWAP_PROGRESS: ReadonlySet<string> = new Set(["pending", "pulling", "starting"]);

function holdServing(row: PlacementRow, report: PlacementReport): boolean {
  if (row.state !== "ready" || tcpPort(row.host_port) === null) return false;
  return SWAP_PROGRESS.has(report.state);
}

type WorkerLabelRow = { id: string; region: string; status: string; enrolled_at: number; token_hash: string | null; labels_json: string; labels: Record<string, string> };

type PoolVerification = "verified" | "not_member" | "unavailable";

const INSTANCE_ID_SQL = `CASE WHEN json_valid(labels_json) THEN json_extract(labels_json, '$."oci.instance-id"') END`;

function reapedInstanceKey(instanceId: string): string {
  return `reaped_instance:${instanceId}`;
}

const OCI_RETRY_TOKEN_TTL_MS = 86_400_000;
const DETACHED_INSTANCE_TOMBSTONE_MS = 86_400_000;
const FAILED_WORK_REQUEST_STATES: ReadonlySet<string> = new Set(["FAILED", "CANCELED"]);
const SETTLED_WORK_REQUEST_STATES: ReadonlySet<string> = new Set([...FAILED_WORK_REQUEST_STATES, "MISSING"]);
const MAX_PENDING_DETACH_LOOKUPS = 2;
const POOL_PAGE_STATE_TTL_MS = 300_000;

type PoolListing = { items: readonly PoolInstance[]; startedAt: number };
type PoolListings = Map<string, PoolListing | null>;

type PendingDetach = {
  kind: "reap" | "terminate";
  nodeId?: string;
  tokenHash: string | null;
  region: string;
  ociRegion: string;
  compartmentId: string;
  poolId: string;
  instanceId: string;
  decrementSize: boolean;
  retryToken: string;
  ambiguous: boolean;
  accepted: boolean;
  workRequestId: string | null;
  reason: string;
  createdAt: number;
  dispatchedAt: number;
  workRequestState?: string;
  instanceCreatedAt?: number;
  penalizeScaleUp?: boolean;
};

function definitelyRejected(error: unknown): boolean {
  return error instanceof OciError && error.status >= 400 && error.status < 500 &&
    error.status !== 408 && error.status !== 409 && error.status !== 429;
}

function pendingDetachKey(instanceId: string): string {
  return `pending_detach:${instanceId}`;
}

function workerJoinedAtKey(region: string): string {
  return `worker_joined_at:${region}`;
}

function terminating(): HttpError {
  return new HttpError(409, "conflict", "The instance is being terminated", "Boot a new instance instead of reusing this one.");
}

function detailStrings(detail: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(detail)) {
    if (value === undefined) continue;
    out[key] = typeof value === "string" ? value : JSON.stringify(value);
  }
  return out;
}

function requiredToken(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed.length === 0 || /\s/.test(trimmed)) return null;
  return trimmed;
}

function isLoopbackHost(hostname: string): boolean {
  const bare = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  const host = bare.endsWith(".") ? bare.slice(0, -1).toLowerCase() : bare.toLowerCase();
  if (host === "localhost" || host === "::1" || host === "0:0:0:0:0:0:0:1") return true;
  const parts = host.split(".");
  if (parts.length !== 4 || !parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part))) return false;
  const octets = parts.map((part) => Number(part));
  return octets.every((octet) => octet <= 255) && octets[0] === 127;
}

function isManagementUrl(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.username !== "" || url.password !== "" || url.hostname.length === 0) return false;
  if (url.protocol === "https:") return true;
  return url.protocol === "http:" && isLoopbackHost(url.hostname);
}

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    const octet = Number(part);
    return Number.isInteger(octet) && octet >= 0 && octet <= 255 && String(octet) === part;
  });
}

function vcnAddress(ip: string, cidr: string | undefined, localDev: boolean): boolean {
  if (!isIpv4(ip)) return false;
  if (localDev && isLoopbackHost(ip)) return true;
  const [first, second = 0] = ip.split(".").map(Number);
  if (!(first === 10 || (first === 172 && second >= 16 && second <= 31) || (first === 192 && second === 168))) return false;
  if (typeof cidr !== "string" || !isCidr(cidr)) return false;
  const slash = cidr.indexOf("/");
  const network = cidr.slice(0, slash);
  if (!isIpv4(network)) return false;
  const asNumber = (address: string) => address.split(".").reduce((sum, octet) => sum * 256 + Number(octet), 0);
  const hostRange = 2 ** (32 - Number(cidr.slice(slash + 1)));
  return Math.floor(asNumber(ip) / hostRange) === Math.floor(asNumber(network) / hostRange);
}

async function nodeIdFor(instanceId: string, region: string, poolKind: string): Promise<string> {
  if (/^[a-z0-9][a-z0-9-]{0,47}$/.test(instanceId)) return instanceId;
  return `${region}-${poolKind === "stateful" ? "s" : "w"}-${(await sha256Hex(instanceId)).slice(0, 10)}`;
}

function withVolumeUsage(volumesJson: string, poolKind: string, usedPct: number): string {
  const volumes = parseJson<VolumeInfo[]>(volumesJson, []);
  let found = false;
  for (const volume of volumes) {
    if (volume.mountPath === DATA_VOLUME_PATH) {
      volume.usedPct = usedPct;
      found = true;
    }
  }
  if (!found && poolKind === "stateful") {
    volumes.push({ mountPath: DATA_VOLUME_PATH, device: "/dev/oracleoci/oraclevdb", sizeGiB: 50, usedPct });
  }
  return JSON.stringify(volumes);
}

function reportedVolumes(value: unknown): string | null {
  if (!Array.isArray(value)) return null;
  const volumes: VolumeInfo[] = [];
  for (const entry of value) {
    if (!isRecord(entry) || typeof entry.mountPath !== "string" || typeof entry.device !== "string") continue;
    const { identity } = entry;
    volumes.push({
      mountPath: entry.mountPath,
      device: entry.device,
      sizeGiB: finite(entry.sizeGiB),
      usedPct: finite(entry.usedPct),
      ...(typeof identity === "string" && identity.trim().length > 0 ? { identity } : {}),
    });
  }
  return JSON.stringify(volumes);
}

function sameVolume(live: VolumeInfo, target: VolumeGrowTarget): boolean {
  return (
    hasStableVolumeIdentity(live.identity) &&
    live.mountPath === target.mountPath &&
    live.device === target.device &&
    live.identity === target.identity
  );
}

type PendingVolumeGrow = {
  at: number;
  lastAttemptAt: number;
  previousSizeGiB: number;
  newSizeGiB: number;
  reason: string;
  volumeId: string;
  attachmentId: string;
  tokenHash: string | null;
  target: VolumeGrowTarget;
};

interface VolumeReconcileMarker {
  nextAt: number;
}

function measuredGiB(sizeGiB: unknown): sizeGiB is number {
  return typeof sizeGiB === "number" && Number.isFinite(sizeGiB) && sizeGiB > 0;
}

type VolumeResizeTarget = { targetSizeGiB: number; expiresAt: number };

function volumeResizeTarget(value: unknown): VolumeResizeTarget | null {
  if (!isRecord(value) || typeof value.targetSizeGiB !== "number" || typeof value.expiresAt !== "number") return null;
  return { targetSizeGiB: value.targetSizeGiB, expiresAt: value.expiresAt };
}

function volumeReconcileMarker(value: unknown): VolumeReconcileMarker {
  return { nextAt: isRecord(value) && typeof value.nextAt === "number" ? value.nextAt : 0 };
}

function pendingVolumeGrow(value: unknown): PendingVolumeGrow | null {
  if (!isRecord(value) || !isRecord(value.target)) return null;
  const { target } = value;
  if (typeof target.mountPath !== "string" || typeof target.device !== "string" || !hasStableVolumeIdentity(target.identity)) return null;
  if (
    typeof value.at !== "number" ||
    typeof value.lastAttemptAt !== "number" ||
    typeof value.previousSizeGiB !== "number" ||
    typeof value.newSizeGiB !== "number" ||
    typeof value.reason !== "string" ||
    typeof value.volumeId !== "string" ||
    typeof value.attachmentId !== "string" ||
    value.attachmentId.length === 0 ||
    (value.tokenHash !== null && typeof value.tokenHash !== "string")
  ) {
    return null;
  }
  return {
    at: value.at,
    lastAttemptAt: value.lastAttemptAt,
    previousSizeGiB: value.previousSizeGiB,
    newSizeGiB: value.newSizeGiB,
    reason: value.reason,
    volumeId: value.volumeId,
    attachmentId: value.attachmentId,
    tokenHash: value.tokenHash,
    target: { mountPath: target.mountPath, device: target.device, identity: target.identity },
  };
}

type AttachedVolume = { attachmentId: string; id: string; device: string; sizeGiB: number; attachedAt: number };

type VolumeBindingRecord = { attachmentId: string; volumeId: string; device: string; identity: string };

type VolumeBindingChallenge = VolumeBindingRecord & { mountPath: string; challenge: string; sessionId: string; volumeSeq: number; ociSizeGiB: number };

function volumeBindingRecord(value: unknown): VolumeBindingRecord | null {
  if (!isRecord(value) || typeof value.attachmentId !== "string" || typeof value.volumeId !== "string" ||
    typeof value.device !== "string" || !hasStableVolumeIdentity(value.identity)) return null;
  return { attachmentId: value.attachmentId, volumeId: value.volumeId, device: value.device, identity: value.identity };
}

function volumeBindingChallenge(value: unknown): VolumeBindingChallenge | null {
  const record = volumeBindingRecord(value);
  if (record === null || !isRecord(value) || typeof value.mountPath !== "string" || value.mountPath.length === 0 ||
    typeof value.challenge !== "string" || value.challenge.length === 0 ||
    typeof value.sessionId !== "string" || value.sessionId.length === 0 ||
    typeof value.volumeSeq !== "number" || !Number.isSafeInteger(value.volumeSeq) ||
    typeof value.ociSizeGiB !== "number" || !Number.isFinite(value.ociSizeGiB)) return null;
  return { ...record, mountPath: value.mountPath, challenge: value.challenge, sessionId: value.sessionId, volumeSeq: value.volumeSeq, ociSizeGiB: value.ociSizeGiB };
}

function sameBinding(left: VolumeBindingRecord, right: VolumeBindingRecord): boolean {
  return left.attachmentId === right.attachmentId && left.volumeId === right.volumeId &&
    left.device === right.device && left.identity === right.identity;
}

type VolumeBindingCheck = "bound" | "stale" | "conflict";

function sameAttachedVolume(left: VolumeBindingRecord, right: VolumeBindingRecord): boolean {
  return left.volumeId === right.volumeId && left.device === right.device && left.identity === right.identity;
}

type DataVolumeLookup =
  | { kind: "unavailable" }
  | { kind: "stale" }
  | { kind: "found"; volume: OciDataVolume; instanceId: string; bound: { row: NodeRow; target: VolumeInfo }; guestSizeGiB: number };

type FoundDataVolume = Extract<DataVolumeLookup, { kind: "found" }>;

function guestBehindOci(guestSizeGiB: number, volume: OciDataVolume): boolean {
  return guestSizeGiB > 0 && !volumeReachedTarget(guestSizeGiB, volume.sizeGiB);
}

function growVolumeCommand({ volumeId, target }: PendingVolumeGrow): BackplaneMessage {
  return {
    type: "grow_volume",
    mountPath: target.mountPath,
    volumeId,
    device: target.device,
    volumeIdentity: target.identity,
  };
}

function metricsBucket(ts: number): number {
  return Math.floor(ts / 10_000) * 10_000;
}

function minuteBucket(ts: number): number {
  return Math.floor(ts / MINUTE_MS) * MINUTE_MS;
}

function ipv6GroupCount(part: string): number | null {
  if (part.length === 0) return 0;
  const groups = part.split(":");
  if (groups.some((group) => group.length === 0 || group.length > 4 || /[^0-9a-fA-F]/.test(group))) return null;
  return groups.length;
}

function isIpv6(value: string): boolean {
  if (value.length === 0 || value.includes(":::")) return false;
  const halves = value.split("::");
  if (halves.length > 2) return false;
  const left = ipv6GroupCount(halves[0] ?? "");
  if (left === null) return false;
  if (halves.length === 1) return left === 8;
  const right = ipv6GroupCount(halves[1] ?? "");
  return right !== null && left + right < 8;
}

function isCidr(value: string): boolean {
  const slash = value.indexOf("/");
  if (slash <= 0 || slash !== value.lastIndexOf("/")) return false;
  const address = value.slice(0, slash);
  const prefixText = value.slice(slash + 1);
  if (!/^(0|[1-9]\d{0,2})$/.test(prefixText)) return false;
  const prefix = Number(prefixText);
  if (address.includes(":")) return prefix <= 128 && isIpv6(address);
  return prefix <= 32 && isIpv4(address);
}

function parseNetBird(input: unknown): NetBirdConfig | string {
  if (!isRecord(input)) return "fleet.netbird must be an object";
  const managementUrl = requiredToken(input.managementUrl);
  if (managementUrl === null || !isManagementUrl(managementUrl)) {
    return "fleet.netbird.managementUrl must be an https URL or a loopback http URL";
  }
  const dnsDomain = requiredToken(input.dnsDomain);
  if (dnsDomain === null) return "fleet.netbird.dnsDomain is required";
  const networkRange = requiredToken(input.networkRange);
  if (networkRange === null || !isCidr(networkRange)) return "fleet.netbird.networkRange must be a CIDR";
  const setupKeySecret = requiredToken(input.setupKeySecret);
  if (setupKeySecret === null) return "fleet.netbird.setupKeySecret is required";
  const operatorsSetupKeySecret = requiredToken(input.operatorsSetupKeySecret);
  if (operatorsSetupKeySecret === null) return "fleet.netbird.operatorsSetupKeySecret is required";
  const adminPatSecret = requiredToken(input.adminPatSecret);
  if (adminPatSecret === null) return "fleet.netbird.adminPatSecret is required";
  const ownerEmail = requiredToken(input.ownerEmail);
  if (ownerEmail === null) return "fleet.netbird.ownerEmail is required";
  const ownerPasswordSecret = requiredToken(input.ownerPasswordSecret);
  if (ownerPasswordSecret === null) return "fleet.netbird.ownerPasswordSecret is required";
  return {
    managementUrl,
    dnsDomain,
    networkRange,
    setupKeySecret,
    operatorsSetupKeySecret,
    adminPatSecret,
    ownerEmail,
    ownerPasswordSecret,
  };
}

function parseAbsolutePaths(value: unknown, label: string): string[] | string {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return `${label} must be a list of non-empty paths starting with /`;
  const paths: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || item.length === 0 || !item.startsWith("/")) {
      return `${label} must be a list of non-empty paths starting with /`;
    }
    paths.push(item);
  }
  return paths;
}

function parseRegexList(value: unknown, label: string): string[] | string {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return `${label} must be a list of regular expressions`;
  const patterns: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || item.length === 0) return `${label} entries must be non-empty regular expressions`;
    try {
      new RegExp(item);
    } catch {
      return `${label} contains an invalid regular expression: ${item}`;
    }
    patterns.push(item);
  }
  return patterns;
}

function parseHttpMethods(value: unknown, label: string): string[] | string {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return `${label} must be a list of HTTP methods`;
  const methods: string[] = [];
  for (const item of value) {
    if (typeof item !== "string" || !/^[A-Za-z]+$/.test(item)) {
      return `${label} entries must be valid HTTP method names`;
    }
    methods.push(item.toUpperCase());
  }
  return methods;
}

function parseRouteRules(name: string, value: unknown): HttpRouteRule[] | string {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return `${name}: routeRules must be a list`;
  const rules: HttpRouteRule[] = [];
  for (const item of value) {
    if (!isRecord(item)) return `${name}: routeRules entries must be objects`;
    const patterns = parseRegexList(item.pathPatterns, `${name}: routeRules.pathPatterns`);
    if (typeof patterns === "string") return patterns;
    if (patterns.length === 0) return `${name}: routeRules entries require non-empty pathPatterns`;
    const methods = parseHttpMethods(item.methods, `${name}: routeRules.methods`);
    if (typeof methods === "string") return methods;
    const rule: HttpRouteRule = { pathPatterns: patterns };
    if (methods.length > 0) rule.methods = methods;
    rules.push(rule);
  }
  return rules;
}

function configTargetProblem(target: string): string | null {
  if (!target.startsWith("/")) return "must start with /";
  if (target.split(/[\\/]/).includes("..")) return "must not contain .. segments";
  return null;
}

function parseConfigFiles(name: string, value: unknown, secrets: ServiceSpec["secrets"]): ConfigFileSpec[] | string {
  if (value === undefined) return [];
  if (!Array.isArray(value)) return `${name}: configFiles must be a list`;
  const files: ConfigFileSpec[] = [];
  const seen = new Set<string>();
  for (const item of value) {
    if (!isRecord(item) || typeof item.target !== "string" || typeof item.template !== "string") {
      return `${name}: configFiles entries need target and template`;
    }
    const problem = configTargetProblem(item.target);
    if (problem !== null) return `${name}: configFiles target ${problem}`;
    if (item.template.length === 0) return `${name}: configFiles template must be non-empty`;
    if (seen.has(item.target)) return `${name}: configFiles target ${item.target} is duplicated`;
    seen.add(item.target);
    for (const match of item.template.matchAll(/\{\{([^{}]*)\}\}/g)) {
      const key = match[1] ?? "";
      if (!Object.hasOwn(secrets, key)) return `${name}: configFiles template placeholder {{${key}}} is not a declared secret`;
    }
    files.push({ target: item.target, template: item.template });
  }
  return files;
}

function parseServiceSpec(input: unknown): ServiceSpec | string {
  if (!isRecord(input)) return "service must be an object";
  const { name, mode, priority, image, regions, port } = input;
  if (typeof name !== "string" || !NAME_RE.test(name)) return "name must match ^[a-z][a-z0-9-]{0,62}$";
  if (typeof mode !== "string" || !MODES.has(mode)) return `${name}: mode must be daemon, replicated or stateful`;
  if (typeof priority !== "string" || !PRIORITIES.has(priority)) return `${name}: priority must be high, normal or low`;
  if (typeof image !== "string" || image.length === 0 || image.length > 512) return `${name}: image is required`;
  const regionList = stringArray(regions);
  if (regionList === null || regionList.length === 0 || !regionList.every((r) => REGION_RE.test(r))) {
    return `${name}: regions must be a non-empty list of region labels`;
  }
  if (typeof port !== "number" || !Number.isInteger(port) || port < 1 || port > 65535) return `${name}: port must be 1-65535`;
  const hostnames = stringArray(input.hostnames);
  const args = stringArray(input.args);
  const env = stringRecord(input.env);
  if (hostnames === null || args === null || env === null) return `${name}: hostnames, args and env must be strings`;
  const udpPorts = input.udpPorts === undefined ? [] : input.udpPorts;
  if (!Array.isArray(udpPorts) || !udpPorts.every((p) => typeof p === "number" && Number.isInteger(p) && p > 0 && p < 65536)) {
    return `${name}: udpPorts must be port numbers`;
  }
  const secrets: ServiceSpec["secrets"] = {};
  if (input.secrets !== undefined) {
    if (!isRecord(input.secrets)) return `${name}: secrets must be an object`;
    for (const [key, ref] of Object.entries(input.secrets)) {
      if (!isRecord(ref) || typeof ref.vault !== "string" || typeof ref.name !== "string") return `${name}: secret ${key} needs vault and name`;
      secrets[key] = { vault: ref.vault, name: ref.name };
    }
  }
  const mounts: ServiceSpec["mounts"] = [];
  if (input.mounts !== undefined) {
    if (!Array.isArray(input.mounts)) return `${name}: mounts must be a list`;
    for (const mount of input.mounts) {
      if (!isRecord(mount) || typeof mount.source !== "string" || typeof mount.target !== "string") return `${name}: mounts need source and target`;
      mounts.push({ source: mount.source, target: mount.target });
    }
  }
  const replicas = positiveInt(input.replicas, 1);
  const cpuRequestMilli = positiveInt(input.cpuRequestMilli, 100);
  const memRequestMiB = positiveInt(input.memRequestMiB, 128);
  const spec: ServiceSpec = {
    name,
    mode: mode as PlacementMode,
    priority: priority as PriorityTier,
    image,
    regions: regionList,
    replicas,
    minReplicas: positiveInt(input.minReplicas, replicas),
    maxReplicas: Math.max(positiveInt(input.maxReplicas, replicas), replicas),
    cpuRequestMilli,
    cpuLimitMilli: Math.max(positiveInt(input.cpuLimitMilli, cpuRequestMilli * 4), cpuRequestMilli),
    memRequestMiB,
    memLimitMiB: Math.max(positiveInt(input.memLimitMiB, memRequestMiB * 2), memRequestMiB),
    pidsLimit: positiveInt(input.pidsLimit, 512),
    port,
    readyPath: typeof input.readyPath === "string" ? input.readyPath : "/readyz",
    readyTimeoutSeconds: positiveInt(input.readyTimeoutSeconds, 60),
    hostnames,
    env,
    secrets,
    mounts,
    args,
    udpPorts: udpPorts as number[],
  };
  if (isRecord(input.postgres)) {
    const pgHosts = stringArray(input.postgres.hostnames);
    const pgPort = input.postgres.port;
    if (typeof pgPort !== "number" || !Number.isInteger(pgPort) || pgPort < 1 || pgPort > 65535 || pgHosts === null) {
      return `${name}: postgres port must be an integer from 1 to 65535 and hostnames are required`;
    }
    spec.postgres = { port: pgPort, hostnames: pgHosts };
  }
  if (isRecord(input.autoscale)) {
    const targetCpuPct = input.autoscale.targetCpuPct;
    const targetP95Ms = input.autoscale.targetP95Ms;
    if (typeof targetCpuPct !== "number" || !Number.isFinite(targetCpuPct) || targetCpuPct <= 0 || targetCpuPct > 100) {
      return `${name}: autoscale.targetCpuPct must be a finite number greater than 0 and at most 100`;
    }
    if (typeof targetP95Ms !== "number" || !Number.isFinite(targetP95Ms) || targetP95Ms <= 0) {
      return `${name}: autoscale.targetP95Ms must be a finite number greater than 0`;
    }
    spec.autoscale = {
      targetCpuPct,
      targetP95Ms,
      scaleUpCooldownSeconds: positiveInt(input.autoscale.scaleUpCooldownSeconds, 120),
      scaleDownCooldownSeconds: positiveInt(input.autoscale.scaleDownCooldownSeconds, 600),
    };
  }
  const pathPrefixes = parseAbsolutePaths(input.pathPrefixes, `${name}: pathPrefixes`);
  if (typeof pathPrefixes === "string") return pathPrefixes;
  if (pathPrefixes.length > 0) spec.pathPrefixes = pathPrefixes;
  if (input.matchGrpc !== undefined) {
    if (typeof input.matchGrpc !== "boolean") return `${name}: matchGrpc must be a boolean`;
    if (input.matchGrpc) spec.matchGrpc = true;
  }
  const blockedPaths = parseAbsolutePaths(input.blockedPaths, `${name}: blockedPaths`);
  if (typeof blockedPaths === "string") return blockedPaths;
  if (blockedPaths.length > 0) spec.blockedPaths = blockedPaths;
  const configFiles = parseConfigFiles(name, input.configFiles, secrets);
  if (typeof configFiles === "string") return configFiles;
  if (configFiles.length > 0) spec.configFiles = configFiles;
  if (input.internalPort !== undefined) {
    if (
      typeof input.internalPort !== "number" ||
      !Number.isInteger(input.internalPort) ||
      input.internalPort < 1 ||
      input.internalPort > 65535
    ) {
      return `${name}: internalPort must be 1-65535`;
    }
    spec.internalPort = input.internalPort;
  }
  if (input.clusterPeers !== undefined) {
    if (typeof input.clusterPeers !== "boolean") return `${name}: clusterPeers must be a boolean`;
    if (input.clusterPeers) spec.clusterPeers = true;
  }
  const pathPatterns = parseRegexList(input.pathPatterns, `${name}: pathPatterns`);
  if (typeof pathPatterns === "string") return pathPatterns;
  if (pathPatterns.length > 0) spec.pathPatterns = pathPatterns;
  const methods = parseHttpMethods(input.methods, `${name}: methods`);
  if (typeof methods === "string") return methods;
  if (methods.length > 0) spec.methods = methods;
  const routeRules = parseRouteRules(name, input.routeRules);
  if (typeof routeRules === "string") return routeRules;
  if (routeRules.length > 0) spec.routeRules = routeRules;
  return spec;
}

function nonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function parsePoolSizes(label: string, pools: Record<string, unknown>): string | null {
  const { worker, stateful } = pools;
  if (!isRecord(worker)) return `${label}: pools.worker is required`;
  if (!nonNegativeInteger(worker.min) || !nonNegativeInteger(worker.max)) {
    return `${label}: pools.worker.min and pools.worker.max must be non-negative integers`;
  }
  if (worker.min > worker.max) return `${label}: pools.worker.min must not exceed pools.worker.max`;
  if (worker.min > WORKER_POOL_MAX) return `${label}: pools.worker.min must not exceed ${WORKER_POOL_MAX}`;
  if (!isRecord(stateful)) return `${label}: pools.stateful is required`;
  if (!nonNegativeInteger(stateful.count)) return `${label}: pools.stateful.count must be a non-negative integer`;
  if (!nonNegativeInteger(stateful.dataGiB)) return `${label}: pools.stateful.dataGiB must be a non-negative integer`;
  return null;
}

type DataDiskSample = { identity: string; usedPct: number | null };

function dataDiskSample(volumes: unknown): DataDiskSample | null {
  if (!Array.isArray(volumes)) return null;
  const data: unknown = volumes.find((volume: unknown) =>
    isRecord(volume) && volume.mountPath === DATA_VOLUME_PATH && typeof volume.device === "string");
  if (!isRecord(data)) return null;
  const usedPct = typeof data.usedPct === "number" && Number.isFinite(data.usedPct) ? data.usedPct : null;
  return { identity: hasStableVolumeIdentity(data.identity) && usedPct !== null ? data.identity : "", usedPct };
}

function parseFleetConfig(input: unknown): FleetConfig | string {
  if (!isRecord(input)) return "fleet must be an object";
  if (!Array.isArray(input.regions) || input.regions.length === 0) return "fleet.regions must be a non-empty list";
  for (const region of input.regions) {
    if (!isRecord(region) || typeof region.label !== "string" || !REGION_RE.test(region.label)) return "every region needs a label";
    if (typeof region.ociRegion !== "string" || !isOciRegion(region.ociRegion)) return `${region.label}: ociRegion is invalid`;
    if (typeof region.compartmentId !== "string") return `${region.label}: compartmentId is required`;
    if (region.instancePoolId !== undefined && typeof region.instancePoolId !== "string") {
      return `${region.label}: instancePoolId must be a string`;
    }
    if (!isRecord(region.location) || !isRecord(region.endpoints) || !isRecord(region.pools)) {
      return `${region.label}: location, endpoints and pools are required`;
    }
    const pools = parsePoolSizes(region.label, region.pools);
    if (pools !== null) return pools;
  }
  if (!isRecord(input.atlas) || !Array.isArray(input.atlas.services)) return "fleet.atlas.services is required";
  if (input.rolloutOrder !== undefined && stringArray(input.rolloutOrder) === null) return "fleet.rolloutOrder must be a list";
  if (!("netbird" in input) || input.netbird === undefined) {
    delete input.netbird;
  } else {
    const netbird = parseNetBird(input.netbird);
    if (typeof netbird === "string") return netbird;
    input.netbird = netbird;
  }
  return input as unknown as FleetConfig;
}

export class FleetDO extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  private readonly execWaiters = new Map<string, ExecWaiter>();
  private readonly logRequests = new Map<string, LogRequest>();
  private readonly logStreams = new Map<string, LogStream>();
  private readonly eventSubscribers = new Set<EventSubscriber>();
  private readonly reapingInstances = new Set<string>();
  private readonly detachCheckedAt = new Map<string, number>();
  private readonly poolListedAt = new Map<string, number>();
  private readonly poolListPages = new Map<string, { items: PoolInstance[]; nextPage: string; seen: Set<string>; startedAt: number; refreshedAt: number }>();
  private readonly poolAbortControllers = new Map<string, AbortController>();
  private readonly volumeOperations = new Set<string>();
  private readonly volumeReconciles = new Set<string>();
  private readonly backgroundVolumeReconciles = new Set<string>();
  private volumeGrowDeferred = false;
  private readonly deferredGrowNodes = new Set<string>();
  private readonly lastVolumeOpAttempt = new Map<string, number>();
  private ociClient: Promise<OciRestClient | null> | undefined;
  private tlsEnsureInFlight: Promise<unknown> | undefined;
  private nodeSyncPending = Promise.resolve();
  private topologyPublishPending = Promise.resolve();
  private readonly pendingRollups = new Map<string, number>();
  private lastPrunedAt = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.migrate();
    this.seedPendingRollups(Date.now());
    ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  private migrate(): void {
    const statements = [
      "CREATE TABLE IF NOT EXISTS regions (label TEXT PRIMARY KEY, oci_region TEXT NOT NULL, compartment_id TEXT NOT NULL, instance_pool_id TEXT, min_workers INTEGER NOT NULL DEFAULT 0, max_workers INTEGER NOT NULL DEFAULT 0, rollout_order INTEGER NOT NULL DEFAULT 0, config_json TEXT NOT NULL, updated_at INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS nodes (id TEXT PRIMARY KEY, region TEXT NOT NULL, pool_kind TEXT NOT NULL, vcn_ip TEXT NOT NULL DEFAULT '', netbird_ip TEXT, arch TEXT NOT NULL DEFAULT 'arm64', shape TEXT NOT NULL DEFAULT '', fault_domain TEXT NOT NULL DEFAULT '', cpu_total_m INTEGER NOT NULL DEFAULT 0, mem_total_mib INTEGER NOT NULL DEFAULT 0, disk_total_gib INTEGER NOT NULL DEFAULT 0, labels_json TEXT NOT NULL DEFAULT '{}', volumes_json TEXT NOT NULL DEFAULT '[]', volumes_verified INTEGER NOT NULL DEFAULT 0, volumes_verified_at INTEGER NOT NULL DEFAULT 0, token_hash TEXT, status TEXT NOT NULL DEFAULT 'pending', drain_requested INTEGER NOT NULL DEFAULT 0, drain_reason TEXT, last_seen_at INTEGER NOT NULL DEFAULT 0, last_heartbeat_at INTEGER NOT NULL DEFAULT 0, agent_version TEXT NOT NULL DEFAULT '', enrolled_at INTEGER NOT NULL DEFAULT 0)",
      "CREATE TABLE IF NOT EXISTS services (name TEXT PRIMARY KEY, mode TEXT NOT NULL, priority TEXT NOT NULL, image TEXT NOT NULL, spec_json TEXT NOT NULL, config_version INTEGER NOT NULL DEFAULT 1, updated_at INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS placements (id TEXT PRIMARY KEY, service_name TEXT NOT NULL, region TEXT NOT NULL, node_id TEXT, slot INTEGER NOT NULL, desired_image TEXT NOT NULL, desired_config_hash TEXT, active_image TEXT, active_config_hash TEXT, host_port INTEGER, postgres_host_port INTEGER, internal_host_port INTEGER, candidate_image TEXT, candidate_error TEXT, state TEXT NOT NULL, error TEXT, updated_at INTEGER NOT NULL)",
      "CREATE INDEX IF NOT EXISTS placements_node ON placements (node_id)",
      "CREATE INDEX IF NOT EXISTS placements_service ON placements (service_name, region)",
      "CREATE TABLE IF NOT EXISTS rollouts (id TEXT PRIMARY KEY, service_name TEXT NOT NULL, target_image TEXT NOT NULL, previous_image TEXT, state TEXT NOT NULL, current_region TEXT, wave_json TEXT NOT NULL DEFAULT '{}', baseline_p95_ms REAL, baseline_5xx_pct REAL, canary_started_at INTEGER, started_at INTEGER NOT NULL, finished_at INTEGER, error TEXT)",
      "CREATE INDEX IF NOT EXISTS rollouts_service ON rollouts (service_name, started_at)",
      "CREATE TABLE IF NOT EXISTS auth_challenges (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, nonce TEXT NOT NULL, expires_at INTEGER NOT NULL, client_ip TEXT NOT NULL DEFAULT '')",
      "CREATE TABLE IF NOT EXISTS metrics_10s (node_id TEXT NOT NULL, ts INTEGER NOT NULL, cpu_pct REAL NOT NULL, cpu_psi_10 REAL NOT NULL, mem_used_mib REAL NOT NULL, mem_psi_10 REAL NOT NULL, disk_used_pct REAL NOT NULL, net_rx_bps REAL NOT NULL, net_tx_bps REAL NOT NULL, containers_json TEXT NOT NULL, edge_json TEXT, PRIMARY KEY (node_id, ts))",
      "CREATE INDEX IF NOT EXISTS metrics_10s_ts ON metrics_10s (ts)",
      "CREATE TABLE IF NOT EXISTS data_disk_samples (node_id TEXT NOT NULL, identity TEXT NOT NULL, ts INTEGER NOT NULL, disk_pct REAL NOT NULL, synthetic INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (node_id, identity, ts, synthetic))",
      "CREATE INDEX IF NOT EXISTS data_disk_samples_ts ON data_disk_samples (ts)",
      "CREATE INDEX IF NOT EXISTS idx_data_disk_samples_node_syn_ts ON data_disk_samples (node_id, synthetic, ts)",
      "CREATE TABLE IF NOT EXISTS data_disk_1m (node_id TEXT NOT NULL, bucket INTEGER NOT NULL, min_disk_pct REAL NOT NULL, PRIMARY KEY (node_id, bucket))",
      "CREATE INDEX IF NOT EXISTS data_disk_1m_bucket ON data_disk_1m (bucket)",
      "CREATE TABLE IF NOT EXISTS metrics_1m (node_id TEXT NOT NULL, ts INTEGER NOT NULL, cpu_avg REAL NOT NULL, cpu_p95 REAL NOT NULL, cpu_psi_avg REAL NOT NULL, mem_avg_mib REAL NOT NULL, disk_pct REAL NOT NULL, edge_rps REAL NOT NULL, edge_5xx REAL NOT NULL, edge_p95_ms REAL NOT NULL, PRIMARY KEY (node_id, ts))",
      "CREATE INDEX IF NOT EXISTS metrics_1m_ts ON metrics_1m (ts)",
      "CREATE TABLE IF NOT EXISTS tls_certs (id TEXT PRIMARY KEY, domains_json TEXT NOT NULL, cert_pem TEXT NOT NULL, key_pem_enc TEXT NOT NULL, not_after INTEGER NOT NULL, renewed_at INTEGER NOT NULL)",
      "CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, region TEXT, subject TEXT NOT NULL, detail_json TEXT NOT NULL)",
      "CREATE INDEX IF NOT EXISTS events_ts ON events (ts)",
      "CREATE TABLE IF NOT EXISTS kv_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    ];
    for (const statement of statements) this.sql.exec(statement);
    const nodeColumns = this.sql.exec<{ name: string }>("PRAGMA table_info(nodes)").toArray();
    if (!nodeColumns.some((column) => column.name === "netbird_ip")) {
      this.sql.exec("ALTER TABLE nodes ADD COLUMN netbird_ip TEXT");
    }
    if (!nodeColumns.some((column) => column.name === "drain_reason")) {
      this.sql.exec("ALTER TABLE nodes ADD COLUMN drain_reason TEXT");
    }
    if (!nodeColumns.some((column) => column.name === "last_heartbeat_at")) {
      this.sql.exec("ALTER TABLE nodes ADD COLUMN last_heartbeat_at INTEGER NOT NULL DEFAULT 0");
    }
    if (!nodeColumns.some((column) => column.name === "volumes_verified")) {
      this.sql.exec("ALTER TABLE nodes ADD COLUMN volumes_verified INTEGER NOT NULL DEFAULT 0");
    }
    if (!nodeColumns.some((column) => column.name === "volumes_verified_at")) {
      this.sql.exec("ALTER TABLE nodes ADD COLUMN volumes_verified_at INTEGER NOT NULL DEFAULT 0");
    }
    if (!nodeColumns.some((column) => column.name === "enrolled_at")) {
      this.sql.exec("ALTER TABLE nodes ADD COLUMN enrolled_at INTEGER NOT NULL DEFAULT 0");
      this.sql.exec("UPDATE nodes SET enrolled_at = ? WHERE status = 'pending' AND enrolled_at = 0", Date.now());
    }
    const challengeColumns = this.sql.exec<{ name: string }>("PRAGMA table_info(auth_challenges)").toArray();
    if (!challengeColumns.some((column) => column.name === "client_ip")) {
      this.sql.exec("ALTER TABLE auth_challenges ADD COLUMN client_ip TEXT NOT NULL DEFAULT ''");
    }
    this.sql.exec("CREATE INDEX IF NOT EXISTS auth_challenges_expiry ON auth_challenges (expires_at)");
    this.sql.exec("CREATE INDEX IF NOT EXISTS auth_challenges_client_ip ON auth_challenges (client_ip, expires_at)");
    const placementColumns = this.sql.exec<{ name: string }>("PRAGMA table_info(placements)").toArray();
    if (!placementColumns.some((column) => column.name === "postgres_host_port")) {
      this.sql.exec("ALTER TABLE placements ADD COLUMN postgres_host_port INTEGER");
    }
    if (!placementColumns.some((column) => column.name === "internal_host_port")) {
      this.sql.exec("ALTER TABLE placements ADD COLUMN internal_host_port INTEGER");
    }
    if (!placementColumns.some((column) => column.name === "candidate_image")) {
      this.sql.exec("ALTER TABLE placements ADD COLUMN candidate_image TEXT");
    }
    if (!placementColumns.some((column) => column.name === "candidate_error")) {
      this.sql.exec("ALTER TABLE placements ADD COLUMN candidate_error TEXT");
    }
  }

  private getState<T>(key: string): T | null {
    const row = this.sql.exec<StateRow>("SELECT value FROM kv_state WHERE key = ?", key).toArray()[0];
    return row === undefined ? null : parseJson<T | null>(row.value, null);
  }

  private setState(key: string, value: unknown): void {
    this.sql.exec(
      "INSERT INTO kv_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
      key,
      JSON.stringify(value),
    );
  }

  private deleteState(key: string): void {
    this.sql.exec("DELETE FROM kv_state WHERE key = ?", key);
  }

  private nextRevision(): number {
    const revision = (this.getState<number>("revision") ?? 0) + 1;
    this.setState("revision", revision);
    return revision;
  }

  private fleetConfig(): FleetConfig | null {
    return this.getState<FleetConfig>("fleet_config");
  }

  private rolloutOrder(): string[] {
    const fleet = this.fleetConfig();
    if (fleet !== null && Array.isArray(fleet.rolloutOrder) && fleet.rolloutOrder.length > 0) return fleet.rolloutOrder;
    return this.loadRegionRows().map((row) => row.label);
  }

  private loadRegionRows(): RegionRow[] {
    return this.sql.exec<RegionRow>("SELECT * FROM regions ORDER BY rollout_order, label").toArray();
  }

  private loadRegions(): RegionConfig[] {
    return this.loadRegionRows().map((row) => parseJson<RegionConfig>(row.config_json, {} as RegionConfig));
  }

  private nodeFromRow(row: NodeRow): NodeInfo {
    const node: NodeInfo = {
      id: row.id,
      region: row.region,
      poolKind: row.pool_kind as PoolKind,
      vcnIp: row.vcn_ip,
      arch: row.arch as CpuArch,
      shape: row.shape,
      faultDomain: row.fault_domain,
      cpuTotalMilli: row.cpu_total_m,
      memTotalMiB: row.mem_total_mib,
      diskTotalGiB: row.disk_total_gib,
      labels: parseLabels(row.labels_json),
      volumes: parseJson<VolumeInfo[]>(row.volumes_json, []),
      status: row.status as NodeStatus,
      drainRequested: row.drain_requested === 1,
      lastSeenAt: row.last_seen_at,
      agentVersion: row.agent_version,
    };
    if (row.netbird_ip !== null && row.netbird_ip.length > 0) node.netbirdIp = row.netbird_ip;
    return node;
  }

  private loadNodes(): NodeInfo[] {
    return this.sql.exec<NodeRow>("SELECT * FROM nodes ORDER BY id").toArray().map((row) => this.nodeFromRow(row));
  }

  private loadNodeRow(id: string): NodeRow | undefined {
    return this.sql.exec<NodeRow>("SELECT * FROM nodes WHERE id = ?", id).toArray()[0];
  }

  private placementFromRow(row: PlacementRow): PlacementInfo {
    const placement: PlacementInfo = {
      id: row.id,
      serviceName: row.service_name,
      region: row.region,
      slot: row.slot,
      desiredImage: row.desired_image,
      state: row.state as PlacementState,
      updatedAt: row.updated_at,
    };
    if (row.node_id !== null) placement.nodeId = row.node_id;
    if (row.active_image !== null) placement.activeImage = row.active_image;
    if (row.active_config_hash !== null) placement.activeConfigHash = row.active_config_hash;
    if (row.host_port !== null) placement.hostPort = row.host_port;
    if (row.postgres_host_port !== null) placement.postgresHostPort = row.postgres_host_port;
    if (row.internal_host_port !== null) placement.internalHostPort = row.internal_host_port;
    if (row.candidate_image !== null) placement.candidateImage = row.candidate_image;
    if (row.candidate_error !== null) placement.candidateError = row.candidate_error;
    return placement;
  }

  private loadPlacements(): PlacementInfo[] {
    return this.sql
      .exec<PlacementRow>("SELECT * FROM placements ORDER BY id")
      .toArray()
      .map((row) => this.placementFromRow(row));
  }

  private serviceFromRow(row: ServiceRow): ServiceSpec {
    return { ...parseJson<ServiceSpec>(row.spec_json, {} as ServiceSpec), image: row.image };
  }

  private loadServices(): ServiceSpec[] {
    return this.sql.exec<ServiceRow>("SELECT * FROM services ORDER BY name").toArray().map((row) => this.serviceFromRow(row));
  }

  private loadServiceRow(name: string): ServiceRow | undefined {
    return this.sql.exec<ServiceRow>("SELECT * FROM services WHERE name = ?", name).toArray()[0];
  }

  private rolloutFromRow(row: RolloutRow): RolloutInfo {
    const wave = parseJson<{
      region?: string;
      currentWave?: number;
      totalWaves?: number;
      waveStartedAt?: number;
      regionOrder?: string[];
      activeRegions?: string[];
      regionProgress?: RolloutRegionProgress[];
    }>(row.wave_json, {});
    const rollout: RolloutInfo = {
      id: row.id,
      serviceName: row.service_name,
      targetImage: row.target_image,
      phase: row.state as RolloutPhase,
      currentWave: wave.currentWave ?? 0,
      totalWaves: wave.totalWaves ?? 0,
      startedAt: row.started_at,
    };
    if (typeof wave.region === "string") rollout.region = wave.region;
    if (typeof wave.waveStartedAt === "number") rollout.waveStartedAt = wave.waveStartedAt;
    if (row.previous_image !== null) rollout.previousImage = row.previous_image;
    if (row.current_region !== null) rollout.currentRegion = row.current_region;
    if (row.baseline_p95_ms !== null) rollout.baselineP95Ms = row.baseline_p95_ms;
    if (row.baseline_5xx_pct !== null) rollout.baseline5xxPct = row.baseline_5xx_pct;
    if (row.canary_started_at !== null) rollout.canaryStartedAt = row.canary_started_at;
    if (row.finished_at !== null) rollout.finishedAt = row.finished_at;
    if (row.error !== null) rollout.error = row.error;
    if (Array.isArray(wave.regionOrder)) rollout.regionOrder = wave.regionOrder;
    if (Array.isArray(wave.activeRegions)) rollout.activeRegions = wave.activeRegions;
    if (Array.isArray(wave.regionProgress)) rollout.regionProgress = wave.regionProgress;
    return rollout;
  }

  private loadRollouts(activeOnly: boolean, limit = 50): RolloutInfo[] {
    const rows = activeOnly
      ? this.sql
          .exec<RolloutRow>("SELECT * FROM rollouts WHERE state NOT IN ('succeeded', 'rolled_back', 'failed') ORDER BY started_at")
          .toArray()
      : this.sql
          .exec<RolloutRow>(
            "SELECT * FROM rollouts WHERE state NOT IN ('succeeded', 'rolled_back', 'failed') OR id IN (SELECT id FROM rollouts ORDER BY started_at DESC, id DESC LIMIT ?) ORDER BY started_at DESC, id DESC",
            limit,
          )
          .toArray();
    return rows.map((row) => this.rolloutFromRow(row));
  }

  private saveRollout(rollout: RolloutInfo): void {
    this.sql.exec(
      "INSERT INTO rollouts (id, service_name, target_image, previous_image, state, current_region, wave_json, baseline_p95_ms, baseline_5xx_pct, canary_started_at, started_at, finished_at, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET target_image = excluded.target_image, previous_image = excluded.previous_image, state = excluded.state, current_region = excluded.current_region, wave_json = excluded.wave_json, baseline_p95_ms = excluded.baseline_p95_ms, baseline_5xx_pct = excluded.baseline_5xx_pct, canary_started_at = excluded.canary_started_at, finished_at = excluded.finished_at, error = excluded.error",
      rollout.id,
      rollout.serviceName,
      rollout.targetImage,
      rollout.previousImage ?? null,
      rollout.phase,
      rollout.currentRegion ?? null,
      JSON.stringify({
        region: rollout.region,
        currentWave: rollout.currentWave,
        totalWaves: rollout.totalWaves,
        waveStartedAt: rollout.waveStartedAt,
        regionOrder: rollout.regionOrder,
        activeRegions: rollout.activeRegions,
        regionProgress: rollout.regionProgress,
      }),
      rollout.baselineP95Ms ?? null,
      rollout.baseline5xxPct ?? null,
      rollout.canaryStartedAt ?? null,
      rollout.startedAt,
      rollout.finishedAt ?? null,
      rollout.error ?? null,
    );
  }

  private recordEvent(kind: EventKind, subject: string, detail: Record<string, unknown> = {}, region?: string): EventRecord {
    const ts = Date.now();
    const strings = detailStrings(detail);
    const row = this.sql
      .exec<{ id: number }>(
        "INSERT INTO events (ts, kind, region, subject, detail_json) VALUES (?, ?, ?, ?, ?) RETURNING id",
        ts,
        kind,
        region ?? null,
        subject,
        JSON.stringify(strings),
      )
      .toArray()[0];
    const event: EventRecord = { id: row?.id ?? 0, ts, kind, subject, detail: strings };
    if (region !== undefined) event.region = region;
    for (const subscriber of this.eventSubscribers) {
      if (subscriber.region === null || subscriber.region === region) subscriber.push(event);
    }
    return event;
  }

  private eventFromRow(row: EventRow): EventRecord {
    const event: EventRecord = {
      id: row.id,
      ts: row.ts,
      kind: row.kind as EventKind,
      subject: row.subject,
      detail: parseJson<Record<string, string>>(row.detail_json, {}),
    };
    if (row.region !== null) event.region = row.region;
    return event;
  }

  private sockets(nodeId: string): WebSocket[] {
    return this.ctx.getWebSockets(nodeId).filter((ws) => ws.readyState === WebSocket.OPEN);
  }

  private connected(nodeId: string): boolean {
    return this.sockets(nodeId).length > 0;
  }

  private volumeSockets(nodeId: string): WebSocket[] {
    return this.sockets(nodeId).filter(sessionVerified);
  }

  private hasVolumeSession(nodeId: string): boolean {
    return this.volumeSockets(nodeId).length > 0;
  }

  private send(nodeId: string, message: BackplaneMessage, sockets = this.sockets(nodeId)): number {
    const payload = JSON.stringify(message);
    let sent = 0;
    for (const ws of sockets) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      try {
        ws.send(payload);
        sent++;
      } catch (error) {
        console.error("websocket send failed", nodeId, error);
      }
    }
    return sent;
  }

  private async ensureAlarm(delayMs = 1_000): Promise<void> {
    const current = await this.ctx.storage.getAlarm();
    const target = Date.now() + Math.max(250, delayMs);
    if (current === null || current > target) await this.ctx.storage.setAlarm(target);
  }

  private nextBakeDeadline(now: number): number | null {
    const rollouts = this.loadRollouts(true);
    let earliest: number | null = null;
    for (const startedAt of rollouts.flatMap((rollout) => bakingStartTimes(rollout))) {
      const minimum = startedAt + DEFAULT_CANARY_BAKE_MS;
      const deadline = now < minimum ? minimum : Math.max(now + 250, startedAt + MAX_CANARY_BAKE_MS);
      if (earliest === null || deadline < earliest) earliest = deadline;
    }
    return earliest;
  }

  private async scheduleNextAlarm(): Promise<void> {
    const now = Date.now();
    const bakeDeadline = this.nextBakeDeadline(now);
    const nodes = this.sql.exec<CountRow>("SELECT COUNT(*) AS count FROM nodes").toArray()[0]?.count ?? 0;
    const rollouts =
      this.sql
        .exec<CountRow>("SELECT COUNT(*) AS count FROM rollouts WHERE state NOT IN ('succeeded', 'rolled_back', 'failed')")
        .toArray()[0]?.count ?? 0;
    const regions = this.sql.exec<CountRow>("SELECT COUNT(*) AS count FROM regions").toArray()[0]?.count ?? 0;
    let targetAt: number | null = null;
    if (bakeDeadline !== null) targetAt = Math.min(bakeDeadline, now + ALARM_INTERVAL_MS);
    else if (nodes > 0 || rollouts > 0 || this.logStreams.size > 0) targetAt = now + ALARM_INTERVAL_MS;
    else if (regions > 0) targetAt = now + IDLE_ALARM_INTERVAL_MS;
    const freeVolumeSlots = Math.min(MAX_BACKGROUND_RECONCILES - this.backgroundVolumeReconciles.size, MAX_VOLUME_OPS - this.volumeReconciles.size);
    const urgentVolumeWork = (this.volumeGrowDeferred && this.volumeReconciles.size < MAX_VOLUME_OPS) ||
      (freeVolumeSlots > 0 && this.dueVolumeReconciles(now).length > 0);
    if (this.deferredGrowNodes.size > 0 && this.takeDeferredGrows(this.deferredGrowNodes, now)) {
      this.setState("autoscale_at", 0);
      targetAt = Math.min(targetAt ?? Number.POSITIVE_INFINITY, now + 1_000);
    }
    if (urgentVolumeWork) targetAt = Math.min(targetAt ?? Number.POSITIVE_INFINITY, now + 1_000);
    if (targetAt === null) return;
    const existing = await this.ctx.storage.getAlarm();
    if (existing !== null && existing > now && existing < targetAt) return;
    await this.ctx.storage.setAlarm(targetAt);
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    try {
      if (path === "/ws/node") return await this.acceptNode(request, url);
      if (method === "POST" && path === "/api/auth/ssh/challenge") return await this.sshChallenge(request, url);
      if (method === "POST" && path === "/api/auth/ssh/verify") return await this.sshVerify(request);
      if (method === "POST" && path === "/api/nodes/enroll") return await this.enrollNode(request, url);
      const principal = decodePrincipal(request.headers.get(PRINCIPAL_HEADER));
      if (principal === null) return errorJson(401, "unauthorized", "Authentication required");
      return await this.route(request, url, principal);
    } catch (error) {
      if (error instanceof HttpError) return errorJson(error.status, error.code, error.message, error.fix);
      console.error("fleet request failed", path, error);
      return errorJson(500, "internal", error instanceof Error ? error.message : "Internal error");
    }
  }

  private async route(request: Request, url: URL, principal: Principal): Promise<Response> {
    const path = url.pathname;
    const method = request.method;
    if (method === "GET") {
      switch (path) {
        case "/api/status":
          return json(await this.status(url));
        case "/api/top":
          return json(this.top(url));
        case "/api/metrics":
          return json(this.metrics(url));
        case "/api/events":
          return this.events(request, url);
        case "/api/services":
          return json({ services: this.loadServices() });
        case "/api/nodes":
          return json({ nodes: this.loadNodes() });
        case "/api/rollouts":
          return json({ rollouts: this.loadRollouts(false) });
        case "/api/tls":
          return json(this.tlsStatus());
        case "/api/logs":
          return this.logs(request, url);
        case "/api/export":
          return json(this.exportState());
        case "/api/fleet": {
          const fleet = this.fleetConfig();
          if (fleet === null) throw new HttpError(404, "not_found", "Fleet config is not seeded");
          return json(fleet);
        }
        default:
          break;
      }
    }
    if (method === "POST") {
      switch (path) {
        case "/api/fleet/seed":
          return json(await this.seed(request, principal));
        case "/api/services":
          return json(await this.applyServices(request, principal));
        case "/api/services/diff":
          return json({ diff: this.diffServices(await this.readJson(request)) });
        case "/api/deploy":
          return json(await this.deploy(request, principal), 202);
        case "/api/rollback":
          return json(await this.rollback(request, principal));
        case "/api/exec":
          return json(await this.exec(request, principal));
        case "/api/secrets/refresh":
          return json(await this.refreshSecrets(request, principal));
        case "/api/tls/ensure":
          return json(await this.ensureTls(url));
        case "/api/nodes/upgrade":
          return json(this.upgradeNodes(await this.readJson(request), url, principal));
        case "/api/dev/chaos":
          if (!localDevAllowed(url, this.env)) throw new HttpError(404, "not_found", "Not found");
          return json(await this.chaos(request, principal));
        default:
          break;
      }
      const nodeAction = /^\/api\/nodes\/([^/]+)\/(drain|activate|reboot)$/.exec(path);
      if (nodeAction !== null) {
        const nodeId = decodeURIComponent(nodeAction[1] ?? "");
        const action = nodeAction[2];
        if (action === "drain") return json(await this.drainNode(nodeId, `operator:${principal.owner}`));
        if (action === "activate") return json(await this.activateNode(nodeId));
        return json(await this.rebootNode(nodeId, principal));
      }
    }
    if (method === "DELETE") {
      const nodeMatch = /^\/api\/nodes\/([^/]+)$/.exec(path);
      if (nodeMatch !== null) {
        const nodeId = decodeURIComponent(nodeMatch[1] ?? "");
        return json(await this.deleteNode(nodeId, url.searchParams.get("force") === "true", principal));
      }
      const match = /^\/api\/services\/([^/]+)$/.exec(path);
      const name = match !== null ? decodeURIComponent(match[1] ?? "") : path === "/api/services" ? url.searchParams.get("name") : null;
      if (name !== null) return json(await this.deleteService(name, principal));
    }
    throw new HttpError(404, "not_found", "Not found");
  }

  private async readJson(request: Request): Promise<unknown> {
    const length = Number(request.headers.get("Content-Length") ?? "0");
    if (length > MAX_JSON_BYTES) throw new HttpError(413, "validation", "Body is too large");
    const reader = request.body?.getReader();
    if (reader === undefined) return {};
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        total += next.value.byteLength;
        if (total > MAX_JSON_BYTES) throw new HttpError(413, "validation", "Body is too large");
        chunks.push(next.value);
      }
    } finally {
      await reader.cancel().catch(() => undefined);
    }
    if (total === 0) return {};
    const merged = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    try {
      const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(merged);
      if (text.trim().length === 0) return {};
      return JSON.parse(text) as unknown;
    } catch {
      throw new HttpError(400, "validation", "Body must be JSON");
    }
  }

  private async sshChallenge(request: Request, url: URL): Promise<Response> {
    const body = (await this.readJson(request)) as Partial<SshChallengeRequest>;
    const fp = typeof body.fingerprint === "string" ? body.fingerprint.trim() : "";
    if (fp.length === 0 || fp.length > 128) throw new HttpError(400, "validation", "fingerprint is required");
    const allowed = await parseAllowedSshKeys(this.env.ALLOWED_SSH_KEYS, localDevAllowed(url, this.env) ? "admin" : "read");
    if (!allowed.some((key) => key.fingerprint === fp)) {
      throw new HttpError(403, "forbidden", "The SSH key is not allowed");
    }
    const now = Date.now();
    const clientIp = request.headers.get("CF-Connecting-IP") ?? "";
    const challenge: SshChallengeResponse = {
      challengeId: randomToken(16),
      nonce: randomToken(32),
      namespace: SSH_NAMESPACE,
      expiresAt: now + SSH_CHALLENGE_TTL_MS,
    };
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM auth_challenges WHERE expires_at <= ?", now);
      this.sql.exec(
        "DELETE FROM auth_challenges WHERE rowid IN (SELECT rowid FROM auth_challenges WHERE client_ip = ? ORDER BY expires_at DESC, rowid DESC LIMIT -1 OFFSET ?)",
        clientIp,
        MAX_CHALLENGES_PER_IP - 1,
      );
      this.sql.exec(
        "DELETE FROM auth_challenges WHERE rowid IN (SELECT rowid FROM auth_challenges ORDER BY expires_at DESC, rowid DESC LIMIT -1 OFFSET ?)",
        MAX_CHALLENGES - 1,
      );
      this.sql.exec(
        "INSERT INTO auth_challenges (id, fingerprint, nonce, expires_at, client_ip) VALUES (?, ?, ?, ?, ?)",
        challenge.challengeId,
        fp,
        challenge.nonce,
        challenge.expiresAt,
        clientIp,
      );
    });
    return json(challenge);
  }

  private async sshVerify(request: Request): Promise<Response> {
    const body = (await this.readJson(request)) as Partial<SshVerifyRequest>;
    if (typeof body.challengeId !== "string" || typeof body.publicKey !== "string" || typeof body.signature !== "string") {
      throw new HttpError(400, "validation", "challengeId, publicKey and signature are required");
    }
    const row = this.sql.exec<ChallengeRow>("SELECT * FROM auth_challenges WHERE id = ?", body.challengeId).toArray()[0];
    this.sql.exec("DELETE FROM auth_challenges WHERE id = ?", body.challengeId);
    const now = Date.now();
    if (row === undefined || row.expires_at <= now) throw new HttpError(401, "unauthorized", "The challenge is unknown or expired", "Request a new challenge.");
    const loginUrl = new URL(request.url);
    const result = await verifySshLogin(this.env, loginUrl, {
      publicKey: body.publicKey,
      signature: body.signature,
      nonce: row.nonce,
      fingerprint: row.fingerprint,
    });
    if (!result.ok) throw new HttpError(result.status, result.code as ErrorCode, result.message);
    const session = await mintSshSession(this.env, result.owner, result.role, result.fingerprint, now, loginUrl);
    if (session === null) throw new HttpError(503, "unavailable", "SESSION_SECRET is not configured");
    const response: SshVerifyResponse = { token: session.token, owner: result.owner, role: result.role, expiresAt: session.expiresAt };
    return json(response);
  }

  private async enrollNode(request: Request, url: URL): Promise<Response> {
    const body = (await this.readJson(request)) as Partial<NodeEnrollRequest>;
    if (!checkEnrollSecret(this.env, body.enrollmentSecret)) throw new HttpError(401, "unauthorized", "Invalid enrollment secret");
    const { instanceId, region, poolKind, vcnIp } = body;
    if (typeof instanceId !== "string" || instanceId.length === 0 || instanceId.length > 255) {
      throw new HttpError(400, "validation", "instanceId is required");
    }
    if (typeof region !== "string" || !REGION_RE.test(region)) throw new HttpError(400, "validation", "region is invalid");
    if (poolKind !== "stateful" && poolKind !== "worker") throw new HttpError(400, "validation", "poolKind must be stateful or worker");
    const nodeId = await nodeIdFor(instanceId, region, poolKind);
    const token = newNodeToken();
    const tokenHash = await hashNodeToken(token);
    const regionRow = this.sql.exec<RegionRow>("SELECT * FROM regions WHERE label = ?", region).toArray()[0];
    if (regionRow === undefined) throw new HttpError(409, "conflict", `Region ${region} is not part of the fleet`, "Seed the fleet first.");
    const config = parseJson<RegionConfig | null>(regionRow.config_json, null);
    if (typeof vcnIp !== "string" || vcnIp.length > 15 || !vcnAddress(vcnIp, config?.network?.vcnCidr, localDevAllowed(url, this.env))) {
      throw new HttpError(400, "validation", "vcnIp must be a private IPv4 address in the region's VCN");
    }
    const alreadyRegistered = () => this.sql.exec(
      `SELECT id FROM nodes WHERE id = ? OR ${INSTANCE_ID_SQL} = ? LIMIT 1`, nodeId, instanceId,
    ).toArray().length > 0;
    const conflict = () => new HttpError(409, "conflict", "The node is already registered", "Remove the existing registration before enrolling again.");
    if (alreadyRegistered()) throw conflict();
    const labels: Record<string, string> = { [INSTANCE_ID_LABEL]: instanceId };
    const poolId = poolKind === "worker" && regionRow.instance_pool_id !== null && regionRow.instance_pool_id.length > 0 ? regionRow.instance_pool_id : null;
    if (poolId !== null && instanceId.startsWith("ocid1.instance.") && !localDevAllowed(url, this.env)) {
      const oci = await this.oci();
      if (oci === null) throw new HttpError(503, "unavailable", "OCI credentials are not configured");
      const members = await oci.listInstancePoolInstances(regionRow.oci_region, poolId, regionRow.compartment_id);
      if (this.regionPoolId(region) !== poolId || !members.some(({ id }) => id === instanceId)) {
        throw new HttpError(409, "conflict", "Instance is not a member of the region's configured worker pool");
      }
      labels[INSTANCE_POOL_ID_LABEL] = poolId;
    } else if (poolId !== null) {
      labels[INSTANCE_POOL_ID_LABEL] = poolId;
    }
    if (poolKind === "stateful" && instanceId.startsWith("ocid1.instance.")) {
      const oci = await this.oci();
      const identity = await oci?.statefulIdentity(regionRow.oci_region, region, regionRow.compartment_id, instanceId);
      if (identity !== null && identity !== undefined) {
        labels[DATA_VOLUME_ID_LABEL] = identity.volumeId;
        if (identity.index !== null) labels["oci.stateful-index"] = identity.index;
      }
    }
    const enrolledAt = Date.now();
    if (this.isReapingOrReaped(instanceId, enrolledAt)) throw terminating();
    const inserted = this.sql.exec(
      `INSERT INTO nodes (id, region, pool_kind, vcn_ip, labels_json, token_hash, enrolled_at) SELECT ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM nodes WHERE id = ? OR ${INSTANCE_ID_SQL} = ?) RETURNING id`,
      nodeId, region, poolKind, vcnIp, JSON.stringify(labels), tokenHash, enrolledAt, nodeId, instanceId,
    ).toArray();
    if (inserted.length === 0) {
      throw conflict();
    }
    this.recordEvent("node_enrolled", nodeId, { instanceId, poolKind, vcnIp }, region);
    await this.ensureAlarm(ALARM_INTERVAL_MS);
    const response: NodeEnrollResponse = {
      nodeId,
      token,
      wsUrl: `${url.protocol === "https:" ? "wss" : "ws"}://${url.host}/ws/node`,
    };
    return json(response);
  }

  private closeSocket(ws: WebSocket, code: number, reason: string): void {
    try {
      ws.close(code, reason);
    } catch (error) {
      console.error("websocket close failed", error);
    }
  }

  private async acceptNode(request: Request, url: URL): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return errorJson(426, "validation", "Expected a WebSocket upgrade");
    }
    const token = nodeBearer(request);
    if (token === null) return errorJson(401, "unauthorized", "Node token required");
    const hint = url.searchParams.get("nodeId") ?? request.headers.get("X-TsOrch-Node-Id");
    const row =
      hint !== null
        ? this.loadNodeRow(hint)
        : this.sql.exec<NodeRow>("SELECT * FROM nodes WHERE token_hash = ?", await hashNodeToken(token)).toArray()[0];
    if (row === undefined || !(await verifyNodeToken(token, row.token_hash))) {
      return errorJson(401, "unauthorized", "Invalid node token", "Re-enroll the node.");
    }
    const loaded = this.loadNodeRow(row.id);
    if (loaded !== undefined && this.needsPoolVerification(loaded)) {
      const verification = await this.verifyPendingWorkerPool(loaded, localDevAllowed(url, this.env));
      if (verification === "unavailable") throw new HttpError(503, "unavailable", "Worker pool membership cannot be verified");
      if (verification === "not_member") throw terminating();
    }
    const current = this.loadNodeRow(row.id);
    if (current === undefined || current.token_hash !== row.token_hash) {
      return errorJson(401, "unauthorized", "Invalid node token", "Re-enroll the node.");
    }
    if (this.nodeBlocked(current, Date.now())) throw terminating();
    for (const ws of this.sockets(row.id)) this.closeSocket(ws, 4001, "replaced");
    this.sql.exec("UPDATE nodes SET volumes_verified = 0 WHERE id = ?", row.id);
    this.deleteState(`volume_binding_pending:${row.id}`);
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server, [row.id, `region:${row.region}`]);
    const attachment: Attachment = {
      nodeId: row.id,
      region: row.region,
      poolKind: row.pool_kind as PoolKind,
      sessionId: crypto.randomUUID(),
      volumesVerified: false,
      growVolumeId: false,
      lastVolumeSeq: 0,
      volumeReconcileScheduled: false,
    };
    server.serializeAttachment(attachment);
    await this.ensureAlarm(ALARM_INTERVAL_MS);
    return new Response(null, { status: 101, webSocket: client });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const attachment = ws.deserializeAttachment() as Attachment | null;
    if (attachment === null || typeof attachment.nodeId !== "string") {
      this.closeSocket(ws, 4003, "unidentified");
      return;
    }
    if (ws.readyState !== WebSocket.OPEN) return;
    if (typeof message !== "string" || message.length > MAX_EXEC_RESULT_FRAME_BYTES) return;
    const execResult = /^\{\s*"type"\s*:\s*"exec_result"\s*[,}]/.test(message.slice(0, 128));
    if (message.length > MAX_NODE_FRAME_BYTES && !execResult) return;
    const bytes = encoder.encode(message).byteLength;
    const large = bytes > MAX_NODE_FRAME_BYTES;
    if (bytes > MAX_EXEC_RESULT_FRAME_BYTES || (large && (!execResult || this.execWaiters.size === 0))) return;
    let parsed: AgentMessage;
    try {
      parsed = JSON.parse(message) as AgentMessage;
    } catch {
      return;
    }
    if (!isRecord(parsed) || typeof parsed.type !== "string") return;
    if (large && (parsed.type !== "exec_result" || typeof parsed.requestId !== "string" ||
        this.execWaiters.get(parsed.requestId)?.nodeId !== attachment.nodeId)) return;
    const now = Date.now();
    const unverified = this.loadNodeRow(attachment.nodeId);
    const verification: PoolVerification = unverified !== undefined && this.needsPoolVerification(unverified)
      ? await this.verifyPendingWorkerPool(unverified, this.env.LOCAL_DEV === "true")
      : "verified";
    const sender = this.loadNodeRow(attachment.nodeId);
    if (verification !== "verified" || sender === undefined || this.nodeBlocked(sender, Date.now())) {
      this.closeSocket(ws, 4010, "terminating");
      return;
    }
    try {
      switch (parsed.type) {
        case "hello":
          await this.onHello(ws, attachment, parsed, now);
          break;
        case "heartbeat":
          await this.onHeartbeat(ws, attachment, parsed, now);
          break;
        case "placement_event": {
          const report: PlacementReport = {
            placementId: parsed.placementId,
            serviceName: "",
            state: parsed.state,
            image: parsed.image,
            configHash: parsed.configHash,
          };
          if (parsed.hostPort !== undefined) report.hostPort = parsed.hostPort;
          if (parsed.postgresHostPort !== undefined) report.postgresHostPort = parsed.postgresHostPort;
          if (parsed.internalHostPort !== undefined) report.internalHostPort = parsed.internalHostPort;
          if (parsed.candidateImage !== undefined) report.candidateImage = parsed.candidateImage;
          if (parsed.candidateError !== undefined) report.candidateError = parsed.candidateError;
          if (parsed.error !== undefined) report.error = parsed.error;
          this.touchNode(attachment.nodeId, now);
          if (this.applyReport(attachment.nodeId, report, now)) {
            await this.syncNodes("routes", attachment.poolKind === "stateful" ? undefined : attachment.region);
          }
          await this.advanceRollouts(now);
          break;
        }
        case "drain_complete":
          await this.onDrainComplete(attachment, now);
          break;
        case "volume_grown":
          this.onVolumeGrown(attachment, parsed.volumePath, parsed.newSizeGiB, parsed.volumeId);
          break;
        case "log_chunk":
          this.onLogChunk(attachment.nodeId, parsed.requestId, parsed.stream, parsed.line);
          break;
        case "exec_result": {
          const waiter = this.execWaiters.get(parsed.requestId);
          if (waiter !== undefined && waiter.nodeId === attachment.nodeId) {
            this.execWaiters.delete(parsed.requestId);
            waiter.resolve({ exitCode: parsed.exitCode, stdout: parsed.stdout, stderr: parsed.stderr });
          }
          break;
        }
        default:
          break;
      }
    } catch (error) {
      console.error("agent message failed", attachment.nodeId, parsed.type, error);
    }
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string, _wasClean: boolean): Promise<void> {
    this.closeSocket(ws, code === 1005 || code === 1006 || code === 1015 ? 1000 : code, reason);
    const attachment = ws.deserializeAttachment() as Attachment | null;
    if (attachment === null) return;
    this.releaseVolumeSession(attachment.nodeId, ws);
    this.detachNodeStreams(attachment.nodeId, ws);
  }

  override async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
    console.error("websocket error", error);
    const attachment = ws.deserializeAttachment() as Attachment | null;
    if (attachment === null) return;
    this.releaseVolumeSession(attachment.nodeId, ws);
    this.detachNodeStreams(attachment.nodeId, ws);
  }

  private releaseVolumeSession(nodeId: string, closing: WebSocket): void {
    const closingSession = (closing.deserializeAttachment() as Attachment | null)?.sessionId;
    const pendingKey = `volume_binding_pending:${nodeId}`;
    if (volumeBindingChallenge(this.getState<unknown>(pendingKey))?.sessionId === closingSession) this.deleteState(pendingKey);
    if (this.volumeSockets(nodeId).some((ws) => ws !== closing)) return;
    this.sql.exec("UPDATE nodes SET volumes_verified = 0 WHERE id = ? AND volumes_verified <> 0", nodeId);
  }

  private detachNodeStreams(nodeId: string, closing: WebSocket): void {
    if (this.sockets(nodeId).some((ws) => ws !== closing && ws.readyState === WebSocket.OPEN)) return;
    for (const [requestId, waiter] of this.execWaiters) {
      if (waiter.nodeId !== nodeId) continue;
      this.execWaiters.delete(requestId);
      waiter.resolve(null);
    }
    for (const [requestId, logRequest] of this.logRequests) {
      if (logRequest.nodeId !== nodeId) continue;
      this.logRequests.delete(requestId);
      const stream = this.logStreams.get(logRequest.streamId);
      if (stream === undefined) continue;
      stream.requests.delete(requestId);
      if (stream.requests.size === 0) void this.closeLogStream(logRequest.streamId, false);
    }
  }

  private touchNode(nodeId: string, now: number): void {
    this.sql.exec("UPDATE nodes SET last_seen_at = ? WHERE id = ?", now, nodeId);
  }

  private liveStatus(row: NodeRow): NodeStatus {
    if (row.drain_requested === 1) return row.status === "drained" ? "drained" : "draining";
    return "active";
  }

  private async onHello(ws: WebSocket, attachment: Attachment, hello: HelloMessage, now: number): Promise<void> {
    if (hello.nodeId !== attachment.nodeId) {
      this.closeSocket(ws, 4003, "node id mismatch");
      return;
    }
    const row = this.loadNodeRow(attachment.nodeId);
    if (row === undefined) {
      this.closeSocket(ws, 4004, "unknown node");
      return;
    }
    const stored = parseLabels(row.labels_json);
    const labels = Object.fromEntries(
      Object.entries(isRecord(hello.labels) ? hello.labels : {})
        .filter(([key, value]) => !key.startsWith("oci.") && typeof value === "string"),
    );
    for (const [key, value] of Object.entries(stored)) {
      if (key.startsWith("oci.")) labels[key] = value;
    }
    const previous = row.status;
    const status = this.liveStatus(row);
    const netbirdIp = typeof hello.netbirdIp === "string" && hello.netbirdIp.length > 0 ? hello.netbirdIp : row.netbird_ip;
    const growVolumeId = Array.isArray(hello.capabilities) && hello.capabilities.includes(GROW_VOLUME_ID_CAPABILITY);
    updateSessionVolumes(ws, attachment, { growVolumeId });
    const helloVolumesAccepted = acceptVolumeSeq(ws, attachment, hello.volumeSeq);
    const helloVolumes = helloVolumesAccepted ? reportedVolumes(hello.volumes) : null;
    const tracksDataDisk = row.pool_kind === "stateful" || dataDiskSample(parseJson<unknown>(row.volumes_json, null)) !== null;
    this.sql.exec(
      "UPDATE nodes SET netbird_ip = ?, arch = ?, shape = ?, fault_domain = ?, cpu_total_m = ?, mem_total_mib = ?, disk_total_gib = ?, labels_json = ?, volumes_json = ?, volumes_verified = ?, volumes_verified_at = ?, agent_version = ?, status = ?, last_seen_at = ? WHERE id = ?",
      netbirdIp,
      hello.arch === "x64" ? "x64" : "arm64",
      String(hello.shape ?? ""),
      String(hello.faultDomain ?? ""),
      Math.max(0, Math.floor(finite(hello.cpuTotalMilli))),
      Math.max(0, Math.floor(finite(hello.memTotalMiB))),
      Math.max(0, Math.floor(finite(hello.diskTotalGiB))),
      JSON.stringify(labels),
      helloVolumes ?? row.volumes_json,
      helloVolumes === null ? 0 : 1,
      helloVolumes === null ? row.volumes_verified_at : now,
      String(hello.agentVersion ?? ""),
      status,
      now,
      attachment.nodeId,
    );
    if (helloVolumesAccepted) {
      this.recordDataDiskSample(attachment.nodeId, dataDiskSample(hello.volumes) ?? (tracksDataDisk ? { identity: "", usedPct: null } : null), now, false);
    }
    markSessionVolumes(ws, attachment, helloVolumes !== null);
    this.scheduleSessionVolumeReconcile(ws, attachment, helloVolumes);
    if (hello.region !== attachment.region || hello.poolKind !== attachment.poolKind) {
      console.warn("hello region/pool mismatch ignored", attachment.nodeId, hello.region, hello.poolKind);
    }
    if (attachment.poolKind === "worker" && previous === "pending" && status === "active") this.recordWorkerJoin(attachment.region);
    this.recordEvent("node_connected", attachment.nodeId, { previous, agentVersion: hello.agentVersion, status }, attachment.region);
    this.deleteState(`sent_desired:${attachment.nodeId}`);
    this.deleteState(`sent_routes:${attachment.nodeId}`);
    if (status === "draining") this.send(attachment.nodeId, { type: "drain", reason: row.drain_reason ?? "draining" });
    await this.reconcile(now);
    this.resumeVolumeGrow(attachment.nodeId, false);
    const tls = await this.loadTls();
    if (tls !== null) this.sendTls(attachment.nodeId, tls);
    await this.publishTopology(now, false);
    await this.ensureAlarm(ALARM_INTERVAL_MS);
  }

  private chaosState(now: number): ChaosState {
    const state = this.getState<ChaosState>("chaos") ?? { fiveXx: {}, cpu: {}, disk: {} };
    let changed = false;
    for (const [key, value] of Object.entries(state.fiveXx)) {
      if (value.until <= now) {
        delete state.fiveXx[key];
        changed = true;
      }
    }
    for (const [key, value] of Object.entries(state.cpu)) {
      if (value.until <= now) {
        delete state.cpu[key];
        changed = true;
      }
    }
    if (changed) this.setState("chaos", state);
    return state;
  }

  private applyChaos(nodeId: string, heartbeat: HeartbeatMessage, now: number): { containers: ContainerMetrics[]; edge: EdgeMetricsSnapshot | undefined } {
    const chaos = this.chaosState(now);
    const host = heartbeat.hostMetrics;
    let containers = Array.isArray(heartbeat.containerMetrics) ? heartbeat.containerMetrics : [];
    let edge = heartbeat.edgeMetrics;
    const cpu = chaos.cpu[nodeId];
    if (cpu !== undefined) {
      const limits = new Map(this.loadServices().map((service) => [service.name, service.cpuLimitMilli]));
      host.cpuPct = Math.max(finite(host.cpuPct), cpu.cpuPct);
      host.cpuPsi10 = Math.max(finite(host.cpuPsi10), cpu.cpuPct >= 90 ? 40 : cpu.cpuPct >= 75 ? 20 : 5);
      host.load1 = Math.max(finite(host.load1), cpu.cpuPct / 25);
      containers = containers.map((container) => {
        const limitMilli = limits.get(container.serviceName) ?? 1000;
        const scaled = limitMilli > 0 ? (cpu.cpuPct * limitMilli) / 1000 : cpu.cpuPct;
        return { ...container, cpuPct: Math.max(container.cpuPct, scaled) };
      });
    }
    const disk = chaos.disk[nodeId];
    if (disk !== undefined) host.diskUsedPct = disk.usedPct;
    const faulty = Object.entries(chaos.fiveXx);
    if (faulty.length > 0) {
      const hosted = new Set(
        this.sql
          .exec<{ service_name: string }>("SELECT DISTINCT service_name FROM placements WHERE node_id = ?", nodeId)
          .toArray()
          .map((row) => row.service_name),
      );
      const services: EdgeServiceMetrics[] = edge === undefined ? [] : edge.services.map((entry) => ({ ...entry }));
      for (const [serviceName, fault] of faulty) {
        if (!hosted.has(serviceName)) continue;
        const entry = services.find((item) => item.serviceName === serviceName);
        if (entry === undefined) {
          services.push({
            serviceName,
            rps: 10,
            errorRate5xxPct: fault.ratePct,
            p50Ms: 5,
            p95Ms: 20,
            p99Ms: 40,
            requests: 100,
            responses5xx: Math.round(fault.ratePct),
            activeConnections: 1,
          });
        } else {
          entry.requests = Math.max(entry.requests, 100);
          entry.errorRate5xxPct = Math.max(entry.errorRate5xxPct, fault.ratePct);
          entry.responses5xx = Math.max(entry.responses5xx, Math.round((entry.requests * fault.ratePct) / 100));
        }
      }
      edge = {
        ts: edge?.ts ?? now,
        windowSeconds: edge?.windowSeconds ?? 10,
        services,
        postgresConnections: edge?.postgresConnections ?? 0,
      };
    }
    return { containers, edge };
  }

  private async onHeartbeat(ws: WebSocket, attachment: Attachment, heartbeat: HeartbeatMessage, now: number): Promise<void> {
    const row = this.loadNodeRow(attachment.nodeId);
    if (row === undefined || !acceptVolumeSeq(ws, attachment, heartbeat.volumeSeq)) return;
    const throttled = now - row.last_heartbeat_at < MIN_HEARTBEAT_INTERVAL_MS;
    const chaosDisk = this.chaosState(now).disk[attachment.nodeId];
    const reported = reportedVolumes(heartbeat.volumes);
    const heartbeatVolumes =
      reported === null || chaosDisk === undefined ? reported : withVolumeUsage(reported, row.pool_kind, chaosDisk.usedPct);
    markSessionVolumes(ws, attachment, heartbeatVolumes !== null);
    this.scheduleSessionVolumeReconcile(ws, attachment, heartbeatVolumes);
    if (typeof heartbeat.volumeChallenge === "string") {
      this.promoteVolumeBinding(ws, attachment, heartbeat.volumeChallenge, heartbeat.volumeSeq, reported);
    }
    if (throttled && heartbeatVolumes !== null) {
      this.sql.exec("UPDATE nodes SET volumes_json = ?, volumes_verified = 1, volumes_verified_at = ? WHERE id = ?", heartbeatVolumes, now, attachment.nodeId);
    } else if (throttled && row.volumes_verified !== 0) {
      this.sql.exec("UPDATE nodes SET volumes_verified = 0 WHERE id = ?", attachment.nodeId);
    }
    const tracksDataDisk = row.pool_kind === "stateful" || dataDiskSample(parseJson<unknown>(row.volumes_json, null)) !== null;
    const dataDisk = dataDiskSample(heartbeat.volumes) ?? (tracksDataDisk ? { identity: "", usedPct: null } : null);
    this.recordDataDiskSample(attachment.nodeId, dataDisk, now, false);
    if (chaosDisk !== undefined) {
      this.recordDataDiskSample(attachment.nodeId, dataDisk?.identity === "" ? dataDisk : dataDiskSample(parseJson<unknown>(heartbeatVolumes, null)), now, true);
    }
    const rolloutPlacements = throttled ? this.activeRolloutPlacements(row.id) : null;
    if (rolloutPlacements?.size === 0) return;

    let reconcileNeeded = false;
    let netbirdChanged = false;
    if (!throttled) {
      const status = this.liveStatus(row);
      const nextNetbirdIp =
        typeof heartbeat.netbirdIp === "string" && heartbeat.netbirdIp.length > 0 ? heartbeat.netbirdIp : row.netbird_ip;
      netbirdChanged = nextNetbirdIp !== row.netbird_ip;
      this.sql.exec(
        "UPDATE nodes SET last_seen_at = ?, last_heartbeat_at = ?, status = ?, netbird_ip = ?, volumes_json = ?, volumes_verified = ?, volumes_verified_at = ? WHERE id = ?",
        now,
        now,
        status,
        nextNetbirdIp,
        heartbeatVolumes ?? row.volumes_json,
        heartbeatVolumes === null ? 0 : 1,
        heartbeatVolumes === null ? row.volumes_verified_at : now,
        attachment.nodeId,
      );
      if (attachment.poolKind === "worker" && row.status === "pending" && status === "active") this.recordWorkerJoin(attachment.region);
      if (row.status === "down" || row.status === "pending") {
        this.recordEvent("node_connected", attachment.nodeId, { previous: row.status }, attachment.region);
        reconcileNeeded = true;
      }
    }
    let routesChanged = false;
    for (const report of Array.isArray(heartbeat.placements) ? heartbeat.placements : []) {
      if (rolloutPlacements !== null && (!isRecord(report) || !rolloutPlacements.has(report.placementId))) continue;
      if (this.applyReport(attachment.nodeId, report, now)) routesChanged = true;
    }
    let edge: NodeEdgeMetrics | undefined;
    if (!throttled) {
      if (isRecord(heartbeat.hostMetrics)) this.storeMetrics(attachment, heartbeat, now);
      if (chaosDisk !== undefined && heartbeatVolumes === null) this.setVolumeUsage(attachment.nodeId, chaosDisk.usedPct);
    } else if (isRecord(heartbeat.hostMetrics)) {
      edge = this.nodeEdgeMetrics(this.applyChaos(attachment.nodeId, heartbeat, now).edge, now);
    }
    if (reconcileNeeded) {
      await this.reconcile(now);
      await this.publishTopology(now, false);
    } else if (netbirdChanged) {
      await this.syncNodes("routes");
    } else if (routesChanged) {
      await this.syncNodes("routes", attachment.poolKind === "stateful" ? undefined : attachment.region);
      await this.publishTopology(now, false);
    }
    await this.advanceRollouts(now, edge === undefined ? undefined : { nodeId: attachment.nodeId, edge });
  }

  private activeRolloutPlacements(nodeId: string): Set<string> {
    const regionsByService = new Map<string, Set<string>>();
    for (const rollout of this.loadRollouts(true)) {
      if (rollout.phase === "pending") continue;
      const regions = regionsByService.get(rollout.serviceName) ?? new Set<string>();
      for (const region of rollout.activeRegions ?? []) regions.add(region);
      if (rollout.currentRegion !== undefined) regions.add(rollout.currentRegion);
      regionsByService.set(rollout.serviceName, regions);
    }
    if (regionsByService.size === 0) return new Set();
    return new Set(
      this.sql
        .exec<{ id: string; service_name: string; region: string }>("SELECT id, service_name, region FROM placements WHERE node_id = ?", nodeId)
        .toArray()
        .filter((placement) => regionsByService.get(placement.service_name)?.has(placement.region) === true)
        .map(({ id }) => id),
    );
  }

  private verifiedTargetVolume(nodeId: string, tokenHash: string | null, target: VolumeGrowTarget): { row: NodeRow; target: VolumeInfo } | undefined {
    const row = this.loadNodeRow(nodeId);
    if (row === undefined || row.token_hash !== tokenHash || row.status === "down" || row.volumes_verified !== 1) return undefined;
    if (!this.hasVolumeSession(nodeId)) return undefined;
    const live = parseJson<VolumeInfo[]>(row.volumes_json, []).find((info) => sameVolume(info, target));
    return live === undefined ? undefined : { row, target: live };
  }

  private volumeBinding(nodeId: string, bound: { row: NodeRow; target: VolumeInfo }, volume: AttachedVolume, target: VolumeGrowTarget): VolumeBindingCheck {
    if (volume.device !== target.device) return "conflict";
    const { row } = bound;
    if (row.volumes_verified !== 1 || row.volumes_verified_at - VOLUME_ATTACH_SKEW_MS <= volume.attachedAt) return "stale";
    if (!measuredGiB(bound.target.sizeGiB)) return "stale";
    if (bound.target.sizeGiB > volume.sizeGiB) return "conflict";
    const observed: VolumeBindingRecord = { attachmentId: volume.attachmentId, volumeId: volume.id, device: volume.device, identity: target.identity };
    const key = `volume_binding:${nodeId}`;
    const stored = this.getState<unknown>(key);
    if (stored !== null) {
      const binding = volumeBindingRecord(stored);
      if (binding === null || !sameAttachedVolume(binding, observed)) return "conflict";
      if (sameBinding(binding, observed)) return "bound";
    }
    const [session] = this.volumeSockets(nodeId);
    const sessionAttachment = session?.deserializeAttachment() as Attachment | null | undefined;
    if (session === undefined || typeof sessionAttachment?.sessionId !== "string") return "stale";
    const { sessionId, lastVolumeSeq } = sessionAttachment;
    const pendingKey = `volume_binding_pending:${nodeId}`;
    const pending = volumeBindingChallenge(this.getState<unknown>(pendingKey));
    const reusable = pending !== null && pending.sessionId === sessionId && pending.mountPath === target.mountPath &&
      pending.ociSizeGiB === volume.sizeGiB && sameBinding(pending, observed);
    const challenge = reusable ? pending.challenge : crypto.randomUUID();
    if (!reusable) {
      const issued: VolumeBindingChallenge = { ...observed, mountPath: target.mountPath, challenge, sessionId, volumeSeq: lastVolumeSeq, ociSizeGiB: volume.sizeGiB };
      this.setState(pendingKey, issued);
    }
    this.send(nodeId, { type: "probe_volumes", challenge }, [session]);
    return "stale";
  }

  private promoteVolumeBinding(ws: WebSocket, attachment: Attachment, challenge: string, volumeSeq: number, volumesJson: string | null): void {
    const pendingKey = `volume_binding_pending:${attachment.nodeId}`;
    const pending = volumeBindingChallenge(this.getState<unknown>(pendingKey));
    if (pending === null || volumesJson === null || !sessionVerified(ws) || this.volumeOperations.has(attachment.nodeId)) return;
    if (pending.sessionId !== attachment.sessionId || pending.challenge !== challenge || !(volumeSeq > pending.volumeSeq)) return;
    const probed = parseJson<VolumeInfo[]>(volumesJson, []).some(
      (volume) =>
        hasStableVolumeIdentity(volume.identity) &&
        volume.mountPath === pending.mountPath &&
        volume.device === pending.device &&
        volume.identity === pending.identity &&
        measuredGiB(volume.sizeGiB) &&
        volume.sizeGiB <= pending.ociSizeGiB,
    );
    if (!probed) return;
    const key = `volume_binding:${attachment.nodeId}`;
    const stored = this.getState<unknown>(key);
    const binding = stored === null ? null : volumeBindingRecord(stored);
    if (stored === null || (binding !== null && sameAttachedVolume(binding, pending))) {
      this.setState(key, { attachmentId: pending.attachmentId, volumeId: pending.volumeId, device: pending.device, identity: pending.identity });
    }
    this.deleteState(pendingKey);
  }

  private setVolumeUsage(nodeId: string, usedPct: number): void {
    const row = this.loadNodeRow(nodeId);
    if (row === undefined) return;
    this.sql.exec(
      "UPDATE nodes SET volumes_json = ? WHERE id = ?",
      withVolumeUsage(row.volumes_json, row.pool_kind, usedPct),
      nodeId,
    );
  }

  private recordDataDiskSample(nodeId: string, sample: DataDiskSample | null, now: number, synthetic: boolean): void {
    if (sample === null) return;
    this.sql.exec(
      "INSERT INTO data_disk_samples (node_id, identity, ts, disk_pct, synthetic) VALUES (?, ?, ?, ?, ?) ON CONFLICT(node_id, identity, ts, synthetic) DO UPDATE SET disk_pct = MIN(disk_pct, excluded.disk_pct)",
      nodeId,
      sample.identity,
      now,
      sample.usedPct ?? 0,
      synthetic ? 1 : 0,
    );
    if (synthetic || sample.usedPct === null) return;
    this.sql.exec(
      "INSERT INTO data_disk_1m (node_id, bucket, min_disk_pct) VALUES (?, ?, ?) ON CONFLICT(node_id, bucket) DO UPDATE SET min_disk_pct = MIN(min_disk_pct, excluded.min_disk_pct)",
      nodeId,
      minuteBucket(now),
      sample.usedPct,
    );
  }

  private seedChaosDataDisk(nodeId: string, usedPct: number, now: number): void {
    this.sql.exec("DELETE FROM data_disk_samples WHERE node_id = ? AND synthetic = 1", nodeId);
    const measured = this.sql
      .exec<{ identity: string }>("SELECT identity FROM data_disk_samples WHERE node_id = ? AND synthetic = 0 ORDER BY ts DESC LIMIT 1", nodeId)
      .toArray()[0];
    if (measured?.identity === "") return;
    const sample = dataDiskSample(parseJson<unknown>(this.loadNodeRow(nodeId)?.volumes_json ?? null, null));
    if (sample === null || !hasStableVolumeIdentity(sample.identity) || usedPct <= VOLUME_USAGE_THRESHOLD_PCT) return;
    for (let ts = now - 330_000; ts <= now; ts += 10_000) this.recordDataDiskSample(nodeId, { identity: sample.identity, usedPct }, ts, true);
  }

  private backfillDiskHistory(nodeId: string, usedPct: number, now: number): void {
    const windowStart = now - 330_000;
    const latest = this.sql
      .exec<Metrics10Row>(
        "SELECT * FROM metrics_10s WHERE node_id = ? AND ts >= ? ORDER BY ts DESC LIMIT 1",
        nodeId,
        now - METRICS_10S_RETENTION_MS,
      )
      .toArray()[0];
    this.sql.exec("UPDATE metrics_10s SET disk_used_pct = ? WHERE node_id = ? AND ts >= ?", usedPct, nodeId, windowStart);
    for (const ts of [330_000, 270_000, 210_000, 150_000, 90_000, 30_000].map((ago) => now - ago)) {
      this.sql.exec(
        "INSERT OR IGNORE INTO metrics_10s (node_id, ts, cpu_pct, cpu_psi_10, mem_used_mib, mem_psi_10, disk_used_pct, net_rx_bps, net_tx_bps, containers_json, edge_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        nodeId,
        metricsBucket(ts),
        latest?.cpu_pct ?? 0,
        latest?.cpu_psi_10 ?? 0,
        latest?.mem_used_mib ?? 0,
        latest?.mem_psi_10 ?? 0,
        usedPct,
        latest?.net_rx_bps ?? 0,
        latest?.net_tx_bps ?? 0,
        "[]",
        null,
      );
    }
    for (let bucket = Math.floor(windowStart / 60_000) * 60_000; bucket <= now; bucket += 60_000) this.rollupMinute(nodeId, bucket);
  }

  private applyReport(nodeId: string, report: PlacementReport, now: number): boolean {
    if (!isRecord(report) || typeof report.placementId !== "string" || !PLACEMENT_STATES.has(report.state)) return false;
    const row = this.sql
      .exec<PlacementRow>("SELECT * FROM placements WHERE id = ? AND node_id = ?", report.placementId, nodeId)
      .toArray()[0];
    if (row === undefined) return false;
    const hold = holdServing(row, report);
    const reportedHost = tcpPort(report.hostPort);
    const reportedPg = tcpPort(report.postgresHostPort);
    const reportedInternal = tcpPort(report.internalHostPort);
    const state = hold ? "ready" : report.state;
    const hostPort = hold ? row.host_port : reportedHost ?? row.host_port;
    const postgresHostPort = reportedPg ?? row.postgres_host_port;
    const internalHostPort = hold ? row.internal_host_port : reportedInternal ?? row.internal_host_port;
    const image = hold ? row.active_image : typeof report.image === "string" && report.image.length > 0 ? report.image : row.active_image;
    const configHash = hold
      ? row.active_config_hash
      : typeof report.configHash === "string" && report.configHash.length > 0
        ? report.configHash
        : row.active_config_hash;
    const error = hold ? row.error : typeof report.error === "string" ? report.error.slice(0, 1024) : null;
    const hasCandidate = typeof report.candidateImage === "string" && report.candidateImage.length > 0;
    const clearStaleCandidate = !hold && image === row.desired_image && (state === "ready" || state === "failed");
    const candidateImage = hasCandidate ? report.candidateImage! : clearStaleCandidate ? null : row.candidate_image;
    const candidateError = hasCandidate
      ? typeof report.candidateError === "string"
        ? report.candidateError.slice(0, 1024)
        : null
      : clearStaleCandidate
        ? null
        : row.candidate_error;
    if (
      row.state === state &&
      row.host_port === hostPort &&
      row.postgres_host_port === postgresHostPort &&
      row.internal_host_port === internalHostPort &&
      row.active_image === image &&
      row.active_config_hash === configHash &&
      row.candidate_image === candidateImage &&
      row.candidate_error === candidateError &&
      row.error === error
    ) {
      return false;
    }
    this.sql.exec(
      "UPDATE placements SET state = ?, host_port = ?, postgres_host_port = ?, internal_host_port = ?, active_image = ?, active_config_hash = ?, candidate_image = ?, candidate_error = ?, error = ?, updated_at = ? WHERE id = ?",
      state,
      hostPort,
      postgresHostPort,
      internalHostPort,
      image,
      configHash,
      candidateImage,
      candidateError,
      error,
      now,
      row.id,
    );
    return (
      row.state !== state ||
      row.host_port !== hostPort ||
      row.postgres_host_port !== postgresHostPort ||
      row.internal_host_port !== internalHostPort ||
      row.active_image !== image
    );
  }

  private storeMetrics(attachment: Attachment, heartbeat: HeartbeatMessage, now: number): void {
    const host = heartbeat.hostMetrics;
    const { containers, edge } = this.applyChaos(attachment.nodeId, heartbeat, now);
    const ts = metricsBucket(now);
    const containersJson = JSON.stringify(containers);
    const edgeJson = edge === undefined ? null : JSON.stringify(edge);
    if (encoder.encode(containersJson).length > MAX_NODE_FRAME_BYTES ||
        (edgeJson !== null && encoder.encode(edgeJson).length > MAX_NODE_FRAME_BYTES)) return;
    const previous = this.sql
      .exec<{ containers_json: string }>("SELECT containers_json FROM metrics_10s WHERE node_id = ? ORDER BY ts DESC LIMIT 1", attachment.nodeId)
      .toArray()[0];
    if (previous !== undefined) {
      const before = new Map(parseJson<ContainerMetrics[]>(previous.containers_json, []).map((c) => [c.placementId, c.oomKills]));
      for (const container of containers) {
        const prior = before.get(container.placementId);
        if (prior !== undefined && container.oomKills > prior) {
          this.recordEvent(
            "oom_kill",
            container.serviceName,
            { nodeId: attachment.nodeId, placementId: container.placementId, oomKills: container.oomKills },
            attachment.region,
          );
        }
      }
    }
    this.sql.exec(
      "INSERT INTO metrics_10s (node_id, ts, cpu_pct, cpu_psi_10, mem_used_mib, mem_psi_10, disk_used_pct, net_rx_bps, net_tx_bps, containers_json, edge_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(node_id, ts) DO UPDATE SET cpu_pct = excluded.cpu_pct, cpu_psi_10 = excluded.cpu_psi_10, mem_used_mib = excluded.mem_used_mib, mem_psi_10 = excluded.mem_psi_10, disk_used_pct = excluded.disk_used_pct, net_rx_bps = excluded.net_rx_bps, net_tx_bps = excluded.net_tx_bps, containers_json = excluded.containers_json, edge_json = excluded.edge_json",
      attachment.nodeId,
      ts,
      finite(host.cpuPct),
      finite(host.cpuPsi10),
      Math.round(finite(host.memUsedMiB)),
      finite(host.memPsi10),
      finite(host.diskUsedPct),
      finite(host.netRxBps),
      finite(host.netTxBps),
      containersJson,
      edgeJson,
    );
    this.advanceRollup(attachment.nodeId, ts);
  }

  private seedPendingRollups(now: number): void {
    const since = now - METRICS_10S_RETENTION_MS;
    const currentBucket = minuteBucket(now);
    const fullBucketSince = currentBucket - METRICS_10S_RETENTION_MS + MINUTE_MS;
    const rows = this.sql
      .exec<{ node_id: string; bucket: number }>(
        "SELECT m.node_id, (m.ts / 60000) * 60000 AS bucket FROM metrics_10s m WHERE m.ts >= ? AND NOT EXISTS (SELECT 1 FROM metrics_1m r WHERE r.node_id = m.node_id AND r.ts = (m.ts / 60000) * 60000) UNION SELECT node_id, (MAX(ts) / 60000) * 60000 AS bucket FROM metrics_10s WHERE ts >= ? GROUP BY node_id ORDER BY bucket",
        since,
        fullBucketSince,
      )
      .toArray();
    for (const row of rows) {
      if (row.bucket < currentBucket) {
        this.rollupMinute(row.node_id, row.bucket);
      } else {
        this.pendingRollups.set(row.node_id, row.bucket);
      }
    }
  }

  private advanceRollup(nodeId: string, ts: number): void {
    const bucket = minuteBucket(ts);
    const pending = this.pendingRollups.get(nodeId);
    if (pending !== undefined && pending !== bucket) this.rollupMinute(nodeId, pending);
    this.pendingRollups.set(nodeId, bucket);
  }

  private flushStaleRollups(now: number): void {
    const cutoff = minuteBucket(now);
    for (const [nodeId, bucket] of this.pendingRollups) {
      if (bucket >= cutoff) continue;
      this.rollupMinute(nodeId, bucket);
      this.pendingRollups.delete(nodeId);
    }
  }

  private computeMinutePoint(nodeId: string, ts: number): MetricsPoint1m | null {
    const bucket = minuteBucket(ts);
    const rows = this.sql
      .exec<Metrics10Row>("SELECT * FROM metrics_10s WHERE node_id = ? AND ts >= ? AND ts < ? ORDER BY ts", nodeId, bucket, bucket + MINUTE_MS)
      .toArray();
    if (rows.length === 0) return null;
    const cpu = rows.map((row) => row.cpu_pct);
    let requests = 0;
    let errors = 0;
    const rps: number[] = [];
    const p95: number[] = [];
    for (const row of rows) {
      const edge = parseJson<EdgeMetricsSnapshot | null>(row.edge_json, null);
      if (edge === null) continue;
      let rowRps = 0;
      let rowP95 = 0;
      for (const service of edge.services) {
        rowRps += finite(service.rps);
        requests += finite(service.requests);
        errors += finite(service.responses5xx);
        if (service.requests > 0) rowP95 = Math.max(rowP95, finite(service.p95Ms));
      }
      rps.push(rowRps);
      p95.push(rowP95);
    }
    return {
      nodeId,
      ts: bucket,
      cpuAvg: round(average(cpu), 2),
      cpuP95: round(percentile(cpu, 95), 2),
      cpuPsiAvg: round(average(rows.map((row) => row.cpu_psi_10)), 2),
      memAvgMiB: Math.round(average(rows.map((row) => row.mem_used_mib))),
      diskPct: round(Math.max(...rows.map((row) => row.disk_used_pct)), 2),
      edgeRps: round(average(rps), 2),
      edge5xx: requests > 0 ? round((errors / requests) * 100, 3) : 0,
      edgeP95Ms: round(average(p95), 1),
    };
  }

  private rollupMinute(nodeId: string, ts: number): void {
    const point = this.computeMinutePoint(nodeId, ts);
    if (point === null) return;
    this.sql.exec(
      "INSERT OR REPLACE INTO metrics_1m (node_id, ts, cpu_avg, cpu_p95, cpu_psi_avg, mem_avg_mib, disk_pct, edge_rps, edge_5xx, edge_p95_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
      point.nodeId,
      point.ts,
      point.cpuAvg,
      point.cpuP95,
      point.cpuPsiAvg,
      point.memAvgMiB,
      point.diskPct,
      point.edgeRps,
      point.edge5xx,
      point.edgeP95Ms,
    );
  }

  private async onDrainComplete(attachment: Attachment, now: number): Promise<void> {
    const row = this.loadNodeRow(attachment.nodeId);
    if (row === undefined || row.status === "pending") return;
    this.sql.exec("UPDATE nodes SET status = 'drained', drain_requested = 1, last_seen_at = ? WHERE id = ?", now, attachment.nodeId);
    this.recordEvent("node_drained", attachment.nodeId, {}, attachment.region);
    await this.reconcile(now);
  }

  private scheduleSessionVolumeReconcile(ws: WebSocket, attachment: Attachment, volumesJson: string | null): void {
    if (attachment.poolKind !== "stateful" || volumesJson === null || !attachment.growVolumeId || attachment.volumeReconcileScheduled) return;
    const data = parseJson<VolumeInfo[]>(volumesJson, []).find((volume) => volume.mountPath === DATA_VOLUME_PATH);
    if (data === undefined || volumeGrowTarget(data) === null) return;
    this.scheduleVolumeReconcile(attachment.nodeId, 0);
    updateSessionVolumes(ws, attachment, { volumeReconcileScheduled: true });
  }

  private expireVolumeGrow(nodeId: string): void {
    this.deleteState(`volume_grow:${nodeId}`);
    this.scheduleVolumeReconcile(nodeId, 0);
  }

  private clearPendingVolumeGrow(nodeId: string): void {
    this.deleteState(`volume_grow:${nodeId}`);
    const row = this.loadNodeRow(nodeId);
    if (row === undefined || row.pool_kind !== "stateful" || row.status === "down" || row.volumes_verified !== 1 || !this.hasVolumeSession(nodeId)) return;
    const periodicAt = Date.now() + VOLUME_RECONCILE_PERIODIC_MS;
    const scheduled = this.getState<unknown>(`volume_reconcile:${nodeId}`);
    if (scheduled === null || volumeReconcileMarker(scheduled).nextAt > periodicAt) this.scheduleVolumeReconcile(nodeId, periodicAt);
  }

  private loadVolumeReconcile(nodeId: string): VolumeReconcileMarker {
    return volumeReconcileMarker(this.getState<unknown>(`volume_reconcile:${nodeId}`));
  }

  private loadVolumeResizeTarget(volumeId: string, now: number): VolumeResizeTarget | null {
    const key = `volume_resize_target:${volumeId}`;
    const stored = this.getState<unknown>(key);
    if (stored === null) return null;
    const target = volumeResizeTarget(stored);
    if (target !== null && now < target.expiresAt) return target;
    this.deleteState(key);
    return null;
  }

  private reserveVolumeResizeTarget(volumeId: string, targetSizeGiB: number, expiresAt: number): void {
    const existing = this.loadVolumeResizeTarget(volumeId, Date.now());
    this.setState(`volume_resize_target:${volumeId}`, {
      targetSizeGiB: Math.max(targetSizeGiB, existing?.targetSizeGiB ?? 0),
      expiresAt: Math.max(expiresAt, existing?.expiresAt ?? 0),
    });
  }

  private pruneVolumeResizeTargets(now: number): void {
    const volumeIds = this.sql
      .exec<{ key: string }>("SELECT key FROM kv_state WHERE key LIKE 'volume_resize_target:%'")
      .toArray()
      .map(({ key }) => key.slice("volume_resize_target:".length));
    for (const volumeId of volumeIds) this.loadVolumeResizeTarget(volumeId, now);
  }

  private scheduleVolumeReconcile(nodeId: string, nextAt: number): void {
    const marker: VolumeReconcileMarker = { nextAt };
    this.setState(`volume_reconcile:${nodeId}`, marker);
  }

  private onVolumeGrown(attachment: Attachment, volumePath: unknown, newSizeGiB: unknown, volumeId: unknown): void {
    if (typeof volumePath !== "string" || typeof newSizeGiB !== "number" || !Number.isFinite(newSizeGiB) || newSizeGiB <= 0) return;
    if (typeof volumeId !== "string" || !attachment.volumesVerified || !attachment.growVolumeId) return;
    const pending = this.loadPendingVolumeGrow(attachment.nodeId);
    if (pending === null) return;
    if (volumeGrowExpired(pending.at, Date.now())) {
      this.expireVolumeGrow(attachment.nodeId);
      return;
    }
    if (volumePath !== pending.target.mountPath || volumeId !== pending.volumeId) return;
    const live = this.verifiedTargetVolume(attachment.nodeId, pending.tokenHash, pending.target);
    if (live === undefined) return;
    const volumes = parseJson<VolumeInfo[]>(live.row.volumes_json, []);
    let grew = false;
    for (const volume of volumes) {
      if (!sameVolume(volume, pending.target) || newSizeGiB <= volume.sizeGiB) continue;
      volume.sizeGiB = newSizeGiB;
      grew = true;
    }
    if (grew) this.sql.exec("UPDATE nodes SET volumes_json = ? WHERE id = ?", JSON.stringify(volumes), attachment.nodeId);
    const cleared = volumeReachedTarget(newSizeGiB, pending.newSizeGiB, pending.previousSizeGiB);
    if (cleared) this.clearPendingVolumeGrow(attachment.nodeId);
    if (grew || cleared) this.recordEvent("volume_grown", attachment.nodeId, { volumePath, newSizeGiB }, attachment.region);
  }

  private loadPendingVolumeGrow(nodeId: string): PendingVolumeGrow | null {
    const stored = this.sql.exec<StateRow>("SELECT value FROM kv_state WHERE key = ?", `volume_grow:${nodeId}`).toArray()[0];
    if (stored === undefined) return null;
    const pending = pendingVolumeGrow(parseJson<unknown>(stored.value, null));
    if (pending === null) {
      this.deleteState(`volume_grow:${nodeId}`);
      this.scheduleVolumeReconcile(nodeId, 0);
    }
    return pending;
  }

  private sendPendingVolumeGrow(nodeId: string, pending: PendingVolumeGrow): void {
    const key = `volume_grow:${nodeId}`;
    if (this.loadNodeRow(nodeId)?.token_hash !== pending.tokenHash) {
      this.clearPendingVolumeGrow(nodeId);
      return;
    }
    if (volumeGrowExpired(pending.at, Date.now())) {
      this.expireVolumeGrow(nodeId);
      return;
    }
    if (this.verifiedTargetVolume(nodeId, pending.tokenHash, pending.target) === undefined) return;
    const sockets = this.volumeSockets(nodeId);
    if (sockets.length === 0) return;
    const sentAt = Date.now();
    if (volumeGrowExpired(pending.at, sentAt)) {
      this.expireVolumeGrow(nodeId);
      return;
    }
    if (this.send(nodeId, growVolumeCommand(pending), sockets) > 0) this.setState(key, { ...pending, lastAttemptAt: sentAt });
  }

  private resumeVolumeGrow(nodeId: string, throttled: boolean): void {
    const pending = this.loadPendingVolumeGrow(nodeId);
    if (pending === null) return;
    const loadedAt = Date.now();
    if (volumeGrowExpired(pending.at, loadedAt)) {
      this.expireVolumeGrow(nodeId);
      return;
    }
    if ((throttled && loadedAt - pending.lastAttemptAt < VOLUME_GROW_RETRY_MS) || !this.hasVolumeSession(nodeId)) return;
    const deferredAt = this.loadVolumeReconcile(nodeId).nextAt;
    if (throttled && deferredAt > loadedAt && deferredAt - loadedAt <= VOLUME_RECONCILE_PROBE_MS) return;
    this.setState(`volume_grow:${nodeId}`, { ...pending, lastAttemptAt: loadedAt });
    this.scheduleVolumeReconcile(nodeId, 0);
  }

  private retryPendingVolumeGrows(): void {
    const nodeIds = this.sql
      .exec<{ key: string }>("SELECT key FROM kv_state WHERE key LIKE 'volume_grow:%'")
      .toArray()
      .map(({ key }) => key.slice("volume_grow:".length));
    for (const nodeId of nodeIds) this.resumeVolumeGrow(nodeId, true);
  }

  private replicaOverrides(): Record<string, number> {
    return this.getState<Record<string, number>>("replica_overrides") ?? {};
  }

  private servicesForRegion(services: ServiceSpec[], region: string, overrides: Record<string, number>): ServiceSpec[] {
    return services
      .filter((service) => service.regions.includes(region))
      .map((service) => {
        const override = overrides[`${service.name}|${region}`];
        if (override === undefined || service.mode !== "replicated") return service;
        return { ...service, replicas: Math.min(service.maxReplicas, Math.max(service.minReplicas, override)) };
      });
  }

  private async reconcile(now: number): Promise<void> {
    const regions = this.loadRegions();
    const labels = new Set(regions.map((region) => region.label));
    const nodes = this.loadNodes();
    const services = this.loadServices();
    const placements = this.loadPlacements();
    const overrides = this.replicaOverrides();
    const versions = new Map(
      this.sql
        .exec<{ name: string; config_version: number }>("SELECT name, config_version FROM services")
        .toArray()
        .map((row) => [row.name, String(row.config_version)]),
    );
    const activeRollouts = this.loadRollouts(true);
    const rolloutOrder = this.rolloutOrder();
    const unschedulable: UnschedulableEntry[] = [];
    const existing = new Map(placements.map((placement) => [placement.id, placement]));
    this.ctx.storage.transactionSync(() => {
      for (const placement of placements) {
        if (!labels.has(placement.region)) this.sql.exec("DELETE FROM placements WHERE id = ?", placement.id);
      }
      for (const region of regions) {
        const result: ScheduleResult = computeSchedule({
          regions: [region],
          nodes: nodes.filter((node) => node.region === region.label),
          services: this.servicesForRegion(services, region.label, overrides),
          currentPlacements: placements.filter((placement) => placement.region === region.label),
          nowMs: now,
          heartbeatTimeoutMs: DEFAULT_HEARTBEAT_TIMEOUT_MS,
          rollouts: activeRollouts,
          rolloutOrder,
        });
        for (const desired of result.desired) {
          const current = existing.get(desired.id);
          if (current === undefined) {
            this.sql.exec(
              "INSERT INTO placements (id, service_name, region, node_id, slot, desired_image, desired_config_hash, active_image, active_config_hash, host_port, postgres_host_port, internal_host_port, state, error, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, 'pending', NULL, ?)",
              desired.id,
              desired.serviceName,
              desired.region,
              desired.nodeId,
              desired.slot,
              desired.desiredImage,
              versions.get(desired.serviceName) ?? null,
              desired.hostPort,
              desired.postgresHostPort ?? null,
              desired.internalHostPort ?? null,
              now,
            );
          } else if (
            current.nodeId !== desired.nodeId ||
            current.slot !== desired.slot ||
            current.hostPort !== desired.hostPort ||
            current.postgresHostPort !== desired.postgresHostPort ||
            current.internalHostPort !== desired.internalHostPort
          ) {
            this.sql.exec(
              "UPDATE placements SET node_id = ?, slot = ?, host_port = ?, postgres_host_port = ?, internal_host_port = ?, updated_at = ? WHERE id = ?",
              desired.nodeId,
              desired.slot,
              desired.hostPort,
              desired.postgresHostPort ?? null,
              desired.internalHostPort ?? null,
              now,
              desired.id,
            );
          }
          const version = versions.get(desired.serviceName);
          if (version !== undefined) {
            this.sql.exec(
              "UPDATE placements SET desired_config_hash = ? WHERE id = ? AND desired_config_hash IS NOT ?",
              version,
              desired.id,
              version,
            );
          }
        }
        for (const id of result.removedIds) this.sql.exec("DELETE FROM placements WHERE id = ?", id);
        for (const nodeId of result.failedOverNodeIds) {
          this.recordEvent("failover", nodeId, { reason: "node_unavailable" }, region.label);
        }
        unschedulable.push(...result.unschedulable);
      }
      this.setState("unschedulable", unschedulable);
    });
    await this.syncNodes("all");
  }

  private syncNodes(kind: "all" | "desired" | "routes", region?: string): Promise<void> {
    const sync = this.nodeSyncPending.then(async () => {
      if (kind !== "desired") await this.pushRoutes(region);
      if (kind !== "routes") await this.pushDesired();
    });
    this.nodeSyncPending = sync.then(() => undefined, () => undefined);
    return sync;
  }

  private async pushDesired(): Promise<void> {
    const services = new Map(this.loadServices().map((service) => [service.name, service]));
    const placements = this.loadPlacements();
    for (const node of this.loadNodes()) {
      const sockets = this.sockets(node.id);
      if (sockets.length === 0) continue;
      const desired: DesiredPlacement[] = placements
        .filter((placement) => placement.nodeId === node.id)
        .flatMap((placement) => {
          const service = services.get(placement.serviceName);
          if (service === undefined) return [];
          const entry: DesiredPlacement = {
            placementId: placement.id,
            slot: placement.slot,
            service: { ...service, image: placement.desiredImage },
          };
          if (placement.hostPort !== undefined) entry.hostPort = placement.hostPort;
          if (service.postgres !== undefined && placement.postgresHostPort !== undefined) entry.postgresHostPort = placement.postgresHostPort;
          if (service.internalPort !== undefined && placement.internalHostPort !== undefined) {
            entry.internalHostPort = placement.internalHostPort;
          }
          return [entry];
        });
      const fp = await sha256Hex(JSON.stringify(desired));
      const key = `sent_desired:${node.id}`;
      if (this.getState<string>(key) === fp) continue;
      if (this.send(node.id, { type: "sync_desired", revision: this.nextRevision(), placements: desired }, sockets) > 0) this.setState(key, fp);
    }
  }

  private async pushRoutes(onlyRegion?: string): Promise<void> {
    const services = this.loadServices();
    const placements = this.loadPlacements();
    const nodes = this.loadNodes();
    for (const node of nodes) {
      if (onlyRegion !== undefined && node.region !== onlyRegion) continue;
      const sockets = this.sockets(node.id);
      if (sockets.length === 0) continue;
      const routes = computeRoutes(node.region, services, placements, nodes, node.id);
      const clusterPeers = computeClusterPeers(nodes, placements, services, node.id);
      const payload = {
        httpRoutes: routes.httpRoutes,
        postgresRoutes: routes.postgresRoutes,
        ...(routes.internalRoutes.length > 0 ? { internalRoutes: routes.internalRoutes } : {}),
        ...(clusterPeers.length > 0 ? { clusterPeers } : {}),
      };
      const fp = await sha256Hex(JSON.stringify(payload));
      const key = `sent_routes:${node.id}`;
      if (this.getState<string>(key) === fp) continue;
      const sent = this.send(node.id, {
        type: "sync_routes",
        revision: this.nextRevision(),
        ...payload,
      }, sockets);
      if (sent > 0) this.setState(key, fp);
    }
  }

  private regionOk(region: RegionConfig, nodes: NodeInfo[], services: ServiceSpec[], placements: PlacementInfo[], now: number): boolean {
    const alive = new Set(nodes.filter((node) => node.region === region.label && nodeAlive(node, now)).map((node) => node.id));
    if (alive.size === 0) return false;
    let apiHost = "";
    try {
      apiHost = new URL(region.endpoints.api).hostname;
    } catch {
      apiHost = "";
    }
    const fronting = services.filter(
      (service) =>
        service.regions.includes(region.label) &&
        service.hostnames.some((hostname) => expandRegionTemplate(hostname, region.label) === apiHost),
    );
    return (
      fronting.length > 0 &&
      fronting.every((service) =>
        placements.some(
          (placement) =>
            placement.serviceName === service.name &&
            placement.region === region.label &&
            placement.state === "ready" &&
            placement.nodeId !== undefined &&
            alive.has(placement.nodeId),
        ),
      )
    );
  }

  private buildTopology(now: number): Omit<AtlasTopology, "updated"> | null {
    const fleet = this.fleetConfig();
    const regions = this.loadRegions();
    if (fleet === null || regions.length === 0) return null;
    const nodes = this.loadNodes();
    const services = this.loadServices();
    const placements = this.loadPlacements();
    const atlasRegions: AtlasRegion[] = regions.map((region) => ({
      id: region.label,
      name: region.location.name,
      country: region.location.country,
      lat: region.location.lat,
      lon: region.location.lon,
      api: region.endpoints.api,
      auth: region.endpoints.auth,
      ok: this.regionOk(region, nodes, services, placements, now),
    }));
    return { v: 1, regions: atlasRegions, services: fleet.atlas.services };
  }

  private publishTopology(now: number, force: boolean): Promise<{ published: boolean; result?: unknown; error?: string }> {
    const publish = this.topologyPublishPending.then(() => this.publishTopologySnapshot(now, force));
    this.topologyPublishPending = publish.then(() => undefined, () => undefined);
    return publish;
  }

  private async publishTopologySnapshot(at: number, force: boolean): Promise<{ published: boolean; result?: unknown; error?: string }> {
    const now = Math.max(at, Date.now());
    const body = this.buildTopology(now);
    if (body === null) return { published: false, error: "fleet_not_seeded" };
    const fp = await sha256Hex(JSON.stringify(body));
    const last = this.getState<{ fp: string; updated: number; at: number }>("topology_published");
    const changed = last === null || last.fp !== fp;
    const nowSeconds = Math.floor(now / 1000);
    if (!force && !changed && last !== null && now - last.at < TOPOLOGY_REFRESH_MS) return { published: false };
    const updated = last === null ? nowSeconds : changed || force ? Math.max(nowSeconds, last.updated + 1) : nowSeconds;
    if (last !== null && updated <= last.updated) return { published: false };
    const topology: AtlasTopology = { ...body, updated };
    const fleet = this.fleetConfig();
    const configuredRequired = fleet?.atlas.requiredServices;
    const requiredServices =
      configuredRequired !== undefined && configuredRequired.length > 0 ? configuredRequired : ATLAS_REQUIRED_SERVICES;
    const valid = validateAtlasTopology(topology, {
      devOrigins: this.env.DEV_ORIGINS === "1" || this.env.LOCAL_DEV === "true",
      requiredServices,
    });
    if (valid === null) {
      this.setState("topology_error", { at: now, message: "topology failed Atlas validation" });
      return { published: false, error: "invalid_topology" };
    }
    try {
      const response = await atlasStub(this.env).fetch("https://atlas-store/publish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ topology: valid }),
      });
      const result: unknown = await response.json();
      if (!response.ok) throw new Error(`atlas publish failed: ${response.status}`);
      this.setState("topology_published", { fp, updated, at: now });
      this.deleteState("topology_error");
      return { published: true, result };
    } catch (error) {
      console.error("topology publish failed", error);
      this.setState("topology_error", { at: now, message: error instanceof Error ? error.message : String(error) });
      return { published: false, error: "atlas_unavailable" };
    }
  }

  private async runMaintenanceTask(task: string, run: () => unknown, errorKey?: string): Promise<void> {
    try {
      await run();
    } catch (error) {
      console.error("fleet alarm task failed", task, error);
      if (errorKey !== undefined) {
        try {
          this.setState(errorKey, { at: Date.now(), message: error instanceof Error ? error.message : String(error) });
        } catch (storageError) {
          console.error("fleet alarm error could not be recorded", task, storageError);
        }
      }
    }
  }

  override async alarm(): Promise<void> {
    const now = Date.now();
    try {
      await this.runMaintenanceTask("mark_down_nodes", () => this.markDownNodes(now));
      if (now - this.lastPrunedAt >= PRUNE_INTERVAL_MS) await this.runMaintenanceTask("prune", () => this.prune(now));
      await this.runMaintenanceTask("rollups", () => this.flushStaleRollups(now));
      await this.runMaintenanceTask("reconcile", () => this.reconcile(now));
      await this.runMaintenanceTask("rollouts", () => this.advanceRollouts(now));
      await this.runMaintenanceTask("pending_volume_grows", () => this.retryPendingVolumeGrows());
      this.ctx.waitUntil(this.runMaintenanceTask("tls", () => this.maybeAutoEnsureTls(now), "tls_error"));
      await Promise.all([
        this.runMaintenanceTask("autoscaler", () => this.runAutoscaler(now), "last_autoscale_error"),
        this.runMaintenanceTask("topology", () => this.publishTopology(now, false), "topology_error"),
      ]);
    } finally {
      try {
        await this.scheduleNextAlarm();
      } catch (error) {
        console.error("fleet alarm scheduling failed; scheduling the next regular tick", error);
        await this.ctx.storage.setAlarm(Date.now() + ALARM_INTERVAL_MS);
      }
    }
    await this.runMaintenanceTask("volume_reconcile", () => this.startVolumeReconciles(Date.now()));
  }

  private markDownNodes(now: number): void {
    const cutoff = now - DEFAULT_HEARTBEAT_TIMEOUT_MS;
    const lost = this.sql
      .exec<NodeRow>("SELECT * FROM nodes WHERE status IN ('active', 'draining', 'drained') AND last_seen_at < ?", cutoff)
      .toArray();
    for (const row of lost) {
      this.sql.exec("UPDATE nodes SET status = 'down' WHERE id = ?", row.id);
      for (const ws of this.sockets(row.id)) this.closeSocket(ws, 4008, "heartbeat timeout");
      this.recordEvent("node_lost", row.id, { lastSeenAt: row.last_seen_at, previous: row.status }, row.region);
    }
  }

  private prune(now: number): void {
    this.sql.exec("DELETE FROM metrics_10s WHERE ts < ?", now - METRICS_10S_RETENTION_MS);
    this.sql.exec("DELETE FROM metrics_1m WHERE ts < ?", now - METRICS_1M_RETENTION_MS);
    this.sql.exec("DELETE FROM data_disk_samples WHERE ts < ?", now - METRICS_10S_RETENTION_MS);
    this.sql.exec("DELETE FROM data_disk_1m WHERE bucket < ?", now - METRICS_1M_RETENTION_MS);
    this.sql.exec("DELETE FROM auth_challenges WHERE expires_at < ?", now);
    this.sql.exec("DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)", EVENTS_KEEP);
    this.ctx.storage.transactionSync(() => {
      const removed = this.sql.exec<{ id: string }>(
        `WITH service_history AS (
          SELECT r.id, ROW_NUMBER() OVER (PARTITION BY r.service_name ORDER BY r.started_at DESC, r.id DESC) AS position
          FROM rollouts r JOIN services s ON s.name = r.service_name
        )
        DELETE FROM rollouts
        WHERE state IN ('succeeded', 'rolled_back', 'failed')
          AND id NOT IN (SELECT id FROM rollouts ORDER BY started_at DESC, id DESC LIMIT ?)
          AND id NOT IN (SELECT id FROM service_history WHERE position <= ?)
        RETURNING id`,
        ROLLOUT_HISTORY_KEEP,
        SERVICE_ROLLBACK_HISTORY_KEEP,
      ).toArray();
      for (const { id } of removed) this.deleteState(`rollout_by:${id}`);
    });
    this.sql.exec("DELETE FROM kv_state WHERE key >= 'reaped_instance:' AND key < 'reaped_instance;' AND CAST(value AS INTEGER) <= ?", now);
    this.lastPrunedAt = now;
  }

  private nodeEdgeMetrics(snapshot: EdgeMetricsSnapshot | null | undefined, receivedAt: number): NodeEdgeMetrics | undefined {
    if (!snapshot || !Array.isArray(snapshot.services)) return undefined;
    let ts = finite(snapshot.ts, receivedAt);
    if (ts < 1e12) ts *= 1000;
    return { ts, windowSeconds: Math.max(0, finite(snapshot.windowSeconds)), services: snapshot.services };
  }

  private latestEdgeByNode(now: number): Map<string, NodeEdgeMetrics> {
    const rows = this.sql
      .exec<{ node_id: string; ts: number; edge_json: string | null }>(
        "SELECT m.node_id, m.ts, m.edge_json FROM metrics_10s m JOIN (SELECT node_id, MAX(ts) AS ts FROM metrics_10s WHERE ts >= ? AND edge_json IS NOT NULL GROUP BY node_id) latest ON latest.node_id = m.node_id AND latest.ts = m.ts",
        now - EDGE_FRESH_MS,
      )
      .toArray();
    const out = new Map<string, NodeEdgeMetrics>();
    for (const row of rows) {
      const edge = this.nodeEdgeMetrics(parseJson<EdgeMetricsSnapshot | null>(row.edge_json, null), row.ts);
      if (edge !== undefined) out.set(row.node_id, edge);
    }
    return out;
  }

  private baseline(serviceName: string, region: string | undefined, now: number): { p95: number; fiveXx: number } {
    const nodeIds = new Set(
      this.sql
        .exec<{ node_id: string }>(
          "SELECT DISTINCT node_id FROM placements WHERE service_name = ? AND node_id IS NOT NULL AND (? IS NULL OR region = ?)",
          serviceName,
          region ?? null,
          region ?? null,
        )
        .toArray()
        .map((row) => row.node_id),
    );
    const rows = this.sql
      .exec<{ node_id: string; edge_json: string | null }>("SELECT node_id, edge_json FROM metrics_10s WHERE ts >= ?", now - BASELINE_WINDOW_MS)
      .toArray();
    const p95: number[] = [];
    const rates: number[] = [];
    for (const row of rows) {
      if (!nodeIds.has(row.node_id)) continue;
      const edge = parseJson<EdgeMetricsSnapshot | null>(row.edge_json, null);
      const entry = edge?.services.find((service) => service.serviceName === serviceName);
      if (entry === undefined || entry.requests <= 0) continue;
      p95.push(entry.p95Ms);
      rates.push(entry.errorRate5xxPct);
    }
    return { p95: round(average(p95), 1), fiveXx: round(average(rates), 3) };
  }

  private eventKind(kind: string): EventKind {
    return EVENT_KINDS.has(kind) ? (kind as EventKind) : "chaos";
  }

  private applyStep(step: RolloutStep, now: number): void {
    this.ctx.storage.transactionSync(() => {
      for (const update of step.imageUpdates) {
        this.sql.exec(
          "UPDATE placements SET desired_image = ?, state = CASE WHEN state = 'failed' THEN 'pending' ELSE state END, error = CASE WHEN state = 'failed' THEN NULL ELSE error END, candidate_image = NULL, candidate_error = NULL, updated_at = ? WHERE id = ?",
          update.targetImage,
          now,
          update.placementId,
        );
      }
      this.saveRollout(step.rollout);
      const initiator = this.getState<Record<string, string>>(`rollout_by:${step.rollout.id}`) ?? {};
      for (const event of step.events) {
        const detail = event.kind === "deploy_started" ? { ...event.detail, ...initiator } : event.detail;
        this.recordEvent(this.eventKind(event.kind), event.subject, detail, event.region);
      }
      if (TERMINAL_PHASES.has(step.rollout.phase)) this.deleteState(`rollout_by:${step.rollout.id}`);
      const rollout = step.rollout;
      if (rollout.phase === "succeeded") {
        if (rollout.region === undefined) {
          this.sql.exec("UPDATE placements SET desired_image = ? WHERE service_name = ?", rollout.targetImage, rollout.serviceName);
        } else {
          this.sql.exec(
            "UPDATE placements SET desired_image = ? WHERE service_name = ? AND region = ?",
            rollout.targetImage,
            rollout.serviceName,
            rollout.region,
          );
        }
        const row = this.loadServiceRow(rollout.serviceName);
        if (row !== undefined) {
          const spec = this.serviceFromRow(row);
          if (rollout.region === undefined || spec.regions.every((region) => region === rollout.region)) {
            this.setServiceImage(rollout.serviceName, rollout.targetImage, now);
          }
        }
      }
    });
  }

  private setServiceImage(name: string, image: string, now: number): void {
    const row = this.loadServiceRow(name);
    if (row === undefined) return;
    const spec = { ...this.serviceFromRow(row), image };
    this.sql.exec("UPDATE services SET image = ?, spec_json = ?, updated_at = ? WHERE name = ?", image, JSON.stringify(spec), now, name);
  }

  private async advanceRollouts(now: number, heartbeat?: { nodeId: string; edge: NodeEdgeMetrics }): Promise<void> {
    const rollouts = this.loadRollouts(true);
    if (rollouts.length === 0) return;
    const nodes = this.loadNodes();
    const services = new Map(this.loadServices().map((service) => [service.name, service]));
    const order = this.rolloutOrder();
    const metrics = this.latestEdgeByNode(now);
    if (heartbeat !== undefined && heartbeat.edge.ts >= (metrics.get(heartbeat.nodeId)?.ts ?? 0)) {
      metrics.set(heartbeat.nodeId, heartbeat.edge);
    }
    let changed = false;
    for (const rollout of rollouts) {
      const service = services.get(rollout.serviceName);
      if (service === undefined) {
        this.saveRollout({ ...rollout, phase: "failed", finishedAt: now, error: "service_deleted" });
        continue;
      }
      const step = advanceRollout({
        rollout,
        service,
        placements: this.loadPlacements(),
        nodes,
        rolloutOrder: order,
        latestMetricsByNode: metrics,
        nowMs: now,
      });
      if (step.imageUpdates.length > 0 || step.events.length > 0 || JSON.stringify(step.rollout) !== JSON.stringify(rollout)) {
        this.applyStep(step, now);
        changed = true;
      }
    }
    if (changed) {
      await this.syncNodes("all");
    }
    const wakeAt = this.nextBakeDeadline(now);
    if (wakeAt !== null) await this.ensureAlarm(Math.max(250, wakeAt - Date.now()));
  }

  private async oci(): Promise<OciRestClient | null> {
    if (this.ociClient === undefined) {
      this.ociClient = (async () => {
        const env = this.env;
        const base = env.OCI_BASE_URL !== undefined && env.OCI_BASE_URL.length > 0 ? env.OCI_BASE_URL : undefined;
        if (env.OCI_TENANCY_ID && env.OCI_USER_ID && env.OCI_FINGERPRINT && env.OCI_PRIVATE_KEY_PEM) {
          return new OciRestClient({
            tenancyId: env.OCI_TENANCY_ID,
            userId: env.OCI_USER_ID,
            fingerprint: env.OCI_FINGERPRINT,
            privateKeyPem: env.OCI_PRIVATE_KEY_PEM,
            ...(base === undefined ? {} : { baseUrlOverride: base }),
          });
        }
        if (base === undefined) return null;
        const pair = (await crypto.subtle.generateKey(
          { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
          true,
          ["sign", "verify"],
        )) as CryptoKeyPair;
        const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
        let binary = "";
        for (const byte of pkcs8) binary += String.fromCharCode(byte);
        const lines = btoa(binary).match(/.{1,64}/g) ?? [];
        return new OciRestClient({
          tenancyId: env.OCI_TENANCY_ID ?? "ocid1.tenancy.oc1..localdev",
          userId: env.OCI_USER_ID ?? "ocid1.user.oc1..localdev",
          fingerprint: env.OCI_FINGERPRINT ?? "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
          privateKeyPem: `-----BEGIN PRIVATE KEY-----\n${lines.join("\n")}\n-----END PRIVATE KEY-----\n`,
          baseUrlOverride: base,
        });
      })().catch((error: unknown) => {
        this.ociClient = undefined;
        throw error;
      });
    }
    return this.ociClient;
  }

  private async runAutoscaler(now: number): Promise<void> {
    const last = this.getState<number>("autoscale_at") ?? 0;
    if (now - last < AUTOSCALE_INTERVAL_MS) return;
    this.setState("autoscale_at", now);
    const reconciledRows = this.loadRegionRows();
    if (reconciledRows.length === 0) return;
    const listings: PoolListings = new Map();
    try {
      await this.planAndRunAutoscale(now, reconciledRows, listings);
    } finally {
      await this.reconcilePendingDetaches(listings);
    }
  }

  private async planAndRunAutoscale(now: number, reconciledRows: readonly RegionRow[], listings: PoolListings): Promise<void> {
    const verified = await this.reconcilePoolMembership(reconciledRows, now, listings);
    const regionRows = this.loadRegionRows();
    const unreconciled = new Set(this.env.LOCAL_DEV === "true" ? [] : regionRows
      .filter(({ label, instance_pool_id: poolId }) => poolId !== null && poolId.length > 0 && verified.get(label) !== poolId &&
        this.hasUnlabeledOciWorker(label))
      .map(({ label }) => label));
    const regions = this.loadRegions();
    const nodes = this.loadNodes();
    const poolIds = new Map<string, string>();
    for (const row of regionRows) {
      if (row.instance_pool_id !== null && row.instance_pool_id.length > 0) poolIds.set(row.label, row.instance_pool_id);
    }
    if (nodes.length === 0 && poolIds.size === 0) return;
    const services = this.loadServices();
    const placements = this.loadPlacements();
    const overrides = this.replicaOverrides();
    const unschedulable = this.getState<UnschedulableEntry[]>("unschedulable") ?? [];
    const metrics10s = this.metricsPoints10s(now - 20 * 60_000);
    const metrics1m = this.metricsPoints1m(now - 3600_000);
    const dataDisk = this.dataDiskSamples(now);
    const failures = this.actionFailures();
    const verifiedVolumeNodeIds = new Set(
      this.sql
        .exec<{ id: string; volumes_json: string }>("SELECT id, volumes_json FROM nodes WHERE volumes_verified = 1")
        .toArray()
        .filter(({ volumes_json }) =>
          parseJson<VolumeInfo[]>(volumes_json, []).some((volume) => volume.mountPath === DATA_VOLUME_PATH && volumeGrowTarget(volume) !== null),
        )
        .map(({ id }) => id)
        .filter((id) => this.hasVolumeSession(id)),
    );
    const drainReasons = new Map<string, string>();
    for (const row of this.sql.exec<{ id: string; drain_reason: string | null }>("SELECT id, drain_reason FROM nodes WHERE drain_reason IS NOT NULL").toArray()) {
      if (row.drain_reason !== null) drainReasons.set(row.id, row.drain_reason);
    }
    const settledDetachInstanceIds = new Set<string>();
    const unsettledDetachInstanceIds = new Set<string>();
    for (const { entry } of this.pendingDetaches()) {
      if (!isRecord(entry) || typeof entry.instanceId !== "string") continue;
      if (entry.accepted || now - entry.dispatchedAt >= OCI_RETRY_TOKEN_TTL_MS) settledDetachInstanceIds.add(entry.instanceId);
      else unsettledDetachInstanceIds.add(entry.instanceId);
    }
    let cooldowns = new Map(Object.entries(this.getState<Record<string, number>>("autoscale_cooldowns") ?? {}));
    const actions: AutoscaleAction[] = [];
    for (const region of regions) {
      const result = evaluateAutoscale({
        regions: [region],
        nodes: nodes.filter((node) => node.region === region.label),
        services: this.servicesForRegion(services, region.label, overrides),
        placements: placements.filter((placement) => placement.region === region.label),
        unschedulable: unschedulable.filter((entry) => entry.region === region.label),
        metrics10s,
        metrics1m,
        dataDisk,
        cooldowns,
        failures,
        nowMs: now,
        verifiedVolumeNodeIds,
        poolIds,
        drainReasons,
        settledDetachInstanceIds,
        unsettledDetachInstanceIds,
      });
      cooldowns = result.updatedCooldowns;
      actions.push(...result.actions.filter((action) => !unreconciled.has(region.label) ||
        (action.kind !== "reap_unjoined" && action.kind !== "drain_for_scale_down" && action.kind !== "terminate_drained_worker")));
    }
    this.saveCooldowns(cooldowns);
    if (actions.length === 0) return;
    const oci = await this.oci();
    let reschedule = false;
    const attempted = (nodeId: string): number => this.lastVolumeOpAttempt.get(nodeId) ?? 0;
    const grows = actions
      .filter((action): action is Extract<AutoscaleAction, { kind: "grow_volume" }> => action.kind === "grow_volume")
      .sort((left, right) => attempted(left.nodeId) - attempted(right.nodeId));
    let nextGrow = 0;
    const mutatedPools = new Set<string>();
    for (const action of actions.map((action) => (action.kind === "grow_volume" ? (grows[nextGrow++] ?? action) : action))) {
      if ((action.kind === "terminate_drained_worker" || action.kind === "scale_pool_up" || action.kind === "reap_unjoined") &&
          mutatedPools.has(action.poolId)) continue;
      if (actionBackedOff(this.actionFailures(), action, Date.now())) continue;
      const nodeId = "nodeId" in action ? action.nodeId : undefined;
      const tokenHash = nodeId === undefined ? undefined : this.loadNodeRow(nodeId)?.token_hash;
      try {
        if (await this.executeAction(action, oci, overrides, now, cooldowns, listings, mutatedPools)) reschedule = true;
        this.saveCooldowns(cooldowns);
      } catch (error) {
        if (nodeId === undefined || (tokenHash !== undefined && this.loadNodeRow(nodeId)?.token_hash === tokenHash)) this.recordActionFailure(action, error);
      }
    }
    if (reschedule) await this.reconcile(now);
  }

  private async enrolledInstanceId(row: NodeRow): Promise<string | null> {
    const instanceId = parseLabels(row.labels_json)[INSTANCE_ID_LABEL];
    if (!isOciInstanceId(instanceId)) return null;
    return row.id === await nodeIdFor(instanceId, row.region, row.pool_kind) ? instanceId : null;
  }

  private async reapUnjoinedWorker(
    action: Extract<AutoscaleAction, { kind: "scale_pool_up" | "reap_unjoined" }>,
    oci: OciRestClient,
    listings: PoolListings,
    cooldowns: Map<string, number>,
    penalizeEligible: boolean,
    mutatedPools: Set<string>,
    ociPoolSize?: number,
  ): Promise<void> {
    const reapKey = reapUnjoinedFailureKey(action.region, action.poolId);
    const checkedAt = Date.now();
    if (this.isFailureBackedOff(reapKey, checkedAt) || this.isFailureBackedOff(poolListFailureKey(action.region, action.poolId), checkedAt) ||
        !cooled(cooldowns, reapKey, checkedAt, POOL_UP_COOLDOWN_MS)) return;
    const members = await this.listPoolMembers(oci, listings, action.region, action.ociRegion, action.poolId, action.compartmentId);
    if (members === null || this.regionPoolId(action.region) !== action.poolId) return;
    const selectedAt = Date.now();
    cooldowns.set(reapKey, selectedAt);
    this.saveCooldowns(cooldowns);
    const bootCutoff = selectedAt - POOL_ENROLLMENT_GRACE_MS;
    const aged = members.filter(({ state, createdAt }) => state === "RUNNING" && createdAt <= bootCutoff);
    const protectedInstances = new Set<string | null>(this.reapingInstances);
    for (const worker of this.workerLabelRows(action.region)) {
      if (worker.status !== "pending" || worker.enrolled_at > selectedAt - PENDING_HELLO_GRACE_MS) protectedInstances.add(worker.labels[INSTANCE_ID_LABEL] ?? null);
    }
    const reaped = (id: string): boolean => (this.getState<number>(reapedInstanceKey(id)) ?? 0) > Date.now();
    const replayable = (id: string): PendingDetach | null => {
      const stored = this.getState<PendingDetach>(pendingDetachKey(id));
      return stored !== null && stored.kind === "reap" && stored.instanceId === id && stored.poolId === action.poolId &&
        stored.ambiguous && !stored.accepted && stored.dispatchedAt > 0 && Date.now() - stored.dispatchedAt < OCI_RETRY_TOKEN_TTL_MS &&
        (!stored.decrementSize || this.workerPoolDecrementable(action.region)) ? stored : null;
    };
    for (const { id } of aged) {
      if (reaped(id) || (this.hasPendingDetach(id) && replayable(id) === null)) protectedInstances.add(id);
    }
    const target = oldestUnjoinedMember(aged, protectedInstances);
    if (target === undefined) {
      if (!aged.some(({ id }) => this.hasPendingDetach(id))) this.clearActionFailure(reapKey);
      return;
    }
    const targetPendingRows = () => this.workerLabelRows(action.region)
      .filter((worker) => worker.status === "pending" && worker.labels[INSTANCE_ID_LABEL] === target.id)
      .map(({ id }) => id);
    const signal = this.poolSignal(action.region);
    if (signal.aborted) return;
    this.reapingInstances.add(target.id);
    const pendingKey = pendingDetachKey(target.id);
    const prior = replayable(target.id);
    const decrementSize = prior === null ? this.workerPoolDecrementable(action.region) : prior.decrementSize;
    const entry: PendingDetach = prior !== null ? { ...prior } : {
      kind: "reap",
      tokenHash: null,
      region: action.region,
      ociRegion: action.ociRegion,
      compartmentId: action.compartmentId,
      poolId: action.poolId,
      instanceId: target.id,
      decrementSize,
      retryToken: crypto.randomUUID(),
      ambiguous: true,
      accepted: false,
      workRequestId: null,
      reason: "enrollment_timeout",
      createdAt: Date.now(),
      dispatchedAt: 0,
      instanceCreatedAt: target.createdAt,
      penalizeScaleUp: false,
    };
    let persisted = false;
    try {
      for (const nodeId of targetPendingRows()) {
        for (const ws of this.sockets(nodeId)) this.closeSocket(ws, 4010, "terminating");
      }
      const stillReapable = (): boolean => {
        if (signal.aborted || this.regionPoolId(action.region) !== action.poolId ||
            this.workerLabelRows(action.region).some((worker) => worker.status !== "pending" && worker.labels[INSTANCE_ID_LABEL] === target.id) ||
            (decrementSize && !this.workerPoolDecrementable(action.region)) || reaped(target.id) ||
            (prior === null ? this.hasPendingDetach(target.id) : replayable(target.id)?.retryToken !== prior.retryToken)) return false;
        const livePenalize = penalizeEligible &&
          !restoresWorkerFloor(this.registeredPoolWorkers(action.region, action.poolId), this.workerPoolFloor(action.region), ociPoolSize);
        entry.penalizeScaleUp = prior ? Boolean(prior.penalizeScaleUp) && livePenalize : livePenalize;
        if (entry.dispatchedAt === 0) entry.dispatchedAt = Date.now();
        this.setState(pendingKey, entry);
        persisted = true;
        mutatedPools.add(action.poolId);
        return true;
      };
      await oci.detachPoolInstance(action.ociRegion, action.poolId, target.id, signal, decrementSize, stillReapable, entry.retryToken).then(
        (dispatched) => {
          if (dispatched !== null) this.setState(pendingKey, { ...entry, ambiguous: false, accepted: true, workRequestId: dispatched.workRequestId ?? entry.workRequestId });
        },
        (error: unknown) => {
          if (persisted) {
            if (prior === null && definitelyRejected(error)) this.deleteState(pendingKey);
            else this.setState(pendingKey, { ...entry, ambiguous: true });
          }
          if (signal.aborted || this.regionPoolId(action.region) !== action.poolId) return;
          this.recordFailure(reapKey, "reap_unjoined_worker", error, target.id);
        },
      );
    } finally {
      this.reapingInstances.delete(target.id);
    }
  }

  private pendingDetaches(): { key: string; entry: PendingDetach | null }[] {
    return this.sql
      .exec<{ key: string; value: string }>("SELECT key, value FROM kv_state WHERE key >= 'pending_detach:' AND key < 'pending_detach;'")
      .toArray()
      .map(({ key, value }) => ({ key, entry: parseJson<PendingDetach | null>(value, null) }));
  }

  private async reconcilePendingDetaches(listings: PoolListings): Promise<void> {
    const pending = this.pendingDetaches();
    if (pending.length === 0) return;
    const oci = await this.oci();
    if (oci === null) return;
    const keys = new Set(pending.map(({ key }) => key));
    for (const key of [...this.detachCheckedAt.keys()]) {
      if (!keys.has(key)) this.detachCheckedAt.delete(key);
    }
    pending.sort((left, right) => (this.detachCheckedAt.get(left.key) ?? 0) - (this.detachCheckedAt.get(right.key) ?? 0));
    const listingKeyOf = (entry: PendingDetach): string => `${entry.ociRegion}:${entry.poolId}`;
    const current = (key: string, entry: PendingDetach): boolean => this.getState<PendingDetach>(key)?.retryToken === entry.retryToken;
    const leftPool = (entry: PendingDetach): boolean => {
      const listing = listings.get(listingKeyOf(entry));
      return listing !== undefined && listing !== null && listing.startedAt >= entry.dispatchedAt &&
        !listing.items.some(({ id }) => id === entry.instanceId);
    };
    const expired = (entry: PendingDetach): boolean => Date.now() - entry.dispatchedAt >= OCI_RETRY_TOKEN_TTL_MS;
    const settledState = (entry: PendingDetach): string | undefined => {
      if (typeof entry.workRequestState === "string" && SETTLED_WORK_REQUEST_STATES.has(entry.workRequestState)) return entry.workRequestState;
      return entry.workRequestId === null && expired(entry) ? "MISSING" : undefined;
    };
    type LiveDetach = { key: string; entry: PendingDetach; directDone: boolean };
    const live: LiveDetach[] = [];
    for (const { key, entry } of pending) {
      if (!isRecord(entry) || typeof entry.instanceId !== "string" || typeof entry.retryToken !== "string" ||
          (entry.kind !== "reap" && typeof entry.nodeId !== "string")) {
        this.deleteState(key);
        continue;
      }
      if (!listings.has(listingKeyOf(entry)) && this.isFailureBackedOff(poolListFailureKey(entry.region, entry.poolId), Date.now())) {
        listings.set(listingKeyOf(entry), null);
      }
      if (leftPool(entry)) this.finalizeDetach(key, entry);
      else live.push({ key, entry, directDone: false });
    }
    for (const [listingKey, partial] of [...this.poolListPages]) {
      if (Date.now() - partial.refreshedAt < POOL_PAGE_STATE_TTL_MS) continue;
      this.poolListPages.delete(listingKey);
      this.poolListedAt.set(listingKey, Date.now());
    }
    const listingKeys = new Set(live.map(({ entry }) => listingKeyOf(entry)));
    for (const listingKey of [...this.poolListedAt.keys()]) {
      if (!listingKeys.has(listingKey)) this.poolListedAt.delete(listingKey);
    }
    const listingInProgress = (listingKey: string): boolean => {
      const partial = this.poolListPages.get(listingKey);
      return partial !== undefined && Date.now() - partial.refreshedAt < POOL_PAGE_STATE_TTL_MS;
    };
    const nextListing = (): LiveDetach | undefined => {
      const unlisted = live.filter(({ entry }) => {
        const listing = listings.get(listingKeyOf(entry));
        return listing === undefined || (listing !== null && listing.startedAt < entry.dispatchedAt);
      });
      return unlisted.find(({ entry }) => listingInProgress(listingKeyOf(entry))) ??
        unlisted.sort((left, right) => (this.poolListedAt.get(listingKeyOf(left.entry)) ?? 0) - (this.poolListedAt.get(listingKeyOf(right.entry)) ?? 0))[0];
    };
    const drop = (item: LiveDetach): void => {
      const index = live.indexOf(item);
      if (index >= 0) live.splice(index, 1);
    };
    const directLookup = async (item: LiveDetach): Promise<void> => {
      const { key, entry } = item;
      this.detachCheckedAt.set(key, Date.now());
      const settled = settledState(entry);
      if (settled === undefined && entry.workRequestId !== null) {
        const status = await oci.getWorkRequestStatus(entry.ociRegion, entry.workRequestId).then(
          (value): string | undefined | null => value,
          (error: unknown) => (error instanceof OciError && error.status === 404 ? undefined : null),
        );
        if (!current(key, entry)) {
          drop(item);
          return;
        }
        if (status === "SUCCEEDED") {
          this.finalizeDetach(key, entry);
          drop(item);
          return;
        }
        const next = status !== undefined && status !== null && FAILED_WORK_REQUEST_STATES.has(status)
          ? status
          : status === undefined && expired(entry) ? "MISSING" : undefined;
        if (next === undefined) {
          item.directDone = true;
          return;
        }
        item.entry = { ...entry, workRequestState: next };
        this.setState(key, item.entry);
        return;
      }
      item.directDone = true;
      const attachment = await oci.getInstancePoolInstance(entry.ociRegion, entry.poolId, entry.instanceId).catch(() => undefined);
      if (!current(key, entry)) {
        drop(item);
        return;
      }
      if (attachment?.lifecycleState !== "ACTIVE") return;
      this.deleteState(key);
      this.detachCheckedAt.delete(key);
      this.recordFailure(this.detachFailureKey(entry), entry.nodeId === undefined ? "reap_unjoined_worker" : "terminate_drained_worker",
        new Error(settled === "MISSING"
          ? `OCI never confirmed detaching ${entry.instanceId} before its retry token expired`
          : `OCI detach work request ${entry.workRequestId ?? ""} ended ${settled ?? ""}`), entry.instanceId);
      drop(item);
    };
    let remainingCalls = MAX_PENDING_DETACH_LOOKUPS;
    let directCalls = 0;
    while (remainingCalls > 0) {
      const direct = live.find((item) => !item.directDone && (item.entry.workRequestId !== null || settledState(item.entry) !== undefined));
      const listing = nextListing();
      if (direct === undefined && listing === undefined) break;
      remainingCalls -= 1;
      if (direct !== undefined && (listing === undefined || directCalls === 0)) {
        directCalls += 1;
        await directLookup(direct);
      } else if (listing !== undefined) {
        await this.listPoolMembersPage(oci, listings, listing.entry);
      }
    }
    for (const { key, entry } of [...live]) {
      if (current(key, entry) && leftPool(entry)) this.finalizeDetach(key, entry);
    }
  }

  private async listPoolMembersPage(oci: OciRestClient, listings: PoolListings, entry: PendingDetach): Promise<readonly PoolInstance[] | null | undefined> {
    const listingKey = `${entry.ociRegion}:${entry.poolId}`;
    const failureKey = poolListFailureKey(entry.region, entry.poolId);
    const startedAt = Date.now();
    const partial = this.poolListPages.get(listingKey);
    const resume = partial !== undefined && startedAt - partial.refreshedAt < POOL_PAGE_STATE_TTL_MS ? partial : undefined;
    this.poolListPages.delete(listingKey);
    const page = await oci.listInstancePoolInstancesPage(entry.ociRegion, entry.poolId, entry.compartmentId, resume?.nextPage).catch((error: unknown) => {
      this.recordFailure(failureKey, "list_pool_members", error);
      return null;
    });
    const seen = resume?.seen ?? new Set<string>();
    if (page !== null && page.nextPage !== null && seen.has(page.nextPage)) {
      this.recordFailure(failureKey, "list_pool_members", new Error("OCI instance pool pagination repeated a page token"));
    } else if (page !== null) {
      const items = [...(resume?.items ?? []), ...page.items];
      if (page.nextPage !== null) {
        seen.add(page.nextPage);
        this.poolListPages.set(listingKey, { items, nextPage: page.nextPage, seen, startedAt: resume?.startedAt ?? startedAt, refreshedAt: Date.now() });
        return undefined;
      }
      this.clearActionFailure(failureKey);
      this.poolListedAt.set(listingKey, Date.now());
      listings.set(listingKey, { items, startedAt: resume?.startedAt ?? startedAt });
      return items;
    }
    this.poolListedAt.set(listingKey, Date.now());
    listings.set(listingKey, null);
    return null;
  }

  private detachFailureKey(entry: PendingDetach): string {
    return entry.nodeId === undefined ? reapUnjoinedFailureKey(entry.region, entry.poolId) : terminateWorkerFailureKey(entry.region, entry.nodeId);
  }

  private finalizeDetach(key: string, entry: PendingDetach): void {
    if (entry.nodeId !== undefined) this.finishDetachedNode(entry, entry.nodeId);
    else this.finishReapedInstance(entry);
    this.ctx.storage.transactionSync(() => {
      this.deleteState(key);
      this.setState(reapedInstanceKey(entry.instanceId), Date.now() + DETACHED_INSTANCE_TOMBSTONE_MS);
      const failureKey = this.detachFailureKey(entry);
      const instanceId = this.actionFailures().get(failureKey)?.instanceId;
      if (instanceId === undefined || instanceId === entry.instanceId) this.clearActionFailure(failureKey);
    });
    this.detachCheckedAt.delete(key);
  }

  private finishReapedInstance(entry: PendingDetach): void {
    const stalePending = this.workerLabelRows(entry.region)
      .filter((worker) => worker.status === "pending" && worker.labels[INSTANCE_ID_LABEL] === entry.instanceId)
      .map(({ id }) => id);
    for (const nodeId of stalePending) {
      for (const ws of this.sockets(nodeId)) this.closeSocket(ws, 4010, "terminated");
    }
    this.ctx.storage.transactionSync(() => {
      for (const nodeId of stalePending) this.deleteNodeRows(nodeId);
      this.recordEvent(
        entry.decrementSize ? "pool_scale_down" : "pool_worker_replaced",
        entry.instanceId,
        {
          instanceId: entry.instanceId,
          poolId: entry.poolId,
          reason: entry.reason,
          workRequestId: entry.workRequestId,
          createdAt: typeof entry.instanceCreatedAt === "number" ? new Date(entry.instanceCreatedAt).toISOString() : undefined,
          nodeId: stalePending[0],
        },
        entry.region,
      );
      if (entry.penalizeScaleUp === true && this.regionPoolId(entry.region) === entry.poolId &&
          (this.getState<number>(workerJoinedAtKey(entry.region)) ?? 0) < entry.createdAt) {
        this.setState(poolEnrollmentFailureKey(entry.region), Date.now());
      }
    });
  }

  private finishDetachedNode(entry: PendingDetach, nodeId: string): void {
    const row = this.loadNodeRow(nodeId);
    if (row === undefined || row.token_hash !== entry.tokenHash) return;
    for (const ws of this.sockets(nodeId)) this.closeSocket(ws, 4010, "terminated");
    this.ctx.storage.transactionSync(() => {
      this.deleteNodeRows(nodeId);
      this.recordEvent(
        entry.decrementSize ? "pool_scale_down" : "pool_worker_replaced",
        nodeId,
        { instanceId: entry.instanceId, poolId: entry.poolId, reason: entry.reason, workRequestId: entry.workRequestId },
        entry.region,
      );
    });
  }

  private async listPoolMembers(
    oci: OciRestClient,
    listings: PoolListings,
    region: string,
    ociRegion: string,
    poolId: string,
    compartmentId: string,
    signal?: AbortSignal,
  ): Promise<readonly PoolInstance[] | null> {
    const listingKey = `${ociRegion}:${poolId}`;
    const cached = listings.get(listingKey);
    if (cached !== undefined) return cached?.items ?? null;
    const key = poolListFailureKey(region, poolId);
    const startedAt = Date.now();
    const members = this.isFailureBackedOff(key, Date.now())
      ? null
      : await oci.listInstancePoolInstances(ociRegion, poolId, compartmentId, signal).catch((error: unknown) => {
        if (signal?.aborted !== true) this.recordFailure(key, "list_pool_members", error);
        return null;
      });
    if (members !== null) {
      this.clearActionFailure(key);
      this.poolListPages.delete(listingKey);
    }
    listings.set(listingKey, members === null ? null : { items: members, startedAt });
    return members;
  }

  private async reconcilePoolMembership(
    regionRows: readonly RegionRow[],
    now: number,
    listings: PoolListings,
  ): Promise<ReadonlyMap<string, string>> {
    const verified = new Map(regionRows.flatMap(({ label, instance_pool_id: poolId }) =>
      poolId === null || poolId.length === 0 ? [] : [[label, poolId] as const]));
    if (this.env.LOCAL_DEV === "true") return verified;
    const enrolledBefore = now - POOL_ENROLLMENT_GRACE_MS;
    const workers = this.workerLabelRows();
    const due = regionRows.filter(({ label, instance_pool_id: poolId }) =>
      poolId !== null && poolId.length > 0 && workers.some((worker) => worker.region === label && (
        (worker.labels[INSTANCE_POOL_ID_LABEL] === undefined && isOciInstanceId(worker.labels[INSTANCE_ID_LABEL])) ||
        (worker.status === "pending" && worker.enrolled_at <= enrolledBefore && worker.labels[INSTANCE_POOL_ID_LABEL] === poolId))));
    if (due.length === 0) return verified;
    const oci = await this.oci();
    if (oci === null) return verified;
    for (const region of due) {
      const poolId = region.instance_pool_id;
      if (poolId === null) continue;
      verified.delete(region.label);
      if (this.regionPoolId(region.label) !== poolId) continue;
      const signal = this.poolSignal(region.label);
      try {
        const members = await this.listPoolMembers(oci, listings, region.label, region.oci_region, poolId, region.compartment_id, signal);
        if (members === null || signal.aborted || this.regionPoolId(region.label) !== poolId) continue;
        verified.set(region.label, poolId);
        const memberIds = new Set(members.map(({ id }) => id));
        this.labelVerifiedWorkers(region.label, poolId, memberIds);
        this.sweepRegionOrphans(region.label, poolId, memberIds, enrolledBefore);
      } catch (error) {
        if (signal.aborted || this.regionPoolId(region.label) !== poolId) continue;
        console.error("worker pool membership reconcile failed", region.label, error);
        this.setState("last_autoscale_error", { at: now, action: "reconcile_pool_membership", message: error instanceof Error ? error.message : String(error) });
      }
    }
    return verified;
  }

  private hasUnlabeledOciWorker(region: string): boolean {
    return this.workerLabelRows(region).some(({ labels }) => labels[INSTANCE_POOL_ID_LABEL] === undefined && isOciInstanceId(labels[INSTANCE_ID_LABEL]));
  }

  private workerPoolMin(region: string): number | undefined {
    const min: unknown = this.loadRegions().find(({ label }) => label === region)?.pools?.worker?.min;
    return nonNegativeInteger(min) ? Math.min(min, WORKER_POOL_MAX) : undefined;
  }

  private workerPoolBounds(region: string): { min: number; max: number } | undefined {
    const worker = this.loadRegions().find(({ label }) => label === region)?.pools?.worker;
    return workerPoolBoundsOf(worker?.min, worker?.max);
  }

  private workerPoolDecrementable(region: string): boolean {
    return this.workerPoolBounds(region)?.min === 0;
  }

  private workerPoolFloor(region: string): number | undefined {
    const worker = this.loadRegions().find(({ label }) => label === region)?.pools?.worker;
    const min: unknown = worker?.min;
    const max: unknown = worker?.max;
    if (!nonNegativeInteger(min)) return undefined;
    return Math.min(min, nonNegativeInteger(max) ? max : WORKER_POOL_MAX, WORKER_POOL_MAX);
  }

  private registeredPoolWorkers(region: string, poolId: string): number {
    return this.workerLabelRows(region)
      .filter(({ status, labels }) => status !== "down" && status !== "pending" && labels[INSTANCE_POOL_ID_LABEL] === poolId).length;
  }

  private liveActiveWorkerIds(region: string, poolId: string): string[] {
    return this.sql
      .exec<{ id: string; labels_json: string }>(
        "SELECT id, labels_json FROM nodes WHERE pool_kind = 'worker' AND region = ? AND status = 'active' AND drain_requested = 0 AND last_seen_at >= ?",
        region,
        Date.now() - DEFAULT_HEARTBEAT_TIMEOUT_MS,
      )
      .toArray()
      .filter(({ labels_json }) => parseLabels(labels_json)[INSTANCE_POOL_ID_LABEL] === poolId)
      .map(({ id }) => id);
  }

  private workerLabelRows(region?: string): WorkerLabelRow[] {
    const rows = region === undefined
      ? this.sql.exec<Omit<WorkerLabelRow, "labels">>("SELECT id, region, status, enrolled_at, token_hash, labels_json FROM nodes WHERE pool_kind = 'worker'").toArray()
      : this.sql.exec<Omit<WorkerLabelRow, "labels">>("SELECT id, region, status, enrolled_at, token_hash, labels_json FROM nodes WHERE pool_kind = 'worker' AND region = ?", region).toArray();
    return rows.map((row) => ({ ...row, labels: parseLabels(row.labels_json) }));
  }

  private stampPoolLabel(worker: WorkerLabelRow, poolId: string): boolean {
    const labels = JSON.stringify({ ...worker.labels, [INSTANCE_POOL_ID_LABEL]: poolId });
    return this.sql.exec("UPDATE nodes SET labels_json = ? WHERE id = ? AND labels_json = ? RETURNING id", labels, worker.id, worker.labels_json).toArray().length > 0;
  }

  private labelVerifiedWorkers(region: string, poolId: string, poolMembers: ReadonlySet<string>): void {
    for (const worker of this.workerLabelRows(region)) {
      const instanceId = worker.labels[INSTANCE_ID_LABEL];
      if (worker.labels[INSTANCE_POOL_ID_LABEL] !== undefined || instanceId === undefined || !poolMembers.has(instanceId)) continue;
      this.stampPoolLabel(worker, poolId);
    }
  }

  private needsPoolVerification(row: NodeRow): boolean {
    if (row.pool_kind !== "worker" || row.status !== "pending") return false;
    const currentPoolId = this.regionPoolId(row.region);
    return currentPoolId !== null && currentPoolId.length > 0 &&
      parseLabels(row.labels_json)[INSTANCE_POOL_ID_LABEL] === undefined;
  }

  private async verifyPendingWorkerPool(row: NodeRow, localDev: boolean): Promise<PoolVerification> {
    const poolId = this.regionPoolId(row.region);
    const region = this.sql.exec<RegionRow>("SELECT * FROM regions WHERE label = ?", row.region).toArray()[0];
    if (poolId === null || region === undefined || !isRecord(parseJson<unknown>(row.labels_json, null))) return "not_member";
    const instanceId = parseLabels(row.labels_json)[INSTANCE_ID_LABEL];
    if (instanceId === undefined || instanceId.length === 0) return "not_member";
    const concurrentlyVerified = (): boolean => {
      const latest = this.workerLabelRows(row.region).find(({ id }) => id === row.id);
      return latest !== undefined && latest.token_hash === row.token_hash && this.regionPoolId(row.region) === poolId &&
        latest.labels[INSTANCE_POOL_ID_LABEL] === poolId;
    };
    let members: ReadonlySet<string> | null = null;
    if (isOciInstanceId(instanceId) && !localDev) {
      const oci = await this.oci();
      if (oci === null) return concurrentlyVerified() ? "verified" : "unavailable";
      const listed = await oci.listInstancePoolInstances(region.oci_region, poolId, region.compartment_id).then(
        (instances) => new Set(instances.map(({ id }) => id)),
        (error: unknown) => {
          console.error("worker pool membership check failed", row.id, error);
          return null;
        },
      );
      if (listed === null) return concurrentlyVerified() ? "verified" : "unavailable";
      members = listed;
    }
    const current = this.workerLabelRows(row.region).find(({ id }) => id === row.id);
    if (current === undefined || current.token_hash !== row.token_hash || this.regionPoolId(row.region) !== poolId) return "not_member";
    if (current.labels[INSTANCE_POOL_ID_LABEL] !== undefined) return current.labels[INSTANCE_POOL_ID_LABEL] === poolId ? "verified" : "not_member";
    if (current.status !== "pending") return "not_member";
    if (members !== null && !members.has(instanceId)) return "not_member";
    return this.stampPoolLabel(current, poolId) ? "verified" : "not_member";
  }

  private sweepRegionOrphans(region: string, poolId: string, poolMembers: ReadonlySet<string>, enrolledBefore: number): void {
    const orphans = this.workerLabelRows(region).flatMap(({ id, status, enrolled_at, labels }) => {
      const instanceId = labels[INSTANCE_ID_LABEL];
      return status === "pending" && enrolled_at <= enrolledBefore && labels[INSTANCE_POOL_ID_LABEL] === poolId &&
        isOciInstanceId(instanceId) && !poolMembers.has(instanceId) && !this.reapingInstances.has(instanceId) && !this.hasPendingDetach(instanceId)
        ? [{ id, instanceId }]
        : [];
    });
    if (orphans.length === 0) return;
    for (const { id } of orphans) {
      for (const ws of this.sockets(id)) this.closeSocket(ws, 4010, "terminated");
    }
    const sweptAt = Date.now();
    this.ctx.storage.transactionSync(() => {
      for (const { id, instanceId } of orphans) {
        this.deleteNodeRows(id);
        this.setState(reapedInstanceKey(instanceId), sweptAt + REAPED_INSTANCE_TOMBSTONE_MS);
        this.recordEvent("node_lost", id, { instanceId, poolId, reason: "left_pool_before_join" }, region);
      }
    });
  }

  private releaseRegionPool(region: string): void {
    this.poolAbortControllers.get(region)?.abort();
    this.poolAbortControllers.delete(region);
    this.deleteState(poolEnrollmentFailureKey(region));
  }

  private replaceRegionPool(region: string, poolId: string): void {
    this.releaseRegionPool(region);
    const obsolete = this.workerLabelRows(region).filter(({ status, labels }) => status === "pending" && labels[INSTANCE_POOL_ID_LABEL] !== poolId);
    for (const { id } of obsolete) {
      for (const ws of this.sockets(id)) this.closeSocket(ws, 4010, "terminating");
      this.deleteNodeRows(id);
      this.recordEvent("node_lost", id, { poolId, reason: "pool_replaced" }, region);
    }
  }

  private saveCooldowns(cooldowns: ReadonlyMap<string, number>): void {
    const currentPoolKeys = new Set(this.loadRegionRows().flatMap(({ label, instance_pool_id: poolId }) =>
      poolId === null || poolId.length === 0 ? [] : [poolScaleUpCooldownKey(label, poolId), poolScaleDownCooldownKey(label, poolId), reapUnjoinedFailureKey(label, poolId)]));
    const merged = new Map(cooldowns);
    const volumePrefix = volumeGrowCooldownKey("");
    for (const [key, at] of Object.entries(this.getState<Record<string, number>>("autoscale_cooldowns") ?? {})) {
      if (key.startsWith(volumePrefix)) merged.set(key, Math.max(at, merged.get(key) ?? at));
    }
    this.setState("autoscale_cooldowns", Object.fromEntries(
      [...merged].filter(([key]) => !(key.startsWith("pool-up:") || key.startsWith("pool-down:") || key.startsWith("pool-reap:")) || currentPoolKeys.has(key))));
  }

  private poolSignal(region: string): AbortSignal {
    const existing = this.poolAbortControllers.get(region);
    if (existing !== undefined) return existing.signal;
    const controller = new AbortController();
    this.poolAbortControllers.set(region, controller);
    return controller.signal;
  }

  private regionPoolId(region: string): string | null {
    return this.sql.exec<{ instance_pool_id: string | null }>("SELECT instance_pool_id FROM regions WHERE label = ?", region).toArray()[0]?.instance_pool_id ?? null;
  }

  private hasPendingDetach(instanceId: string): boolean {
    return this.getState<PendingDetach>(pendingDetachKey(instanceId)) !== null;
  }

  private isReapingOrReaped(instanceId: string, now: number): boolean {
    return this.reapingInstances.has(instanceId) || (this.getState<number>(reapedInstanceKey(instanceId)) ?? 0) > now ||
      this.hasPendingDetach(instanceId);
  }

  private nodeBlocked(row: NodeRow, now: number): boolean {
    const labels = parseLabels(row.labels_json);
    const instanceId = labels[INSTANCE_ID_LABEL];
    if (instanceId !== undefined && this.isReapingOrReaped(instanceId, now)) return true;
    if (row.pool_kind !== "worker" || row.status !== "pending") return false;
    const currentPoolId = this.regionPoolId(row.region);
    const poolId = labels[INSTANCE_POOL_ID_LABEL];
    return currentPoolId !== null && currentPoolId.length > 0 && poolId !== undefined && poolId !== currentPoolId;
  }

  private recordWorkerJoin(region: string): void {
    this.setState(workerJoinedAtKey(region), Date.now());
    this.deleteState(poolEnrollmentFailureKey(region));
  }

  private deleteNodeRows(nodeId: string): void {
    const row = this.loadNodeRow(nodeId);
    this.sql.exec("DELETE FROM placements WHERE node_id = ?", nodeId);
    this.sql.exec("DELETE FROM metrics_10s WHERE node_id = ?", nodeId);
    this.sql.exec("DELETE FROM metrics_1m WHERE node_id = ?", nodeId);
    this.sql.exec("DELETE FROM data_disk_samples WHERE node_id = ?", nodeId);
    this.sql.exec("DELETE FROM data_disk_1m WHERE node_id = ?", nodeId);
    this.sql.exec("DELETE FROM nodes WHERE id = ?", nodeId);
    this.deleteState(`sent_desired:${nodeId}`);
    this.deleteState(`sent_routes:${nodeId}`);
    this.deleteState(`volume_grow:${nodeId}`);
    this.deleteState(`volume_binding:${nodeId}`);
    this.deleteState(`volume_binding_pending:${nodeId}`);
    this.deleteState(`volume_reconcile:${nodeId}`);
    this.pendingRollups.delete(nodeId);
    this.lastVolumeOpAttempt.delete(nodeId);
    this.deferredGrowNodes.delete(nodeId);
    if (row !== undefined) this.clearActionFailure(volumeGrowCooldownKey(nodeId), terminateWorkerFailureKey(row.region, nodeId));
  }

  private async executeAction(
    action: AutoscaleAction,
    oci: OciRestClient | null,
    overrides: Record<string, number>,
    now: number,
    cooldowns: Map<string, number>,
    listings: PoolListings,
    mutatedPools: Set<string>,
  ): Promise<boolean> {
    switch (action.kind) {
      case "scale_replicas": {
        const key = `${action.serviceName}|${action.region}`;
        const row = this.loadServiceRow(action.serviceName);
        const current = overrides[key] ?? (row === undefined ? action.desiredReplicas : this.serviceFromRow(row).replicas);
        if (current === action.desiredReplicas) return false;
        overrides[key] = action.desiredReplicas;
        this.setState("replica_overrides", overrides);
        this.recordEvent(
          action.desiredReplicas > current ? "replica_scale_up" : "replica_scale_down",
          action.serviceName,
          { from: current, to: action.desiredReplicas, reason: action.reason },
          action.region,
        );
        this.clearActionFailure(autoscaleActionKey(action));
        return true;
      }
      case "scale_pool_up": {
        if (oci === null) return false;
        const cooldownKey = poolScaleUpCooldownKey(action.region, action.poolId);
        const failureKey = poolEnrollmentFailureKey(action.region);
        if (this.regionPoolId(action.region) !== action.poolId) return false;
        const pool = await oci.getInstancePool(action.ociRegion, action.poolId);
        const bounds = this.workerPoolBounds(action.region);
        if (this.regionPoolId(action.region) !== action.poolId || bounds === undefined) return false;
        const registeredWorkers = this.registeredPoolWorkers(action.region, action.poolId);
        const plan = planPoolScaleUp({
          ociPoolSize: pool.size,
          ociPoolState: pool.state,
          registeredWorkers,
          minSize: bounds.min,
          maxSize: bounds.max,
          enrollmentFailedAt: this.getState<number>(failureKey) ?? undefined,
          nowMs: now,
        });
        const floorRestore = plan.floorRestore || action.reason.startsWith("below_min_workers:");
        if (plan.kind === "scale") {
          const signal = this.poolSignal(action.region);
          const stillScalable = (): boolean => {
            const liveMax: unknown = this.loadRegions().find(({ label }) => label === action.region)?.pools?.worker?.max;
            const liveFloor = this.workerPoolFloor(action.region);
            if (this.regionPoolId(action.region) !== action.poolId || !nonNegativeInteger(liveMax) ||
                plan.newSize > Math.min(liveMax, WORKER_POOL_MAX) || (liveFloor !== undefined && liveFloor > plan.newSize)) return false;
            const liveMin = this.workerPoolMin(action.region);
            const failedAt = this.getState<number>(failureKey);
            const penalized = failedAt !== null && Date.now() - failedAt < POOL_ENROLLMENT_FAILURE_BACKOFF_MS;
            const allowed = (!floorRestore && !penalized) || (liveMin !== undefined && plan.newSize <= liveMin);
            if (allowed) mutatedPools.add(action.poolId);
            return allowed;
          };
          const resized = await oci.updateInstancePool(action.ociRegion, action.poolId, plan.newSize, pool.etag, signal, stillScalable).then(
            (sent) => sent,
            (error: unknown) => {
              if (signal.aborted) return false;
              throw error;
            },
          );
          if (!resized || this.regionPoolId(action.region) !== action.poolId) return false;
          cooldowns.set(cooldownKey, now);
          this.clearActionFailure(autoscaleActionKey(action));
          this.recordEvent("pool_scale_up", action.poolId, { from: pool.size, newSize: plan.newSize, registeredWorkers, reason: action.reason }, action.region);
          return false;
        }
        this.recordEvent(
          "pool_scale_blocked",
          action.poolId,
          { reason: plan.reason, ociPoolSize: pool.size, poolState: pool.state, registeredWorkers, maxSize: bounds.max, trigger: action.reason },
          action.region,
        );
        if (plan.reason === "unjoined_workers_pending") {
          await this.reapUnjoinedWorker(action, oci, listings, cooldowns, !action.reason.startsWith("below_min_workers:"), mutatedPools, pool.size).catch((error: unknown) => {
            if (this.regionPoolId(action.region) === action.poolId) this.recordFailure(reapUnjoinedFailureKey(action.region, action.poolId), "reap_unjoined_worker", error);
          });
          const liveFloor = this.workerPoolFloor(action.region);
          if (this.workerPoolBounds(action.region) === undefined || (liveFloor !== undefined && liveFloor > pool.size)) return false;
        }
        if (this.regionPoolId(action.region) !== action.poolId) return false;
        cooldowns.set(cooldownKey, now);
        this.saveCooldowns(cooldowns);
        return false;
      }
      case "reap_unjoined": {
        if (oci === null || this.regionPoolId(action.region) !== action.poolId) return false;
        const aboveFloor = action.reason !== "unjoined_cleanup" &&
          !restoresWorkerFloor(this.registeredPoolWorkers(action.region, action.poolId), this.workerPoolFloor(action.region));
        const ociPoolSize = aboveFloor
          ? await oci.getInstancePool(action.ociRegion, action.poolId).then(({ size }) => size, () => undefined)
          : undefined;
        if (this.regionPoolId(action.region) !== action.poolId) return false;
        await this.reapUnjoinedWorker(action, oci, listings, cooldowns, ociPoolSize !== undefined, mutatedPools, ociPoolSize);
        return false;
      }
      case "drain_for_scale_down": {
        if (oci === null || this.regionPoolId(action.region) !== action.poolId) return false;
        const row = this.loadNodeRow(action.nodeId);
        if (row === undefined || row.pool_kind !== "worker" || row.region !== action.region ||
            parseLabels(row.labels_json)[INSTANCE_POOL_ID_LABEL] !== action.poolId) return false;
        const minWorkers = this.workerPoolMin(action.region);
        if (minWorkers === undefined) return false;
        const activeWorkerIds = this.liveActiveWorkerIds(action.region, action.poolId);
        if (!activeWorkerIds.includes(action.nodeId) || activeWorkerIds.length - 1 < minWorkers) return false;
        await this.drainNode(action.nodeId, `autoscaler:${action.reason}`);
        const drained = this.loadNodeRow(action.nodeId);
        if (this.regionPoolId(action.region) !== action.poolId || drained === undefined || drained.token_hash !== row.token_hash ||
            drained.pool_kind !== "worker" || drained.region !== action.region ||
            parseLabels(drained.labels_json)[INSTANCE_POOL_ID_LABEL] !== action.poolId) return false;
        cooldowns.set(poolScaleDownCooldownKey(action.region, action.poolId), now);
        this.clearActionFailure(autoscaleActionKey(action));
        return false;
      }
      case "terminate_drained_worker": {
        if (oci === null) return false;
        const row = this.loadNodeRow(action.nodeId);
        if (row === undefined || row.pool_kind !== "worker" || row.region !== action.region ||
            parseLabels(row.labels_json)[INSTANCE_POOL_ID_LABEL] !== action.poolId ||
            await this.enrolledInstanceId(row) !== action.instanceId) return false;
        const current = this.loadNodeRow(action.nodeId);
        if (current === undefined || current.token_hash !== row.token_hash || current.drain_requested !== 1) return false;
        const region = this.sql.exec<RegionRow>("SELECT * FROM regions WHERE label = ?", row.region).toArray()[0];
        if (region?.instance_pool_id !== action.poolId || region.oci_region !== action.ociRegion) return false;
        if (this.workerPoolMin(action.region) === undefined) return false;
        const pendingKey = pendingDetachKey(action.instanceId);
        const stored = this.getState<PendingDetach>(pendingKey);
        const prior = stored !== null && stored.nodeId === action.nodeId && stored.tokenHash === row.token_hash &&
          stored.poolId === action.poolId && stored.instanceId === action.instanceId ? stored : null;
        if (stored !== null && (prior === null || prior.accepted || Date.now() - prior.dispatchedAt >= OCI_RETRY_TOKEN_TTL_MS)) return false;
        const { size: poolSize } = await oci.getInstancePool(action.ociRegion, action.poolId);
        if (this.regionPoolId(action.region) !== action.poolId) return false;
        const canDecrement = (): boolean => {
          const minWorkers = this.workerPoolMin(action.region);
          return minWorkers !== undefined && poolSize > minWorkers &&
            this.liveActiveWorkerIds(action.region, action.poolId).filter((id) => id !== action.nodeId).length >= minWorkers;
        };
        const decrementSize = prior === null ? canDecrement() : prior.decrementSize;
        const entry: PendingDetach = prior === null
          ? {
            kind: "terminate",
            nodeId: action.nodeId,
            tokenHash: row.token_hash,
            region: action.region,
            ociRegion: action.ociRegion,
            compartmentId: region.compartment_id,
            poolId: action.poolId,
            instanceId: action.instanceId,
            decrementSize,
            retryToken: crypto.randomUUID(),
            ambiguous: true,
            accepted: false,
            workRequestId: null,
            reason: action.reason,
            createdAt: Date.now(),
            dispatchedAt: 0,
          }
          : { ...prior, ambiguous: true };
        const signal = this.poolSignal(action.region);
        let persisted = false;
        const stillTerminable = (): boolean => {
          const live = this.loadNodeRow(action.nodeId);
          if (signal.aborted || this.regionPoolId(action.region) !== action.poolId || live === undefined || live.token_hash !== row.token_hash ||
              live.pool_kind !== "worker" || live.region !== action.region ||
              parseLabels(live.labels_json)[INSTANCE_POOL_ID_LABEL] !== action.poolId || parseLabels(live.labels_json)[INSTANCE_ID_LABEL] !== action.instanceId ||
              live.drain_requested !== 1 || live.drain_reason?.startsWith("autoscaler:") !== true ||
              (live.status !== "drained" && live.status !== "down") ||
              activePlacementCount(action.nodeId, this.loadPlacements()) > 0 ||
              this.workerPoolMin(action.region) === undefined || (decrementSize && !canDecrement()) ||
              this.getState<PendingDetach>(pendingKey)?.retryToken !== prior?.retryToken ||
              (prior !== null && Date.now() - prior.dispatchedAt >= OCI_RETRY_TOKEN_TTL_MS)) return false;
          if (entry.dispatchedAt === 0) entry.dispatchedAt = Date.now();
          this.setState(pendingKey, entry);
          persisted = true;
          mutatedPools.add(action.poolId);
          return true;
        };
        const detached = await oci.detachPoolInstance(action.ociRegion, action.poolId, action.instanceId, signal, decrementSize, stillTerminable, entry.retryToken).then(
          (dispatched) => dispatched,
          (error: unknown) => {
            if (persisted) {
              if (prior === null && definitelyRejected(error)) this.deleteState(pendingKey);
              else this.setState(pendingKey, { ...entry, ambiguous: true });
            }
            if (signal.aborted) return null;
            throw error;
          },
        );
        if (detached === null) return false;
        this.setState(pendingKey, { ...entry, ambiguous: false, accepted: true, workRequestId: detached.workRequestId ?? entry.workRequestId });
        for (const ws of this.sockets(action.nodeId)) this.closeSocket(ws, 4010, "terminating");
        return false;
      }
      case "grow_volume": {
        if (oci === null) return false;
        const row = this.loadNodeRow(action.nodeId);
        if (row === undefined || row.pool_kind !== "stateful" || row.region !== action.region) return false;
        if (this.verifiedTargetVolume(action.nodeId, row.token_hash, action.target) === undefined) return false;
        const region = this.sql.exec<RegionRow>("SELECT * FROM regions WHERE label = ?", row.region).toArray()[0];
        if (region === undefined || region.oci_region !== action.ociRegion) return false;
        if (this.backgroundVolumeReconciles.has(action.nodeId)) {
          this.deferredGrowNodes.add(action.nodeId);
          return false;
        }
        if (this.volumeOperations.has(action.nodeId) || this.volumeReconciles.has(action.nodeId)) return false;
        if (this.volumeReconciles.size >= MAX_VOLUME_OPS) {
          this.volumeGrowDeferred = true;
          return false;
        }
        this.volumeOperations.add(action.nodeId);
        this.volumeReconciles.add(action.nodeId);
        this.lastVolumeOpAttempt.set(action.nodeId, Date.now());
        this.ctx.waitUntil(this.runVolumeGrow(action, row, region, oci, now));
        return false;
      }
      default:
        return false;
    }
  }

  private async runVolumeGrow(
    action: Extract<AutoscaleAction, { kind: "grow_volume" }>,
    row: NodeRow,
    region: RegionRow,
    oci: OciRestClient,
    now: number,
  ): Promise<void> {
    try {
      await this.runMaintenanceTask("volume_grow", async () => {
        const grown = await this.growVolume(action, row, region, oci, now).catch((error: unknown) => {
          if (this.loadNodeRow(action.nodeId)?.token_hash === row.token_hash) this.recordActionFailure(action, error);
          return false;
        });
        if (grown) this.clearActionFailure(autoscaleActionKey(action));
      });
    } finally {
      this.volumeOperations.delete(action.nodeId);
      this.volumeReconciles.delete(action.nodeId);
    }
    await this.wakeAfterVolumeSlotRelease();
  }

  private async wakeAfterVolumeSlotRelease(released: readonly string[] = []): Promise<void> {
    await this.runMaintenanceTask("volume_reconcile_alarm", async () => {
      const regrow = this.takeDeferredGrows(released, Date.now());
      const deferred = this.volumeGrowDeferred || regrow;
      this.volumeGrowDeferred = false;
      if (deferred) this.setState("autoscale_at", 0);
      if (deferred || this.dueVolumeReconciles(Date.now()).length > 0) await this.ensureAlarm();
    });
  }

  private takeDeferredGrows(nodeIds: Iterable<string>, now: number): boolean {
    const ready = [...nodeIds].filter((nodeId) => !this.volumeReconciles.has(nodeId) && this.deferredGrowNodes.delete(nodeId) &&
      !this.volumeOperations.has(nodeId) && this.getState(`volume_grow:${nodeId}`) === null);
    if (ready.length === 0) return false;
    const cooldowns = this.getState<Record<string, number>>("autoscale_cooldowns") ?? {};
    return ready.some((nodeId) => hasVolumeGrowthBudget(cooldowns[volumeGrowCooldownKey(nodeId)], now));
  }

  private actionFailures(): Map<string, ActionFailure> {
    const stored = this.getState<Record<string, ActionFailure>>("autoscale_failures") ?? {};
    return new Map(Object.entries(stored).filter(([, failure]) =>
      isRecord(failure) && Number.isSafeInteger(failure.failures) && failure.failures > 0 && Number.isFinite(failure.retryAt)));
  }

  private saveActionFailures(failures: ReadonlyMap<string, ActionFailure>, now: number): void {
    const live = [...failures].filter(([, failure]) => !actionFailureExpired(failure, now));
    if (live.length === 0) this.deleteState("autoscale_failures");
    else this.setState("autoscale_failures", Object.fromEntries(live));
  }

  private recordActionFailure(action: AutoscaleAction, error: unknown): void {
    this.recordFailure(autoscaleActionKey(action), action.kind, error);
  }

  private recordFailure(key: string, kind: string, error: unknown, instanceId?: string): void {
    const caughtAt = Date.now();
    const failures = this.actionFailures();
    const next = nextActionFailure(failures.get(key), caughtAt);
    const failure: ActionFailure = instanceId === undefined ? next : { ...next, instanceId };
    failures.set(key, failure);
    this.saveActionFailures(failures, caughtAt);
    const message = error instanceof Error ? error.message : String(error);
    console.error("autoscale action failed", kind, key, failure.failures, error);
    console.log(JSON.stringify({ type: "autoscale_action_backoff", action: kind, key, failures: failure.failures, retryAt: failure.retryAt, at: caughtAt }));
    this.setState("last_autoscale_error", { at: caughtAt, action: kind, key, failures: failure.failures, retryAt: failure.retryAt, message });
  }

  private isFailureBackedOff(key: string, now: number): boolean {
    const failure = this.actionFailures().get(key);
    return failure !== undefined && failure.retryAt > now;
  }

  private clearActionFailure(...keys: string[]): void {
    const failures = this.actionFailures();
    if (keys.filter((key) => failures.delete(key)).length === 0) return;
    this.saveActionFailures(failures, Date.now());
  }

  private dataDiskSamples(now: number, nodeId: string | null = null): DataDiskPoint[] {
    return this.sql
      .exec<{ node_id: string; identity: string; ts: number; disk_pct: number }>(
        "SELECT node_id, identity, ts, disk_pct FROM data_disk_samples AS sample WHERE ts >= ? AND (? IS NULL OR node_id = ?) AND (synthetic = EXISTS (SELECT 1 FROM data_disk_samples AS chaos WHERE chaos.node_id = sample.node_id AND chaos.synthetic = 1) OR (synthetic = 0 AND identity = '')) ORDER BY ts ASC",
        now - VOLUME_SUSTAIN_MS - DEFAULT_HEARTBEAT_TIMEOUT_MS,
        nodeId,
        nodeId,
      )
      .toArray()
      .map((row) => ({ nodeId: row.node_id, identity: row.identity, ts: row.ts, usedPct: row.disk_pct }));
  }

  private stampVolumeGrowCooldown(nodeId: string, at: number): void {
    const stored = Object.entries(this.getState<Record<string, number>>("autoscale_cooldowns") ?? {});
    this.saveCooldowns(new Map([...stored, [volumeGrowCooldownKey(nodeId), at]]));
  }

  private async growVolume(
    action: Extract<AutoscaleAction, { kind: "grow_volume" }>,
    row: NodeRow,
    region: RegionRow,
    oci: OciRestClient,
    now: number,
  ): Promise<boolean> {
    const lookup = await this.lookupDataVolume(action.nodeId, row, region, oci, action.target);
    if (lookup.kind === "stale") return false;
    if (lookup.kind === "unavailable") {
      this.stampVolumeGrowCooldown(action.nodeId, now);
      return false;
    }
    const { volume, instanceId, bound, guestSizeGiB } = lookup;
    const binding = this.volumeBinding(action.nodeId, bound, volume, action.target);
    if (binding === "conflict") {
      console.warn("volume grow refused: OCI attachment does not match the bound guest volume", action.nodeId, volume.id);
      this.stampVolumeGrowCooldown(action.nodeId, now);
      return false;
    }
    if (binding === "stale") return false;
    if (volume.lifecycleState !== "AVAILABLE") {
      const checkedAt = Date.now();
      if (guestBehindOci(guestSizeGiB, volume) || this.loadVolumeResizeTarget(volume.id, checkedAt) !== null) {
        this.scheduleVolumeReconcile(action.nodeId, checkedAt + VOLUME_RECONCILE_PROBE_MS);
      }
      return false;
    }
    if (guestBehindOci(guestSizeGiB, volume)) {
      await this.recoverGuestVolume(action.nodeId, row, region, oci, lookup, action.target, action.reason);
      this.stampVolumeGrowCooldown(action.nodeId, now);
      return false;
    }
    const budget = `volume_resize_at:${volume.id}`;
    if (volume.sizeGiB >= VOLUME_MAX_GIB || !hasVolumeGrowthBudget(this.getState<number>(budget) ?? undefined, now)) {
      this.stampVolumeGrowCooldown(action.nodeId, now);
      return false;
    }
    const newSizeGiB = Math.min(VOLUME_MAX_GIB, volume.sizeGiB + VOLUME_GROW_GIB);
    const reservation = { budgetExhausted: false, previousSizeGiB: 0 };
    const update = await oci.updateVolumeSize(action.ociRegion, region.compartment_id, instanceId, volume, newSizeGiB, () => {
      const live = this.verifiedTargetVolume(action.nodeId, row.token_hash, action.target);
      if (live === undefined || this.volumeBinding(action.nodeId, live, volume, action.target) !== "bound") return false;
      const requestedAt = Date.now();
      if (!sustainedDataDisk(action.nodeId, action.target.identity, finite(live.target.usedPct, 0), this.dataDiskSamples(requestedAt, action.nodeId), requestedAt)) return false;
      if (!hasVolumeGrowthBudget(this.getState<number>(budget) ?? undefined, requestedAt)) {
        reservation.budgetExhausted = true;
        return false;
      }
      reservation.previousSizeGiB = finite(live.target.sizeGiB, 0);
      const labels = { ...parseLabels(live.row.labels_json), [DATA_VOLUME_ID_LABEL]: volume.id };
      this.sql.exec("UPDATE nodes SET labels_json = ? WHERE id = ?", JSON.stringify(labels), action.nodeId);
      this.setState(budget, requestedAt);
      this.scheduleVolumeReconcile(action.nodeId, requestedAt + VOLUME_RECONCILE_PROBE_MS);
      this.reserveVolumeResizeTarget(volume.id, newSizeGiB, requestedAt + VOLUME_GROW_MAX_MS);
      return true;
    });
    if (!update.dispatched) {
      if (reservation.budgetExhausted) this.stampVolumeGrowCooldown(action.nodeId, now);
      return false;
    }
    const attached = await oci.dataVolumeStillAttached(action.ociRegion, region.compartment_id, instanceId, volume);
    const current = this.loadNodeRow(action.nodeId);
    if (current?.token_hash !== row.token_hash) {
      if (current !== undefined) this.scheduleVolumeReconcile(action.nodeId, Math.min(this.loadVolumeReconcile(action.nodeId).nextAt, Date.now()));
      return false;
    }
    if (!attached) {
      this.scheduleVolumeReconcile(action.nodeId, 0);
      this.stampVolumeGrowCooldown(action.nodeId, now);
      return false;
    }
    const pending: PendingVolumeGrow = {
      at: Date.now(),
      lastAttemptAt: 0,
      previousSizeGiB: reservation.previousSizeGiB,
      newSizeGiB,
      reason: action.reason,
      volumeId: volume.id,
      attachmentId: volume.attachmentId,
      tokenHash: row.token_hash,
      target: action.target,
    };
    this.setState(`volume_grow:${action.nodeId}`, pending);
    this.stampVolumeGrowCooldown(action.nodeId, now);
    if (update.volume === null || !ociVolumeReady(update.volume, newSizeGiB)) {
      this.scheduleVolumeReconcile(action.nodeId, Date.now() + VOLUME_RECONCILE_PROBE_MS);
      return true;
    }
    this.deleteState(`volume_reconcile:${action.nodeId}`);
    this.dispatchVolumeGrow(action.nodeId, pending, volume);
    return true;
  }

  private async lookupDataVolume(nodeId: string, row: NodeRow, region: RegionRow, oci: OciRestClient, target: VolumeGrowTarget): Promise<DataVolumeLookup> {
    const instanceId = await this.enrolledInstanceId(row);
    if (instanceId === null) return { kind: "unavailable" };
    if (!measuredGiB(this.verifiedTargetVolume(nodeId, row.token_hash, target)?.target.sizeGiB)) return { kind: "stale" };
    const volume = await oci.statefulDataVolume(region.oci_region, region.label, region.compartment_id, instanceId);
    if (volume === null) return { kind: "unavailable" };
    const bound = this.verifiedTargetVolume(nodeId, row.token_hash, target);
    if (bound === undefined || !measuredGiB(bound.target.sizeGiB)) return { kind: "stale" };
    return { kind: "found", volume, instanceId, bound, guestSizeGiB: bound.target.sizeGiB };
  }

  private dispatchVolumeGrow(nodeId: string, pending: PendingVolumeGrow, volume: OciDataVolume): void {
    const live = this.verifiedTargetVolume(nodeId, pending.tokenHash, pending.target);
    if (live === undefined || this.volumeBinding(nodeId, live, volume, pending.target) !== "bound") return;
    this.sendPendingVolumeGrow(nodeId, pending);
  }

  private async recoverGuestVolume(
    nodeId: string,
    row: NodeRow,
    region: RegionRow,
    oci: OciRestClient,
    { volume, instanceId, guestSizeGiB }: FoundDataVolume,
    target: VolumeGrowTarget,
    reason: string,
  ): Promise<void> {
    const attached = await oci.dataVolumeStillAttached(region.oci_region, region.compartment_id, instanceId, volume);
    if (this.loadNodeRow(nodeId)?.token_hash !== row.token_hash || this.loadPendingVolumeGrow(nodeId) !== null) return;
    if (!attached) {
      this.scheduleVolumeReconcile(nodeId, 0);
      return;
    }
    if (!ociVolumeReady(volume, volume.sizeGiB)) {
      this.scheduleVolumeReconcile(nodeId, Date.now() + VOLUME_RECONCILE_PROBE_MS);
      return;
    }
    const recovered: PendingVolumeGrow = {
      at: Date.now(),
      lastAttemptAt: 0,
      previousSizeGiB: guestSizeGiB,
      newSizeGiB: volume.sizeGiB,
      reason,
      volumeId: volume.id,
      attachmentId: volume.attachmentId,
      tokenHash: row.token_hash,
      target,
    };
    this.setState(`volume_grow:${nodeId}`, recovered);
    this.deleteState(`volume_reconcile:${nodeId}`);
    this.dispatchVolumeGrow(nodeId, recovered, volume);
  }

  private dueVolumeReconciles(now: number): string[] {
    return this.sql
      .exec<{ key: string; value: string }>("SELECT key, value FROM kv_state WHERE key LIKE 'volume_reconcile:%'")
      .toArray()
      .map(({ key, value }) => ({ nodeId: key.slice("volume_reconcile:".length), nextAt: volumeReconcileMarker(parseJson<unknown>(value, null)).nextAt }))
      .filter(({ nodeId, nextAt }) => nextAt <= now && !this.volumeOperations.has(nodeId) && !this.volumeReconciles.has(nodeId))
      .map(({ nodeId, nextAt }) => ({ nodeId, nextAt, order: Math.max(nextAt, this.lastVolumeOpAttempt.get(nodeId) ?? 0) }))
      .sort((left, right) => left.order - right.order || left.nextAt - right.nextAt)
      .map(({ nodeId }) => nodeId);
  }

  private startVolumeReconciles(now: number): void {
    this.pruneVolumeResizeTargets(now);
    const free = Math.min(MAX_BACKGROUND_RECONCILES - this.backgroundVolumeReconciles.size, MAX_VOLUME_OPS - this.volumeReconciles.size);
    const batch = this.dueVolumeReconciles(now).slice(0, Math.max(0, free));
    if (batch.length === 0) return;
    const startedAt = Date.now();
    for (const nodeId of batch) {
      this.volumeReconciles.add(nodeId);
      this.backgroundVolumeReconciles.add(nodeId);
      this.lastVolumeOpAttempt.set(nodeId, startedAt);
    }
    this.ctx.waitUntil(this.runVolumeReconciles(batch, now));
  }

  private async runVolumeReconciles(batch: string[], now: number): Promise<void> {
    try {
      const oci = await this.oci();
      await Promise.all(batch.map((nodeId) => this.runMaintenanceTask("volume_reconcile", () => this.reconcileVolumeSize(nodeId, oci, now))));
    } catch (error) {
      console.error("fleet volume reconcile batch failed", error);
    } finally {
      for (const nodeId of batch) {
        this.volumeReconciles.delete(nodeId);
        this.backgroundVolumeReconciles.delete(nodeId);
      }
    }
    await this.wakeAfterVolumeSlotRelease(batch);
  }

  private async reconcileVolumeSize(nodeId: string, oci: OciRestClient | null, now: number): Promise<void> {
    const key = `volume_reconcile:${nodeId}`;
    const row = this.loadNodeRow(nodeId);
    const region = row === undefined ? undefined : this.sql.exec<RegionRow>("SELECT * FROM regions WHERE label = ?", row.region).toArray()[0];
    const reported = row === undefined ? undefined : parseJson<VolumeInfo[]>(row.volumes_json, []).find((volume) => volume.mountPath === DATA_VOLUME_PATH);
    const target = reported === undefined ? null : volumeGrowTarget(reported);
    if (oci === null || row === undefined || row.pool_kind !== "stateful" || region === undefined) {
      this.deleteState(key);
      return;
    }
    const pending = this.loadPendingVolumeGrow(nodeId);
    const offline = !this.connected(nodeId) || row.status === "down";
    if (offline) console.log(JSON.stringify({ type: "volume_reconcile_offline_dropped", nodeId, status: row.status, pending: pending !== null, at: Date.now() }));
    if (pending !== null) {
      this.deleteState(key);
      if (!offline && !this.volumeOperations.has(nodeId)) await this.replayPendingVolumeGrow(nodeId, pending, row, region, oci);
      return;
    }
    if (offline) {
      this.deleteState(key);
      return;
    }
    if (this.volumeOperations.has(nodeId)) return;
    if (target === null || this.verifiedTargetVolume(nodeId, row.token_hash, target) === undefined) {
      this.scheduleVolumeReconcile(nodeId, now + VOLUME_RECONCILE_PROBE_MS);
      return;
    }
    this.scheduleVolumeReconcile(nodeId, now + VOLUME_RECONCILE_RETRY_MS);
    this.volumeOperations.add(nodeId);
    try {
      const lookup = await this.lookupDataVolume(nodeId, row, region, oci, target);
      if (lookup.kind === "unavailable") return;
      if (lookup.kind === "stale") {
        if (this.loadNodeRow(nodeId)?.token_hash === row.token_hash) this.scheduleVolumeReconcile(nodeId, Date.now() + VOLUME_RECONCILE_PROBE_MS);
        return;
      }
      const { volume, bound, guestSizeGiB } = lookup;
      const checkedAt = Date.now();
      const resize = this.loadVolumeResizeTarget(volume.id, checkedAt);
      if (!ociVolumeReady(volume, resize?.targetSizeGiB ?? 0)) {
        if (this.loadNodeRow(nodeId)?.token_hash === row.token_hash) this.scheduleVolumeReconcile(nodeId, checkedAt + VOLUME_RECONCILE_PROBE_MS);
        return;
      }
      if (resize !== null) this.deleteState(`volume_resize_target:${volume.id}`);
      if (!guestBehindOci(guestSizeGiB, volume)) {
        if (this.loadNodeRow(nodeId)?.token_hash === row.token_hash) this.scheduleVolumeReconcile(nodeId, checkedAt + VOLUME_RECONCILE_PERIODIC_MS);
        return;
      }
      const binding = this.volumeBinding(nodeId, bound, volume, target);
      if (binding === "conflict") {
        console.warn("volume reconcile refused: OCI attachment does not match the bound guest volume", nodeId, volume.id);
        return;
      }
      if (binding === "stale") {
        this.scheduleVolumeReconcile(nodeId, Date.now() + VOLUME_RECONCILE_PROBE_MS);
        return;
      }
      if (this.loadPendingVolumeGrow(nodeId) === null) await this.recoverGuestVolume(nodeId, row, region, oci, lookup, target, "oci_size_reconcile");
    } finally {
      this.volumeOperations.delete(nodeId);
    }
  }

  private async replayPendingVolumeGrow(nodeId: string, pending: PendingVolumeGrow, row: NodeRow, region: RegionRow, oci: OciRestClient): Promise<void> {
    const key = `volume_grow:${nodeId}`;
    if (row.token_hash !== pending.tokenHash) {
      this.clearPendingVolumeGrow(nodeId);
      return;
    }
    this.volumeOperations.add(nodeId);
    try {
      const lookup = await this.lookupDataVolume(nodeId, row, region, oci, pending.target);
      if (lookup.kind !== "found") return;
      const loaded = this.loadPendingVolumeGrow(nodeId);
      if (loaded === null || loaded.at !== pending.at) return;
      const { volume, bound, instanceId, guestSizeGiB } = lookup;
      const checkedAt = Date.now();
      if (volumeGrowExpired(loaded.at, checkedAt)) {
        this.expireVolumeGrow(nodeId);
        return;
      }
      if (volumeReachedTarget(guestSizeGiB, loaded.newSizeGiB, loaded.previousSizeGiB)) {
        this.clearPendingVolumeGrow(nodeId);
        return;
      }
      if (volume.id !== loaded.volumeId || volume.attachmentId !== loaded.attachmentId) {
        this.deleteState(key);
        this.scheduleVolumeReconcile(nodeId, 0);
        return;
      }
      if (!ociVolumeReady(volume, loaded.newSizeGiB)) {
        if (this.loadNodeRow(nodeId)?.token_hash === loaded.tokenHash) this.scheduleVolumeReconcile(nodeId, checkedAt + VOLUME_RECONCILE_PROBE_MS);
        return;
      }
      if (!guestBehindOci(guestSizeGiB, volume)) {
        this.clearPendingVolumeGrow(nodeId);
        return;
      }
      const binding = this.volumeBinding(nodeId, bound, volume, loaded.target);
      if (binding === "stale") return;
      if (binding === "conflict") {
        this.deleteState(key);
        this.scheduleVolumeReconcile(nodeId, 0);
        return;
      }
      const attached = await oci.dataVolumeStillAttached(region.oci_region, region.compartment_id, instanceId, volume);
      const current = this.loadPendingVolumeGrow(nodeId);
      if (current === null || current.at !== pending.at) return;
      if (!attached) {
        this.deleteState(key);
        this.scheduleVolumeReconcile(nodeId, 0);
        return;
      }
      this.dispatchVolumeGrow(nodeId, current, volume);
    } finally {
      this.volumeOperations.delete(nodeId);
    }
  }

  private metricsFromRow(row: Metrics10Row): MetricsPoint10s {
    const point: MetricsPoint10s = {
      nodeId: row.node_id,
      ts: row.ts,
      cpuPct: row.cpu_pct,
      cpuPsi10: row.cpu_psi_10,
      memUsedMiB: row.mem_used_mib,
      memPsi10: row.mem_psi_10,
      diskUsedPct: row.disk_used_pct,
      netRxBps: row.net_rx_bps,
      netTxBps: row.net_tx_bps,
      containers: parseJson<ContainerMetrics[]>(row.containers_json, []),
    };
    const edge = parseJson<EdgeMetricsSnapshot | null>(row.edge_json, null);
    if (edge !== null) point.edge = edge;
    return point;
  }

  private metricsPoints10s(since: number, nodeIds?: Set<string>): MetricsPoint10s[] {
    return this.sql
      .exec<Metrics10Row>("SELECT * FROM metrics_10s WHERE ts >= ? ORDER BY ts", since)
      .toArray()
      .filter((row) => nodeIds === undefined || nodeIds.has(row.node_id))
      .map((row) => this.metricsFromRow(row));
  }

  private metricsPoints1m(since: number, nodeIds?: Set<string>): MetricsPoint1m[] {
    return this.sql
      .exec<Metrics1mRow>("SELECT * FROM metrics_1m WHERE ts >= ? ORDER BY ts", since)
      .toArray()
      .filter((row) => nodeIds === undefined || nodeIds.has(row.node_id))
      .map((row) => ({
        nodeId: row.node_id,
        ts: row.ts,
        cpuAvg: row.cpu_avg,
        cpuP95: row.cpu_p95,
        cpuPsiAvg: row.cpu_psi_avg,
        memAvgMiB: row.mem_avg_mib,
        diskPct: row.disk_pct,
        edgeRps: row.edge_rps,
        edge5xx: row.edge_5xx,
        edgeP95Ms: row.edge_p95_ms,
      }));
  }

  private metricsPoints1mLive(now: number, nodeIds?: Set<string>): MetricsPoint1m[] {
    const since = now - METRICS_1M_RETENTION_MS;
    const byKey = new Map<string, MetricsPoint1m>();
    for (const point of this.metricsPoints1m(since, nodeIds)) {
      byKey.set(`${point.nodeId}|${point.ts}`, point);
    }
    for (const [nodeId, bucket] of this.pendingRollups) {
      if (bucket < since) continue;
      if (nodeIds !== undefined && !nodeIds.has(nodeId)) continue;
      const live = this.computeMinutePoint(nodeId, bucket);
      if (live !== null) byKey.set(`${nodeId}|${bucket}`, live);
    }
    return [...byKey.values()].sort((a, b) => a.ts - b.ts || (a.nodeId < b.nodeId ? -1 : a.nodeId > b.nodeId ? 1 : 0));
  }

  private nodeFilter(url: URL): Set<string> | undefined {
    const region = url.searchParams.get("region");
    const node = url.searchParams.get("node");
    if (region === null && node === null) return undefined;
    return new Set(
      this.loadNodes()
        .filter((item) => (region === null || item.region === region) && (node === null || item.id === node))
        .map((item) => item.id),
    );
  }

  private top(url: URL): TopResponse {
    const now = Date.now();
    const filter = this.nodeFilter(url);
    const latest = new Map<string, MetricsPoint10s>();
    for (const point of this.metricsPoints10s(now - 60_000, filter)) latest.set(point.nodeId, point);
    return { ts: now, nodes: [...latest.values()].sort((a, b) => (a.nodeId < b.nodeId ? -1 : 1)) };
  }

  private metrics(url: URL): unknown {
    const now = Date.now();
    const window = url.searchParams.get("window") === "48h" ? "48h" : "1h";
    const filter = this.nodeFilter(url);
    if (window === "48h") return { window, ts: now, points: this.metricsPoints1mLive(now, filter) };
    return { window, ts: now, points: this.metricsPoints10s(now - METRICS_10S_RETENTION_MS, filter) };
  }

  private async atlasCounts(): Promise<Record<string, number>> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        (async () => {
          const response = await atlasStub(this.env).fetch("https://atlas-store/counts");
          if (!response.ok) return {};
          const body = (await response.json()) as { counts?: Record<string, number> };
          return body.counts ?? {};
        })(),
        new Promise<Record<string, number>>((resolve) => {
          timer = setTimeout(() => resolve({}), 1_500);
        }),
      ]);
    } catch {
      return {};
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  private async status(url: URL): Promise<unknown> {
    const now = Date.now();
    const regionFilter = url.searchParams.get("region");
    const regions = this.loadRegions().filter((region) => regionFilter === null || region.label === regionFilter);
    const allNodes = this.loadNodes();
    const nodes = allNodes.filter((node) => regionFilter === null || node.region === regionFilter);
    const services = this.loadServices();
    const servicesByName = new Map(services.map((service) => [service.name, service]));
    const allPlacements = this.loadPlacements();
    const placements = allPlacements.filter((placement) => regionFilter === null || placement.region === regionFilter);
    const unschedulable = (this.getState<UnschedulableEntry[]>("unschedulable") ?? []).filter(
      (entry) => regionFilter === null || entry.region === regionFilter,
    );
    const counts = await this.atlasCounts();
    const summaries: RegionSummary[] = regions.map((region) => {
      const regionNodes = nodes.filter((node) => node.region === region.label);
      const ready = regionNodes.filter((node) => nodeAlive(node, now));
      const readyIds = new Set(ready.map((node) => node.id));
      let cpuRequested = 0;
      let memRequested = 0;
      for (const placement of placements) {
        if (placement.region !== region.label || placement.nodeId === undefined || !readyIds.has(placement.nodeId)) continue;
        if (INACTIVE_PLACEMENT_STATES.has(placement.state)) continue;
        const service = servicesByName.get(placement.serviceName);
        if (service === undefined) continue;
        cpuRequested += service.cpuRequestMilli;
        memRequested += service.memRequestMiB;
      }
      const cpuTotal = ready.reduce((sum, node) => sum + node.cpuTotalMilli, 0);
      const memTotal = ready.reduce((sum, node) => sum + node.memTotalMiB, 0);
      const cpuAlloc = ready.reduce((sum, node) => sum + allocatableCpuMilli(node), 0);
      const memAlloc = ready.reduce((sum, node) => sum + allocatableMemMiB(node), 0);
      const packing = Math.max(cpuAlloc > 0 ? cpuRequested / cpuAlloc : 0, memAlloc > 0 ? memRequested / memAlloc : 0);
      const health: HealthState =
        ready.length === 0
          ? regionNodes.length === 0
            ? "unknown"
            : "down"
          : this.regionOk(region, allNodes, services, allPlacements, now)
            ? "ok"
            : "down";
      return {
        label: region.label,
        health,
        nodes: regionNodes.length,
        nodesReady: ready.length,
        statefulNodes: regionNodes.filter((node) => node.poolKind === "stateful").length,
        workerNodes: regionNodes.filter((node) => node.poolKind === "worker").length,
        cpuTotalMilli: cpuTotal,
        cpuRequestedMilli: cpuRequested,
        memTotalMiB: memTotal,
        memRequestedMiB: memRequested,
        databases: counts[region.label] ?? 0,
        packingPct: round(packing * 100, 1),
      };
    });
    const serviceSummaries: ServiceSummary[] = services
      .filter((service) => regionFilter === null || service.regions.includes(regionFilter))
      .map((service) => {
        const own = placements.filter((placement) => placement.serviceName === service.name);
        const missing = unschedulable.filter((entry) => entry.serviceName === service.name).reduce((sum, entry) => sum + entry.missing, 0);
        return {
          name: service.name,
          mode: service.mode,
          priority: service.priority,
          image: service.image,
          regions: service.regions,
          desired: own.length + missing,
          ready: own.filter((placement) => placement.state === "ready").length,
        };
      });
    const nodeCpu = new Map<string, number>();
    const nodeMem = new Map<string, number>();
    for (const placement of placements) {
      if (placement.nodeId === undefined || INACTIVE_PLACEMENT_STATES.has(placement.state)) continue;
      const service = servicesByName.get(placement.serviceName);
      if (service === undefined) continue;
      nodeCpu.set(placement.nodeId, (nodeCpu.get(placement.nodeId) ?? 0) + service.cpuRequestMilli);
      nodeMem.set(placement.nodeId, (nodeMem.get(placement.nodeId) ?? 0) + service.memRequestMiB);
    }
    const statusNodes: NodeInfo[] = nodes.map((node) => ({
      ...node,
      cpuRequestedMilli: nodeCpu.get(node.id) ?? 0,
      memRequestedMiB: nodeMem.get(node.id) ?? 0,
    }));
    const rollouts = this.loadRollouts(false, 20).filter(
      (rollout) => regionFilter === null || rollout.region === undefined || rollout.region === regionFilter,
    );
    const tls = this.sql.exec<TlsRow>("SELECT * FROM tls_certs WHERE id = 'shared'").toArray()[0];
    const response: StatusResponse = {
      ts: now,
      regions: summaries,
      nodes: statusNodes,
      services: serviceSummaries,
      placements,
      rollouts,
    };
    return {
      ...response,
      unschedulable,
      atlas: { databases: counts, topology: this.getState("topology_published"), error: this.getState("topology_error") },
      tls: tls === undefined ? null : { domains: parseJson<string[]>(tls.domains_json, []), notAfter: tls.not_after, renewedAt: tls.renewed_at },
      tls_error: this.getState("tls_error"),
      last_autoscale_error: this.getState("last_autoscale_error"),
      localDev: this.env.LOCAL_DEV === "true",
      version: this.env.VERSION ?? "dev",
    };
  }

  private events(request: Request, url: URL): Response {
    const region = url.searchParams.get("region");
    const since = Number(url.searchParams.get("since") ?? "0");
    const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? "200") || 200, 1), EVENTS_KEEP);
    const rows = this.sql
      .exec<EventRow>(
        "SELECT * FROM events WHERE ts >= ? AND (? IS NULL OR region = ?) ORDER BY id DESC LIMIT ?",
        Number.isFinite(since) ? since : 0,
        region,
        region,
        limit,
      )
      .toArray()
      .reverse()
      .map((row) => this.eventFromRow(row));
    const follow = url.searchParams.get("follow") === "1" || url.searchParams.get("follow") === "true";
    if (!follow) return json({ events: rows });
    const sse = (request.headers.get("Accept") ?? "").includes("text/event-stream");
    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
    const writer = writable.getWriter();
    const format = (event: EventRecord): Uint8Array =>
      encoder.encode(sse ? `id: ${event.id}\ndata: ${JSON.stringify(event)}\n\n` : `${JSON.stringify(event)}\n`);
    let keepAlive: ReturnType<typeof setInterval> | undefined;
    let maxTimer: ReturnType<typeof setTimeout> | undefined;
    const subscriber: EventSubscriber = {
      region,
      push: (event) => {
        writer.write(format(event)).catch(() => stop());
      },
    };
    const stop = (): void => {
      if (!this.eventSubscribers.delete(subscriber)) return;
      if (keepAlive !== undefined) clearInterval(keepAlive);
      if (maxTimer !== undefined) clearTimeout(maxTimer);
      writer.close().catch(() => undefined);
    };
    this.eventSubscribers.add(subscriber);
    for (const event of rows) writer.write(format(event)).catch(() => stop());
    keepAlive = setInterval(() => {
      writer.write(encoder.encode(sse ? ": keepalive\n\n" : "\n")).catch(() => stop());
    }, KEEPALIVE_MS);
    maxTimer = setTimeout(stop, STREAM_MAX_MS);
    return new Response(readable, {
      headers: {
        "Content-Type": sse ? "text/event-stream" : "application/x-ndjson",
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",
      },
    });
  }

  private logs(request: Request, url: URL): Response {
    const serviceName = url.searchParams.get("service");
    if (serviceName === null || serviceName.length === 0) throw new HttpError(400, "validation", "service is required");
    const nodeFilter = url.searchParams.get("node");
    const tailText = url.searchParams.get("tail");
    if (tailText !== null && !/^(0|[1-9][0-9]*)$/.test(tailText)) {
      throw new HttpError(400, "validation", "tail must be a non-negative integer");
    }
    const parsedTail = tailText === null ? 100 : Number(tailText);
    if (!Number.isSafeInteger(parsedTail) || parsedTail < 0) throw new HttpError(400, "validation", "tail must be a non-negative integer");
    const tail = Math.min(parsedTail, 10_000);
    const follow = url.searchParams.get("follow") === "1" || url.searchParams.get("follow") === "true";
    const targets = this.loadPlacements().filter(
      (placement) =>
        placement.serviceName === serviceName &&
        placement.nodeId !== undefined &&
        (nodeFilter === null || placement.nodeId === nodeFilter) &&
        placement.state !== "stopped",
    );
    if (targets.length === 0) throw new HttpError(404, "not_found", `No placements of ${serviceName} match`);
    const sse = (request.headers.get("Accept") ?? "").includes("text/event-stream");
    const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
    const streamId = randomToken(12);
    const stream: LogStream = {
      writer: writable.getWriter(),
      sse,
      follow,
      requests: new Set(),
      idleTimer: undefined,
      maxTimer: undefined,
      keepAlive: undefined,
      closed: false,
    };
    this.logStreams.set(streamId, stream);
    for (const placement of targets) {
      const nodeId = placement.nodeId;
      if (nodeId === undefined) continue;
      const requestId = randomToken(12);
      this.logRequests.set(requestId, { streamId, nodeId, placementId: placement.id });
      stream.requests.add(requestId);
      const sent = this.send(nodeId, { type: "stream_logs", requestId, containerName: placement.id, tail, follow });
      if (sent === 0) {
        this.logRequests.delete(requestId);
        stream.requests.delete(requestId);
      }
    }
    if (stream.requests.size === 0) {
      this.logStreams.delete(streamId);
      stream.writer.close().catch(() => undefined);
      throw new HttpError(503, "unavailable", `No node hosting ${serviceName} is connected`);
    }
    if (follow) {
      stream.keepAlive = setInterval(() => {
        stream.writer.write(encoder.encode(sse ? ": keepalive\n\n" : "\n")).catch(() => void this.closeLogStream(streamId, true));
      }, KEEPALIVE_MS);
      stream.maxTimer = setTimeout(() => void this.closeLogStream(streamId, true), STREAM_MAX_MS);
    } else {
      stream.idleTimer = setTimeout(() => void this.closeLogStream(streamId, true), LOG_FIRST_MS);
      stream.maxTimer = setTimeout(() => void this.closeLogStream(streamId, true), LOG_MAX_MS);
    }
    void this.ensureAlarm(ALARM_INTERVAL_MS);
    return new Response(readable, {
      headers: {
        "Content-Type": sse ? "text/event-stream" : "application/x-ndjson",
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",
      },
    });
  }

  private onLogChunk(nodeId: string, requestId: string, channel: string, line: string): void {
    const request = this.logRequests.get(requestId);
    if (request === undefined) {
      this.send(nodeId, { type: "stop_logs", requestId });
      return;
    }
    if (request.nodeId !== nodeId) return;
    const stream = this.logStreams.get(request.streamId);
    if (stream === undefined || stream.closed) return;
    const payload = JSON.stringify({ nodeId, placementId: request.placementId, stream: channel, line });
    stream.writer
      .write(encoder.encode(stream.sse ? `data: ${payload}\n\n` : `${payload}\n`))
      .catch(() => void this.closeLogStream(request.streamId, true));
    if (!stream.follow) {
      if (stream.idleTimer !== undefined) clearTimeout(stream.idleTimer);
      stream.idleTimer = setTimeout(() => void this.closeLogStream(request.streamId, true), LOG_IDLE_MS);
    }
  }

  private async closeLogStream(streamId: string, notifyNodes: boolean): Promise<void> {
    const stream = this.logStreams.get(streamId);
    if (stream === undefined || stream.closed) return;
    stream.closed = true;
    this.logStreams.delete(streamId);
    if (stream.idleTimer !== undefined) clearTimeout(stream.idleTimer);
    if (stream.maxTimer !== undefined) clearTimeout(stream.maxTimer);
    if (stream.keepAlive !== undefined) clearInterval(stream.keepAlive);
    for (const requestId of stream.requests) {
      const request = this.logRequests.get(requestId);
      this.logRequests.delete(requestId);
      if (notifyNodes && request !== undefined) this.send(request.nodeId, { type: "stop_logs", requestId });
    }
    await stream.writer.close().catch(() => undefined);
  }

  private async exec(request: Request, principal: Principal): Promise<ExecResponse> {
    const body = (await this.readJson(request)) as Partial<ExecRequest>;
    if (typeof body.nodeId !== "string" || typeof body.service !== "string") {
      throw new HttpError(400, "validation", "nodeId and service are required");
    }
    if (!Array.isArray(body.command) || body.command.length === 0 || !body.command.every((part) => typeof part === "string")) {
      throw new HttpError(400, "validation", "command must be a non-empty list of strings");
    }
    const timeoutSeconds = Math.min(Math.max(Math.floor(finite(body.timeoutSeconds, 30)), 1), EXEC_MAX_SECONDS);
    const placement = this.loadPlacements().find(
      (item) => item.nodeId === body.nodeId && item.serviceName === body.service && item.state !== "stopped",
    );
    if (placement === undefined) throw new HttpError(404, "not_found", `${body.service} is not placed on ${body.nodeId}`);
    if (!this.connected(body.nodeId)) throw new HttpError(503, "unavailable", `${body.nodeId} is not connected`);
    const requestId = randomToken(12);
    const nodeId = body.nodeId;
    const executable = (body.command[0] ?? "").split("/").pop() ?? "";
    this.recordEvent("container_exec", placement.id, {
      by: principal.owner,
      nodeId,
      container: placement.id,
      service: body.service,
      command: /^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$/.test(executable) ? executable : "[redacted]",
    }, placement.region);
    const result = await new Promise<ExecResponse | null>((resolve) => {
      const timer = setTimeout(() => {
        this.execWaiters.delete(requestId);
        resolve(null);
      }, (timeoutSeconds + 5) * 1000);
      this.execWaiters.set(requestId, {
        nodeId,
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
      });
      const sent = this.send(nodeId, {
        type: "exec_command",
        requestId,
        containerName: placement.id,
        command: body.command as string[],
        timeoutSeconds,
      });
      if (sent === 0) {
        this.execWaiters.delete(requestId);
        clearTimeout(timer);
        resolve(null);
      }
    });
    if (result === null) throw new HttpError(504, "unavailable", "The node did not return an exec result in time");
    return result;
  }

  private async seed(request: Request, principal: Principal): Promise<unknown> {
    const body = await this.readJson(request);
    if (!isRecord(body)) throw new HttpError(400, "validation", "Body must be an object");
    const fleetInput = "fleet" in body ? body.fleet : body;
    const fleet = parseFleetConfig(fleetInput);
    if (typeof fleet === "string") throw new HttpError(400, "validation", fleet);
    const replace = body.replaceServices === true;
    const poolIds = isRecord(body.instancePoolIds) ? body.instancePoolIds : {};
    const servicesInput = Array.isArray(body.services) ? body.services : [];
    const specs: ServiceSpec[] = [];
    for (const input of servicesInput) {
      const spec = parseServiceSpec(input);
      if (typeof spec === "string") throw new HttpError(400, "validation", spec);
      specs.push(spec);
    }
    const now = Date.now();
    const order = fleet.rolloutOrder ?? [];
    const labels = fleet.regions.map((region) => region.label);
    const added: string[] = [];
    const replaced: string[] = [];
    const skipped: string[] = [];
    this.ctx.storage.transactionSync(() => {
      this.setState("fleet_config", fleet);
      for (const [index, region] of fleet.regions.entries()) {
        const overridePoolId = poolIds[region.label];
        const poolId =
          typeof overridePoolId === "string" && overridePoolId.length > 0
            ? overridePoolId
            : typeof region.instancePoolId === "string" && region.instancePoolId.length > 0
              ? region.instancePoolId
              : null;
        const orderIndex = order.indexOf(region.label);
        const previousPoolId = this.regionPoolId(region.label);
        if (poolId !== null && previousPoolId !== null && previousPoolId.length > 0 && previousPoolId !== poolId) this.replaceRegionPool(region.label, poolId);
        this.sql.exec(
          "INSERT INTO regions (label, oci_region, compartment_id, instance_pool_id, min_workers, max_workers, rollout_order, config_json, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(label) DO UPDATE SET oci_region = excluded.oci_region, compartment_id = excluded.compartment_id, instance_pool_id = COALESCE(excluded.instance_pool_id, regions.instance_pool_id), min_workers = excluded.min_workers, max_workers = excluded.max_workers, rollout_order = excluded.rollout_order, config_json = excluded.config_json, updated_at = excluded.updated_at",
          region.label,
          region.ociRegion,
          region.compartmentId,
          poolId,
          positiveInt(region.pools.worker?.min, 0),
          positiveInt(region.pools.worker?.max, 0),
          orderIndex >= 0 ? orderIndex : order.length + index,
          JSON.stringify(region),
          now,
        );
      }
      const placeholders = labels.map(() => "?").join(", ");
      for (const removed of this.sql.exec<{ label: string }>(`SELECT label FROM regions WHERE label NOT IN (${placeholders})`, ...labels).toArray()) {
        this.releaseRegionPool(removed.label);
      }
      this.sql.exec(`DELETE FROM regions WHERE label NOT IN (${placeholders})`, ...labels);
      this.saveCooldowns(new Map(Object.entries(this.getState<Record<string, number>>("autoscale_cooldowns") ?? {})));
      for (const spec of specs) {
        const existing = this.loadServiceRow(spec.name);
        if (existing !== undefined && !replace) {
          skipped.push(spec.name);
          continue;
        }
        this.upsertService(spec, existing, now);
        (existing === undefined ? added : replaced).push(spec.name);
      }
      this.recordEvent("chaos", "fleet_seed", { by: principal.owner, regions: labels, added, replaced, skipped });
    });
    await this.reconcile(now);
    this.ctx.waitUntil(this.runMaintenanceTask("tls", () => this.maybeAutoEnsureTls(now), "tls_error"));
    const topology = await this.publishTopology(now, true);
    await this.ensureAlarm(ALARM_INTERVAL_MS);
    return { regions: labels, services: { added, replaced, skipped }, topology };
  }

  private upsertService(spec: ServiceSpec, existing: ServiceRow | undefined, now: number): void {
    const version = existing === undefined ? 1 : existing.spec_json === JSON.stringify(spec) ? existing.config_version : existing.config_version + 1;
    this.sql.exec(
      "INSERT INTO services (name, mode, priority, image, spec_json, config_version, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(name) DO UPDATE SET mode = excluded.mode, priority = excluded.priority, image = excluded.image, spec_json = excluded.spec_json, config_version = excluded.config_version, updated_at = excluded.updated_at",
      spec.name,
      spec.mode,
      spec.priority,
      spec.image,
      JSON.stringify(spec),
      version,
      now,
    );
  }

  private serviceInputs(body: unknown): unknown[] {
    if (Array.isArray(body)) return body;
    if (isRecord(body) && Array.isArray(body.services)) return body.services;
    if (isRecord(body)) return [body];
    throw new HttpError(400, "validation", "Body must be a service, a list of services or { services }");
  }

  private async applyServices(request: Request, principal: Principal): Promise<unknown> {
    const inputs = this.serviceInputs(await this.readJson(request));
    const specs: ServiceSpec[] = [];
    for (const input of inputs) {
      const spec = parseServiceSpec(input);
      if (typeof spec === "string") throw new HttpError(400, "validation", spec);
      specs.push(spec);
    }
    const now = Date.now();
    const applied: { name: string; result: "added" | "changed" | "unchanged"; rolloutId?: string }[] = [];
    this.ctx.storage.transactionSync(() => {
      for (const spec of specs) {
        const existing = this.loadServiceRow(spec.name);
        if (existing === undefined) {
          this.upsertService(spec, undefined, now);
          applied.push({ name: spec.name, result: "added" });
          continue;
        }
        const live = this.serviceFromRow(existing);
        const hasPlacements =
          (this.sql.exec<CountRow>("SELECT COUNT(*) AS count FROM placements WHERE service_name = ?", spec.name).toArray()[0]?.count ?? 0) > 0;
        const imageChanged = live.image !== spec.image;
        const stored = imageChanged && hasPlacements ? { ...spec, image: live.image } : spec;
        const unchanged = JSON.stringify(stored) === existing.spec_json && !imageChanged;
        if (!unchanged) this.upsertService(stored, existing, now);
        const entry: { name: string; result: "added" | "changed" | "unchanged"; rolloutId?: string } = {
          name: spec.name,
          result: unchanged ? "unchanged" : "changed",
        };
        if (imageChanged && hasPlacements) {
          const rollout = this.startRollout(stored, spec.image, undefined, principal, now);
          entry.rolloutId = rollout.id;
        }
        applied.push(entry);
      }
    });
    await this.reconcile(now);
    await this.advanceRollouts(now);
    await this.ensureAlarm(ALARM_INTERVAL_MS);
    return { applied };
  }

  private async deleteService(name: string, principal: Principal): Promise<unknown> {
    const row = this.loadServiceRow(name);
    if (row === undefined) throw new HttpError(404, "not_found", `Service ${name} does not exist`);
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      this.sql.exec("DELETE FROM services WHERE name = ?", name);
      for (const rollout of this.loadRollouts(true).filter((item) => item.serviceName === name)) {
        this.saveRollout({ ...rollout, phase: "failed", finishedAt: now, error: "service_deleted" });
      }
      const overrides = this.replicaOverrides();
      for (const key of Object.keys(overrides)) if (key.startsWith(`${name}|`)) delete overrides[key];
      this.setState("replica_overrides", overrides);
      this.recordEvent("replica_scale_down", name, { reason: "service_deleted", by: principal.owner });
    });
    await this.reconcile(now);
    await this.publishTopology(now, false);
    return { deleted: name };
  }

  private diffServices(body: unknown): DiffItem[] {
    const local = new Map<string, ServiceSpec>();
    for (const input of this.serviceInputs(body)) {
      const spec = parseServiceSpec(input);
      if (typeof spec === "string") throw new HttpError(400, "validation", spec);
      local.set(spec.name, spec);
    }
    const live = new Map(this.loadServices().map((service) => [service.name, service]));
    const items: DiffItem[] = [];
    for (const [name, spec] of local) {
      const current = live.get(name);
      if (current === undefined) {
        items.push({ service: name, kind: "added", fields: [] });
        continue;
      }
      const keys = new Set([
        ...Object.keys(spec),
        ...Object.keys(current),
        "pathPrefixes",
        "matchGrpc",
        "blockedPaths",
        "configFiles",
        "internalPort",
        "clusterPeers",
        "pathPatterns",
        "methods",
        "routeRules",
      ]);
      const fields = [...keys]
        .filter(
          (key) =>
            JSON.stringify((spec as unknown as Record<string, unknown>)[key]) !==
            JSON.stringify((current as unknown as Record<string, unknown>)[key]),
        )
        .sort();
      if (fields.length > 0) items.push({ service: name, kind: "changed", fields });
    }
    for (const name of live.keys()) {
      if (!local.has(name)) items.push({ service: name, kind: "removed", fields: [] });
    }
    return items.sort((a, b) => (a.service < b.service ? -1 : a.service > b.service ? 1 : 0));
  }

  private startRollout(service: ServiceSpec, image: string, region: string | undefined, principal: Principal, now: number): RolloutInfo {
    const active = this.loadRollouts(true).find((rollout) => rollout.serviceName === service.name);
    if (active !== undefined) {
      throw new HttpError(409, "conflict", `Rollout ${active.id} for ${service.name} is still ${active.phase}`, "Wait for it or run `ts-orch rollback`.");
    }
    const order = this.rolloutOrder();
    const regions = region === undefined ? service.regions : [region];
    const first = orderRegions(regions, order)[0];
    const baseline = this.baseline(service.name, first, now);
    const rollout = createRollout(service, image, regions, order, baseline.p95, baseline.fiveXx, now);
    this.saveRollout(rollout);
    this.setState(`rollout_by:${rollout.id}`, { by: principal.owner, via: principal.via });
    return rollout;
  }

  private async deploy(request: Request, principal: Principal): Promise<RolloutInfo> {
    const body = (await this.readJson(request)) as Partial<DeployRequest>;
    if (typeof body.service !== "string" || typeof body.image !== "string" || body.image.length === 0 || body.image.length > 512) {
      throw new HttpError(400, "validation", "service and image are required");
    }
    const row = this.loadServiceRow(body.service);
    if (row === undefined) throw new HttpError(404, "not_found", `Service ${body.service} does not exist`);
    const service = this.serviceFromRow(row);
    if (body.region !== undefined && !service.regions.includes(body.region)) {
      throw new HttpError(400, "validation", `${body.service} does not run in ${body.region}`);
    }
    const now = Date.now();
    const rollout = this.startRollout(service, body.image, body.region, principal, now);
    await this.advanceRollouts(now);
    await this.ensureAlarm(ALARM_INTERVAL_MS);
    return this.loadRollouts(false, 50).find((item) => item.id === rollout.id) ?? rollout;
  }

  private async rollback(request: Request, principal: Principal): Promise<RolloutInfo> {
    const body = (await this.readJson(request)) as Partial<RollbackRequest>;
    if (typeof body.service !== "string") throw new HttpError(400, "validation", "service is required");
    const region = typeof body.region === "string" ? body.region : undefined;
    const rows = this.sql
      .exec<RolloutRow>("SELECT * FROM rollouts WHERE service_name = ? ORDER BY started_at DESC, id DESC LIMIT ?", body.service, SERVICE_ROLLBACK_HISTORY_KEEP)
      .toArray()
      .map((row) => this.rolloutFromRow(row));
    const activeGlobal = region !== undefined ? rows.find((rollout) => rollout.region === undefined && !TERMINAL_PHASES.has(rollout.phase)) : undefined;
    if (activeGlobal !== undefined) {
      throw new HttpError(
        409,
        "conflict",
        `Global rollout ${activeGlobal.id} for ${body.service} is still ${activeGlobal.phase}`,
        "Roll back the global rollout, or wait until it finishes.",
      );
    }
    const target = rows.find((rollout) => region === undefined || rollout.region === undefined || rollout.region === region);
    if (target === undefined) throw new HttpError(404, "not_found", `No rollout of ${body.service} to roll back`);
    if (target.phase === "rolled_back" || target.phase === "failed") {
      throw new HttpError(409, "conflict", `Rollout ${target.id} is already ${target.phase}`);
    }
    const now = Date.now();
    const scoped: RolloutInfo = region !== undefined && target.region === undefined ? { ...target, region } : target;
    const step = rollbackRollout(scoped, this.loadPlacements(), now);
    const saved: RolloutInfo = { ...step.rollout };
    if (target.region === undefined) delete saved.region;
    step.rollout = saved;
    for (const event of step.events) event.detail = { ...event.detail, by: principal.owner };
    this.applyStep(step, now);
    if (target.phase === "succeeded" && target.previousImage !== undefined && region === undefined) {
      this.setServiceImage(target.serviceName, target.previousImage, now);
    }
    await this.syncNodes("desired");
    await this.ensureAlarm(ALARM_INTERVAL_MS);
    return step.rollout;
  }

  private async drainNode(nodeId: string, reason: string): Promise<NodeInfo> {
    const row = this.loadNodeRow(nodeId);
    if (row === undefined) throw new HttpError(404, "not_found", `Node ${nodeId} does not exist`);
    if (this.nodeBlocked(row, Date.now())) throw terminating();
    const status: NodeStatus = row.status === "pending" ? "pending" : row.status === "down" ? "down" : row.status === "drained" ? "drained" : "draining";
    this.sql.exec("UPDATE nodes SET drain_requested = 1, drain_reason = ?, status = ? WHERE id = ?", reason, status, nodeId);
    if (status !== "pending") this.send(nodeId, { type: "drain", reason });
    this.recordEvent("node_drained", nodeId, { phase: "requested", reason }, row.region);
    const now = Date.now();
    await this.reconcile(now);
    await this.publishTopology(now, false);
    await this.ensureAlarm(ALARM_INTERVAL_MS);
    return this.nodeFromRow(this.loadNodeRow(nodeId) ?? row);
  }

  private async activateNode(nodeId: string): Promise<NodeInfo> {
    const row = this.loadNodeRow(nodeId);
    if (row === undefined) throw new HttpError(404, "not_found", `Node ${nodeId} does not exist`);
    const now = Date.now();
    if (this.nodeBlocked(row, now)) throw terminating();
    const live = this.connected(nodeId) && now - row.last_seen_at <= DEFAULT_HEARTBEAT_TIMEOUT_MS;
    const status: NodeStatus = row.status === "pending" ? "pending" : live ? "active" : "down";
    this.sql.exec("UPDATE nodes SET drain_requested = 0, drain_reason = NULL, status = ? WHERE id = ?", status, nodeId);
    this.recordEvent("node_connected", nodeId, { phase: "activated", status }, row.region);
    await this.reconcile(now);
    await this.publishTopology(now, false);
    return this.nodeFromRow(this.loadNodeRow(nodeId) ?? row);
  }

  private async deleteNode(nodeId: string, force: boolean, principal: Principal): Promise<{ deleted: string }> {
    const row = this.loadNodeRow(nodeId);
    if (row === undefined) throw new HttpError(404, "not_found", `Node ${nodeId} does not exist`);
    if (!force && row.pool_kind === "stateful" && (row.status !== "down" || this.connected(nodeId))) {
      throw new HttpError(409, "conflict", `Stateful node ${nodeId} must be down and disconnected`, "Decommission the node first or pass --force.");
    }
    if (!force && row.pool_kind !== "stateful") {
      if (row.status === "active") {
        throw new HttpError(409, "conflict", `Node ${nodeId} is still active`, "Drain the node first or pass --force.");
      }
      const activePlacements =
        this.sql
          .exec<CountRow>("SELECT COUNT(*) AS count FROM placements WHERE node_id = ? AND state != 'stopped'", nodeId)
          .toArray()[0]?.count ?? 0;
      if (activePlacements > 0) {
        throw new HttpError(409, "conflict", `Node ${nodeId} still has ${activePlacements} placement(s)`, "Drain the node first or pass --force.");
      }
    }
    for (const ws of this.sockets(nodeId)) this.closeSocket(ws, 4010, "removed");
    const now = Date.now();
    this.ctx.storage.transactionSync(() => {
      this.deleteNodeRows(nodeId);
      this.recordEvent("node_lost", nodeId, { phase: "removed", force, by: principal.owner }, row.region);
    });
    await this.reconcile(now);
    await this.publishTopology(now, false);
    return { deleted: nodeId };
  }

  private upgradeNodes(body: unknown, requestUrl: URL, principal: Principal): { version: string; nodes: string[] } {
    if (!isRecord(body)) throw new HttpError(400, "validation", "Body must be an object");
    const version = requiredToken(body.version);
    const urlText = requiredToken(body.url);
    const sha256 = requiredToken(body.sha256);
    if (version === null || urlText === null || sha256 === null) {
      throw new HttpError(400, "validation", "version, url and sha256 are required");
    }
    if (!/^[0-9a-f]{64}$/i.test(sha256)) {
      throw new HttpError(400, "validation", "sha256 must be 64 hexadecimal characters");
    }
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(urlText);
    } catch {
      throw new HttpError(400, "validation", "url must be a valid URL");
    }
    const allowHttp = localDevAllowed(requestUrl, this.env) && isLoopbackHost(parsedUrl.hostname);
    if (parsedUrl.protocol !== "https:" && !(allowHttp && parsedUrl.protocol === "http:")) {
      throw new HttpError(400, "validation", "url must use https");
    }
    const targetNodeId = typeof body.nodeId === "string" && body.nodeId.length > 0 ? body.nodeId : undefined;
    let targets: NodeInfo[];
    if (targetNodeId !== undefined) {
      const row = this.loadNodeRow(targetNodeId);
      if (row === undefined) throw new HttpError(404, "not_found", `Node ${targetNodeId} does not exist`);
      targets = [this.nodeFromRow(row)];
    } else {
      targets = this.loadNodes();
    }
    const sentTo: string[] = [];
    for (const node of targets) {
      if (this.send(node.id, { type: "upgrade_agent", version, url: urlText, sha256: sha256.toLowerCase() }) > 0) {
        sentTo.push(node.id);
      }
    }
    this.recordEvent("chaos", "agent_upgrade", { version, nodes: sentTo, by: principal.owner });
    return { version, nodes: sentTo };
  }

  private async rebootNode(nodeId: string, principal: Principal): Promise<unknown> {
    const row = this.loadNodeRow(nodeId);
    if (row === undefined) throw new HttpError(404, "not_found", `Node ${nodeId} does not exist`);
    const instanceId = await this.enrolledInstanceId(row);
    const region = this.sql.exec<RegionRow>("SELECT * FROM regions WHERE label = ?", row.region).toArray()[0];
    if (instanceId === null || region === undefined) throw new HttpError(409, "conflict", `Node ${nodeId} has no OCI instance id`);
    const oci = await this.oci();
    if (oci === null) throw new HttpError(503, "unavailable", "OCI credentials are not configured");
    await oci.instanceAction(region.oci_region, instanceId, "SOFTRESET");
    this.recordEvent("node_lost", nodeId, { phase: "reboot_requested", by: principal.owner, instanceId }, row.region);
    return { nodeId, instanceId, action: "SOFTRESET" };
  }

  private async refreshSecrets(request: Request, principal: Principal): Promise<unknown> {
    const body = (await this.readJson(request)) as { service?: unknown };
    if (typeof body.service !== "string") throw new HttpError(400, "validation", "service is required");
    const serviceName = body.service;
    if (this.loadServiceRow(serviceName) === undefined) throw new HttpError(404, "not_found", `Service ${serviceName} does not exist`);
    const nodes = this.notifySecretRefresh(serviceName);
    this.recordEvent("secret_rotated", serviceName, { nodes, by: principal.owner });
    return { service: serviceName, nodes };
  }

  private notifySecretRefresh(serviceName: string): string[] {
    const nodeIds = [
      ...new Set(
        this.sql
          .exec<{ node_id: string }>("SELECT DISTINCT node_id FROM placements WHERE service_name = ? AND node_id IS NOT NULL", serviceName)
          .toArray()
          .map((row) => row.node_id),
      ),
    ].sort();
    return nodeIds.filter((nodeId) => this.send(nodeId, { type: "refresh_secrets", serviceName }) > 0);
  }

  private async deriveSealKey(secret: string): Promise<CryptoKey> {
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode(`${secret}:tls-key`));
    return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  }

  private async tlsKey(requestUrl?: URL): Promise<CryptoKey | null> {
    if (this.env.TLS_SEALING_KEY !== undefined && this.env.TLS_SEALING_KEY.length >= 16) {
      return this.deriveSealKey(this.env.TLS_SEALING_KEY);
    }
    const secret = sessionSecret(this.env, requestUrl);
    if (secret === null) return null;
    return this.deriveSealKey(secret);
  }

  private async sealKey(pem: string, requestUrl?: URL): Promise<string> {
    const key = await this.tlsKey(requestUrl);
    if (key === null) throw new HttpError(503, "unavailable", "TLS sealing key is not configured");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const sealed = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(pem)));
    return `v1.${b64urlEncode(iv)}.${b64urlEncode(sealed)}`;
  }

  private async openKeyWith(sealed: string, key: CryptoKey): Promise<string | null> {
    const [version, iv, data] = sealed.split(".");
    if (version !== "v1" || iv === undefined || data === undefined) return null;
    try {
      const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64urlDecode(iv) }, key, b64urlDecode(data));
      return new TextDecoder().decode(plain);
    } catch {
      return null;
    }
  }

  private async openKey(sealed: string): Promise<string | null> {
    const primary = await this.tlsKey();
    if (primary !== null) {
      const opened = await this.openKeyWith(sealed, primary);
      if (opened !== null) return opened;
    }
    if (this.env.TLS_SEALING_KEY !== undefined && this.env.TLS_SEALING_KEY.length >= 16) {
      const fallbackSecret = sessionSecret(this.env);
      if (fallbackSecret !== null && fallbackSecret !== this.env.TLS_SEALING_KEY) {
        return this.openKeyWith(sealed, await this.deriveSealKey(fallbackSecret));
      }
    }
    return null;
  }

  private async loadTls(requestUrl?: URL): Promise<TlsBundle | null> {
    const row = this.sql.exec<TlsRow>("SELECT * FROM tls_certs WHERE id = 'shared'").toArray()[0];
    if (row === undefined) return null;
    const sealed = row.key_pem_enc;
    let keyPem: string | null;
    if (sealed.startsWith("plain.")) {
      keyPem = sealed.slice("plain.".length);
      try {
        const encrypted = await this.sealKey(keyPem, requestUrl);
        const updated = this.sql.exec<{ id: string }>(
          "UPDATE tls_certs SET key_pem_enc = ? WHERE id = 'shared' AND key_pem_enc = ? RETURNING id",
          encrypted,
          sealed,
        ).toArray()[0];
        if (updated === undefined) return this.loadTls(requestUrl);
        console.warn("Sealed a plaintext TLS key in the fleet store");
      } catch (error) {
        console.error("Could not seal the stored TLS key; using the existing key", error);
      }
    } else {
      keyPem = await this.openKey(sealed);
    }
    if (keyPem === null) return null;
    return { domains: parseJson<string[]>(row.domains_json, []), certPem: row.cert_pem, keyPem, notAfter: row.not_after };
  }

  private tlsStatus(): unknown {
    const row = this.sql.exec<TlsRow>("SELECT * FROM tls_certs WHERE id = 'shared'").toArray()[0];
    const error = this.getState<{ at: number; message: string }>("tls_error");
    if (row === undefined) {
      return {
        configured: false,
        domains: this.tlsDomains(),
        ...(error !== null ? { error } : {}),
      };
    }
    return {
      configured: true,
      domains: parseJson<string[]>(row.domains_json, []),
      notAfter: row.not_after,
      renewedAt: row.renewed_at,
      ...(error !== null ? { error } : {}),
    };
  }

  private sendTls(nodeId: string, bundle: TlsBundle): void {
    this.send(nodeId, {
      type: "sync_tls",
      revision: this.nextRevision(),
      domains: bundle.domains,
      certPem: bundle.certPem,
      keyPem: bundle.keyPem,
      notAfter: bundle.notAfter,
    });
  }

  private tlsDomains(): string[] {
    const raw = this.env.TLS_DOMAINS;
    const domains = (raw ?? "").split(/[\s,]+/).filter((domain) => domain.length > 0);
    if (domains.length > 0) return domains;
    return this.env.LOCAL_DEV === "true" ? ["localhost", "*.localhost"] : [...DEFAULT_PROD_TLS_DOMAINS];
  }

  private async loadAcmeAccount(directoryUrl: string): Promise<AcmeAccountState | undefined> {
    const sealed = this.getState<string>("acme_account");
    if (sealed === null) return undefined;
    const plain = await this.openKey(sealed);
    if (plain === null) return undefined;
    const parsed = parseJson<{ directoryUrl?: string; kid?: string; jwk?: JsonWebKey } | null>(plain, null);
    if (parsed === null || parsed.directoryUrl !== directoryUrl || typeof parsed.kid !== "string" || !isRecord(parsed.jwk)) {
      return undefined;
    }
    return { kid: parsed.kid, jwk: parsed.jwk };
  }

  private async saveAcmeAccount(directoryUrl: string, account: AcmeAccountState, requestUrl?: URL): Promise<void> {
    const sealed = await this.sealKey(JSON.stringify({ directoryUrl, kid: account.kid, jwk: account.jwk }), requestUrl);
    this.setState("acme_account", sealed);
  }

  private async maybeAutoEnsureTls(now: number): Promise<void> {
    if (this.env.LOCAL_DEV === "true" || !this.env.CF_DNS_API_TOKEN || !this.env.CF_DNS_ZONE_ID) return;
    if (this.tlsEnsureInFlight !== undefined) return;
    if ((await this.loadTls()) !== null) return;
    const lastError = this.getState<{ at?: number }>("tls_error");
    if (lastError !== null && typeof lastError.at === "number" && now - lastError.at < TLS_RETRY_BACKOFF_MS) return;
    await this.ensureTls();
  }

  private async ensureTls(requestUrl?: URL): Promise<unknown> {
    if (this.tlsEnsureInFlight !== undefined) return this.tlsEnsureInFlight;
    const work = this.ensureTlsInner(requestUrl).finally(() => {
      this.tlsEnsureInFlight = undefined;
    });
    this.tlsEnsureInFlight = work;
    return work;
  }

  private async ensureTlsInner(requestUrl?: URL): Promise<unknown> {
    const now = Date.now();
    const current = await this.loadTls(requestUrl);
    const directoryUrl = this.env.ACME_DIRECTORY_URL ?? LETS_ENCRYPT_DIRECTORY;
    const config: TlsManagerConfig = {
      domains: this.tlsDomains(),
      localDev: this.env.LOCAL_DEV === "true",
      onAccountCreated: async (account) => {
        await this.saveAcmeAccount(directoryUrl, account, requestUrl);
      },
    };
    if (this.env.CF_DNS_API_TOKEN) config.cfApiToken = this.env.CF_DNS_API_TOKEN;
    if (this.env.CF_DNS_ZONE_ID) config.cfZoneId = this.env.CF_DNS_ZONE_ID;
    if (this.env.ACME_DIRECTORY_URL) config.acmeDirectoryUrl = this.env.ACME_DIRECTORY_URL;
    if (this.env.ACME_ACCOUNT_EMAIL) config.accountEmail = this.env.ACME_ACCOUNT_EMAIL;
    const storedAccount = await this.loadAcmeAccount(directoryUrl);
    if (storedAccount !== undefined) config.account = storedAccount;
    let outcome: { renewed: boolean; bundle: TlsBundle };
    try {
      outcome = await ensureCertificate(config, current, now);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.setState("tls_error", { at: now, message });
      throw new HttpError(503, "unavailable", `TLS renewal failed: ${message}`);
    }
    const { renewed, bundle } = outcome;
    let pushed: string[] = [];
    if (renewed) {
      this.sql.exec(
        "INSERT INTO tls_certs (id, domains_json, cert_pem, key_pem_enc, not_after, renewed_at) VALUES ('shared', ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET domains_json = excluded.domains_json, cert_pem = excluded.cert_pem, key_pem_enc = excluded.key_pem_enc, not_after = excluded.not_after, renewed_at = excluded.renewed_at",
        JSON.stringify(bundle.domains),
        bundle.certPem,
        await this.sealKey(bundle.keyPem, requestUrl),
        bundle.notAfter,
        now,
      );
      this.deleteState("tls_error");
      this.recordEvent("tls_renewed", bundle.domains.join(","), { notAfter: new Date(bundle.notAfter).toISOString() });
      pushed = this.loadNodes()
        .map((node) => node.id)
        .filter((nodeId) => this.connected(nodeId));
      for (const nodeId of pushed) this.sendTls(nodeId, bundle);
    }
    return { renewed, domains: bundle.domains, notAfter: bundle.notAfter, pushedTo: pushed };
  }

  private exportState(): unknown {
    const tls = this.sql.exec<TlsRow>("SELECT id, domains_json, not_after, renewed_at FROM tls_certs").toArray();
    return {
      exportedAt: new Date().toISOString(),
      fleetConfig: this.fleetConfig(),
      regions: this.loadRegionRows().map((row) => ({
        label: row.label,
        instancePoolId: row.instance_pool_id,
        rolloutOrder: row.rollout_order,
        config: parseJson<RegionConfig | null>(row.config_json, null),
      })),
      services: this.loadServices(),
      nodes: this.loadNodes(),
      placements: this.loadPlacements(),
      rollouts: this.loadRollouts(false, ROLLOUT_HISTORY_KEEP),
      replicaOverrides: this.replicaOverrides(),
      tlsCerts: tls.map((row) => ({
        id: row.id,
        domains: parseJson<string[]>(row.domains_json, []),
        notAfter: row.not_after,
        renewedAt: row.renewed_at,
      })),
    };
  }

  private async chaos(request: Request, principal: Principal): Promise<unknown> {
    const body = (await this.readJson(request)) as DevChaosRequest;
    if (!isRecord(body) || typeof body.kind !== "string") throw new HttpError(400, "validation", "kind is required");
    const now = Date.now();
    const state = this.chaosState(now);
    const duration = (seconds: unknown): number => Math.min(Math.max(finite(seconds, 120), 1), 3600) * 1000;
    switch (body.kind) {
      case "kill_node": {
        const row = this.loadNodeRow(body.nodeId);
        if (row === undefined) throw new HttpError(404, "not_found", `Node ${body.nodeId} does not exist`);
        for (const ws of this.sockets(body.nodeId)) this.closeSocket(ws, 4000, "chaos kill");
        this.sql.exec("UPDATE nodes SET status = 'down', last_seen_at = 0 WHERE id = ?", body.nodeId);
        this.recordEvent("chaos", body.nodeId, { kind: body.kind, by: principal.owner }, row.region);
        this.recordEvent("node_lost", body.nodeId, { reason: "chaos" }, row.region);
        await this.reconcile(now);
        await this.publishTopology(now, false);
        return { kind: body.kind, nodeId: body.nodeId };
      }
      case "inject_5xx": {
        if (this.loadServiceRow(body.service) === undefined) throw new HttpError(404, "not_found", `Service ${body.service} does not exist`);
        const ratePct = Math.min(Math.max(finite(body.ratePct, 50), 0), 100);
        const until = now + duration(body.durationSeconds);
        if (ratePct <= 0) delete state.fiveXx[body.service];
        else state.fiveXx[body.service] = { ratePct, until };
        this.setState("chaos", state);
        this.recordEvent("chaos", body.service, { kind: body.kind, ratePct, until, by: principal.owner });
        await this.advanceRollouts(now);
        return { kind: body.kind, service: body.service, ratePct, until };
      }
      case "cpu_load": {
        if (this.loadNodeRow(body.nodeId) === undefined) throw new HttpError(404, "not_found", `Node ${body.nodeId} does not exist`);
        const cpuPct = Math.min(Math.max(finite(body.cpuPct, 95), 0), 100);
        const until = now + duration(body.durationSeconds);
        if (cpuPct <= 0) delete state.cpu[body.nodeId];
        else state.cpu[body.nodeId] = { cpuPct, until };
        this.setState("chaos", state);
        this.recordEvent("chaos", body.nodeId, { kind: body.kind, cpuPct, until, by: principal.owner });
        return { kind: body.kind, nodeId: body.nodeId, cpuPct, until };
      }
      case "fill_disk": {
        if (this.loadNodeRow(body.nodeId) === undefined) throw new HttpError(404, "not_found", `Node ${body.nodeId} does not exist`);
        const usedPct = Math.min(Math.max(finite(body.usedPct, 90), 0), 100);
        if (usedPct <= 0) delete state.disk[body.nodeId];
        else {
          state.disk[body.nodeId] = { usedPct };
          this.setVolumeUsage(body.nodeId, usedPct);
        }
        this.setState("chaos", state);
        this.seedChaosDataDisk(body.nodeId, usedPct, now);
        if (usedPct > VOLUME_USAGE_THRESHOLD_PCT) {
          this.backfillDiskHistory(body.nodeId, usedPct, now);
          this.setState("autoscale_at", 0);
          await this.ensureAlarm(1_000);
        }
        this.recordEvent("chaos", body.nodeId, { kind: body.kind, usedPct, by: principal.owner });
        return { kind: body.kind, nodeId: body.nodeId, usedPct };
      }
      case "bump_secret": {
        if (typeof body.secretName !== "string" || body.secretName.length === 0) throw new HttpError(400, "validation", "secretName is required");
        const affected = this.loadServices().filter((service) =>
          Object.values(service.secrets).some((ref) => ref.name === body.secretName),
        );
        const notified: Record<string, string[]> = {};
        for (const service of affected) {
          notified[service.name] = this.notifySecretRefresh(service.name);
          this.recordEvent("secret_rotated", service.name, { secretName: body.secretName, nodes: notified[service.name], by: principal.owner });
        }
        this.recordEvent("chaos", body.secretName, { kind: body.kind, services: Object.keys(notified), by: principal.owner });
        return { kind: body.kind, secretName: body.secretName, services: notified };
      }
      case "atlas_placement": {
        const placement: AtlasPlacement | null = validateAtlasPlacement({
          v: 1,
          project: body.project,
          database: body.database,
          region: body.region,
          updated: Math.floor(now / 1000),
        });
        if (placement === null) throw new HttpError(400, "validation", "project, database and region must be valid Atlas identifiers");
        const response = await atlasStub(this.env).fetch("https://atlas-store/publish", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ placements: [placement] }),
        });
        const result: unknown = await response.json();
        this.recordEvent("chaos", `${placement.project}/${placement.database}`, { kind: body.kind, region: placement.region, by: principal.owner });
        return { kind: body.kind, placement, result };
      }
      case "atlas_roundtrip": {
        const regions = this.loadRegions();
        const targetRegion = body.region ?? regions[0]?.label ?? "gru";
        const project = body.project ?? "chaos-probe";
        const database = body.database ?? "roundtrip";
        const placement: AtlasPlacement | null = validateAtlasPlacement({
          v: 1,
          project,
          database,
          region: targetRegion,
          updated: Math.floor(now / 1000),
        });
        if (placement === null) throw new HttpError(400, "validation", "Invalid Atlas roundtrip parameters");
        const pub = await atlasStub(this.env).fetch("https://atlas-store/publish", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ placements: [placement] }),
        });
        const published: unknown = await pub.json();
        const read = await atlasStub(this.env).fetch(
          `https://atlas-store/placement?project=${encodeURIComponent(project)}&database=${encodeURIComponent(database)}`,
        );
        const resolved: unknown = await read.json();
        this.recordEvent("chaos", `${project}/${database}`, { kind: body.kind, region: targetRegion, by: principal.owner });
        return { kind: body.kind, placement, published, resolved };
      }
      default:
        throw new HttpError(400, "validation", "kind must be kill_node, inject_5xx, cpu_load, bump_secret, fill_disk, atlas_placement or atlas_roundtrip");
    }
  }
}
