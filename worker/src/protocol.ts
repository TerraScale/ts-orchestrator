export type PlacementMode = "daemon" | "replicated" | "stateful";
export type PriorityTier = "high" | "normal" | "low";
export type PoolKind = "stateful" | "worker";
export type CpuArch = "arm64" | "x64";
export type NodeStatus = "pending" | "active" | "draining" | "drained" | "down";
export type PlacementState =
  | "pending"
  | "unschedulable"
  | "pulling"
  | "starting"
  | "ready"
  | "draining"
  | "stopped"
  | "failed";
export type RolloutPhase = "pending" | "canary" | "baking" | "waves" | "succeeded" | "rolled_back" | "failed";
export type RolloutRegionPhase = "canary" | "baking" | "waves" | "succeeded" | "skipped";
export type EventKind =
  | "deploy_started"
  | "canary_started"
  | "canary_passed"
  | "rollback"
  | "rollout_succeeded"
  | "rollout_failed"
  | "replica_scale_up"
  | "replica_scale_down"
  | "pool_scale_up"
  | "pool_scale_down"
  | "pool_scale_blocked"
  | "node_enrolled"
  | "node_connected"
  | "node_lost"
  | "node_drained"
  | "failover"
  | "oom_kill"
  | "volume_grown"
  | "container_exec"
  | "secret_rotated"
  | "tls_renewed"
  | "chaos";
export type HealthState = "ok" | "unknown" | "down";
export type LogChannel = "stdout" | "stderr";
export type OperatorRole = "admin" | "deploy" | "read";
export type DiffKind = "added" | "changed" | "removed";
export type AtlasPlacementState = "any" | "known";
export type ErrorCode =
  | "not_found"
  | "validation"
  | "conflict"
  | "forbidden"
  | "unauthorized"
  | "unavailable"
  | "internal";

export interface ErrorDetail {
  code: string;
  message: string;
  fix?: string;
}

export interface ErrorResponse {
  error: ErrorDetail;
}

export interface NetBirdConfig {
  managementUrl: string;
  dnsDomain: string;
  networkRange: string;
  setupKeySecret: string;
  operatorsSetupKeySecret: string;
  adminPatSecret: string;
  ownerEmail: string;
  ownerPasswordSecret: string;
}

export interface FleetConfig {
  backplane: BackplaneConfig;
  oci: OciConfig;
  dns: DnsConfig;
  atlas: AtlasConfig;
  rolloutOrder: string[];
  regions: RegionConfig[];
  netbird?: NetBirdConfig;
}

export interface BackplaneConfig {
  locationHint: string;
  orchHost: string;
  atlasHost: string;
}

export interface OciConfig {
  tenancyId: string;
  registry: RegistryConfig;
  vault: VaultConfig;
}

export interface RegistryConfig {
  namespace: string;
  repoPrefix: string;
}

export interface VaultConfig {
  region: string;
  vaultId: string;
}

export interface DnsConfig {
  zone: string;
  compartmentId: string;
  steeredNames: string[];
  ttlSeconds: number;
  healthCheckPath: string;
}

export interface AtlasConfig {
  requiredServices: string[];
  services: AtlasService[];
}

export interface RegionConfig {
  label: string;
  ociRegion: string;
  compartmentId: string;
  location: RegionLocation;
  network: RegionNetwork;
  endpoints: RegionEndpoints;
  pools: RegionPools;
  instancePoolId?: string;
}

export interface RegionLocation {
  name: string;
  country: string;
  lat: number;
  lon: number;
  continents: string[];
}

export interface RegionNetwork {
  vcnCidr: string;
  publicSubnetCidr: string;
  privateSubnetCidr: string;
}

export interface RegionEndpoints {
  api: string;
  auth: string;
}

export interface RegionPools {
  stateful: StatefulPool;
  worker: WorkerPool;
}

export interface ComputeShape {
  name: string;
  ocpus: number;
  memoryGiB: number;
  bootGiB: number;
}

export interface StatefulPool {
  count: number;
  shape: ComputeShape;
  dataGiB: number;
  dataVpusPerGiB: number;
}

export interface WorkerPool {
  min: number;
  max: number;
  shape: ComputeShape;
}

export interface HttpRouteRule {
  pathPatterns: string[];
  methods?: string[];
}

export interface ConfigFileSpec {
  target: string;
  template: string;
}

export interface ServiceSpec {
  name: string;
  mode: PlacementMode;
  priority: PriorityTier;
  image: string;
  regions: string[];
  replicas: number;
  minReplicas: number;
  maxReplicas: number;
  cpuRequestMilli: number;
  cpuLimitMilli: number;
  memRequestMiB: number;
  memLimitMiB: number;
  pidsLimit: number;
  port: number;
  readyPath: string;
  readyTimeoutSeconds: number;
  hostnames: string[];
  postgres?: PostgresSpec;
  env: Record<string, string>;
  secrets: Record<string, SecretRef>;
  mounts: MountSpec[];
  args: string[];
  udpPorts: number[];
  autoscale?: AutoscaleSpec;
  pathPrefixes?: string[];
  matchGrpc?: boolean;
  blockedPaths?: string[];
  configFiles?: ConfigFileSpec[];
  internalPort?: number;
  clusterPeers?: boolean;
  pathPatterns?: string[];
  methods?: string[];
  routeRules?: HttpRouteRule[];
}

export interface SecretRef {
  vault: string;
  name: string;
}

export interface MountSpec {
  source: string;
  target: string;
}

export interface PostgresSpec {
  port: number;
  hostnames: string[];
}

export interface AutoscaleSpec {
  targetCpuPct: number;
  targetP95Ms: number;
  scaleUpCooldownSeconds: number;
  scaleDownCooldownSeconds: number;
}

export interface VolumeInfo {
  mountPath: string;
  device: string;
  sizeGiB: number;
  usedPct: number;
  identity?: string;
}

export interface NodeInfo {
  id: string;
  region: string;
  poolKind: PoolKind;
  vcnIp: string;
  arch: CpuArch;
  shape: string;
  faultDomain: string;
  cpuTotalMilli: number;
  memTotalMiB: number;
  diskTotalGiB: number;
  labels: Record<string, string>;
  volumes: VolumeInfo[];
  status: NodeStatus;
  drainRequested: boolean;
  lastSeenAt: number;
  agentVersion: string;
  cpuRequestedMilli?: number;
  memRequestedMiB?: number;
  netbirdIp?: string;
}

export interface PlacementInfo {
  id: string;
  serviceName: string;
  region: string;
  nodeId?: string;
  slot: number;
  desiredImage: string;
  activeImage?: string;
  activeConfigHash?: string;
  hostPort?: number;
  postgresHostPort?: number;
  internalHostPort?: number;
  candidateImage?: string;
  candidateError?: string;
  state: PlacementState;
  updatedAt: number;
}

export interface DesiredPlacement {
  placementId: string;
  slot: number;
  service: ServiceSpec;
  hostPort?: number;
  postgresHostPort?: number;
  internalHostPort?: number;
}

export interface PlacementReport {
  placementId: string;
  serviceName: string;
  state: PlacementState;
  image: string;
  configHash: string;
  hostPort?: number;
  postgresHostPort?: number;
  internalHostPort?: number;
  candidateImage?: string;
  candidateError?: string;
  error?: string;
}

export interface RolloutInfo {
  id: string;
  serviceName: string;
  region?: string;
  targetImage: string;
  previousImage?: string;
  phase: RolloutPhase;
  currentRegion?: string;
  currentWave: number;
  totalWaves: number;
  baselineP95Ms?: number;
  baseline5xxPct?: number;
  canaryStartedAt?: number;
  waveStartedAt?: number;
  startedAt: number;
  finishedAt?: number;
  error?: string;
  regionOrder?: string[];
  activeRegions?: string[];
  regionProgress?: RolloutRegionProgress[];
}

export interface RolloutRegionProgress {
  region: string;
  phase: RolloutRegionPhase;
  canaryStartedAt?: number;
  waveStartedAt?: number;
}

export interface EventRecord {
  id: number;
  ts: number;
  kind: EventKind;
  region?: string;
  subject: string;
  detail: Record<string, string>;
}

export interface TlsBundle {
  domains: string[];
  certPem: string;
  keyPem: string;
  notAfter: number;
}

export interface HostMetrics {
  ts: number;
  cpuPct: number;
  cpuPsi10: number;
  memTotalMiB: number;
  memUsedMiB: number;
  memPsi10: number;
  ioPsi10: number;
  diskUsedPct: number;
  netRxBps: number;
  netTxBps: number;
  load1: number;
}

export interface ContainerMetrics {
  placementId: string;
  serviceName: string;
  cpuPct: number;
  memUsedMiB: number;
  memLimitMiB: number;
  pids: number;
  netRxBps: number;
  netTxBps: number;
  restarts: number;
  oomKills: number;
}

export interface EdgeServiceMetrics {
  serviceName: string;
  rps: number;
  errorRate5xxPct: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  requests: number;
  responses5xx: number;
  activeConnections: number;
}

export interface EdgeMetricsSnapshot {
  ts: number;
  windowSeconds: number;
  services: EdgeServiceMetrics[];
  postgresConnections: number;
}

export interface MetricsPoint10s {
  nodeId: string;
  ts: number;
  cpuPct: number;
  cpuPsi10: number;
  memUsedMiB: number;
  memPsi10: number;
  diskUsedPct: number;
  netRxBps: number;
  netTxBps: number;
  containers: ContainerMetrics[];
  edge?: EdgeMetricsSnapshot;
}

export interface MetricsPoint1m {
  nodeId: string;
  ts: number;
  cpuAvg: number;
  cpuP95: number;
  cpuPsiAvg: number;
  memAvgMiB: number;
  diskPct: number;
  edgeRps: number;
  edge5xx: number;
  edgeP95Ms: number;
}

export interface EdgeRoutesSnapshot {
  revision: number;
  httpRoutes: HttpRouteEntry[];
  postgresRoutes: PostgresRouteEntry[];
  internalRoutes?: InternalRouteEntry[];
}

export interface HttpRouteEntry {
  serviceName: string;
  hostnames: string[];
  upstreams: HttpUpstream[];
  pathPrefixes?: string[];
  matchGrpc?: boolean;
  blockedPaths?: string[];
  pathPatterns?: string[];
  methods?: string[];
}

export interface HttpUpstream {
  placementId: string;
  nodeId: string;
  address: string;
  port: number;
  local: boolean;
}

export interface InternalRouteEntry {
  serviceName: string;
  upstreams: HttpUpstream[];
}

export interface ClusterPeer {
  nodeId: string;
  region: string;
  host: string;
  quicPort: number;
  internalHttpPort: number;
}

export interface PostgresRouteEntry {
  serviceName: string;
  hostnames: string[];
  listenPort: number;
  upstreams: PostgresUpstream[];
}

export interface PostgresUpstream {
  placementId: string;
  nodeId: string;
  address: string;
  port: number;
  local: boolean;
}

export interface HelloMessage {
  type: "hello";
  nodeId: string;
  region: string;
  poolKind: PoolKind;
  vcnIp: string;
  arch: CpuArch;
  shape: string;
  faultDomain: string;
  cpuTotalMilli: number;
  memTotalMiB: number;
  diskTotalGiB: number;
  labels: Record<string, string>;
  agentVersion: string;
  volumeSeq: number;
  volumes?: VolumeInfo[];
  netbirdIp?: string;
  capabilities?: string[];
}

export interface HeartbeatMessage {
  type: "heartbeat";
  ts: number;
  placements: PlacementReport[];
  hostMetrics: HostMetrics;
  containerMetrics: ContainerMetrics[];
  volumeSeq: number;
  edgeMetrics?: EdgeMetricsSnapshot;
  netbirdIp?: string;
  volumes?: VolumeInfo[];
  volumeChallenge?: string;
}

export interface PlacementEventMessage {
  type: "placement_event";
  placementId: string;
  state: PlacementState;
  hostPort?: number;
  postgresHostPort?: number;
  internalHostPort?: number;
  candidateImage?: string;
  candidateError?: string;
  image: string;
  configHash: string;
  error?: string;
}

export interface DrainCompleteMessage {
  type: "drain_complete";
  nodeId: string;
}

export interface VolumeGrownMessage {
  type: "volume_grown";
  nodeId: string;
  volumePath: string;
  newSizeGiB: number;
  volumeId?: string;
}

export interface LogChunkMessage {
  type: "log_chunk";
  requestId: string;
  stream: LogChannel;
  line: string;
}

export interface ExecResultMessage {
  type: "exec_result";
  requestId: string;
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type AgentMessage =
  | HelloMessage
  | HeartbeatMessage
  | PlacementEventMessage
  | DrainCompleteMessage
  | VolumeGrownMessage
  | LogChunkMessage
  | ExecResultMessage;

export interface SyncDesiredMessage {
  type: "sync_desired";
  revision: number;
  placements: DesiredPlacement[];
}

export interface SyncRoutesMessage {
  type: "sync_routes";
  revision: number;
  httpRoutes: HttpRouteEntry[];
  postgresRoutes: PostgresRouteEntry[];
  internalRoutes?: InternalRouteEntry[];
  clusterPeers?: ClusterPeer[];
}

export interface SyncTlsMessage {
  type: "sync_tls";
  revision: number;
  domains: string[];
  certPem: string;
  keyPem: string;
  notAfter: number;
}

export interface RefreshSecretsMessage {
  type: "refresh_secrets";
  serviceName: string;
}

export interface DrainMessage {
  type: "drain";
  reason: string;
}

export interface GrowVolumeMessage {
  type: "grow_volume";
  mountPath: string;
  volumeId?: string;
  device?: string;
  volumeIdentity?: string;
}

export interface ProbeVolumesMessage {
  type: "probe_volumes";
  challenge: string;
}

export interface StreamLogsMessage {
  type: "stream_logs";
  requestId: string;
  containerName: string;
  tail: number;
  follow: boolean;
}

export interface StopLogsMessage {
  type: "stop_logs";
  requestId: string;
}

export interface ExecCommandMessage {
  type: "exec_command";
  requestId: string;
  containerName: string;
  command: string[];
  timeoutSeconds: number;
}

export interface UpgradeAgentMessage {
  type: "upgrade_agent";
  version: string;
  url: string;
  sha256: string;
}

export type BackplaneMessage =
  | SyncDesiredMessage
  | SyncRoutesMessage
  | SyncTlsMessage
  | RefreshSecretsMessage
  | DrainMessage
  | GrowVolumeMessage
  | ProbeVolumesMessage
  | StreamLogsMessage
  | StopLogsMessage
  | ExecCommandMessage
  | UpgradeAgentMessage;

export interface SshChallengeRequest {
  fingerprint: string;
}

export interface SshChallengeResponse {
  challengeId: string;
  nonce: string;
  namespace: string;
  expiresAt: number;
}

export interface SshVerifyRequest {
  challengeId: string;
  publicKey: string;
  signature: string;
}

export interface SshVerifyResponse {
  token: string;
  owner: string;
  role: OperatorRole;
  expiresAt: number;
}

export interface NodeEnrollRequest {
  enrollmentSecret: string;
  instanceId: string;
  region: string;
  poolKind: PoolKind;
  vcnIp: string;
}

export interface NodeEnrollResponse {
  nodeId: string;
  token: string;
  wsUrl: string;
}

export interface DeployRequest {
  service: string;
  image: string;
  region?: string;
}

export interface RollbackRequest {
  service: string;
  region?: string;
}

export interface RegionSummary {
  label: string;
  health: HealthState;
  nodes: number;
  nodesReady: number;
  statefulNodes: number;
  workerNodes: number;
  cpuTotalMilli: number;
  cpuRequestedMilli: number;
  memTotalMiB: number;
  memRequestedMiB: number;
  databases: number;
  packingPct: number;
}

export interface ServiceSummary {
  name: string;
  mode: PlacementMode;
  priority: PriorityTier;
  image: string;
  regions: string[];
  desired: number;
  ready: number;
}

export interface StatusResponse {
  ts: number;
  regions: RegionSummary[];
  nodes: NodeInfo[];
  services: ServiceSummary[];
  placements: PlacementInfo[];
  rollouts: RolloutInfo[];
}

export interface TopResponse {
  ts: number;
  nodes: MetricsPoint10s[];
}

export interface DiffItem {
  service: string;
  kind: DiffKind;
  fields: string[];
}

export interface ExecRequest {
  nodeId: string;
  service: string;
  command: string[];
  timeoutSeconds: number;
}

export interface ExecResponse {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface KillNodeChaos {
  kind: "kill_node";
  nodeId: string;
}

export interface Inject5xxChaos {
  kind: "inject_5xx";
  service: string;
  ratePct: number;
  durationSeconds: number;
}

export interface CpuLoadChaos {
  kind: "cpu_load";
  nodeId: string;
  cpuPct: number;
  durationSeconds: number;
}

export interface BumpSecretChaos {
  kind: "bump_secret";
  secretName: string;
}

export interface FillDiskChaos {
  kind: "fill_disk";
  nodeId: string;
  usedPct: number;
}

export type ChaosRequest = KillNodeChaos | Inject5xxChaos | CpuLoadChaos | BumpSecretChaos | FillDiskChaos;

export interface AtlasRegion {
  id: string;
  name: string;
  country: string;
  lat: number;
  lon: number;
  api: string;
  auth: string;
  ok: boolean;
}

export interface AtlasService {
  id: string;
  name: string;
  url: string;
  health?: string;
}

export interface AtlasTopology {
  v: 1;
  updated: number;
  regions: AtlasRegion[];
  services: AtlasService[];
}

export interface AtlasPlacement {
  v: 1;
  project: string;
  database: string;
  region: string | null;
  updated: number;
}

export type AtlasPublishKind = "topology" | "placements" | "both";

export interface AtlasPublishRequest {
  topology?: AtlasTopology;
  placements?: AtlasPlacement[];
}

export interface AtlasDiscoveryRegion {
  id: string;
  name: string;
  country: string;
  lat: number;
  lon: number;
  api: string;
  auth: string;
  health: HealthState;
  distanceKm: number | null;
}

export interface AtlasDiscoveryResponse {
  v: 1;
  updated: number;
  stale: boolean;
  closest: string | null;
  regions: AtlasDiscoveryRegion[];
  services: AtlasService[];
}

export interface AtlasResolveResponse {
  v: 1;
  project: string;
  database?: string;
  region: string;
  api: string;
  auth: string;
  health: HealthState;
  placement: AtlasPlacementState;
  stale: boolean;
  pin: string;
  expires: number;
}

export interface AtlasJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  kid: string;
  alg: "ES256";
  use: "sig";
}

export interface AtlasKeysResponse {
  keys: AtlasJwk[];
}
