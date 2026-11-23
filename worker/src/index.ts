import { atlasStub, cacheRecord, placementKey, TOPOLOGY_KEY, type AtlasCacheRecord } from "./atlas-do";
import {
  ATLAS_PUBLISH_SKEW_S,
  atlasDatabaseName,
  atlasProjectId,
  atlasPublishKind,
  b64urlDecode,
  b64urlEncode,
  haversineKm,
  parseAtlasPublishBody,
  publicJwks,
  signPin,
  verifyAtlasPublishSignature,
  type GeoPoint,
} from "./atlas-pin";
import {
  authenticateRequest,
  devLogin,
  encodePrincipal,
  githubCallback,
  githubStart,
  localDevAllowed,
  logout,
  PRINCIPAL_HEADER,
  roleAllows,
  type Principal,
} from "./auth";
import { writeNightlyBackup } from "./backup";
import type { Env } from "./env";
import { fleetStub } from "./fleet-do";
import type {
  AtlasDiscoveryResponse,
  AtlasPlacement,
  AtlasRegion,
  AtlasResolveResponse,
  AtlasTopology,
  ErrorCode,
  ErrorResponse,
  HealthState,
  OperatorRole,
} from "./protocol";
import { INDEX_HTML, LOGIN_HTML } from "./ui-assets";

export { AtlasDO } from "./atlas-do";
export { FleetDO } from "./fleet-do";

const ATLAS_CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Atlas-Timestamp, X-Atlas-Signature",
  "Access-Control-Max-Age": "86400",
};
const MEMORY_TTL_MS = 5_000;
const KV_TTL_MS = 60_000;
const STORE_TIMEOUT_MS = 2_500;
const MAX_PUBLISH_BYTES = 128 * 1024;
const PUBLIC_API_PATHS: ReadonlySet<string> = new Set(["/api/auth/ssh/challenge", "/api/auth/ssh/verify", "/api/nodes/enroll"]);
const CONTINENT_POINTS: Record<string, GeoPoint> = {
  AF: { lat: 0, lon: 20 },
  AN: { lat: -82, lon: 0 },
  AS: { lat: 35, lon: 105 },
  EU: { lat: 50, lon: 15 },
  NA: { lat: 40, lon: -100 },
  OC: { lat: -25, lon: 135 },
  SA: { lat: -15, lon: -60 },
};

type AtlasRecord = AtlasTopology | AtlasPlacement;

interface MemoryEntry extends AtlasCacheRecord<AtlasRecord> {
  remembered: number;
}

interface ReadResult<T> {
  doc: T | null;
  cache: "HIT" | "MISS";
  stale: boolean;
}

const memory = new Map<string, MemoryEntry>();

function atlasError(code: string, message: string, fix: string, status: number, extra?: Record<string, string>): Response {
  return Response.json({ error: { code, message, fix } }, { status, headers: { ...ATLAS_CORS_HEADERS, ...extra } });
}

function orchError(code: ErrorCode, message: string, status: number, fix?: string): Response {
  const body: ErrorResponse = { error: fix === undefined ? { code, message } : { code, message, fix } };
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function remember(key: string, entry: AtlasCacheRecord<AtlasRecord>): void {
  if (memory.size >= 512) {
    const oldest = memory.keys().next();
    if (oldest.done !== true) memory.delete(oldest.value);
  }
  memory.set(key, { ...entry, remembered: Date.now() });
}

function current(at: number, ttl: number): boolean {
  const age = Date.now() - at;
  return age >= 0 && age < ttl;
}

async function readStore<T>(env: Env, path: string): Promise<T | null> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      (async () => {
        const response = await atlasStub(env).fetch(`https://atlas-store${path}`);
        if (!response.ok) throw new Error(`Atlas store returned ${response.status}`);
        return (await response.json()) as T | null;
      })(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("Atlas store read timed out")), STORE_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function load<T extends AtlasRecord>(
  env: Env,
  ctx: ExecutionContext,
  key: string,
  fresh: boolean,
  read: () => Promise<T | null>,
): Promise<ReadResult<T>> {
  let cached = memory.get(key);
  if (!fresh) {
    if (cached !== undefined && current(cached.remembered, MEMORY_TTL_MS) && current(cached.at, KV_TTL_MS)) {
      return { doc: cached.doc as T | null, cache: "HIT", stale: false };
    }
    try {
      const kv = await env.ATLAS_KV.get<AtlasCacheRecord<T>>(key, "json");
      if (kv !== null && typeof kv.at === "number" && "doc" in kv) {
        if (current(kv.at, KV_TTL_MS)) {
          remember(key, kv);
          return { doc: kv.doc, cache: "HIT", stale: false };
        }
        if (cached === undefined || kv.at > cached.at) cached = { ...kv, remembered: 0 };
      }
    } catch (error) {
      console.error("atlas KV read failed", error);
    }
  }
  let doc: T | null;
  try {
    doc = await read();
  } catch (error) {
    cached = memory.get(key) ?? cached;
    if (cached === undefined) {
      try {
        const kv = await env.ATLAS_KV.get<AtlasCacheRecord<T>>(key, "json");
        if (kv !== null && typeof kv.at === "number" && "doc" in kv) cached = { ...kv, remembered: 0 };
      } catch (kvError) {
        console.error("atlas KV recovery read failed", kvError);
      }
    }
    if (cached !== undefined) return { doc: cached.doc as T | null, cache: "HIT", stale: true };
    throw error;
  }
  const entry = cacheRecord(doc);
  remember(key, entry);
  ctx.waitUntil(
    env.ATLAS_KV.put(key, JSON.stringify(entry)).catch((error: unknown) => {
      console.error("atlas KV refill failed", error);
    }),
  );
  return { doc, cache: "MISS", stale: false };
}

function getTopology(env: Env, ctx: ExecutionContext, fresh: boolean): Promise<ReadResult<AtlasTopology>> {
  return load(env, ctx, TOPOLOGY_KEY, fresh, () => readStore<AtlasTopology>(env, "/topology"));
}

function getPlacement(
  env: Env,
  ctx: ExecutionContext,
  project: string,
  database: string,
  fresh: boolean,
): Promise<ReadResult<AtlasPlacement>> {
  const query = new URLSearchParams({ project, database });
  return load(env, ctx, placementKey(project, database), fresh, () =>
    readStore<AtlasPlacement>(env, `/placement?${query.toString()}`),
  );
}

function staleAfterS(env: Env): number {
  const parsed = Number(env.STALE_AFTER_S ?? "60");
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 60;
}

function topologyAge(topology: AtlasTopology): number {
  return Math.max(0, Math.floor(Date.now() / 1000) - topology.updated);
}

function clientPoint(request: Request): GeoPoint | null {
  const cf = request.cf;
  if (cf?.latitude !== undefined && cf.longitude !== undefined) {
    const lat = Number(cf.latitude);
    const lon = Number(cf.longitude);
    if (Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180) return { lat, lon };
  }
  return CONTINENT_POINTS[typeof cf?.continent === "string" ? cf.continent : ""] ?? null;
}

function healthOf(region: AtlasRegion, topology: AtlasTopology, staleLimit: number): HealthState {
  if (topologyAge(topology) > staleLimit) return "unknown";
  return region.ok ? "ok" : "down";
}

function rankedRegions(topology: AtlasTopology, point: GeoPoint | null, staleLimit: number) {
  const healthRank = { ok: 0, unknown: 1, down: 2 } as const;
  return topology.regions
    .map((region, index) => ({
      region,
      index,
      health: healthOf(region, topology, staleLimit),
      distanceKm: point === null ? null : haversineKm(point, { lat: region.lat, lon: region.lon }),
    }))
    .sort((a, b) => {
      const byHealth = healthRank[a.health] - healthRank[b.health];
      if (byHealth !== 0) return byHealth;
      if (a.distanceKm !== null && b.distanceKm !== null && a.distanceKm !== b.distanceKm) return a.distanceKm - b.distanceKm;
      return a.index - b.index;
    });
}

async function discovery(request: Request, env: Env, ctx: ExecutionContext, fresh: boolean): Promise<Response> {
  const { doc: topology, cache, stale } = await getTopology(env, ctx, fresh);
  if (topology === null) {
    return atlasError(
      "discovery_unavailable",
      "No topology copy is available",
      "Retry later; the orchestrator publishes the topology.",
      503,
      { "Cache-Control": "no-store" },
    );
  }
  const staleLimit = staleAfterS(env);
  const ranked = rankedRegions(topology, clientPoint(request), staleLimit);
  const closest = ranked.find((entry) => entry.health !== "down") ?? null;
  const body: AtlasDiscoveryResponse = {
    v: 1,
    updated: topology.updated,
    stale,
    closest: closest === null ? null : closest.region.id,
    regions: ranked.map(({ region, health, distanceKm }) => ({
      id: region.id,
      name: region.name,
      country: region.country,
      lat: region.lat,
      lon: region.lon,
      api: region.api,
      auth: region.auth,
      health,
      distanceKm,
    })),
    services: topology.services,
  };
  return Response.json(body, {
    headers: { ...ATLAS_CORS_HEADERS, "Cache-Control": "no-store", "X-TerraScale-Cache": cache },
  });
}

async function resolve(request: Request, env: Env, ctx: ExecutionContext, url: URL, fresh: boolean): Promise<Response> {
  const project = url.searchParams.get("project") ?? "";
  const database = url.searchParams.get("database");
  if (!atlasProjectId(project)) {
    return atlasError("invalid_project", "project is malformed", "Pass the TerraBase project id.", 400, {
      "Cache-Control": "no-store",
    });
  }
  if (database !== null && !atlasDatabaseName(database)) {
    return atlasError("invalid_database", "database is malformed", "Pass a valid database name.", 400, {
      "Cache-Control": "no-store",
    });
  }
  const headers: Record<string, string> = { ...ATLAS_CORS_HEADERS, "Cache-Control": "no-store" };
  const { doc: topology, cache, stale: topologyStale } = await getTopology(env, ctx, fresh);
  headers["X-TerraScale-Cache"] = cache;
  if (topology === null) {
    return atlasError(
      "discovery_unavailable",
      "No topology copy is available",
      "Retry later; the orchestrator publishes the topology.",
      503,
      headers,
    );
  }
  const placementRead: ReadResult<AtlasPlacement> =
    database === null ? { doc: null, cache: "HIT", stale: false } : await getPlacement(env, ctx, project, database, fresh);
  if (placementRead.cache === "MISS") headers["X-TerraScale-Cache"] = "MISS";
  const stale = topologyStale || placementRead.stale;
  const staleLimit = staleAfterS(env);
  const targetId = placementRead.doc?.region ?? null;
  if (database !== null && targetId === null) {
    return atlasError(
      "placement_unavailable",
      "No database placement is available",
      "Retry after the database placement is published.",
      503,
      headers,
    );
  }
  const ranked = rankedRegions(topology, clientPoint(request), staleLimit);
  const selected =
    targetId === null
      ? (ranked.find((entry) => entry.health !== "down")?.region ?? null)
      : (topology.regions.find((region) => region.id === targetId) ?? null);
  if (selected === null) {
    return atlasError("no_eligible_region", "No region is usable", "Retry after the next topology publish.", 503, headers);
  }
  const signed = await signPin(
    env.PIN_SIGNING_KEY,
    { project, ...(database === null ? {} : { database }), region: selected.id, api: selected.api },
    Math.floor(Date.now() / 1000),
    env.PIN_TTL_S,
  );
  if (signed === null) {
    return atlasError("pin_unavailable", "No pin signing key is configured", "Provision the PIN_SIGNING_KEY secret.", 503, headers);
  }
  const body: AtlasResolveResponse = {
    v: 1,
    project,
    ...(database === null ? {} : { database }),
    region: selected.id,
    api: selected.api,
    auth: selected.auth,
    health: healthOf(selected, topology, staleLimit),
    placement: targetId === null ? "any" : "known",
    stale,
    pin: signed.pin,
    expires: signed.exp,
  };
  return Response.json(body, { headers });
}

async function keys(env: Env): Promise<Response> {
  const jwks = await publicJwks(env.PIN_SIGNING_KEY);
  if (jwks === null) {
    return atlasError("pin_unavailable", "No pin signing key is configured", "Provision the PIN_SIGNING_KEY secret.", 503, {
      ...ATLAS_CORS_HEADERS,
      "Cache-Control": "no-store",
    });
  }
  return new Response(jwks, {
    headers: { ...ATLAS_CORS_HEADERS, "Content-Type": "application/json", "Cache-Control": "public, max-age=300" },
  });
}

class BodyError extends Error {
  constructor(readonly code: "payload_too_large" | "body_timeout") {
    super(code);
  }
}

async function readBody(request: Request): Promise<Uint8Array<ArrayBuffer>> {
  const reader = request.body?.getReader();
  if (reader === undefined) return new Uint8Array();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new BodyError("body_timeout")), 10_000);
  });
  const consume = async (): Promise<Uint8Array<ArrayBuffer>> => {
    const chunks: Uint8Array[] = [];
    let total = 0;
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      total += next.value.length;
      if (total > MAX_PUBLISH_BYTES) throw new BodyError("payload_too_large");
      chunks.push(next.value);
    }
    const result = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  };
  try {
    return await Promise.race([consume(), timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    await reader.cancel();
  }
}

function publishFailure(code: string, message: string, fix: string, status: number): Response {
  return Response.json({ error: { code, message, fix } }, { status });
}

async function publish(request: Request, env: Env): Promise<Response> {
  const now = Math.floor(Date.now() / 1000);
  const timestamp = request.headers.get("X-Atlas-Timestamp");
  const signatureHeader = request.headers.get("X-Atlas-Signature");
  if (
    timestamp === null ||
    !/^[0-9]{1,12}$/.test(timestamp) ||
    Math.abs(now - Number(timestamp)) > ATLAS_PUBLISH_SKEW_S ||
    signatureHeader === null ||
    !/^[A-Za-z0-9_-]{86}$/.test(signatureHeader)
  ) {
    return publishFailure(
      "invalid_signature",
      "Missing, expired or malformed publish headers",
      "Send a current X-Atlas-Timestamp and a base64url ES256 signature.",
      401,
    );
  }
  const signature = b64urlDecode(signatureHeader);
  if (signature.length !== 64 || b64urlEncode(signature) !== signatureHeader) {
    return publishFailure(
      "invalid_signature",
      "Signature must be raw r||s",
      "Send a 64-byte ES256 signature encoded as base64url.",
      401,
    );
  }
  if (!env.TOPOLOGY_PUBLISH_KEYS && !env.PLACEMENT_PUBLISH_KEYS) {
    return publishFailure("publish_disabled", "No publish keys are configured", "Configure the matching public JWKS bindings.", 503);
  }
  let bytes: Uint8Array<ArrayBuffer>;
  try {
    bytes = await readBody(request);
  } catch (error) {
    if (!(error instanceof BodyError)) throw error;
    return publishFailure(
      error.code,
      error.code === "body_timeout" ? "Body did not arrive within 10 seconds" : "Body exceeds 128 KiB",
      "Send a complete publish within the size limit.",
      error.code === "body_timeout" ? 408 : 413,
    );
  }
  let input: unknown;
  try {
    input = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    return publishFailure("empty_publish", "Body is not a JSON publish record", "Send topology or placements.", 400);
  }
  const kind = atlasPublishKind(input);
  if (kind === null) {
    return publishFailure("empty_publish", "No topology or placements supplied", "Send topology or placements.", 400);
  }
  const verified = await verifyAtlasPublishSignature({
    timestamp,
    signature: signatureHeader,
    body: bytes,
    kind,
    keys: { topology: env.TOPOLOGY_PUBLISH_KEYS, placements: env.PLACEMENT_PUBLISH_KEYS },
    nowSeconds: now,
  });
  if (!verified.ok) return publishFailure(verified.code, verified.message, verified.fix, verified.status);
  const parsed = parseAtlasPublishBody(input, now, { devOrigins: env.DEV_ORIGINS === "1" });
  if (!parsed.ok) {
    return publishFailure(
      parsed.code,
      parsed.code === "future_updated" ? "updated is more than 300 seconds ahead" : "Publish record failed validation",
      "Correct the record before publishing again.",
      400,
    );
  }
  try {
    return await atlasStub(env).fetch("https://atlas-store/publish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(parsed.request),
    });
  } catch (error) {
    console.error("atlas store publish failed", error);
    return publishFailure(
      "store_unavailable",
      "The Atlas store could not complete the publish",
      "Publish again; earlier items may have landed.",
      502,
    );
  } finally {
    memory.clear();
  }
}

function atlasRequest(url: URL, env: Env): boolean {
  return url.hostname === env.ATLAS_HOST || (env.LOCAL_DEV === "true" && url.pathname.startsWith("/atlas/"));
}

async function handleAtlas(request: Request, env: Env, ctx: ExecutionContext, url: URL): Promise<Response> {
  const path = url.hostname === env.ATLAS_HOST ? url.pathname : url.pathname.slice("/atlas".length);
  const fresh = url.searchParams.get("fresh") === "1";
  let response: Response;
  try {
    if (request.method === "OPTIONS") response = new Response(null, { status: 204 });
    else if (request.method === "GET" && path === "/v1/discovery") response = await discovery(request, env, ctx, fresh);
    else if (request.method === "GET" && path === "/v1/resolve") response = await resolve(request, env, ctx, url, fresh);
    else if (request.method === "GET" && path === "/v1/keys") response = await keys(env);
    else if (request.method === "POST" && path === "/v1/publish") response = await publish(request, env);
    else response = atlasError("not_found", "No such route", "Use an Atlas v1 route.", 404);
  } catch (error) {
    console.error("atlas request failed", error);
    response = atlasError(
      "discovery_unavailable",
      "The authoritative store is unavailable",
      "Retry after the store recovers.",
      503,
    );
  }
  const result = new Response(response.body, response);
  for (const [key, value] of Object.entries(ATLAS_CORS_HEADERS)) result.headers.set(key, value);
  result.headers.set("Access-Control-Expose-Headers", "X-TerraScale-Cache");
  if (!result.headers.has("Cache-Control")) result.headers.set("Cache-Control", "no-store");
  return result;
}

function html(body: string): Response {
  return new Response(body, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "same-origin",
    },
  });
}

function requiredRole(method: string, path: string): OperatorRole {
  if (method === "GET" || method === "HEAD") return "read";
  if (path === "/api/services/diff") return "read";
  if (path === "/api/deploy" || path === "/api/rollback") return "deploy";
  return "admin";
}

function sameOrigin(request: Request, url: URL): boolean {
  const origin = request.headers.get("Origin");
  if (origin !== null) return origin === url.origin;
  const site = request.headers.get("Sec-Fetch-Site");
  return site === null || site === "same-origin" || site === "none";
}

function forward(request: Request, env: Env, principal: Principal | null): Promise<Response> {
  const forwarded = new Request(request);
  forwarded.headers.delete(PRINCIPAL_HEADER);
  if (principal !== null) forwarded.headers.set(PRINCIPAL_HEADER, encodePrincipal(principal));
  return fleetStub(env).fetch(forwarded);
}

async function me(request: Request, env: Env, url: URL): Promise<Response> {
  const principal = await authenticateRequest(request, env);
  const localDev = localDevAllowed(url, env);
  if (principal === null) return Response.json({ authenticated: false, localDev }, { headers: { "Cache-Control": "no-store" } });
  return Response.json(
    {
      authenticated: true,
      owner: principal.owner,
      role: principal.role,
      via: principal.via,
      expiresAt: principal.exp,
      user: { login: principal.login ?? principal.owner, id: principal.githubId ?? principal.subject },
      localDev,
    },
    { headers: { "Cache-Control": "no-store" } },
  );
}

async function handleOrch(request: Request, env: Env, url: URL): Promise<Response> {
  const path = url.pathname;
  const method = request.method;
  if (path === "/healthz" && method === "GET") return Response.json({ ok: true, version: env.VERSION ?? "dev" });
  if (path === "/" && (method === "GET" || method === "HEAD")) {
    const principal = await authenticateRequest(request, env);
    return html(principal !== null && principal.via !== "ssh" && principal.via !== "oidc" ? INDEX_HTML : LOGIN_HTML);
  }
  if (path.startsWith("/auth/")) {
    if (path === "/auth/github/start" && method === "GET") return githubStart(request, env);
    if (path === "/auth/github/callback" && method === "GET") return githubCallback(request, env);
    if (path === "/auth/logout" && (method === "POST" || method === "GET")) return logout();
    if (path === "/auth/dev-login" && (method === "POST" || method === "GET")) {
      if (!localDevAllowed(url, env)) return orchError("not_found", "Not found", 404);
      return devLogin(request, env);
    }
    return orchError("not_found", "Not found", 404);
  }
  if (path === "/ws/node") {
    if (method !== "GET" || request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return orchError("validation", "Expected a WebSocket upgrade", 426);
    }
    return forward(request, env, null);
  }
  if (path === "/api" || path.startsWith("/api/")) {
    if (path === "/api/me" && method === "GET") return me(request, env, url);
    if (PUBLIC_API_PATHS.has(path)) {
      if (method !== "POST") return orchError("not_found", "Not found", 404);
      return forward(request, env, null);
    }
    const principal = await authenticateRequest(request, env);
    if (principal === null) return orchError("unauthorized", "Authentication required", 401, "Run `ts-orch login` or sign in again.");
    if ((principal.via === "github" || principal.via === "dev") && method !== "GET" && method !== "HEAD" && !sameOrigin(request, url)) {
      return orchError("forbidden", "Cross-site request rejected", 403);
    }
    if (path === "/api/dev/chaos" && env.LOCAL_DEV !== "true") return orchError("not_found", "Not found", 404);
    const required = requiredRole(method, path);
    if (!roleAllows(principal.role, required)) {
      return orchError("forbidden", `The ${principal.role} role cannot perform this action`, 403, `Requires the ${required} role.`);
    }
    return forward(request, env, principal);
  }
  return orchError("not_found", "Not found", 404);
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (atlasRequest(url, env)) return handleAtlas(request, env, ctx, url);
    if (url.hostname !== env.ORCH_HOST && env.LOCAL_DEV !== "true") return orchError("not_found", "Not found", 404);
    try {
      return await handleOrch(request, env, url);
    } catch (error) {
      console.error("orchestrator request failed", error);
      return orchError("internal", "The orchestrator failed to handle the request", 500);
    }
  },

  async scheduled(controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    const system: Principal = {
      subject: "system:cron",
      owner: "cron",
      role: "admin",
      via: "system",
      exp: controller.scheduledTime + 3600_000,
    };
    const headers = { [PRINCIPAL_HEADER]: encodePrincipal(system), "Content-Type": "application/json" };
    const base = `https://${env.ORCH_HOST}`;
    const tls = (async () => {
      const response = await fleetStub(env).fetch(`${base}/api/tls/ensure`, { method: "POST", headers, body: "{}" });
      if (!response.ok) throw new Error(`tls ensure failed: ${response.status} ${await response.text()}`);
    })();
    const backup = (async () => {
      const [fleetResponse, atlasResponse] = await Promise.all([
        fleetStub(env).fetch(`${base}/api/export`, { headers }),
        atlasStub(env).fetch("https://atlas-store/export"),
      ]);
      if (!fleetResponse.ok) throw new Error(`fleet export failed: ${fleetResponse.status}`);
      if (!atlasResponse.ok) throw new Error(`atlas export failed: ${atlasResponse.status}`);
      const key = await writeNightlyBackup(env.FLEET_BACKUPS, {
        exportedAt: new Date(controller.scheduledTime).toISOString(),
        fleet: await fleetResponse.json(),
        atlas: await atlasResponse.json(),
      });
      console.log("nightly backup written", key);
    })();
    const results = await Promise.allSettled([tls, backup]);
    const failures = results.filter((result): result is PromiseRejectedResult => result.status === "rejected");
    for (const failure of failures) console.error("scheduled task failed", failure.reason);
    if (failures.length > 0) throw new Error(`${failures.length} scheduled task(s) failed`);
  },
} satisfies ExportedHandler<Env>;
