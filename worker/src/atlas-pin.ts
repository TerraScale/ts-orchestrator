import type { AtlasPlacement, AtlasPublishKind, AtlasPublishRequest, AtlasRegion, AtlasService, AtlasTopology } from "./protocol";

export interface GeoPoint {
  lat: number;
  lon: number;
}

export interface PinClaims {
  project: string;
  database?: string;
  region: string;
  api: string;
}

export interface AtlasPublishKeys {
  topology?: string | undefined;
  placements?: string | undefined;
}

export interface AtlasPublishVerifyInput {
  timestamp: string | null;
  signature: string | null;
  body: Uint8Array;
  kind: AtlasPublishKind;
  keys: AtlasPublishKeys;
  nowSeconds: number;
}

export type AtlasPublishVerification =
  | { ok: true; kind: AtlasPublishKind }
  | { ok: false; code: string; message: string; fix: string; status: number };

export type AtlasPublishParse =
  | { ok: true; kind: AtlasPublishKind; request: AtlasPublishRequest }
  | { ok: false; code: "empty_publish" | "invalid_topology" | "invalid_placement" | "future_updated" };

export interface AtlasTopologyOptions {
  devOrigins?: boolean;
  requiredServices?: readonly string[];
}

export const ATLAS_REQUIRED_SERVICES: readonly string[] = ["terrabase", "auth", "dashboard", "status", "docs"];
export const ATLAS_PUBLISH_SKEW_S = 300;
export const ATLAS_FUTURE_S = 300;
export const DEFAULT_PIN_TTL_S = 600;

const EARTH_RADIUS_KM = 6371;
const RAD = Math.PI / 180;
const PROJECT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const REGION_ID_RE = /^[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SERVICE_ID_RE = REGION_ID_RE;
const API_ORIGIN_RE = /^https:\/\/[a-z0-9-]+\.api\.terrascale\.tech$/;
const TERRASCALE_ORIGIN_RE = /^https:\/\/([a-z0-9-]+\.)*terrascale\.tech$/;
const LOOPBACK_ORIGIN_RE = /^http:\/\/(127\.0\.0\.1|localhost):[1-9][0-9]{0,4}$/;
const DATABASE_NAME_RE = /^[a-z][a-z0-9_-]{0,62}$/;

export function b64urlEncode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function jsonB64url(value: unknown): string {
  return b64urlEncode(new TextEncoder().encode(JSON.stringify(value)));
}

export function haversineKm(a: GeoPoint, b: GeoPoint): number {
  const dLat = (b.lat - a.lat) * RAD;
  const dLon = (b.lon - a.lon) * RAD;
  const sinLat = Math.sin(dLat / 2);
  const sinLon = Math.sin(dLon / 2);
  const h = sinLat * sinLat + Math.cos(a.lat * RAD) * Math.cos(b.lat * RAD) * sinLon * sinLon;
  return 2 * EARTH_RADIUS_KM * Math.asin(Math.min(1, Math.sqrt(h)));
}

interface SigningKey {
  privateKey: CryptoKey;
  publicKey: JsonWebKey;
  kid: string;
}

let cachedSigningKey: { raw: string | undefined; value: Promise<SigningKey | null> } | undefined;

async function importSigningKey(raw: string | undefined): Promise<SigningKey | null> {
  if (!raw) return null;
  try {
    const jwk = JSON.parse(raw) as JsonWebKey;
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d || !jwk.x || !jwk.y) return null;
    const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, [
      "sign",
    ]);
    const publicKey = { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y };
    const canonical = JSON.stringify({ crv: "P-256", kty: "EC", x: jwk.x, y: jwk.y });
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
    return { privateKey, publicKey, kid: b64urlEncode(new Uint8Array(digest)) };
  } catch {
    return null;
  }
}

function signingKey(raw: string | undefined): Promise<SigningKey | null> {
  if (cachedSigningKey === undefined || cachedSigningKey.raw !== raw) {
    cachedSigningKey = { raw, value: importSigningKey(raw) };
  }
  return cachedSigningKey.value;
}

export async function publicJwks(pinSigningKey: string | undefined): Promise<string | null> {
  const key = await signingKey(pinSigningKey);
  return key === null ? null : JSON.stringify({ keys: [{ ...key.publicKey, kid: key.kid, alg: "ES256", use: "sig" }] });
}

export async function signPin(
  pinSigningKey: string | undefined,
  claims: PinClaims,
  iat: number,
  pinTtlSeconds: string | number | undefined = undefined,
): Promise<{ pin: string; exp: number } | null> {
  const key = await signingKey(pinSigningKey);
  if (key === null) return null;
  const ttl = Number(pinTtlSeconds ?? String(DEFAULT_PIN_TTL_S));
  if (!Number.isSafeInteger(ttl) || ttl <= 0) return null;
  const exp = iat + ttl;
  const header = jsonB64url({ alg: "ES256", typ: "JWT", kid: key.kid });
  const body = jsonB64url({ iss: "atlas.terrascale.tech", ...claims, iat, exp });
  const data = new TextEncoder().encode(`${header}.${body}`);
  const raw = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key.privateKey, data);
  return { pin: `${header}.${body}.${b64urlEncode(new Uint8Array(raw))}`, exp };
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const publishKeyCache = new Map<string, Promise<Map<string, CryptoKey> | null>>();

async function importPublishKeys(raw: string): Promise<Map<string, CryptoKey> | null> {
  try {
    const jwks: unknown = JSON.parse(raw);
    if (!isObject(jwks) || !Array.isArray(jwks.keys) || jwks.keys.length < 1 || jwks.keys.length > 4) return null;
    const keys = new Map<string, CryptoKey>();
    for (const jwk of jwks.keys) {
      if (
        !isObject(jwk) ||
        jwk.kty !== "EC" ||
        jwk.crv !== "P-256" ||
        typeof jwk.x !== "string" ||
        typeof jwk.y !== "string" ||
        "d" in jwk
      )
        return null;
      const key = await crypto.subtle.importKey(
        "jwk",
        { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["verify"],
      );
      keys.set(`${jwk.x}.${jwk.y}`, key);
    }
    return keys;
  } catch {
    return null;
  }
}

function loadPublishKeys(raw: string | undefined): Promise<Map<string, CryptoKey> | null> {
  if (!raw) return Promise.resolve(null);
  let keys = publishKeyCache.get(raw);
  if (keys === undefined) {
    if (publishKeyCache.size >= 2) publishKeyCache.clear();
    keys = importPublishKeys(raw);
    publishKeyCache.set(raw, keys);
  }
  return keys;
}

async function authorizedPublishKeys(keys: AtlasPublishKeys, kind: AtlasPublishKind): Promise<CryptoKey[] | null> {
  if (kind !== "both") {
    const loaded = await loadPublishKeys(kind === "topology" ? keys.topology : keys.placements);
    return loaded === null ? null : [...loaded.values()];
  }
  const [topology, placements] = await Promise.all([loadPublishKeys(keys.topology), loadPublishKeys(keys.placements)]);
  if (topology === null || placements === null) return null;
  return [...topology].filter(([id]) => placements.has(id)).map(([, key]) => key);
}

export function atlasPublishKind(input: unknown): AtlasPublishKind | null {
  if (!isObject(input) || (!("topology" in input) && !("placements" in input))) return null;
  return "topology" in input ? ("placements" in input ? "both" : "topology") : "placements";
}

export async function verifyAtlasPublishSignature(input: AtlasPublishVerifyInput): Promise<AtlasPublishVerification> {
  const { timestamp, signature: signatureHeader } = input;
  if (
    timestamp === null ||
    !/^[0-9]{1,12}$/.test(timestamp) ||
    Math.abs(input.nowSeconds - Number(timestamp)) > ATLAS_PUBLISH_SKEW_S ||
    signatureHeader === null ||
    !/^[A-Za-z0-9_-]{86}$/.test(signatureHeader)
  ) {
    return {
      ok: false,
      code: "invalid_signature",
      message: "Missing, expired or malformed publish headers",
      fix: "Send a current X-Atlas-Timestamp and a base64url ES256 signature.",
      status: 401,
    };
  }
  const signature = b64urlDecode(signatureHeader);
  if (signature.length !== 64 || b64urlEncode(signature) !== signatureHeader) {
    return {
      ok: false,
      code: "invalid_signature",
      message: "Signature must be raw r||s",
      fix: "Send a 64-byte ES256 signature encoded as base64url.",
      status: 401,
    };
  }
  if (!input.keys.topology && !input.keys.placements) {
    return {
      ok: false,
      code: "publish_disabled",
      message: "No publish keys are configured",
      fix: "Configure the matching public JWKS bindings.",
      status: 503,
    };
  }
  const keys = await authorizedPublishKeys(input.keys, input.kind);
  if (keys === null) {
    return {
      ok: false,
      code: "publish_disabled",
      message: "No keys authorize this publish kind",
      fix: "Configure public P-256 JWKS; combined publishes need a shared key.",
      status: 503,
    };
  }
  const prefix = new TextEncoder().encode(`atlas-publish-v1\n${timestamp}\n`);
  const signed = new Uint8Array(prefix.length + input.body.length);
  signed.set(prefix);
  signed.set(input.body, prefix.length);
  for (const key of keys) {
    if (await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, signed)) {
      return { ok: true, kind: input.kind };
    }
  }
  return {
    ok: false,
    code: "invalid_signature",
    message: "Signature verification failed",
    fix: "Sign the exact body with a key authorized for every supplied section.",
    status: 401,
  };
}

function acceptedUrl(url: unknown, devOrigins: boolean, api = false, origin = true): url is string {
  if (typeof url !== "string" || url.length > 512) return false;
  try {
    const parsed = new URL(url);
    const host = url.match(/^[a-z]+:\/\/[^/]+/)?.[0] ?? "";
    if (parsed.username || parsed.password || parsed.search || parsed.hash || url.includes("?") || url.includes("#"))
      return false;
    if (origin && host !== url) return false;
    if ((api ? API_ORIGIN_RE : TERRASCALE_ORIGIN_RE).test(host)) return true;
    return devOrigins && LOOPBACK_ORIGIN_RE.test(host);
  } catch {
    return false;
  }
}

export function isFutureUpdated(updated: unknown, nowSeconds: number): boolean {
  return typeof updated === "number" && Number.isInteger(updated) && updated > nowSeconds + ATLAS_FUTURE_S;
}

export function atlasProjectId(project: string): boolean {
  return PROJECT_ID_RE.test(project);
}

export function atlasDatabaseName(database: string): boolean {
  return DATABASE_NAME_RE.test(database);
}

function parseRegion(input: unknown, devOrigins: boolean): AtlasRegion | null {
  if (!isObject(input)) return null;
  const { id, name, country, lat, lon, api, auth, ok } = input;
  if (typeof id !== "string" || !REGION_ID_RE.test(id)) return null;
  if (typeof name !== "string" || name.length < 1 || name.length > 128) return null;
  if (typeof country !== "string" || !/^[A-Z]{2}$/.test(country)) return null;
  if (typeof lat !== "number" || !Number.isFinite(lat) || lat < -90 || lat > 90) return null;
  if (typeof lon !== "number" || !Number.isFinite(lon) || lon < -180 || lon > 180) return null;
  if (!acceptedUrl(api, devOrigins, true)) return null;
  if (!acceptedUrl(auth, devOrigins)) return null;
  if (typeof ok !== "boolean") return null;
  return { id, name, country, lat, lon, api, auth, ok };
}

function parseService(input: unknown, devOrigins: boolean): AtlasService | null {
  if (!isObject(input)) return null;
  const { id, name, url, health } = input;
  if (typeof id !== "string" || !SERVICE_ID_RE.test(id)) return null;
  if (typeof name !== "string" || name.length < 1 || name.length > 128) return null;
  if (!acceptedUrl(url, devOrigins, false, false)) return null;
  if (health !== undefined && typeof health !== "string") return null;
  if (typeof health === "string" && !acceptedUrl(health, devOrigins, false, false)) return null;
  return { id, name, url, ...(health === undefined ? {} : { health }) };
}

export function validateAtlasTopology(input: unknown, options: AtlasTopologyOptions = {}): AtlasTopology | null {
  const devOrigins = options.devOrigins === true;
  const required = options.requiredServices ?? ATLAS_REQUIRED_SERVICES;
  if (!isObject(input)) return null;
  const { v, updated, regions, services } = input;
  if (v !== 1 || typeof updated !== "number" || !Number.isSafeInteger(updated) || updated < 0) return null;
  if (!Array.isArray(regions) || regions.length < 1 || regions.length > 64) return null;
  if (!Array.isArray(services) || services.length > 32) return null;
  const seen = new Set<string>();
  const parsedRegions: AtlasRegion[] = [];
  for (const raw of regions) {
    const region = parseRegion(raw, devOrigins);
    if (region === null || seen.has(region.id)) return null;
    seen.add(region.id);
    parsedRegions.push(region);
  }
  const serviceIds = new Set<string>();
  const parsedServices: AtlasService[] = [];
  for (const raw of services) {
    const service = parseService(raw, devOrigins);
    if (service === null || serviceIds.has(service.id)) return null;
    serviceIds.add(service.id);
    parsedServices.push(service);
  }
  for (const id of required) {
    if (!serviceIds.has(id)) return null;
  }
  return { v: 1, updated, regions: parsedRegions, services: parsedServices };
}

export function validateAtlasPlacement(input: unknown): AtlasPlacement | null {
  if (!isObject(input)) return null;
  const { v, project, database, region, updated } = input;
  if (v !== 1) return null;
  if (typeof project !== "string" || !atlasProjectId(project)) return null;
  if (typeof database !== "string" || !atlasDatabaseName(database)) return null;
  if (typeof updated !== "number" || !Number.isSafeInteger(updated) || updated < 0) return null;
  if (region !== null && (typeof region !== "string" || !REGION_ID_RE.test(region))) return null;
  return { v: 1, project, database, region, updated };
}

export function parseAtlasPublishBody(
  input: unknown,
  nowSeconds: number,
  options: AtlasTopologyOptions = {},
): AtlasPublishParse {
  if (!isObject(input)) return { ok: false, code: "empty_publish" };
  const hasTopology = "topology" in input;
  const hasPlacements = "placements" in input;
  if (!hasTopology && !hasPlacements) return { ok: false, code: "empty_publish" };
  const request: AtlasPublishRequest = {};
  if (hasTopology) {
    if (isFutureUpdated(isObject(input.topology) ? input.topology.updated : undefined, nowSeconds)) {
      return { ok: false, code: "future_updated" };
    }
    const topology = validateAtlasTopology(input.topology, options);
    if (topology === null) return { ok: false, code: "invalid_topology" };
    request.topology = topology;
  }
  if (hasPlacements) {
    if (!Array.isArray(input.placements)) return { ok: false, code: "invalid_placement" };
    if (input.placements.length === 0 && !hasTopology) return { ok: false, code: "empty_publish" };
    if (input.placements.length > 64) return { ok: false, code: "invalid_placement" };
    const databases = new Set<string>();
    const placements: AtlasPlacement[] = [];
    for (const raw of input.placements) {
      if (isFutureUpdated(isObject(raw) ? raw.updated : undefined, nowSeconds)) {
        return { ok: false, code: "future_updated" };
      }
      const placement = validateAtlasPlacement(raw);
      if (placement === null) return { ok: false, code: "invalid_placement" };
      const key = `${placement.project}:${placement.database}`;
      if (databases.has(key)) return { ok: false, code: "invalid_placement" };
      databases.add(key);
      placements.push(placement);
    }
    request.placements = placements;
  }
  const kind: AtlasPublishKind = hasTopology && hasPlacements ? "both" : hasTopology ? "topology" : "placements";
  return { ok: true, kind, request };
}
