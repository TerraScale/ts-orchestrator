import { b64urlDecode, b64urlEncode } from "./atlas-pin";
import type { Env } from "./env";
import type { OperatorRole } from "./protocol";

export const SESSION_COOKIE = "ts_orch_session";
export const OAUTH_COOKIE = "ts_orch_oauth";
export const SSH_NAMESPACE = "ts-orch";
export const SSH_SESSION_TTL_S = 8 * 3600;
export const UI_SESSION_TTL_S = 24 * 3600;
export const SSH_CHALLENGE_TTL_MS = 30_000;
export const OIDC_ISSUER = "https://token.actions.githubusercontent.com";
export const OIDC_JWKS_URL = "https://token.actions.githubusercontent.com/.well-known/jwks";
export const OIDC_AUDIENCE = "ts-orch";
export const OIDC_OWNER = "TerraScale";
export const OIDC_REF = "refs/heads/main";
export const PRINCIPAL_HEADER = "X-TsOrch-Principal";

const SESSION_PREFIX = "ts1.";
const OAUTH_TTL_S = 600;
const CLOCK_SKEW_S = 60;
const FETCH_TIMEOUT_MS = 15_000;
const OIDC_REPOSITORIES: ReadonlySet<string> = new Set(["TerraScale/terrascale", "TerraScale/ts-orchestrator"]);
const LOCAL_DEV_SECRET = "ts-orch-local-dev-session-secret";
const ROLE_RANK: Record<OperatorRole, number> = { read: 0, deploy: 1, admin: 2 };
const encoder = new TextEncoder();

export type AuthVia = "ssh" | "github" | "dev" | "oidc" | "system";

export interface Principal {
  subject: string;
  owner: string;
  role: OperatorRole;
  via: AuthVia;
  exp: number;
  login?: string;
  githubId?: number;
}

export interface AllowedSshKey {
  keyType: string;
  blob: Uint8Array;
  fingerprint: string;
  owner: string;
  role: OperatorRole;
}

export interface SshPublicKey {
  keyType: string;
  blob: Uint8Array;
  comment: string;
}

export type SshLoginResult =
  | { ok: true; owner: string; role: OperatorRole; fingerprint: string }
  | { ok: false; code: string; message: string; status: number };

export function isOperatorRole(value: unknown): value is OperatorRole {
  return value === "admin" || value === "deploy" || value === "read";
}

export function roleAllows(role: OperatorRole, required: OperatorRole): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[required];
}

export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  const length = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

export function timingSafeEqualText(a: string, b: string): boolean {
  return timingSafeEqual(encoder.encode(a), encoder.encode(b));
}

export function isLoopbackHost(hostname: string): boolean {
  const host = hostname.toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1" || host.endsWith(".localhost");
}

export function localDevAllowed(url: URL, env: Env): boolean {
  return env.LOCAL_DEV === "true" && isLoopbackHost(url.hostname);
}

export function sessionSecret(env: Env, url?: URL): string | null {
  if (env.SESSION_SECRET !== undefined && env.SESSION_SECRET.length >= 16) return env.SESSION_SECRET;
  if (env.LOCAL_DEV !== "true") return null;
  if (url === undefined) return LOCAL_DEV_SECRET;
  return localDevAllowed(url, env) ? LOCAL_DEV_SECRET : null;
}

function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

function standardB64Decode(text: string): Uint8Array<ArrayBuffer> | null {
  try {
    const binary = atob(text.replace(/\s+/g, ""));
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
}

function standardB64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function randomToken(bytes = 32): string {
  return b64urlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256Hex(text: string): Promise<string> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text))));
}

const hmacKeys = new Map<string, Promise<CryptoKey>>();

function hmacKey(secret: string): Promise<CryptoKey> {
  let key = hmacKeys.get(secret);
  if (key === undefined) {
    if (hmacKeys.size >= 4) hmacKeys.clear();
    key = crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
      "verify",
    ]);
    hmacKeys.set(secret, key);
  }
  return key;
}

export async function hmacSign(secret: string, data: string): Promise<string> {
  const signature = await crypto.subtle.sign("HMAC", await hmacKey(secret), encoder.encode(data));
  return b64urlEncode(new Uint8Array(signature));
}

export async function hmacVerify(secret: string, data: string, signature: string): Promise<boolean> {
  const expected = await hmacSign(secret, data);
  return timingSafeEqualText(expected, signature);
}

function decodeJson(segment: string): unknown {
  try {
    return JSON.parse(new TextDecoder().decode(b64urlDecode(segment)));
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function mintSessionToken(
  secret: string,
  principal: Omit<Principal, "exp">,
  ttlSeconds: number,
  nowMs: number,
): Promise<{ token: string; expiresAt: number }> {
  const expiresAt = nowMs + ttlSeconds * 1000;
  const payload = b64urlEncode(encoder.encode(JSON.stringify({ ...principal, exp: expiresAt })));
  const body = `${SESSION_PREFIX}${payload}`;
  return { token: `${body}.${await hmacSign(secret, body)}`, expiresAt };
}

export async function verifySessionToken(secret: string, token: string, nowMs: number): Promise<Principal | null> {
  if (!token.startsWith(SESSION_PREFIX) || token.length > 4096) return null;
  const dot = token.lastIndexOf(".");
  if (dot <= SESSION_PREFIX.length) return null;
  const body = token.slice(0, dot);
  if (!(await hmacVerify(secret, body, token.slice(dot + 1)))) return null;
  const claims = decodeJson(body.slice(SESSION_PREFIX.length));
  if (!isRecord(claims)) return null;
  const { subject, owner, role, via, exp, login, githubId } = claims;
  if (typeof subject !== "string" || typeof owner !== "string" || !isOperatorRole(role)) return null;
  if (via !== "ssh" && via !== "github" && via !== "dev") return null;
  if (typeof exp !== "number" || exp <= nowMs) return null;
  const principal: Principal = { subject, owner, role, via, exp };
  if (typeof login === "string") principal.login = login;
  if (typeof githubId === "number") principal.githubId = githubId;
  return principal;
}

export function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("Cookie");
  if (header === null) return null;
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 0) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}

export function sessionCookie(value: string, maxAgeSeconds: number, path = "/", name = SESSION_COOKIE, secure = true): string {
  return `${name}=${value}; Path=${path}; Max-Age=${maxAgeSeconds}; HttpOnly${secure ? "; Secure" : ""}; SameSite=Lax`;
}

export function clearCookie(name: string, path = "/", secure = true): string {
  return `${name}=; Path=${path}; Max-Age=0; HttpOnly${secure ? "; Secure" : ""}; SameSite=Lax`;
}

class SshReader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {}

  u32(): number {
    if (this.offset + 4 > this.bytes.length) throw new Error("ssh_truncated");
    const b = this.bytes;
    const value = ((b[this.offset]! << 24) | (b[this.offset + 1]! << 16) | (b[this.offset + 2]! << 8) | b[this.offset + 3]!) >>> 0;
    this.offset += 4;
    return value;
  }

  string(): Uint8Array {
    const length = this.u32();
    if (length > this.bytes.length - this.offset) throw new Error("ssh_truncated");
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  raw(length: number): Uint8Array {
    if (length > this.bytes.length - this.offset) throw new Error("ssh_truncated");
    const value = this.bytes.subarray(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  done(): boolean {
    return this.offset === this.bytes.length;
  }
}

function sshString(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function ed25519RawKey(blob: Uint8Array): Uint8Array<ArrayBuffer> | null {
  try {
    const reader = new SshReader(blob);
    const type = new TextDecoder().decode(reader.string());
    const key = reader.string();
    if (type !== "ssh-ed25519" || key.length !== 32 || !reader.done()) return null;
    return Uint8Array.from(key);
  } catch {
    return null;
  }
}

export function parseSshPublicKey(line: string): SshPublicKey | null {
  const parts = line.trim().split(/\s+/);
  const typeIndex = parts.findIndex((part) => part === "ssh-ed25519");
  if (typeIndex < 0) return null;
  const encoded = parts[typeIndex + 1];
  if (encoded === undefined) return null;
  const blob = standardB64Decode(encoded);
  if (blob === null || ed25519RawKey(blob) === null) return null;
  return { keyType: "ssh-ed25519", blob, comment: parts.slice(typeIndex + 2).join(" ") };
}

export async function sshFingerprint(blob: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(blob)));
  return `SHA256:${standardB64Encode(digest).replace(/=+$/, "")}`;
}

function allowedEntry(value: unknown, keyLine: string | undefined, defaultRole: OperatorRole): { key: string; owner: string; role: OperatorRole } | null {
  if (typeof value === "string") return keyLine === undefined ? { key: value, owner: "", role: defaultRole } : { key: keyLine, owner: value, role: defaultRole };
  if (!isRecord(value)) return null;
  const key = typeof value.key === "string" ? value.key : typeof value.publicKey === "string" ? value.publicKey : keyLine;
  if (key === undefined) return null;
  const owner = typeof value.owner === "string" ? value.owner : "";
  const role = isOperatorRole(value.role) ? value.role : defaultRole;
  return { key, owner, role };
}

export async function parseAllowedSshKeys(raw: string | undefined, defaultRole: OperatorRole): Promise<AllowedSshKey[]> {
  if (raw === undefined || raw.trim().length === 0) return [];
  const entries: { key: string; owner: string; role: OperatorRole }[] = [];
  const text = raw.trim();
  if (text.startsWith("[") || text.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(text);
      if (Array.isArray(parsed)) {
        for (const item of parsed) {
          const entry = allowedEntry(item, undefined, defaultRole);
          if (entry !== null) entries.push(entry);
        }
      } else if (isRecord(parsed)) {
        for (const [keyLine, item] of Object.entries(parsed)) {
          const entry = allowedEntry(item, keyLine, defaultRole);
          if (entry !== null) entries.push(entry);
        }
      }
    } catch {
      return [];
    }
  } else {
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
      const first = trimmed.split(/\s+/)[0] ?? "";
      const role = isOperatorRole(first) ? first : defaultRole;
      entries.push({ key: isOperatorRole(first) ? trimmed.slice(first.length) : trimmed, owner: "", role });
    }
  }
  const keys: AllowedSshKey[] = [];
  for (const entry of entries) {
    const parsed = parseSshPublicKey(entry.key);
    if (parsed === null) continue;
    const fingerprint = await sshFingerprint(parsed.blob);
    keys.push({
      keyType: parsed.keyType,
      blob: parsed.blob,
      fingerprint,
      owner: entry.owner.length > 0 ? entry.owner : parsed.comment.length > 0 ? parsed.comment : fingerprint,
      role: entry.role,
    });
  }
  return keys;
}

function dearmorSshSignature(armored: string): Uint8Array | null {
  const match = /-----BEGIN SSH SIGNATURE-----([\s\S]*?)-----END SSH SIGNATURE-----/.exec(armored);
  const body = match === null ? armored : match[1] ?? "";
  if (!/^[A-Za-z0-9+/=\s]+$/.test(body)) return null;
  return standardB64Decode(body);
}

export async function verifySshSignature(
  armored: string,
  message: Uint8Array,
  namespace: string,
  expectedBlob: Uint8Array,
): Promise<boolean> {
  const bytes = dearmorSshSignature(armored);
  if (bytes === null || bytes.length > 4096) return false;
  try {
    const reader = new SshReader(bytes);
    if (new TextDecoder().decode(reader.raw(6)) !== "SSHSIG") return false;
    if (reader.u32() !== 1) return false;
    const publicKey = reader.string();
    const signedNamespace = reader.string();
    const reserved = reader.string();
    const hashAlgorithm = reader.string();
    const signatureBlob = reader.string();
    if (!reader.done()) return false;
    if (new TextDecoder().decode(signedNamespace) !== namespace) return false;
    if (!timingSafeEqual(publicKey, expectedBlob)) return false;
    const rawKey = ed25519RawKey(publicKey);
    if (rawKey === null) return false;
    const hashName = new TextDecoder().decode(hashAlgorithm);
    if (hashName !== "sha512" && hashName !== "sha256") return false;
    const sigReader = new SshReader(signatureBlob);
    if (new TextDecoder().decode(sigReader.string()) !== "ssh-ed25519") return false;
    const signature = Uint8Array.from(sigReader.string());
    if (signature.length !== 64 || !sigReader.done()) return false;
    const digest = new Uint8Array(
      await crypto.subtle.digest(hashName === "sha512" ? "SHA-512" : "SHA-256", Uint8Array.from(message)),
    );
    const signed = concatBytes(
      encoder.encode("SSHSIG"),
      sshString(signedNamespace),
      sshString(reserved),
      sshString(hashAlgorithm),
      sshString(digest),
    );
    const key = await crypto.subtle.importKey("raw", rawKey, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, signature, signed);
  } catch {
    return false;
  }
}

export async function verifySshLogin(
  env: Env,
  url: URL,
  input: { publicKey: string; signature: string; nonce: string; fingerprint: string },
): Promise<SshLoginResult> {
  const parsed = parseSshPublicKey(input.publicKey);
  if (parsed === null) return { ok: false, code: "validation", message: "publicKey must be an ssh-ed25519 key", status: 400 };
  const fingerprint = await sshFingerprint(parsed.blob);
  if (input.fingerprint.length > 0 && input.fingerprint !== fingerprint) {
    return { ok: false, code: "unauthorized", message: "The key does not match the challenge fingerprint", status: 401 };
  }
  const allowed = await parseAllowedSshKeys(env.ALLOWED_SSH_KEYS, localDevAllowed(url, env) ? "admin" : "read");
  const match = allowed.find((key) => timingSafeEqual(key.blob, parsed.blob));
  if (match === undefined) return { ok: false, code: "forbidden", message: "The SSH key is not allowed", status: 403 };
  const valid = await verifySshSignature(input.signature, encoder.encode(input.nonce), SSH_NAMESPACE, parsed.blob);
  if (!valid) return { ok: false, code: "unauthorized", message: "The SSH signature is invalid", status: 401 };
  return { ok: true, owner: match.owner, role: match.role, fingerprint };
}

function redirect(location: string, cookies: string[] = []): Response {
  const headers = new Headers({ Location: location, "Cache-Control": "no-store" });
  for (const cookie of cookies) headers.append("Set-Cookie", cookie);
  return new Response(null, { status: 303, headers });
}

function loginError(code: string, cookies: string[] = []): Response {
  return redirect(`/?error=${encodeURIComponent(code)}`, cookies);
}

function parseGithubAllowlist(raw: string | undefined): Map<number, OperatorRole> {
  const allowed = new Map<number, OperatorRole>();
  for (const token of (raw ?? "").split(/[\s,]+/)) {
    if (token.length === 0) continue;
    const [idText, roleText] = token.split(":");
    const id = Number(idText);
    if (!Number.isSafeInteger(id) || id <= 0) continue;
    allowed.set(id, isOperatorRole(roleText) ? roleText : "read");
  }
  return allowed;
}

export async function githubStart(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const secret = sessionSecret(env, url);
  if (env.GITHUB_CLIENT_ID === undefined || env.GITHUB_CLIENT_ID.length === 0 || secret === null) {
    return loginError("oauth_failed");
  }
  const state = randomToken(24);
  const verifier = randomToken(48);
  const challenge = b64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(verifier))));
  const payload = b64urlEncode(
    encoder.encode(JSON.stringify({ state, verifier, exp: Date.now() + OAUTH_TTL_S * 1000 })),
  );
  const cookieValue = `${payload}.${await hmacSign(secret, `oauth.${payload}`)}`;
  const authorize = new URL("https://github.com/login/oauth/authorize");
  authorize.searchParams.set("client_id", env.GITHUB_CLIENT_ID);
  authorize.searchParams.set("redirect_uri", `${url.origin}/auth/github/callback`);
  authorize.searchParams.set("scope", "read:user");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("code_challenge", challenge);
  authorize.searchParams.set("code_challenge_method", "S256");
  authorize.searchParams.set("allow_signup", "false");
  return redirect(authorize.toString(), [sessionCookie(cookieValue, OAUTH_TTL_S, "/auth/github", OAUTH_COOKIE)]);
}

export async function githubCallback(request: Request, env: Env): Promise<Response> {
  const clearOauth = clearCookie(OAUTH_COOKIE, "/auth/github");
  const url = new URL(request.url);
  const secret = sessionSecret(env, url);
  if (secret === null || !env.GITHUB_CLIENT_ID || !env.GITHUB_CLIENT_SECRET) return loginError("oauth_failed", [clearOauth]);
  const providerError = url.searchParams.get("error");
  if (providerError !== null) return loginError(providerError === "access_denied" ? "access_denied" : "oauth_failed", [clearOauth]);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const cookie = readCookie(request, OAUTH_COOKIE);
  if (code === null || state === null || cookie === null) return loginError("state_mismatch", [clearOauth]);
  const dot = cookie.lastIndexOf(".");
  if (dot <= 0 || !(await hmacVerify(secret, `oauth.${cookie.slice(0, dot)}`, cookie.slice(dot + 1)))) {
    return loginError("state_mismatch", [clearOauth]);
  }
  const stored = decodeJson(cookie.slice(0, dot));
  if (
    !isRecord(stored) ||
    typeof stored.state !== "string" ||
    typeof stored.verifier !== "string" ||
    typeof stored.exp !== "number" ||
    stored.exp < Date.now() ||
    !timingSafeEqualText(stored.state, state)
  ) {
    return loginError("state_mismatch", [clearOauth]);
  }
  let accessToken: string;
  try {
    const exchange = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded", "User-Agent": "ts-orch" },
      body: new URLSearchParams({
        client_id: env.GITHUB_CLIENT_ID,
        client_secret: env.GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${url.origin}/auth/github/callback`,
        code_verifier: stored.verifier,
      }),
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    const body: unknown = await exchange.json();
    if (!exchange.ok || !isRecord(body) || typeof body.access_token !== "string") return loginError("oauth_failed", [clearOauth]);
    accessToken = body.access_token;
  } catch {
    return loginError("oauth_failed", [clearOauth]);
  }
  let user: Record<string, unknown>;
  try {
    const response = await fetch("https://api.github.com/user", {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${accessToken}`,
        "User-Agent": "ts-orch",
        "X-GitHub-Api-Version": "2022-11-28",
      },
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    const body: unknown = await response.json();
    if (!response.ok || !isRecord(body)) return loginError("oauth_failed", [clearOauth]);
    user = body;
  } catch {
    return loginError("oauth_failed", [clearOauth]);
  }
  const id = user.id;
  const login = typeof user.login === "string" ? user.login : "";
  if (typeof id !== "number" || !Number.isSafeInteger(id)) return loginError("oauth_failed", [clearOauth]);
  const role = parseGithubAllowlist(env.ALLOWED_GITHUB_USER_IDS).get(id);
  if (role === undefined) return loginError("unauthorized", [clearOauth]);
  const { token } = await mintSessionToken(
    secret,
    { subject: `github:${id}`, owner: login.length > 0 ? login : `github:${id}`, role, via: "github", login, githubId: id },
    UI_SESSION_TTL_S,
    Date.now(),
  );
  return redirect("/", [clearOauth, sessionCookie(token, UI_SESSION_TTL_S)]);
}

export function logout(request?: Request, env?: Env): Response {
  const secure =
    request === undefined || env === undefined
      ? true
      : (() => {
          const url = new URL(request.url);
          return !(localDevAllowed(url, env) && url.protocol === "http:");
        })();
  return redirect("/", [clearCookie(SESSION_COOKIE, "/", secure), clearCookie(OAUTH_COOKIE, "/auth/github", secure)]);
}

export async function devLogin(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const secret = sessionSecret(env, url);
  if (!localDevAllowed(url, env) || secret === null) {
    return Response.json({ error: { code: "not_found", message: "Not found" } }, { status: 404 });
  }
  const { token } = await mintSessionToken(
    secret,
    { subject: "dev:local", owner: "local-dev", role: "admin", via: "dev", login: "local-dev" },
    UI_SESSION_TTL_S,
    Date.now(),
  );
  return redirect("/", [sessionCookie(token, UI_SESSION_TTL_S, "/", SESSION_COOKIE, url.protocol === "https:")]);
}

interface OidcKeyCache {
  fetchedAt: number;
  keys: Map<string, CryptoKey>;
}

let oidcKeys: OidcKeyCache | undefined;
let oidcFetch: Promise<OidcKeyCache> | undefined;

async function loadOidcKeys(force: boolean): Promise<OidcKeyCache> {
  const now = Date.now();
  if (oidcKeys !== undefined && !force && now - oidcKeys.fetchedAt < 3600_000) return oidcKeys;
  if (oidcKeys !== undefined && force && now - oidcKeys.fetchedAt < 60_000) return oidcKeys;
  if (oidcFetch === undefined) {
    oidcFetch = (async () => {
      const response = await fetch(OIDC_JWKS_URL, {
        headers: { Accept: "application/json", "User-Agent": "ts-orch" },
        signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
      });
      if (!response.ok) throw new Error(`oidc_jwks_${response.status}`);
      const body: unknown = await response.json();
      const keys = new Map<string, CryptoKey>();
      if (isRecord(body) && Array.isArray(body.keys)) {
        for (const jwk of body.keys) {
          if (!isRecord(jwk) || jwk.kty !== "RSA" || typeof jwk.kid !== "string" || typeof jwk.n !== "string" || typeof jwk.e !== "string") continue;
          const key = await crypto.subtle.importKey(
            "jwk",
            { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            false,
            ["verify"],
          );
          keys.set(jwk.kid, key);
        }
      }
      const cache = { fetchedAt: Date.now(), keys };
      oidcKeys = cache;
      return cache;
    })().finally(() => {
      oidcFetch = undefined;
    });
  }
  return oidcFetch;
}

export async function verifyGithubOidc(token: string, nowMs: number): Promise<Principal | null> {
  const parts = token.split(".");
  if (parts.length !== 3 || token.length > 16_384) return null;
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];
  const header = decodeJson(headerPart);
  const claims = decodeJson(payloadPart);
  if (!isRecord(header) || !isRecord(claims) || header.alg !== "RS256" || typeof header.kid !== "string") return null;
  let cache: OidcKeyCache;
  try {
    cache = await loadOidcKeys(false);
    if (!cache.keys.has(header.kid)) cache = await loadOidcKeys(true);
  } catch {
    return null;
  }
  const key = cache.keys.get(header.kid);
  if (key === undefined) return null;
  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = b64urlDecode(signaturePart);
  } catch {
    return null;
  }
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    signature,
    encoder.encode(`${headerPart}.${payloadPart}`),
  );
  if (!valid) return null;
  const now = Math.floor(nowMs / 1000);
  const audience = claims.aud;
  const audienceOk = audience === OIDC_AUDIENCE || (Array.isArray(audience) && audience.includes(OIDC_AUDIENCE));
  if (claims.iss !== OIDC_ISSUER || !audienceOk) return null;
  if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_S < now) return null;
  if (typeof claims.nbf === "number" && claims.nbf - CLOCK_SKEW_S > now) return null;
  if (typeof claims.iat === "number" && claims.iat - CLOCK_SKEW_S > now) return null;
  if (claims.repository_owner !== OIDC_OWNER || claims.ref !== OIDC_REF) return null;
  if (typeof claims.repository !== "string" || !OIDC_REPOSITORIES.has(claims.repository)) return null;
  if (claims.event_name === "pull_request_target") return null;
  const subject = typeof claims.sub === "string" ? claims.sub : "github-actions";
  const owner = claims.repository;
  return { subject, owner, role: "deploy", via: "oidc", exp: claims.exp * 1000 };
}

function bearerToken(request: Request): string | null {
  const header = request.headers.get("Authorization");
  if (header === null) return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match === null ? null : match[1] ?? null;
}

export async function authenticateRequest(request: Request, env: Env, nowMs = Date.now()): Promise<Principal | null> {
  const secret = sessionSecret(env, new URL(request.url));
  const bearer = bearerToken(request);
  if (bearer !== null) {
    if (bearer.startsWith(SESSION_PREFIX)) {
      if (secret === null) return null;
      const principal = await verifySessionToken(secret, bearer, nowMs);
      return principal !== null && principal.via === "ssh" ? principal : null;
    }
    return verifyGithubOidc(bearer, nowMs);
  }
  const cookie = readCookie(request, SESSION_COOKIE);
  if (cookie === null || secret === null) return null;
  const principal = await verifySessionToken(secret, cookie, nowMs);
  if (principal === null) return null;
  if (principal.via === "dev" && !localDevAllowed(new URL(request.url), env)) return null;
  return principal.via === "github" || principal.via === "dev" ? principal : null;
}

export async function mintSshSession(
  env: Env,
  owner: string,
  role: OperatorRole,
  fingerprint: string,
  nowMs: number,
  url?: URL,
): Promise<{ token: string; expiresAt: number } | null> {
  const secret = sessionSecret(env, url);
  if (secret === null) return null;
  return mintSessionToken(secret, { subject: `ssh:${fingerprint}`, owner, role, via: "ssh" }, SSH_SESSION_TTL_S, nowMs);
}

export function encodePrincipal(principal: Principal): string {
  return encodeURIComponent(JSON.stringify(principal));
}

export function decodePrincipal(value: string | null): Principal | null {
  if (value === null) return null;
  try {
    const parsed: unknown = JSON.parse(decodeURIComponent(value));
    if (!isRecord(parsed) || typeof parsed.subject !== "string" || typeof parsed.owner !== "string") return null;
    if (!isOperatorRole(parsed.role)) return null;
    const via = parsed.via;
    if (via !== "ssh" && via !== "github" && via !== "dev" && via !== "oidc" && via !== "system") return null;
    return { subject: parsed.subject, owner: parsed.owner, role: parsed.role, via, exp: typeof parsed.exp === "number" ? parsed.exp : 0 };
  } catch {
    return null;
  }
}

export function checkEnrollSecret(env: Env, provided: unknown): boolean {
  const expected = env.NODE_ENROLL_SECRET;
  if (expected === undefined || typeof provided !== "string") return false;
  if (expected.length < (env.LOCAL_DEV === "true" ? 1 : 16)) return false;
  return timingSafeEqualText(expected, provided);
}

export function newNodeToken(): string {
  return `tsn_${randomToken(32)}`;
}

export function hashNodeToken(token: string): Promise<string> {
  return sha256Hex(token);
}

export async function verifyNodeToken(token: string, storedHash: string | null): Promise<boolean> {
  if (storedHash === null || storedHash.length === 0) return false;
  return timingSafeEqualText(await hashNodeToken(token), storedHash);
}

export function nodeBearer(request: Request): string | null {
  return bearerToken(request);
}
