import type { TlsBundle } from "./protocol";

export interface TlsManagerConfig {
  cfApiToken?: string;
  cfZoneId?: string;
  domains: string[];
  acmeDirectoryUrl?: string;
  accountEmail?: string;
  localDev?: boolean;
}

export class TlsManagerError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "TlsManagerError";
  }
}

type Bytes = Uint8Array<ArrayBuffer>;

export const LETS_ENCRYPT_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory";
export const CLOUDFLARE_API = "https://api.cloudflare.com/client/v4";
export const LOCAL_DEV_VALIDITY_DAYS = 365;
export const DNS_PROPAGATION_MS = 20_000;

const DAY_MS = 86_400_000;
const POLL_INTERVAL_MS = 3_000;
const POLL_ATTEMPTS = 60;
const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";
const OID_P256 = "1.2.840.10045.3.1.7";
const OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
const OID_COMMON_NAME = "2.5.4.3";
const OID_BASIC_CONSTRAINTS = "2.5.29.19";
const OID_KEY_USAGE = "2.5.29.15";
const OID_EXT_KEY_USAGE = "2.5.29.37";
const OID_SUBJECT_ALT_NAME = "2.5.29.17";
const OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
const OID_EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
const EC_ALGORITHM = { name: "ECDSA", namedCurve: "P-256" };
const EC_SIGN = { name: "ECDSA", hash: "SHA-256" };

const encoder = new TextEncoder();

function utf8(text: string): Bytes {
  return new Uint8Array(encoder.encode(text));
}

function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function b64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function b64url(bytes: Uint8Array): string {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlJson(value: unknown): string {
  return b64url(utf8(JSON.stringify(value)));
}

function fromB64(text: string): Bytes {
  const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, ""));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function pem(label: string, der: Uint8Array): string {
  const body = b64(der).match(/.{1,64}/g)?.join("\n") ?? "";
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export const der = {
  length(length: number): Bytes {
    if (length < 0x80) return Uint8Array.of(length);
    const bytes: number[] = [];
    let value = length;
    while (value > 0) {
      bytes.unshift(value & 0xff);
      value = Math.floor(value / 256);
    }
    return Uint8Array.of(0x80 | bytes.length, ...bytes);
  },
  tlv(tag: number, ...content: Uint8Array[]): Bytes {
    const body = concat(...content);
    return concat(Uint8Array.of(tag), der.length(body.length), body);
  },
  sequence(...content: Uint8Array[]): Bytes {
    return der.tlv(0x30, ...content);
  },
  set(...content: Uint8Array[]): Bytes {
    return der.tlv(0x31, ...content);
  },
  integer(bytes: Uint8Array): Bytes {
    let start = 0;
    while (start < bytes.length - 1 && bytes[start] === 0) start++;
    const trimmed = bytes.slice(start);
    const first = trimmed[0] ?? 0;
    return der.tlv(0x02, first & 0x80 ? concat(Uint8Array.of(0), trimmed) : trimmed.length === 0 ? Uint8Array.of(0) : trimmed);
  },
  smallInteger(value: number): Bytes {
    const bytes: number[] = [];
    let current = value;
    do {
      bytes.unshift(current & 0xff);
      current = Math.floor(current / 256);
    } while (current > 0);
    return der.integer(Uint8Array.from(bytes));
  },
  boolean(value: boolean): Bytes {
    return der.tlv(0x01, Uint8Array.of(value ? 0xff : 0x00));
  },
  null(): Bytes {
    return Uint8Array.of(0x05, 0x00);
  },
  oid(dotted: string): Bytes {
    const parts = dotted.split(".").map((part) => Number(part));
    const first = parts[0] ?? 0;
    const second = parts[1] ?? 0;
    const bytes: number[] = [first * 40 + second];
    for (const part of parts.slice(2)) {
      const chunk: number[] = [part & 0x7f];
      let value = Math.floor(part / 128);
      while (value > 0) {
        chunk.unshift((value & 0x7f) | 0x80);
        value = Math.floor(value / 128);
      }
      bytes.push(...chunk);
    }
    return der.tlv(0x06, Uint8Array.from(bytes));
  },
  utf8String(text: string): Bytes {
    return der.tlv(0x0c, utf8(text));
  },
  octetString(bytes: Uint8Array): Bytes {
    return der.tlv(0x04, bytes);
  },
  bitString(bytes: Uint8Array, unusedBits = 0): Bytes {
    return der.tlv(0x03, Uint8Array.of(unusedBits), bytes);
  },
  time(ms: number): Bytes {
    const date = new Date(ms);
    const pad = (value: number): string => String(value).padStart(2, "0");
    const year = date.getUTCFullYear();
    const rest = `${pad(date.getUTCMonth() + 1)}${pad(date.getUTCDate())}${pad(date.getUTCHours())}${pad(date.getUTCMinutes())}${pad(date.getUTCSeconds())}Z`;
    if (year >= 1950 && year < 2050) return der.tlv(0x17, utf8(`${pad(year % 100)}${rest}`));
    return der.tlv(0x18, utf8(`${String(year).padStart(4, "0")}${rest}`));
  },
  explicit(tagNumber: number, ...content: Uint8Array[]): Bytes {
    return der.tlv(0xa0 | tagNumber, ...content);
  },
};

function commonName(cn: string): Bytes {
  return der.sequence(der.set(der.sequence(der.oid(OID_COMMON_NAME), der.utf8String(cn))));
}

function sanExtensionValue(domains: string[]): Bytes {
  return der.sequence(...domains.map((domain) => der.tlv(0x82, utf8(domain))));
}

function extension(oid: string, critical: boolean, value: Uint8Array): Bytes {
  return critical
    ? der.sequence(der.oid(oid), der.boolean(true), der.octetString(value))
    : der.sequence(der.oid(oid), der.octetString(value));
}

function ecdsaSignatureToDer(raw: Uint8Array): Bytes {
  const half = raw.length / 2;
  return der.sequence(der.integer(raw.slice(0, half)), der.integer(raw.slice(half)));
}

function ecdsaAlgorithm(): Bytes {
  return der.sequence(der.oid(OID_ECDSA_SHA256));
}

async function signDer(privateKey: CryptoKey, data: Bytes): Promise<Bytes> {
  const raw = new Uint8Array(await crypto.subtle.sign(EC_SIGN, privateKey, data));
  return ecdsaSignatureToDer(raw);
}

async function generateKeyPair(): Promise<CryptoKeyPair> {
  return (await crypto.subtle.generateKey(EC_ALGORITHM, true, ["sign", "verify"])) as CryptoKeyPair;
}

async function spki(publicKey: CryptoKey): Promise<Bytes> {
  return new Uint8Array((await crypto.subtle.exportKey("spki", publicKey)) as ArrayBuffer);
}

async function privateKeyPem(privateKey: CryptoKey): Promise<string> {
  const pkcs8 = new Uint8Array((await crypto.subtle.exportKey("pkcs8", privateKey)) as ArrayBuffer);
  return pem("PRIVATE KEY", pkcs8);
}

function normalizeDomains(domains: string[]): string[] {
  return [...new Set(domains.map((domain) => domain.trim().toLowerCase()).filter((domain) => domain.length > 0))];
}

export async function createSelfSignedCertificate(
  domains: string[],
  nowMs: number,
  validityDays = LOCAL_DEV_VALIDITY_DAYS,
): Promise<TlsBundle> {
  const names = normalizeDomains(domains);
  if (names.length === 0) names.push("localhost");
  const cn = names[0] ?? "localhost";
  const keys = await generateKeyPair();
  const serial = crypto.getRandomValues(new Uint8Array(16));
  serial[0] = ((serial[0] ?? 0) & 0x7f) | 0x40;
  const notBefore = Math.floor((nowMs - 3_600_000) / 1000) * 1000;
  const notAfter = Math.floor((nowMs + validityDays * DAY_MS) / 1000) * 1000;
  const extensions = der.sequence(
    extension(OID_BASIC_CONSTRAINTS, true, der.sequence()),
    extension(OID_KEY_USAGE, true, der.bitString(Uint8Array.of(0x80), 7)),
    extension(OID_EXT_KEY_USAGE, false, der.sequence(der.oid(OID_SERVER_AUTH))),
    extension(OID_SUBJECT_ALT_NAME, false, sanExtensionValue(names)),
  );
  const tbs = der.sequence(
    der.explicit(0, der.smallInteger(2)),
    der.integer(serial),
    ecdsaAlgorithm(),
    commonName(cn),
    der.sequence(der.time(notBefore), der.time(notAfter)),
    commonName(cn),
    await spki(keys.publicKey),
    der.explicit(3, extensions),
  );
  const signature = await signDer(keys.privateKey, tbs);
  const certificate = der.sequence(tbs, ecdsaAlgorithm(), der.bitString(signature));
  return {
    domains: names,
    certPem: pem("CERTIFICATE", certificate),
    keyPem: await privateKeyPem(keys.privateKey),
    notAfter,
  };
}

export async function createCsr(domains: string[], keys: CryptoKeyPair): Promise<Bytes> {
  const names = normalizeDomains(domains);
  const cn = names[0];
  if (cn === undefined) throw new TlsManagerError("no_domains", "At least one domain is required for a CSR");
  const requested = der.set(der.sequence(extension(OID_SUBJECT_ALT_NAME, false, sanExtensionValue(names))));
  const info = der.sequence(
    der.smallInteger(0),
    commonName(cn),
    await spki(keys.publicKey),
    der.explicit(0, der.sequence(der.oid(OID_EXTENSION_REQUEST), requested)),
  );
  const signature = await signDer(keys.privateKey, info);
  return der.sequence(info, ecdsaAlgorithm(), der.bitString(signature));
}

interface DerNode {
  tag: number;
  start: number;
  end: number;
}

function readNode(bytes: Uint8Array, offset: number): DerNode {
  const tag = bytes[offset];
  let lengthByte = bytes[offset + 1];
  if (tag === undefined || lengthByte === undefined) throw new TlsManagerError("bad_der", "Truncated DER");
  let cursor = offset + 2;
  let length = lengthByte;
  if (lengthByte & 0x80) {
    const count = lengthByte & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) {
      lengthByte = bytes[cursor++];
      if (lengthByte === undefined) throw new TlsManagerError("bad_der", "Truncated DER length");
      length = length * 256 + lengthByte;
    }
  }
  return { tag, start: cursor, end: cursor + length };
}

function children(bytes: Uint8Array, node: DerNode): DerNode[] {
  const out: DerNode[] = [];
  let cursor = node.start;
  while (cursor < node.end) {
    const child = readNode(bytes, cursor);
    out.push(child);
    cursor = child.end;
  }
  return out;
}

function parseDerTime(bytes: Uint8Array, node: DerNode): number {
  const text = new TextDecoder().decode(bytes.slice(node.start, node.end));
  const match = node.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
  if (match === null) throw new TlsManagerError("bad_der", `Unsupported certificate time: ${text}`);
  const [, y, mo, d, h, mi, s] = match.map((part) => Number(part));
  const year = node.tag === 0x17 ? ((y ?? 0) >= 50 ? 1900 + (y ?? 0) : 2000 + (y ?? 0)) : (y ?? 0);
  return Date.UTC(year, (mo ?? 1) - 1, d ?? 1, h ?? 0, mi ?? 0, s ?? 0);
}

export function certificateNotAfter(certPem: string): number {
  const match = /-----BEGIN CERTIFICATE-----([\s\S]+?)-----END CERTIFICATE-----/.exec(certPem);
  if (match === null || match[1] === undefined) throw new TlsManagerError("bad_pem", "No certificate in PEM");
  const bytes = fromB64(match[1]);
  const cert = readNode(bytes, 0);
  const tbsNode = children(bytes, cert)[0];
  if (tbsNode === undefined) throw new TlsManagerError("bad_der", "Missing TBSCertificate");
  const tbs = children(bytes, tbsNode);
  const offset = tbs[0]?.tag === 0xa0 ? 1 : 0;
  const validity = tbs[offset + 3];
  if (validity === undefined) throw new TlsManagerError("bad_der", "Missing validity");
  const times = children(bytes, validity);
  const notAfter = times[1];
  if (notAfter === undefined) throw new TlsManagerError("bad_der", "Missing notAfter");
  return parseDerTime(bytes, notAfter);
}

export function needsRenewal(cert: TlsBundle | null, nowMs: number, renewBeforeDays = 30): boolean {
  if (cert === null || cert.certPem.length === 0 || cert.keyPem.length === 0) return true;
  return cert.notAfter - nowMs < renewBeforeDays * DAY_MS;
}

function sameDomains(a: string[], b: string[]): boolean {
  const left = normalizeDomains(a).sort();
  const right = normalizeDomains(b).sort();
  return left.length === right.length && left.every((domain, index) => domain === right[index]);
}

interface AcmeDirectory {
  newNonce: string;
  newAccount: string;
  newOrder: string;
}

interface AcmeOrder {
  status: string;
  authorizations: string[];
  finalize: string;
  certificate?: string;
}

interface AcmeChallenge {
  type: string;
  url: string;
  token: string;
  status: string;
}

interface AcmeAuthorization {
  status: string;
  identifier: { type: string; value: string };
  wildcard?: boolean;
  challenges: AcmeChallenge[];
}

interface AcmeResponse {
  response: Response;
  body: unknown;
  text: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

class AcmeClient {
  #nonce: string | undefined;
  #kid: string | undefined;
  #publicJwk: JsonWebKey | undefined;
  #directory: AcmeDirectory | undefined;

  constructor(
    readonly directoryUrl: string,
    readonly accountKey: CryptoKeyPair,
  ) {}

  async directory(): Promise<AcmeDirectory> {
    if (this.#directory !== undefined) return this.#directory;
    const response = await fetch(this.directoryUrl);
    if (!response.ok) throw new TlsManagerError("acme_directory", `ACME directory returned ${response.status}`);
    const body: unknown = await response.json();
    if (
      !isRecord(body) ||
      typeof body.newNonce !== "string" ||
      typeof body.newAccount !== "string" ||
      typeof body.newOrder !== "string"
    )
      throw new TlsManagerError("acme_directory", "ACME directory is malformed");
    this.#directory = { newNonce: body.newNonce, newAccount: body.newAccount, newOrder: body.newOrder };
    return this.#directory;
  }

  async jwk(): Promise<JsonWebKey> {
    if (this.#publicJwk === undefined) {
      const exported = (await crypto.subtle.exportKey("jwk", this.accountKey.publicKey)) as JsonWebKey;
      this.#publicJwk = { crv: "P-256", kty: "EC", x: exported.x ?? "", y: exported.y ?? "" };
    }
    return this.#publicJwk;
  }

  async thumbprint(): Promise<string> {
    const jwk = await this.jwk();
    const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
    return b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(canonical))));
  }

  async nonce(): Promise<string> {
    if (this.#nonce !== undefined) {
      const nonce = this.#nonce;
      this.#nonce = undefined;
      return nonce;
    }
    const response = await fetch((await this.directory()).newNonce, { method: "HEAD" });
    const nonce = response.headers.get("replay-nonce");
    if (nonce === null) throw new TlsManagerError("acme_nonce", "ACME server returned no nonce");
    return nonce;
  }

  async post(url: string, payload: unknown | null, accept = "application/json", attempt = 0): Promise<AcmeResponse> {
    const header: Record<string, unknown> = { alg: "ES256", nonce: await this.nonce(), url };
    if (this.#kid !== undefined) header.kid = this.#kid;
    else header.jwk = await this.jwk();
    const protectedHeader = b64urlJson(header);
    const encodedPayload = payload === null ? "" : b64urlJson(payload);
    const signature = new Uint8Array(
      await crypto.subtle.sign(EC_SIGN, this.accountKey.privateKey, utf8(`${protectedHeader}.${encodedPayload}`)),
    );
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/jose+json", accept },
      body: JSON.stringify({ protected: protectedHeader, payload: encodedPayload, signature: b64url(signature) }),
    });
    const replay = response.headers.get("replay-nonce");
    if (replay !== null) this.#nonce = replay;
    const text = await response.text();
    let body: unknown = null;
    if (text.length > 0 && (response.headers.get("content-type") ?? "").includes("json")) {
      try {
        body = JSON.parse(text) as unknown;
      } catch {
        body = null;
      }
    }
    if (!response.ok) {
      const type = isRecord(body) && typeof body.type === "string" ? body.type : "unknown";
      if (type === "urn:ietf:params:acme:error:badNonce" && attempt < 3) return this.post(url, payload, accept, attempt + 1);
      const detail = isRecord(body) && typeof body.detail === "string" ? body.detail : text;
      throw new TlsManagerError("acme_error", `ACME ${url} failed (${response.status} ${type}): ${detail}`);
    }
    return { response, body, text };
  }

  async register(email: string | undefined): Promise<void> {
    const payload: Record<string, unknown> = { termsOfServiceAgreed: true };
    if (email !== undefined && email.length > 0) payload.contact = [`mailto:${email}`];
    const result = await this.post((await this.directory()).newAccount, payload);
    const location = result.response.headers.get("location");
    if (location === null) throw new TlsManagerError("acme_account", "ACME account has no location");
    this.#kid = location;
  }

  async newOrder(domains: string[]): Promise<{ url: string; order: AcmeOrder }> {
    const result = await this.post((await this.directory()).newOrder, {
      identifiers: domains.map((value) => ({ type: "dns", value })),
    });
    const url = result.response.headers.get("location");
    if (url === null) throw new TlsManagerError("acme_order", "ACME order has no location");
    return { url, order: parseOrder(result.body) };
  }

  async getOrder(url: string): Promise<AcmeOrder> {
    return parseOrder((await this.post(url, null)).body);
  }

  async getAuthorization(url: string): Promise<AcmeAuthorization> {
    const body = (await this.post(url, null)).body;
    if (!isRecord(body) || typeof body.status !== "string" || !isRecord(body.identifier) || !Array.isArray(body.challenges))
      throw new TlsManagerError("acme_authz", "ACME authorization is malformed");
    const identifier = body.identifier;
    const challenges: AcmeChallenge[] = [];
    for (const raw of body.challenges) {
      if (
        isRecord(raw) &&
        typeof raw.type === "string" &&
        typeof raw.url === "string" &&
        typeof raw.token === "string" &&
        typeof raw.status === "string"
      )
        challenges.push({ type: raw.type, url: raw.url, token: raw.token, status: raw.status });
    }
    const authorization: AcmeAuthorization = {
      status: body.status,
      identifier: { type: String(identifier.type), value: String(identifier.value) },
      challenges,
    };
    if (body.wildcard === true) authorization.wildcard = true;
    return authorization;
  }
}

function parseOrder(body: unknown): AcmeOrder {
  if (!isRecord(body) || typeof body.status !== "string" || !Array.isArray(body.authorizations) || typeof body.finalize !== "string")
    throw new TlsManagerError("acme_order", "ACME order is malformed");
  const order: AcmeOrder = {
    status: body.status,
    authorizations: body.authorizations.filter((entry): entry is string => typeof entry === "string"),
    finalize: body.finalize,
  };
  if (typeof body.certificate === "string") order.certificate = body.certificate;
  return order;
}

class CloudflareDns {
  constructor(
    readonly token: string,
    readonly zoneId: string,
  ) {}

  async createTxt(name: string, content: string): Promise<string> {
    const response = await fetch(`${CLOUDFLARE_API}/zones/${encodeURIComponent(this.zoneId)}/dns_records`, {
      method: "POST",
      headers: { authorization: `Bearer ${this.token}`, "content-type": "application/json" },
      body: JSON.stringify({ type: "TXT", name, content, ttl: 60, comment: "ts-orch acme dns-01" }),
    });
    const body: unknown = await response.json().catch(() => null);
    if (!response.ok || !isRecord(body) || body.success !== true || !isRecord(body.result) || typeof body.result.id !== "string")
      throw new TlsManagerError("cloudflare_dns", `Cloudflare TXT create for ${name} failed (${response.status})`);
    return body.result.id;
  }

  async deleteRecord(id: string): Promise<void> {
    const response = await fetch(`${CLOUDFLARE_API}/zones/${encodeURIComponent(this.zoneId)}/dns_records/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${this.token}` },
    });
    if (response.status === 404) {
      await response.body?.cancel();
      return;
    }
    if (!response.ok) {
      const text = await response.text();
      throw new TlsManagerError(
        "cloudflare_dns",
        `Cloudflare DNS delete ${id} failed (${response.status}${text.length > 0 ? `: ${text.slice(0, 300)}` : ""})`,
      );
    }
    await response.body?.cancel();
  }
}

async function pollUntil<T>(load: () => Promise<T>, done: (value: T) => boolean, failed: (value: T) => boolean, what: string): Promise<T> {
  for (let attempt = 0; attempt < POLL_ATTEMPTS; attempt++) {
    const value = await load();
    if (done(value)) return value;
    if (failed(value)) throw new TlsManagerError("acme_invalid", `${what} became invalid`);
    await sleep(POLL_INTERVAL_MS);
  }
  throw new TlsManagerError("acme_timeout", `${what} did not complete in time`);
}

export async function issueAcmeCertificate(config: TlsManagerConfig): Promise<TlsBundle> {
  const domains = normalizeDomains(config.domains);
  if (domains.length === 0) throw new TlsManagerError("no_domains", "No TLS domains configured");
  if (!config.cfApiToken || !config.cfZoneId)
    throw new TlsManagerError("cloudflare_config", "Cloudflare API token and zone id are required for DNS-01");
  const dns = new CloudflareDns(config.cfApiToken, config.cfZoneId);
  const acme = new AcmeClient(config.acmeDirectoryUrl ?? LETS_ENCRYPT_DIRECTORY, await generateKeyPair());
  await acme.register(config.accountEmail);
  const { url: orderUrl, order } = await acme.newOrder(domains);
  const thumbprint = await acme.thumbprint();
  const records: string[] = [];
  try {
    const pending: { authzUrl: string; challenge: AcmeChallenge }[] = [];
    for (const authzUrl of order.authorizations) {
      const authz = await acme.getAuthorization(authzUrl);
      if (authz.status === "valid") continue;
      const challenge = authz.challenges.find((entry) => entry.type === "dns-01");
      if (challenge === undefined) throw new TlsManagerError("acme_challenge", `No dns-01 challenge for ${authz.identifier.value}`);
      const keyAuthorization = `${challenge.token}.${thumbprint}`;
      const txt = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(keyAuthorization))));
      const base = authz.identifier.value.replace(/^\*\./, "");
      records.push(await dns.createTxt(`_acme-challenge.${base}`, txt));
      pending.push({ authzUrl, challenge });
    }
    if (pending.length > 0) await sleep(DNS_PROPAGATION_MS);
    for (const entry of pending) {
      await acme.post(entry.challenge.url, {});
    }
    for (const entry of pending) {
      await pollUntil(
        () => acme.getAuthorization(entry.authzUrl),
        (authz) => authz.status === "valid",
        (authz) => authz.status === "invalid" || authz.status === "revoked" || authz.status === "expired",
        `Authorization ${entry.authzUrl}`,
      );
    }
    const certificateKeys = await generateKeyPair();
    const csr = await createCsr(domains, certificateKeys);
    await pollUntil(
      () => acme.getOrder(orderUrl),
      (current) => current.status === "ready" || current.status === "valid",
      (current) => current.status === "invalid",
      "Order readiness",
    );
    await acme.post(order.finalize, { csr: b64url(csr) });
    const finalized = await pollUntil(
      () => acme.getOrder(orderUrl),
      (current) => current.status === "valid" && current.certificate !== undefined,
      (current) => current.status === "invalid",
      "Order finalization",
    );
    const certificateUrl = finalized.certificate;
    if (certificateUrl === undefined) throw new TlsManagerError("acme_certificate", "ACME order has no certificate URL");
    const chain = (await acme.post(certificateUrl, null, "application/pem-certificate-chain")).text;
    return {
      domains,
      certPem: chain.endsWith("\n") ? chain : `${chain}\n`,
      keyPem: await privateKeyPem(certificateKeys.privateKey),
      notAfter: certificateNotAfter(chain),
    };
  } finally {
    const results = await Promise.allSettled(records.map((id) => dns.deleteRecord(id)));
    for (const result of results) {
      if (result.status === "rejected") {
        const reason = result.reason instanceof Error ? result.reason.message : String(result.reason);
        console.error("acme dns cleanup failed", reason);
      }
    }
  }
}

export async function ensureCertificate(
  config: TlsManagerConfig,
  current: TlsBundle | null,
  nowMs: number,
): Promise<{ renewed: boolean; bundle: TlsBundle }> {
  const domains = normalizeDomains(config.domains);
  if (current !== null && !needsRenewal(current, nowMs) && sameDomains(current.domains, domains.length > 0 ? domains : ["localhost"])) {
    return { renewed: false, bundle: current };
  }
  if (config.localDev === true) return { renewed: true, bundle: await createSelfSignedCertificate(domains, nowMs) };
  return { renewed: true, bundle: await issueAcmeCertificate({ ...config, domains }) };
}
