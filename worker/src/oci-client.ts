export interface OciCredentials {
  tenancyId: string;
  userId: string;
  fingerprint: string;
  privateKeyPem: string;
  baseUrlOverride?: string;
}

export type OciInstanceAction = "SOFTRESET" | "RESET" | "SOFTSTOP";

export class OciError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly requestId: string | null,
  ) {
    super(message);
    this.name = "OciError";
  }
}

type Bytes = Uint8Array<ArrayBuffer>;

const API_VERSION = "20160918";
const OCI_TIMEOUT_MS = 15_000;
const RSA_ENCRYPTION_OID = Uint8Array.of(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01);

function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function derLength(length: number): Bytes {
  if (length < 0x80) return Uint8Array.of(length);
  const bytes: number[] = [];
  let value = length;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value = Math.floor(value / 256);
  }
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function tlv(tag: number, ...content: Uint8Array[]): Bytes {
  const body = concat(...content);
  return concat(Uint8Array.of(tag), derLength(body.length), body);
}

function pemBody(pem: string): { label: string; der: Bytes } {
  const normalized = pem.replace(/\\n/g, "\n");
  const match = /-----BEGIN ([A-Z ]+)-----([\s\S]+?)-----END \1-----/.exec(normalized);
  if (match === null || match[1] === undefined || match[2] === undefined) throw new Error("OCI private key is not PEM");
  const binary = atob(match[2].replace(/\s+/g, ""));
  return { label: match[1], der: Uint8Array.from(binary, (char) => char.charCodeAt(0)) };
}

function toPkcs8(pem: string): Bytes {
  const { label, der } = pemBody(pem);
  if (label === "PRIVATE KEY") return der;
  if (label === "RSA PRIVATE KEY") {
    return tlv(0x30, Uint8Array.of(0x02, 0x01, 0x00), tlv(0x30, RSA_ENCRYPTION_OID, Uint8Array.of(0x05, 0x00)), tlv(0x04, der));
  }
  throw new Error(`Unsupported OCI private key type: ${label}`);
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export class OciRestClient {
  readonly #credentials: OciCredentials;
  #key: Promise<CryptoKey> | undefined;

  constructor(credentials: OciCredentials) {
    this.#credentials = credentials;
  }

  get keyId(): string {
    return `${this.#credentials.tenancyId}/${this.#credentials.userId}/${this.#credentials.fingerprint}`;
  }

  async getInstancePool(ociRegion: string, poolId: string): Promise<{ size?: number } | null> {
    const result = await this.#request(ociRegion, "GET", `/${API_VERSION}/instancePools/${encodeURIComponent(poolId)}`);
    if (typeof result !== "object" || result === null || Array.isArray(result)) return null;
    const record = result as Record<string, unknown>;
    return typeof record.size === "number" ? { size: record.size } : {};
  }

  updateInstancePool(ociRegion: string, poolId: string, size: number): Promise<unknown> {
    return this.#request(ociRegion, "PUT", `/${API_VERSION}/instancePools/${encodeURIComponent(poolId)}`, { size });
  }

  detachPoolInstance(ociRegion: string, poolId: string, instanceId: string, decrementSize: boolean): Promise<unknown> {
    return this.#request(
      ociRegion,
      "POST",
      `/${API_VERSION}/instancePools/${encodeURIComponent(poolId)}/actions/detachInstance`,
      { instanceId, isDecrementSize: decrementSize, isAutoTerminate: false },
    );
  }

  terminateInstance(ociRegion: string, instanceId: string, preserveBootVolume = false): Promise<unknown> {
    return this.#request(
      ociRegion,
      "DELETE",
      `/${API_VERSION}/instances/${encodeURIComponent(instanceId)}?preserveBootVolume=${preserveBootVolume ? "true" : "false"}`,
    );
  }

  instanceAction(ociRegion: string, instanceId: string, action: OciInstanceAction): Promise<unknown> {
    return this.#request(
      ociRegion,
      "POST",
      `/${API_VERSION}/instances/${encodeURIComponent(instanceId)}?action=${action}`,
      null,
    );
  }

  updateVolumeSize(ociRegion: string, volumeId: string, sizeInGBs: number): Promise<unknown> {
    return this.#request(ociRegion, "PUT", `/${API_VERSION}/volumes/${encodeURIComponent(volumeId)}`, { sizeInGBs });
  }

  baseUrl(ociRegion: string): string {
    const override = this.#credentials.baseUrlOverride;
    if (override !== undefined && override.length > 0) return override.replace(/\/+$/, "");
    return `https://iaas.${ociRegion}.oraclecloud.com`;
  }

  #privateKey(): Promise<CryptoKey> {
    if (this.#key === undefined) {
      this.#key = crypto.subtle.importKey(
        "pkcs8",
        toPkcs8(this.#credentials.privateKeyPem),
        { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        false,
        ["sign"],
      );
    }
    return this.#key;
  }

  async signedHeaders(method: string, url: URL, body: string | undefined): Promise<Headers> {
    const headers = new Headers();
    const values = new Map<string, string>();
    values.set("(request-target)", `${method.toLowerCase()} ${url.pathname}${url.search}`);
    values.set("x-date", new Date().toUTCString());
    values.set("host", url.host);
    if (body !== undefined) {
      const bytes = new TextEncoder().encode(body);
      const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      values.set("x-content-sha256", base64(digest));
      values.set("content-type", "application/json");
      values.set("content-length", String(bytes.length));
    }
    const names = [...values.keys()];
    const signingString = names.map((name) => `${name}: ${values.get(name) ?? ""}`).join("\n");
    const signature = new Uint8Array(
      await crypto.subtle.sign("RSASSA-PKCS1-v1_5", await this.#privateKey(), new TextEncoder().encode(signingString)),
    );
    for (const [name, value] of values) {
      if (name !== "(request-target)" && name !== "host") headers.set(name, value);
    }
    headers.set(
      "authorization",
      `Signature version="1",keyId="${this.keyId}",algorithm="rsa-sha256",headers="${names.join(" ")}",signature="${base64(signature)}"`,
    );
    headers.set("accept", "application/json");
    return headers;
  }

  async #request(ociRegion: string, method: string, path: string, payload?: unknown): Promise<unknown> {
    const url = new URL(`${this.baseUrl(ociRegion)}${path}`);
    const body = method === "POST" || method === "PUT" ? (payload === null || payload === undefined ? "" : JSON.stringify(payload)) : undefined;
    const headers = await this.signedHeaders(method, url, body);
    const signal = AbortSignal.timeout(OCI_TIMEOUT_MS);
    const response = await fetch(url.toString(), body === undefined ? { method, headers, signal } : { method, headers, body, signal });
    const text = await response.text();
    const requestId = response.headers.get("opc-request-id");
    if (!response.ok) {
      let code = "Unknown";
      let message = text.length > 0 ? text : response.statusText;
      try {
        const parsed = JSON.parse(text) as { code?: unknown; message?: unknown };
        if (typeof parsed.code === "string") code = parsed.code;
        if (typeof parsed.message === "string") message = parsed.message;
      } catch {
        code = "Unknown";
      }
      throw new OciError(response.status, code, `OCI ${method} ${url.pathname} failed (${response.status} ${code}): ${message}`, requestId);
    }
    if (text.length === 0) return null;
    try {
      return JSON.parse(text) as unknown;
    } catch {
      return text;
    }
  }
}
