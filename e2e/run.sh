#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ts-orch-e2e.XXXXXX")"
LOGS="$WORK/logs"
mkdir -p "$LOGS"
GROUPS_TO_STOP=()
PLAIN_PIDS=()
DOCKER_PREFIX=""
WRANGLER_DIR_CREATED=0
[[ -d "$ROOT/worker/.wrangler" ]] || WRANGLER_DIR_CREATED=1

export DOTNET_NOLOGO=true
export DOTNET_CLI_TELEMETRY_OPTOUT=true
export WRANGLER_SEND_METRICS=false
export NO_COLOR=1

log() { printf '\n==> %s\n' "$*"; }
ok() { printf '    ok: %s\n' "$*"; }
die() { printf '\nFAIL: %s\n' "$*" >&2; exit 1; }

cleanup() {
  local status=$?
  set +e
  trap - EXIT INT TERM
  for pid in "${PLAIN_PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null; done
  for pgid in "${GROUPS_TO_STOP[@]}"; do kill -TERM -- "-$pgid" 2>/dev/null; done
  for _ in $(seq 1 50); do
    local alive=0
    for pgid in "${GROUPS_TO_STOP[@]}"; do kill -0 -- "-$pgid" 2>/dev/null && alive=1; done
    [[ $alive -eq 0 ]] && break
    sleep 0.2
  done
  for pgid in "${GROUPS_TO_STOP[@]}"; do kill -KILL -- "-$pgid" 2>/dev/null; done
  wait 2>/dev/null
  if [[ -n "$DOCKER_PREFIX" ]]; then
    docker ps -aq --filter "name=^${DOCKER_PREFIX}-" | xargs -r docker rm -f >/dev/null 2>&1
  fi
  if [[ $status -ne 0 ]]; then
    for file in "$LOGS"/*; do
      [[ -f "$file" ]] || continue
      printf '\n----- %s (last 80 lines) -----\n' "$(basename "$file")" >&2
      tail -n 80 "$file" >&2
    done
  fi
  [[ $WRANGLER_DIR_CREATED -eq 1 ]] && rm -rf "$ROOT/worker/.wrangler"
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

spawn() {
  local name=$1 dir=$2
  shift 2
  ( cd "$dir" && exec setsid "$@" ) >"$LOGS/$name.log" 2>&1 < /dev/null &
  SPAWNED=$!
  GROUPS_TO_STOP+=("$SPAWNED")
}

wait_for() {
  local description=$1 timeout=$2
  shift 2
  local deadline=$((SECONDS + timeout))
  until "$@" >/dev/null 2>&1; do
    (( SECONDS < deadline )) || die "timed out after ${timeout}s waiting for: $description"
    sleep 1
  done
  ok "$description"
}

http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }

expect_code() {
  local expected=$1 description=$2
  shift 2
  local actual
  actual="$(http_code "$@")"
  [[ "$actual" == "$expected" ]] || die "$description: expected HTTP $expected, got $actual"
  ok "$description ($actual)"
}

for tool in dotnet node npm npx curl jq ssh-keygen openssl setsid; do
  command -v "$tool" >/dev/null 2>&1 || die "missing required tool: $tool"
done

cat > "$WORK/e2e.mjs" <<'JS'
import { appendFileSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createServer, request as httpRequest } from "node:http";
import { createServer as createTcpServer, connect as connectTcp } from "node:net";
import { connect as connectTls } from "node:tls";
import { createHash } from "node:crypto";
import { join } from "node:path";

const [command, ...args] = process.argv.slice(2);
const enc = new TextEncoder();
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const fromB64url = (text) => new Uint8Array(Buffer.from(text, "base64url"));
const writeAtomic = (path, content, mode = 0o600) => {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, content, { mode });
  renameSync(tmp, path);
};

async function privateJwk() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d };
}

async function keys(dir) {
  for (const name of ["pin", "placement", "topology"]) {
    const jwk = await privateJwk();
    writeAtomic(join(dir, `${name}.jwk`), JSON.stringify(jwk));
    writeAtomic(join(dir, `${name}.jwks`), JSON.stringify({ keys: [{ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }] }));
  }
}

async function ports(count) {
  const found = new Set();
  while (found.size < Number(count)) {
    const port = await new Promise((resolve, reject) => {
      const server = createServer();
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        const { port: picked } = server.address();
        server.close(() => resolve(picked));
      });
    });
    found.add(port);
  }
  console.log([...found].join(" "));
}

async function publish(url, jwkFile, bodyFile, tamper) {
  const jwk = JSON.parse(readFileSync(jwkFile, "utf8"));
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const body = readFileSync(bodyFile);
  const timestamp = String(Math.floor(Date.now() / 1000));
  const signed = Buffer.concat([Buffer.from(`atlas-publish-v1\n${timestamp}\n`), body]);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, signed));
  if (tamper === "tamper") signature[0] ^= 0xff;
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Atlas-Timestamp": timestamp, "X-Atlas-Signature": b64url(signature) },
    body,
  });
  console.log(JSON.stringify({ status: response.status, body: await response.text() }));
}

async function verifyPin(jwksFile, pin) {
  const jwks = JSON.parse(readFileSync(jwksFile, "utf8"));
  const [headerPart, payloadPart, signaturePart] = pin.split(".");
  const header = JSON.parse(Buffer.from(headerPart, "base64url").toString("utf8"));
  if (header.alg !== "ES256" || header.typ !== "JWT") throw new Error(`unexpected pin header ${JSON.stringify(header)}`);
  const jwk = jwks.keys.find((candidate) => candidate.kid === header.kid);
  if (jwk === undefined) throw new Error(`pin kid ${header.kid} is not in the JWKS`);
  const key = await crypto.subtle.importKey("jwk", { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, fromB64url(signaturePart), enc.encode(`${headerPart}.${payloadPart}`));
  if (!valid) throw new Error("pin signature does not verify against /v1/keys");
  console.log(Buffer.from(payloadPart, "base64url").toString("utf8"));
}

function upstream(port, name) {
  createServer((request, response) => {
    if (request.url?.startsWith("/forwarding?")) {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify(request.headers));
      return;
    }
    response.writeHead(200, { "Content-Type": "text/plain" });
    response.end(`upstream=${name} host=${request.headers.host} path=${request.url}\n`);
  }).listen(Number(port), "127.0.0.1");
}

function pgUpstream(port) {
  createTcpServer((socket) => {
    let seen = "";
    socket.on("data", (chunk) => {
      if (chunk.length >= 8 && chunk.readInt32BE(0) === 8 && chunk.readInt32BE(4) === 80877103) {
        socket.end("UNEXPECTED_SSLREQUEST\n");
        return;
      }
      seen += chunk.toString("utf8");
      if (seen.includes("hello-pg\n")) socket.end("pg-plain-ok\n");
    });
  }).listen(Number(port), "127.0.0.1");
}

async function pgTlsProbe(port, sni) {
  const result = await new Promise((resolve, reject) => {
    const raw = connectTcp(Number(port), "127.0.0.1");
    raw.setTimeout(10000, () => reject(new Error("pg probe timeout")));
    raw.once("error", reject);
    raw.once("connect", () => {
      const sslRequest = Buffer.alloc(8);
      sslRequest.writeInt32BE(8, 0);
      sslRequest.writeInt32BE(80877103, 4);
      raw.write(sslRequest);
    });
    raw.once("data", (chunk) => {
      if (chunk.length !== 1 || chunk[0] !== 0x53) {
        reject(new Error(`expected S response to SSLRequest, got ${chunk.toString("hex")}`));
        return;
      }
      const secure = connectTls({ socket: raw, servername: sni, rejectUnauthorized: false });
      let reply = "";
      secure.once("error", reject);
      secure.once("secureConnect", () => secure.write("hello-pg\n"));
      secure.on("data", (data) => {
        reply += data.toString("utf8");
      });
      secure.once("end", () => resolve(reply.trim()));
    });
  });
  console.log(result);
}

function ociBackplane(port, upstream, instanceId, volumeId, compartmentId) {
  createServer(async (request, response) => {
    const url = new URL(request.url, upstream);
    const send = (body, headers = {}) => {
      response.writeHead(200, { "Content-Type": "application/json", ...headers });
      response.end(JSON.stringify(body));
    };
    if (request.method === "GET" && url.pathname === `/20160918/instances/${instanceId}`) {
      send({ id: instanceId, compartmentId, metadata: { ts_region: "gru", ts_pool: "stateful", ts_stateful_index: "0", ts_data_volume_id: volumeId } });
      return;
    }
    if (request.method === "GET" && url.pathname === "/20160918/volumeAttachments") {
      const attached = url.searchParams.get("instanceId") === instanceId &&
        url.searchParams.get("volumeId") === volumeId && url.searchParams.get("compartmentId") === compartmentId;
      send(attached ? [{ instanceId, volumeId, lifecycleState: "ATTACHED", isReadOnly: false, isShareable: false }] : []);
      return;
    }
    if (request.method === "GET" && url.pathname === `/20160918/volumes/${volumeId}`) {
      const state = await fetch(new URL("/_mock/state", upstream)).then((reply) => reply.json());
      const sizeInGBs = state.volumes[volumeId] ?? 50;
      send({ id: volumeId, sizeInGBs }, { ETag: `"${sizeInGBs}"` });
      return;
    }
    const proxied = httpRequest(url, { method: request.method, headers: request.headers }, (reply) => {
      response.writeHead(reply.statusCode, reply.headers);
      reply.pipe(response);
    });
    proxied.once("error", () => response.destroy());
    request.pipe(proxied);
  }).listen(Number(port), "127.0.0.1");
}

async function fakeNode(url, secret, instanceId, poolKind, logFile, tlsDir) {
  const record = (entry) => appendFileSync(logFile, `${JSON.stringify({ at: Date.now(), ...entry })}\n`);
  const enroll = await fetch(`${url}/api/nodes/enroll`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enrollmentSecret: secret, instanceId, region: "gru", poolKind, vcnIp: "127.0.0.1" }),
  });
  if (!enroll.ok) {
    record({ type: "enroll_failed", status: enroll.status, body: await enroll.text() });
    process.exit(1);
  }
  const { nodeId, token, wsUrl } = await enroll.json();
  record({ type: "enrolled", nodeId, wsUrl });
  const desired = new Map();
  const hash = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
  const hostPort = (placementId) => 30000 + (parseInt(hash(placementId).slice(0, 4), 16) % 20000);
  let socket;
  let connection = 0;
  let reconnect = false;
  let dataVolumeGiB = 50;
  const send = (message) => {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify(message));
  };
  const reports = () =>
    [...desired.values()].map((placement) => ({
      placementId: placement.placementId,
      serviceName: placement.service.name,
      state: "ready",
      image: placement.service.image,
      configHash: hash(placement.service),
      hostPort: hostPort(placement.placementId),
    }));
  const heartbeat = (cpuPct = 5, padding = "") => {
    const ts = Date.now();
    const services = [...new Set([...desired.values()].map((placement) => placement.service.name))];
    send({
      type: "heartbeat",
      ts,
      placements: reports(),
      hostMetrics: { ts, cpuPct, cpuPsi10: 0, memTotalMiB: 16384, memUsedMiB: 2048, memPsi10: 0, ioPsi10: 0, diskUsedPct: 10, netRxBps: 0, netTxBps: 0, load1: 0.1 },
      containerMetrics: [],
      edgeMetrics: {
        ts,
        windowSeconds: 10,
        services: services.map((serviceName) => ({ serviceName, rps: 5, errorRate5xxPct: 0, p50Ms: 3, p95Ms: 12, p99Ms: 20, requests: 50, responses5xx: 0, activeConnections: 1 })),
        postgresConnections: 0,
        ...(padding ? { padding } : {}),
      },
    });
  };
  const onOpen = () => {
    connection += 1;
    record({ type: "connected", connection });
    send({
      type: "hello",
      nodeId,
      region: "gru",
      poolKind,
      vcnIp: "127.0.0.1",
      arch: "x64",
      shape: "VM.Standard.E5.Flex",
      faultDomain: poolKind === "stateful" ? "FAULT-DOMAIN-1" : "FAULT-DOMAIN-2",
      cpuTotalMilli: 4000,
      memTotalMiB: 16384,
      diskTotalGiB: 100,
      labels: { "oci.instance-id": "agent-fixture", "oci.data-volume-id": "agent-fixture", "oci.stateful-index": "9", source: "e2e" },
      volumes: poolKind === "stateful" ? [{ mountPath: "/var/lib/ts-data", device: "/dev/oracleoci/oraclevdb", sizeGiB: dataVolumeGiB, usedPct: 10 }] : [],
      agentVersion: "e2e-simulated",
    });
    if (connection > 1) return;
    if (poolKind === "worker") heartbeat(92, "é".repeat(32_768));
    heartbeat();
    if (poolKind === "worker") heartbeat(91);
    setInterval(heartbeat, 3000);
    setInterval(() => {
      if (socket.readyState === WebSocket.OPEN) socket.send("ping");
    }, 15000);
  };
  const onMessage = (event) => {
    if (typeof event.data !== "string" || event.data === "pong") return;
    const message = JSON.parse(event.data);
    switch (message.type) {
      case "sync_desired":
        desired.clear();
        for (const placement of message.placements) desired.set(placement.placementId, placement);
        record({ type: message.type, revision: message.revision, placements: reports() });
        for (const report of reports()) send({ type: "placement_event", ...report });
        heartbeat();
        break;
      case "sync_tls":
        if (tlsDir) {
          mkdirSync(tlsDir, { recursive: true, mode: 0o700 });
          writeAtomic(join(tlsDir, "key.pem"), message.keyPem);
          writeAtomic(join(tlsDir, "cert.pem"), message.certPem);
        }
        record({ type: message.type, connection, domains: message.domains, notAfter: message.notAfter });
        break;
      case "drain":
        record({ type: message.type, reason: message.reason });
        desired.clear();
        heartbeat();
        send({ type: "drain_complete", nodeId });
        break;
      case "grow_volume": {
        record({ type: message.type, connection, mountPath: message.mountPath });
        const firstGrow = dataVolumeGiB !== 97;
        dataVolumeGiB = 97;
        send({ type: "volume_grown", nodeId, volumePath: message.mountPath, newSizeGiB: dataVolumeGiB });
        if (!firstGrow) break;
        send({ type: "volume_grown", nodeId, volumePath: message.mountPath, newSizeGiB: dataVolumeGiB });
        reconnect = true;
        socket.close(1000, "e2e reconnect after volume grow");
        break;
      }
      case "exec_command":
        record({ type: message.type, containerName: message.containerName, command: message.command });
        send({ type: "exec_result", requestId: message.requestId, exitCode: 0, stdout: `simulated:${message.command.join(" ")}\n`, stderr: "" });
        break;
      case "stream_logs":
        record({ type: message.type, containerName: message.containerName });
        send({ type: "log_chunk", requestId: message.requestId, stream: "stdout", line: `simulated log line from ${nodeId}` });
        break;
      default:
        record({ type: message.type, message });
    }
  };
  const connect = () => {
    socket = new WebSocket(`${wsUrl}?nodeId=${encodeURIComponent(nodeId)}`, { headers: { Authorization: `Bearer ${token}` } });
    socket.addEventListener("open", onOpen);
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", (event) => {
      record({ type: "closed", connection, code: event.code, reason: event.reason });
      if (!reconnect) process.exit(0);
      reconnect = false;
      connect();
    });
    socket.addEventListener("error", () => record({ type: "socket_error" }));
  };
  connect();
}

switch (command) {
  case "keys": await keys(...args); break;
  case "ports": await ports(...args); break;
  case "publish": await publish(...args); break;
  case "verify-pin": await verifyPin(...args); break;
  case "upstream": upstream(...args); break;
  case "pg-upstream": pgUpstream(...args); break;
  case "pg-tls-probe": await pgTlsProbe(...args); break;
  case "oci-backplane": ociBackplane(...args); break;
  case "fake-node": await fakeNode(...args); break;
  default: throw new Error(`unknown helper command ${command}`);
}
JS
helper() { node "$WORK/e2e.mjs" "$@"; }

log "Building ts-orch CLI and TsOrch.AppHost"
if [[ -n "${TS_ORCH_CLI_DIR:-}" && -f "$TS_ORCH_CLI_DIR/ts-orch.dll" ]]; then
  TS=(dotnet "$TS_ORCH_CLI_DIR/ts-orch.dll")
else
  dotnet publish "$ROOT/src/TsOrch.Cli" -c Release --no-self-contained -o "$WORK/cli" -v quiet
  TS=(dotnet "$WORK/cli/ts-orch.dll")
fi
dotnet build "$ROOT/src/TsOrch.AppHost" -c Release -o "$WORK/apphost" -v quiet
[[ -d "$ROOT/worker/node_modules" ]] || npm ci --prefix "$ROOT/worker" --no-audit --no-fund
APPHOST=(dotnet "$WORK/apphost/TsOrch.AppHost.dll")
ok "build complete"

DOCKER=0
DOCKER_SOCKET="${TS_ORCH_DOCKER_SOCKET:-}"
if [[ -z "$DOCKER_SOCKET" ]]; then
  if [[ -S /var/run/docker.sock ]]; then
    DOCKER_SOCKET=/var/run/docker.sock
  elif [[ -S "/run/user/$(id -u)/podman/podman.sock" ]]; then
    DOCKER_SOCKET="/run/user/$(id -u)/podman/podman.sock"
  fi
fi
if [[ -n "$DOCKER_SOCKET" && -z "${DOCKER_HOST:-}" ]]; then
  export DOCKER_HOST="unix://$DOCKER_SOCKET"
fi
if docker info >/dev/null 2>&1; then
  DOCKER=1
  DOCKER_PREFIX="ts-orch-e2e-$$"
  docker pull -q busybox:1.36.1 >/dev/null
  docker pull -q busybox:1.37.0 >/dev/null
fi
if [[ $DOCKER -eq 0 && "${CI:-false}" == "true" ]]; then
  die "Docker is required in CI for Phase 6"
fi

log "Generating ephemeral Ed25519 operator key and ES256 Atlas keys"
ssh-keygen -q -t ed25519 -N "" -C "ts-orch-e2e" -f "$WORK/id_ed25519"
mkdir -m 700 "$WORK/keys"
helper keys "$WORK/keys"
ENROLL_SECRET="$(openssl rand -hex 24)"
SESSION_SECRET="$(openssl rand -hex 32)"
WEB_SECRET_VALUE="e2e-web-$(openssl rand -hex 12)"
BOX_SECRET_VALUE="e2e-box-$(openssl rand -hex 12)"
VAULT_ID="ocid1.vault.oc1.sa-saopaulo-1.e2e"
VOLUME_ID="ocid1.volume.oc1.sa-saopaulo-1.e2e-data-1"
STATEFUL_INSTANCE="ocid1.instance.oc1.sa-saopaulo-1.e2e-stateful-1"
STATEFUL_NODE="gru-s-$(printf '%s' "$STATEFUL_INSTANCE" | openssl dgst -sha256 -r | cut -c 1-10)"
read -r OCI_PORT WORKER_OCI_PORT WORKER_PORT INSPECTOR_PORT EDGE_HTTP EDGE_HTTPS EDGE_PG UP_A UP_B UP_PG AG_HTTP AG_HTTPS AG_PG < <(helper ports 13)
OCI="http://127.0.0.1:$OCI_PORT"
WORKER_OCI="http://127.0.0.1:$WORKER_OCI_PORT"
W="http://127.0.0.1:$WORKER_PORT"
ok "keys and ports ready"

log "Starting oci-mock"
spawn oci-mock "$WORK" "${APPHOST[@]}" --oci-mock --port "$OCI_PORT" \
  --seed-secret "e2e-node-enroll=$ENROLL_SECRET" \
  --seed-secret "e2e-web-token=$WEB_SECRET_VALUE" \
  --seed-secret "e2e-box-token=$BOX_SECRET_VALUE"
wait_for "oci-mock /healthz" 60 curl -sf "$OCI/healthz"
expect_code 401 "IMDS rejects calls without the Oracle bearer" "$OCI/opc/v2/instance/"
curl -sf -H "Authorization: Bearer Oracle" "$OCI/opc/v2/identity/cert.pem" | openssl x509 -noout -subject | grep -q "opc-tenant:" || die "IMDS identity certificate lacks opc-tenant"
ok "IMDS identity certificate carries opc-tenant"
COMPARTMENT_ID="$(jq -er '.regions[] | select(.label == "gru") | .compartmentId' "$ROOT/deploy/fleet.json")"
spawn oci-backplane "$WORK" node "$WORK/e2e.mjs" oci-backplane "$WORKER_OCI_PORT" "$OCI" "$STATEFUL_INSTANCE" "$VOLUME_ID" "$COMPARTMENT_ID"
wait_for "worker OCI fixture /healthz" 30 curl -sf "$WORKER_OCI/healthz"

log "Starting wrangler dev (orch + atlas) against oci-mock"
{
  printf "LOCAL_DEV='true'\n"
  printf "DEV_ORIGINS='1'\n"
  printf "OCI_BASE_URL='%s'\n" "$WORKER_OCI"
  printf "NODE_ENROLL_SECRET='%s'\n" "$ENROLL_SECRET"
  printf "SESSION_SECRET='%s'\n" "$SESSION_SECRET"
  printf "ALLOWED_SSH_KEYS='%s'\n" "$(cat "$WORK/id_ed25519.pub")"
  printf "PIN_SIGNING_KEY='%s'\n" "$(cat "$WORK/keys/pin.jwk")"
  printf "PLACEMENT_PUBLISH_KEYS='%s'\n" "$(cat "$WORK/keys/placement.jwks")"
  printf "TOPOLOGY_PUBLISH_KEYS='%s'\n" "$(cat "$WORK/keys/topology.jwks")"
} > "$WORK/worker.env"
chmod 600 "$WORK/worker.env"
spawn worker "$ROOT/worker" npx wrangler dev --local --infer-origin-from-routes=false \
  --port "$WORKER_PORT" --ip 127.0.0.1 --inspector-port "$INSPECTOR_PORT" \
  --persist-to "$WORK/wrangler-state" --env-file "$WORK/worker.env" --show-interactive-dev-session=false
wait_for "worker /api/me" 180 curl -sf "$W/api/me"
[[ "$(curl -sf "$W/api/me" | jq -r .localDev)" == "true" ]] || die "worker is not in LOCAL_DEV mode"
ok "worker reports localDev"

log "1. Hostname and route isolation"
expect_code 404 "/atlas/api/status is not reachable through the Atlas surface" "$W/atlas/api/status"
expect_code 404 "/atlas/auth/dev-login is not reachable through the Atlas surface" "$W/atlas/auth/dev-login"
curl -sf -D "$WORK/login.headers" "$W/" > "$WORK/login.html"
grep -q "Sign in with GitHub" "$WORK/login.html" || die "unauthenticated / did not serve the login page"
grep -qi '^strict-transport-security: max-age=31536000' "$WORK/login.headers" || die "login page omitted HSTS"
UI_NONCE="$(sed -n "s/.*script-src 'nonce-\([^']*\)' 'strict-dynamic'.*/\1/p" "$WORK/login.headers")"
[[ -n "$UI_NONCE" ]] && grep -q "<script nonce=\"$UI_NONCE\"" "$WORK/login.html" || die "login CSP does not authorize the embedded script"
ok "unauthenticated / serves the login page"
curl -s -D "$WORK/dev-login.headers" -o /dev/null "$W/auth/dev-login"
COOKIE="$(tr -d '\r' < "$WORK/dev-login.headers" | sed -n 's/^[Ss]et-[Cc]ookie: \(ts_orch_session=[^;]*\).*/\1/p' | head -n 1)"
[[ -n "$COOKIE" ]] || die "/auth/dev-login did not set ts_orch_session"
ok "/auth/dev-login issued a session cookie"
curl -sf -H "Cookie: $COOKIE" "$W/" > "$WORK/status.html"
grep -q "Sign Out" "$WORK/status.html" || die "authenticated / did not serve the status UI"
ok "authenticated / serves the status UI"
expect_code 401 "/api/status requires authentication" "$W/api/status"

log "2. SSH Ed25519 login, seed, status, diff"
export TS_ORCH_URL="$W"
export TS_ORCH_SSH_KEY="$WORK/id_ed25519"
export TS_ORCH_SESSION_FILE="$WORK/session.json"
export TS_ORCH_OCI_MOCK_URL="$OCI"
"${TS[@]}" login --key "$WORK/id_ed25519" --url "$W"
[[ "$(stat -c '%a' "$TS_ORCH_SESSION_FILE")" == "600" ]] || die "session file is not 0600"
TOKEN="$(jq -er .token "$TS_ORCH_SESSION_FILE")"
ok "ts-orch login cached a 0600 session"
api() {
  local method=$1 path=$2
  shift 2
  curl -sS --fail-with-body --max-time 30 -X "$method" -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" "$@" "$W$path"
}
chaos() { api POST /api/dev/chaos --data "$1"; }

mkdir -p "$WORK/services"
jq --arg edge "http://127.0.0.1:$EDGE_HTTP" \
  '(.regions[] | select(.label == "gru") | .endpoints) |= {api: $edge, auth: $edge}' \
  "$ROOT/deploy/fleet.json" > "$WORK/fleet.json"
web_spec() {
  jq -n --arg image "$1" --arg vault "$VAULT_ID" '{
    name: "e2e-web", mode: "replicated", priority: "normal", image: $image, regions: ["gru"],
    replicas: 2, minReplicas: 2, maxReplicas: 2, cpuRequestMilli: 50, cpuLimitMilli: 250,
    memRequestMiB: 32, memLimitMiB: 64, pidsLimit: 64, port: 8080, readyPath: "/readyz",
    readyTimeoutSeconds: 60, hostnames: ["web.localhost", "127.0.0.1"], env: {E2E: "1"},
    secrets: {E2E_TOKEN_FILE: {vault: $vault, name: "e2e-web-token"}}, mounts: [], args: [], udpPorts: []
  }'
}
web_spec "registry.e2e.local/web:v1" > "$WORK/services/e2e-web.json"
"${TS[@]}" seed --fleet "$WORK/fleet.json" --services "$WORK/services" --replace
"${TS[@]}" status --json > "$WORK/status.json"
jq -e '[.regions[].label] | index("gru") != null and index("fra") != null and index("sjc") != null' "$WORK/status.json" >/dev/null || die "status does not list gru/fra/sjc"
jq -e '[.services[].name] | index("e2e-web") != null' "$WORK/status.json" >/dev/null || die "status does not list e2e-web"
ok "ts-orch seed + status --json reflect the fleet"
api GET /api/fleet > "$WORK/fleet-live.json"
jq -e --slurpfile want "$WORK/fleet.json" '. == $want[0] and (.netbird.managementUrl | startswith("https://"))' "$WORK/fleet-live.json" >/dev/null || die "GET /api/fleet does not return the seeded fleet.json"
ok "GET /api/fleet returns the seeded fleet.json including netbird.managementUrl"
"${TS[@]}" netbird --help > "$LOGS/netbird-help.txt" || die "ts-orch netbird --help failed"
ok "ts-orch netbird --help succeeds"
"${TS[@]}" diff -f "$WORK/services" | tee "$LOGS/diff.txt"
ok "ts-orch diff ran against live desired state"

log "5a. Real FleetDO enrollment and WS heartbeats (simulated stateful + worker nodes)"
mkdir -p "$WORK/edge-run"
spawn fake-s1 "$WORK" node "$WORK/e2e.mjs" fake-node "$W" "$ENROLL_SECRET" "$STATEFUL_INSTANCE" stateful "$WORK/fake-s1.jsonl" "$WORK/edge-run/tls"
spawn fake-w1 "$WORK" node "$WORK/e2e.mjs" fake-node "$W" "$ENROLL_SECRET" e2e-w1 worker "$WORK/fake-w1.jsonl"
node_status() { api GET /api/nodes | jq -er --arg id "$1" '.nodes[] | select(.id == $id) | .status'; }
node_is() { [[ "$(node_status "$1")" == "$2" ]]; }
wait_for "$STATEFUL_NODE active" 60 node_is "$STATEFUL_NODE" active
wait_for "e2e-w1 active" 60 node_is e2e-w1 active
api GET /api/nodes | jq -e --arg id "$STATEFUL_NODE" --arg instance "$STATEFUL_INSTANCE" --arg volume "$VOLUME_ID" \
  '.nodes[] | select(.id == $id) | .labels | .source == "e2e" and .["oci.instance-id"] == $instance and
    .["oci.data-volume-id"] == $volume and .["oci.stateful-index"] == "0" and (has("oci.instance-pool-id") | not)' \
  >/dev/null || die "hello changed reserved OCI labels"
worker_metrics() { api GET '/api/metrics?node=e2e-w1' | jq -e '.points | length > 0' >/dev/null; }
wait_for "worker metrics available" 30 worker_metrics
api GET '/api/metrics?node=e2e-w1' | jq -e \
  '.points | all(.cpuPct == 5 and (.ts % 10000 == 0)) and (map(.ts) | unique | length) == length' \
  >/dev/null || die "rapid or oversized heartbeats affected the 10-second metrics"
service_ready() { api GET /api/status | jq -e --arg name "$1" --argjson want "$2" '.services[] | select(.name == $name) | .ready >= $want' >/dev/null; }
wait_for "e2e-web 2/2 ready on simulated nodes" 90 service_ready e2e-web 2

log "4a. Shared TLS via /api/tls/ensure -> sync_tls"
api POST /api/tls/ensure --data '{}' | tee "$LOGS/tls-ensure.json" | jq -e '.domains | length > 0' >/dev/null
"${TS[@]}" tls status > "$LOGS/tls-status.txt"
grep -q "localhost" "$LOGS/tls-status.txt" || die "ts-orch tls status did not list domains"
wait_for "sync_tls delivered cert.pem to the edge runtime dir" 60 test -s "$WORK/edge-run/tls/cert.pem"
openssl x509 -in "$WORK/edge-run/tls/cert.pem" -noout -checkend 86400 >/dev/null || die "shared TLS certificate expires within a day"
initial_tls() { jq -se 'any(.[]; .type == "sync_tls" and .connection == 1)' "$WORK/fake-s1.jsonl" >/dev/null; }
wait_for "$STATEFUL_NODE received initial sync_tls on its first connection" 60 initial_tls
chaos "$(jq -cn --arg id "$STATEFUL_NODE" '{kind: "fill_disk", nodeId: $id, usedPct: 90}')" >/dev/null
ok "fill_disk injected on $STATEFUL_NODE (volume grow verified later)"

log "2b. ts-orch secrets check and MCP over stdio"
"${TS[@]}" secrets check -f "$WORK/services" > "$LOGS/secrets-check.txt" 2>&1 || die "ts-orch secrets check failed"
grep -q "e2e-web-token" "$LOGS/secrets-check.txt" || die "secrets check did not list e2e-web-token"
if grep -q "$WEB_SECRET_VALUE" "$LOGS/secrets-check.txt"; then die "secrets check leaked a secret value"; fi
ok "secrets check lists versions without values"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ts-orch-e2e","version":"1.0.0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"status","arguments":{}}}' \
  | timeout 60 "${TS[@]}" mcp > "$WORK/mcp.jsonl" 2> "$LOGS/mcp.stderr"
cp "$WORK/mcp.jsonl" "$LOGS/mcp.jsonl"
jq -se 'map(select(.id == 1))[0].result.protocolVersion | type == "string"' "$WORK/mcp.jsonl" >/dev/null || die "MCP initialize returned no protocolVersion"
jq -se 'map(select(.id == 2))[0].result.tools | map(.name) | (index("status") != null and index("logs") != null and index("metrics") != null and index("events") != null and index("diff") != null)' "$WORK/mcp.jsonl" >/dev/null || die "MCP tools/list is missing read-only tools"
jq -se 'map(select(.id == 3))[0].result | (.isError != true) and (.content[0].text | contains("e2e-web"))' "$WORK/mcp.jsonl" >/dev/null || die "MCP tools/call status did not return live fleet status"
ok "ts-orch mcp answered initialize, tools/list and tools/call status"

log "3. Merged Atlas contract"
jq -n --argjson now "$(date +%s)" '{placements: [{v: 1, project: "e2eproj", database: "maindb", region: "gru", updated: $now}]}' > "$WORK/publish.json"
TAMPERED="$(helper publish "$W/atlas/v1/publish" "$WORK/keys/placement.jwk" "$WORK/publish.json" tamper)"
[[ "$(jq -r .status <<<"$TAMPERED")" == "401" ]] || die "tampered Atlas publish was not rejected: $TAMPERED"
ok "tampered atlas-publish-v1 signature rejected (401)"
WRONG_KEY="$(helper publish "$W/atlas/v1/publish" "$WORK/keys/topology.jwk" "$WORK/publish.json")"
[[ "$(jq -r .status <<<"$WRONG_KEY")" == "401" ]] || die "placement publish signed with the topology key was not rejected: $WRONG_KEY"
ok "placement publish signed by a topology-only key rejected (401)"
PUBLISHED="$(helper publish "$W/atlas/v1/publish" "$WORK/keys/placement.jwk" "$WORK/publish.json")"
[[ "$(jq -r .status <<<"$PUBLISHED")" == "200" ]] || die "Atlas publish failed: $PUBLISHED"
ok "ES256 atlas-publish-v1 placement accepted"
curl -sf "$W/atlas/v1/keys" > "$WORK/jwks.json"
jq -e '.keys | length == 1 and .[0].kty == "EC" and .[0].crv == "P-256" and .[0].alg == "ES256" and (.[0] | has("d") | not)' "$WORK/jwks.json" >/dev/null || die "/v1/keys is not a public P-256 JWKS"
ok "/v1/keys serves the public ES256 JWKS"
discovery_ready() { curl -sf "$W/atlas/v1/discovery" | jq -e '.v == 1 and .closest == "gru" and (.regions | length) == 3 and .regions[0].id == "gru" and .regions[0].health == "ok"' >/dev/null; }
wait_for "/v1/discovery ranks gru first with closest populated" 60 discovery_ready
curl -sf "$W/atlas/v1/resolve?project=e2eproj&database=maindb" > "$WORK/resolve.json"
jq -e --arg api "http://127.0.0.1:$EDGE_HTTP" '.v == 1 and .region == "gru" and .api == $api and .placement == "known" and (.pin | split(".") | length == 3)' "$WORK/resolve.json" >/dev/null || die "resolve returned $(cat "$WORK/resolve.json")"
helper verify-pin "$WORK/jwks.json" "$(jq -r .pin "$WORK/resolve.json")" > "$WORK/pin.json"
jq -e '.iss == "atlas.terrascale.tech" and .project == "e2eproj" and .database == "maindb" and .region == "gru" and .exp > .iat' "$WORK/pin.json" >/dev/null || die "pin claims are wrong: $(cat "$WORK/pin.json")"
ok "/v1/resolve returned region, api and an ES256 pin verified against /v1/keys"
expect_code 404 "Atlas host serves only /v1/* routes" "$W/atlas/v1/status"

log "4b. Real ts-orch edge: readiness, YARP proxy, live route reload, TLS, Postgres TLS, SIGTERM drain"
spawn upstream-a "$WORK" node "$WORK/e2e.mjs" upstream "$UP_A" alpha
spawn upstream-b "$WORK" node "$WORK/e2e.mjs" upstream "$UP_B" bravo
spawn upstream-pg "$WORK" node "$WORK/e2e.mjs" pg-upstream "$UP_PG"
wait_for "upstream alpha" 30 curl -sf "http://127.0.0.1:$UP_A/"
wait_for "upstream bravo" 30 curl -sf "http://127.0.0.1:$UP_B/"
write_routes() {
  jq -n --argjson revision "$1" --argjson port "$2" --argjson apiPort "$UP_A" --argjson pgPort "$UP_PG" '{
    revision: $revision,
    httpRoutes: [
      {serviceName: "e2e-edge", hostnames: ["edge.localhost"], upstreams: [{placementId: "e2e-edge-1", nodeId: "e2e-s1", address: "127.0.0.1", port: $port, local: true}]},
      {serviceName: "e2e-edge-api", hostnames: ["edge.localhost"], pathPrefixes: ["/api"], blockedPaths: ["/api/setup"], upstreams: [{placementId: "e2e-edge-api-1", nodeId: "e2e-s1", address: "127.0.0.1", port: $apiPort, local: true}]},
      {serviceName: "e2e-edge-rows", hostnames: ["edge.localhost"], pathPatterns: ["^/v1/rows/[^/]+$"], methods: ["GET", "HEAD"], upstreams: [{placementId: "e2e-edge-rows-1", nodeId: "e2e-s1", address: "127.0.0.1", port: $apiPort, local: true}]}
    ],
    postgresRoutes: [
      {serviceName: "e2e-pg", hostnames: ["pg.localhost"], listenPort: 6432, upstreams: [{placementId: "e2e-pg-1", nodeId: "e2e-s1", address: "127.0.0.1", port: $pgPort, local: true}]}
    ]
  }' > "$WORK/edge-run/routes.json.tmp"
  mv "$WORK/edge-run/routes.json.tmp" "$WORK/edge-run/routes.json"
}
write_routes 1 "$UP_A"
TS_ORCH_RUNTIME_DIR="$WORK/edge-run" TS_ORCH_EDGE_BIND=127.0.0.1 TS_ORCH_EDGE_HTTP_PORT="$EDGE_HTTP" \
  TS_ORCH_EDGE_HTTPS_PORT="$EDGE_HTTPS" TS_ORCH_EDGE_POSTGRES_PORT="$EDGE_PG" \
  TS_ORCH_EDGE_INTERNAL_TERRABASE_PORT=0 TS_ORCH_EDGE_INTERNAL_PLATFORM_PORT=0 \
  TS_ORCH_EDGE_DRAIN_SECONDS=4 TS_ORCH_EDGE_SHUTDOWN_SECONDS=5 TS_ORCH_EDGE_HTTP3=false \
  spawn edge "$WORK" env 'Logging__Console__LogLevel__Yarp.ReverseProxy.Forwarder.HttpForwarder=Trace' \
  "${TS[@]}" edge
EDGE_PID=$SPAWNED
wait_for "edge /readyz 200" 60 curl -sf "http://127.0.0.1:$EDGE_HTTP/readyz"
proxied() { curl -sf --max-time 5 -H "Host: edge.localhost" "http://127.0.0.1:$EDGE_HTTP/probe" | grep -q "upstream=$1"; }
wait_for "edge proxies edge.localhost to alpha" 30 proxied alpha
write_routes 2 "$UP_B"
wait_for "edge hot-reloads routes.json to bravo" 30 proxied bravo
curl -sf --max-time 5 -k --resolve "edge.localhost:$EDGE_HTTPS:127.0.0.1" "https://edge.localhost:$EDGE_HTTPS/tls" | grep -q "upstream=bravo" || die "HTTPS proxying through the edge failed"
curl -sf --max-time 5 -k --resolve "edge.localhost:$EDGE_HTTPS:127.0.0.1" "https://edge.localhost:$EDGE_HTTPS/readyz" | grep -q "upstream=bravo" || die "HTTPS /readyz did not proxy through to upstream"
ok "HTTPS /readyz proxies through to upstream while HTTP /readyz serves edge readiness"
curl -sf --max-time 5 -k --resolve "edge.localhost:$EDGE_HTTPS:127.0.0.1" \
  -H 'X-Forwarded-For: 192.0.2.1, 192.0.2.2' -H 'X-Real-IP: 192.0.2.3' \
  -H 'X-Forwarded-Proto: http' -H 'X-Forwarded-Host: spoof.invalid' -H 'Forwarded: for=192.0.2.4' \
  "https://edge.localhost:$EDGE_HTTPS/forwarding?code=edge-query-marker" | \
  jq -e --arg host "edge.localhost:$EDGE_HTTPS" '.["x-forwarded-for"] == "127.0.0.1" and
    .["x-real-ip"] == "127.0.0.1" and .["x-forwarded-proto"] == "https" and .["x-forwarded-host"] == $host and
    (has("forwarded") | not)' >/dev/null || die "edge forwarded client-controlled proxy headers"
if grep -q 'edge-query-marker' "$LOGS/edge.log"; then
  die "edge logged a request query parameter"
fi
ok "edge replaces client forwarding headers and keeps query values out of logs"
expect_code 403 "edge blocks /api/setup on the public listener" -H "Host: edge.localhost" "http://127.0.0.1:$EDGE_HTTP/api/setup"
expect_code 403 "edge blocks /api//setup canonicalized path" --path-as-is -H "Host: edge.localhost" "http://127.0.0.1:$EDGE_HTTP/api//setup"
expect_code 403 "edge blocks /API/setup case-insensitively" -H "Host: edge.localhost" "http://127.0.0.1:$EDGE_HTTP/API/setup"
expect_code 403 "edge blocks /api/%73etup percent-encoded path" --path-as-is -H "Host: edge.localhost" "http://127.0.0.1:$EDGE_HTTP/api/%73etup"
curl -sf --max-time 5 -H "Host: edge.localhost" "http://127.0.0.1:$EDGE_HTTP/api/ping" | grep -q "upstream=alpha" || die "edge did not route /api/ping to the /api path-prefix route"
curl -sf --max-time 5 -H "Host: edge.localhost" "http://127.0.0.1:$EDGE_HTTP/v1/rows/42" | grep -q "upstream=alpha" || die "edge did not route GET /v1/rows/42 to the pattern+method route"
curl -sf --max-time 5 -X POST -H "Host: edge.localhost" "http://127.0.0.1:$EDGE_HTTP/v1/rows/42" | grep -q "upstream=bravo" || die "edge did not fall through POST /v1/rows/42 to the catch-all route"
curl -sf --max-time 5 -H "Host: edge.localhost" "http://127.0.0.1:$EDGE_HTTP/tls" | grep -q "upstream=bravo" || die "edge did not fall back to the catch-all route for /tls"
ok "edge honors path prefixes, regex+method routes, blocked-path canonicalization and catch-all fallback"
PG_REPLY="$(helper pg-tls-probe "$EDGE_PG" pg.localhost)"
[[ "$PG_REPLY" == "pg-plain-ok" ]] || die "edge Postgres TLS termination returned unexpected reply: $PG_REPLY"
ok "edge terminates Postgres TLS on port 5432 and bridges plaintext to upstream"
SERVED="$(openssl s_client -connect "127.0.0.1:$EDGE_HTTPS" -servername edge.localhost </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256)"
SHARED="$(openssl x509 -in "$WORK/edge-run/tls/cert.pem" -noout -fingerprint -sha256)"
[[ "$SERVED" == "$SHARED" ]] || die "edge serves a different certificate than /api/tls/ensure issued"
ok "edge serves the backplane-issued shared certificate over HTTPS"
kill -TERM "$EDGE_PID"
readyz_draining() { [[ "$(http_code "http://127.0.0.1:$EDGE_HTTP/readyz")" == "503" ]]; }
wait_for "/readyz flips to 503 on SIGTERM" 4 readyz_draining
proxied bravo || die "edge stopped serving live traffic during the drain window"
ok "edge keeps serving traffic while draining"
EDGE_EXIT=0
wait "$EDGE_PID" || EDGE_EXIT=$?
[[ $EDGE_EXIT -eq 0 ]] || die "ts-orch edge exited with $EDGE_EXIT after SIGTERM"
ok "ts-orch edge drained and exited cleanly"

log "5b. Canary rollout with automatic rollback on injected 5xx"
rollout_phase() { api GET /api/rollouts | jq -r --arg image "$1" '[.rollouts[] | select(.serviceName == "e2e-web" and .targetImage == $image)][0].phase // "missing"'; }
phase_is() { [[ "$(rollout_phase "$1")" == "$2" ]]; }
"${TS[@]}" deploy e2e-web registry.e2e.local/web:v2 --region gru > "$LOGS/deploy-v2.txt"
chaos '{"kind":"inject_5xx","service":"e2e-web","ratePct":60,"durationSeconds":600}' >/dev/null
wait_for "canary of web:v2 rolled back automatically" 150 phase_is registry.e2e.local/web:v2 rolled_back
api GET /api/rollouts | jq -e '.rollouts | any(.serviceName == "e2e-web" and .targetImage == "registry.e2e.local/web:v2" and .error == "canary_5xx_breach")' >/dev/null ||
  die "web:v2 did not roll back on the canary's 5xx metrics"
api GET /api/services | jq -e '.services[] | select(.name == "e2e-web") | .image == "registry.e2e.local/web:v1"' >/dev/null || die "e2e-web did not return to web:v1 after rollback"
ok "e2e-web is back on web:v1"
chaos '{"kind":"inject_5xx","service":"e2e-web","ratePct":0,"durationSeconds":1}' >/dev/null
timeout 300 "${TS[@]}" deploy e2e-web registry.e2e.local/web:v3 --region gru --wait > "$LOGS/deploy-v3.txt" || die "healthy web:v3 rollout did not succeed"
phase_is registry.e2e.local/web:v3 succeeded || die "web:v3 rollout is not succeeded"
ok "healthy canary bake passed and web:v3 rolled out"

log "5c. Vault secret rotation"
curl -sf -X POST "$OCI/_mock/secrets/e2e-web-token/bump" | jq -e '.version == 2' >/dev/null || die "oci-mock did not bump e2e-web-token"
chaos '{"kind":"bump_secret","secretName":"e2e-web-token"}' | jq -e '.services["e2e-web"] | length >= 1' >/dev/null || die "bump_secret did not notify e2e-web nodes"
"${TS[@]}" secrets refresh e2e-web > "$LOGS/secrets-refresh.txt"
refresh_seen() { grep -q '"type":"refresh_secrets"' "$WORK/fake-s1.jsonl" "$WORK/fake-w1.jsonl"; }
wait_for "nodes received refresh_secrets" 30 refresh_seen
"${TS[@]}" secrets check -f "$WORK/services" > "$LOGS/secrets-check-2.txt" 2>&1
{ grep -q "e2e-web-token" "$LOGS/secrets-check-2.txt" && grep -qw "2" "$LOGS/secrets-check-2.txt"; } || die "secrets check does not show e2e-web-token version 2"
ok "Vault rotation propagated (version 2)"

log "5d. Backplane exec and logs through simulated node"
"${TS[@]}" node ls > "$LOGS/node-ls.txt"
{ grep -q "$STATEFUL_NODE" "$LOGS/node-ls.txt" && grep -q "e2e-w1" "$LOGS/node-ls.txt"; } || die "ts-orch node ls is missing nodes"
EXEC_NODE="$(api GET /api/status | jq -er '[.placements[] | select(.serviceName == "e2e-web" and .state == "ready")][0].nodeId')"
timeout 60 "${TS[@]}" exec "$EXEC_NODE" e2e-web -- echo hello > "$LOGS/exec-fake.txt"
grep -q "simulated:echo hello" "$LOGS/exec-fake.txt" || die "ts-orch exec did not round-trip through the node WebSocket"
EXEC_OWNER="$(api GET /api/me | jq -er .owner)"
api GET /api/events | jq -e --arg node "$EXEC_NODE" --arg owner "$EXEC_OWNER" \
  'any(.events[]; .kind == "container_exec" and .region == "gru" and
    (.detail | .by == $owner and .nodeId == $node and .service == "e2e-web" and (.container | length > 0) and .command == "echo"))' \
  >/dev/null || die "exec did not audit the operator, container and executable with arguments redacted"
ok "ts-orch exec round-tripped"
timeout 60 "${TS[@]}" logs e2e-web --node "$EXEC_NODE" --tail 5 > "$LOGS/logs-fake.txt"
grep -q "simulated log line from $EXEC_NODE" "$LOGS/logs-fake.txt" || die "ts-orch logs did not stream node log chunks"
ok "ts-orch logs streamed node output"

log "5e. Disk >75% sustained 5 minutes (backfilled history) -> OCI UpdateVolume"
volume_grown() { curl -sf "$OCI/_mock/state" | jq -e --arg id "$VOLUME_ID" '.volumes[$id] == 100 and ([.calls[] | select(.operation == "UpdateVolume" and .target == $id)] | length >= 1)' >/dev/null; }
wait_for "oci-mock recorded UpdateVolume(100 GB) for $VOLUME_ID" 60 volume_grown
grow_seen() { grep -q '"type":"grow_volume"' "$WORK/fake-s1.jsonl"; }
wait_for "$STATEFUL_NODE received grow_volume" 60 grow_seen
grown_event() {
  api GET /api/events | jq -e --arg node "$STATEFUL_NODE" \
    'any(.events[]; .kind == "volume_grown" and .subject == $node and .detail.newSizeGiB == "97")' >/dev/null
}
wait_for "volume_grown recorded for $STATEFUL_NODE at 97 GiB usable ext4" 60 grown_event
resynced() { jq -se 'any(.[]; .type == "sync_tls" and .connection == 2)' "$WORK/fake-s1.jsonl" >/dev/null; }
wait_for "$STATEFUL_NODE reconnected after a duplicate 97 GiB volume_grown and received sync_tls" 60 resynced
jq -se '[.[] | select(.type == "grow_volume")] | length == 1' "$WORK/fake-s1.jsonl" >/dev/null ||
  die "grow_volume was replayed on reconnect after a 97 GiB ext4 report for a 100 GiB target"
api GET /api/events | jq -e --arg node "$STATEFUL_NODE" \
  '[.events[] | select(.kind == "volume_grown" and .subject == $node)] | length == 1' >/dev/null ||
  die "duplicate volume_grown(97) was recorded more than once for $STATEFUL_NODE"
ok "volume grow cleared within ext4 overhead tolerance and survived a duplicate report and reconnect"

log "5f. Node drain"
"${TS[@]}" node drain e2e-w1 > "$LOGS/drain-fake.txt"
wait_for "e2e-w1 drained" 90 node_is e2e-w1 drained

if [[ $DOCKER -eq 0 ]]; then
  log "Docker is not available: skipping the real agent blue/green phase"
  log "E2E PASSED (backplane, Atlas, edge, CLI, MCP, chaos)"
  exit 0
fi

log "6. Real ts-orch agent + edge against Docker"
"${TS[@]}" service rm e2e-web > "$LOGS/service-rm.txt"
for pid in "${GROUPS_TO_STOP[@]}"; do
  if grep -qs "fake-node" "/proc/$pid/cmdline"; then kill -TERM -- "-$pid" 2>/dev/null || true; fi
done
chaos "$(jq -cn --arg id "$STATEFUL_NODE" '{kind: "kill_node", nodeId: $id}')" >/dev/null
chaos '{"kind":"kill_node","nodeId":"e2e-w1"}' >/dev/null
wait_for "simulated nodes are down" 30 node_is e2e-w1 down
mkdir -p "$WORK/agent/run" "$WORK/agent/state" "$WORK/agent/install" "$WORK/agent/data"
TS_ORCH_RUNTIME_DIR="$WORK/agent/run" TS_ORCH_EDGE_BIND=127.0.0.1 TS_ORCH_EDGE_HTTP_PORT="$AG_HTTP" \
  TS_ORCH_EDGE_HTTPS_PORT="$AG_HTTPS" TS_ORCH_EDGE_POSTGRES_PORT="$AG_PG" \
  TS_ORCH_EDGE_INTERNAL_TERRABASE_PORT=0 TS_ORCH_EDGE_INTERNAL_PLATFORM_PORT=0 \
  TS_ORCH_EDGE_DRAIN_SECONDS=2 TS_ORCH_EDGE_SHUTDOWN_SECONDS=5 TS_ORCH_EDGE_HTTP3=false \
  spawn agent-edge "$WORK" "${TS[@]}" edge
TS_ORCH_BACKPLANE_URL="$W" TS_ORCH_STATE_DIR="$WORK/agent/state" TS_ORCH_RUNTIME_DIR="$WORK/agent/run" \
  TS_ORCH_INSTALL_DIR="$WORK/agent/install" TS_ORCH_DOCKER_SOCKET="$DOCKER_SOCKET" \
  TS_ORCH_DATA_VOLUME="$WORK/agent/data" TS_ORCH_ENROLL_SECRET_VAULT="$VAULT_ID" \
  TS_ORCH_ENROLL_SECRET_NAME=e2e-node-enroll TS_ORCH_NODE_ID=e2e-agent TS_ORCH_REGION=gru \
  TS_ORCH_POOL_KIND=worker TS_ORCH_VCN_IP=127.0.0.1 TS_ORCH_LABEL_PREFIX="$DOCKER_PREFIX" \
  TS_ORCH_CGROUP_PARENT=false TS_ORCH_HEARTBEAT_SECONDS=3 \
  spawn agent "$WORK" "${TS[@]}" agent
wait_for "real agent enrolled via mock Vault and is active" 90 node_is e2e-agent active
wait_for "agent wrote shared TLS for its edge" 60 test -s "$WORK/agent/run/tls/cert.pem"
jq -n --arg vault "$VAULT_ID" '{
  name: "e2e-box", mode: "replicated", priority: "normal", image: "busybox:1.36.1", regions: ["gru"],
  replicas: 1, minReplicas: 1, maxReplicas: 1, cpuRequestMilli: 50, cpuLimitMilli: 250,
  memRequestMiB: 32, memLimitMiB: 64, pidsLimit: 64, port: 8097, readyPath: "/readyz",
  readyTimeoutSeconds: 60, hostnames: ["box.localhost"], env: {},
  secrets: {E2E_TOKEN_FILE: {vault: $vault, name: "e2e-box-token"}}, mounts: [], udpPorts: [],
  args: ["sh", "-c", "mkdir -p /www && echo ok > /www/readyz && echo e2e-box > /www/index.html && exec httpd -f -v -p 8097 -h /www"]
}' > "$WORK/e2e-box.json"
"${TS[@]}" service apply -f "$WORK/e2e-box.json" > "$LOGS/service-apply.txt"
box_served() { curl -sf --max-time 5 -H "Host: box.localhost" "http://127.0.0.1:$AG_HTTP/" | grep -q "e2e-box"; }
wait_for "e2e-box container served through ts-orch edge" 180 box_served
box_container() { docker ps --filter "name=^${DOCKER_PREFIX}-" --format '{{.Names}}' | sort | head -n 1; }
FIRST_CONTAINER="$(box_container)"
[[ -n "$FIRST_CONTAINER" ]] || die "no e2e-box container is running"
ok "container $FIRST_CONTAINER is live"

touch "$WORK/probe.txt"
(
  while [[ ! -e "$WORK/probe.stop" ]]; do
    curl -s -o /dev/null -w '%{http_code}\n' --max-time 5 -H "Host: box.localhost" "http://127.0.0.1:$AG_HTTP/" >> "$WORK/probe.txt" || printf '000\n' >> "$WORK/probe.txt"
    sleep 0.2
  done
) &
PLAIN_PIDS+=("$!")
PROBE_PID=$!
timeout 300 "${TS[@]}" deploy e2e-box busybox:1.37.0 --region gru --wait > "$LOGS/deploy-box.txt" || die "busybox:1.37.0 rollout did not succeed"
box_on() { api GET /api/status | jq -e --arg image "$1" '[.placements[] | select(.serviceName == "e2e-box" and .state == "ready")] | length >= 1 and all(.activeImage == $image)' >/dev/null; }
wait_for "e2e-box runs busybox:1.37.0" 60 box_on busybox:1.37.0
curl -sf -X POST "$OCI/_mock/secrets/e2e-box-token/bump" >/dev/null
PRE_ROTATION="$(box_container)"
"${TS[@]}" secrets refresh e2e-box > "$LOGS/secrets-refresh-box.txt"
rotated() { local current; current="$(box_container)"; [[ -n "$current" && "$current" != "$PRE_ROTATION" ]] && box_served; }
wait_for "secret rotation triggered a blue/green container swap" 120 rotated
sleep 2
touch "$WORK/probe.stop"
wait "$PROBE_PID"
TOTAL="$(wc -l < "$WORK/probe.txt")"
FAILED="$(grep -vc '^200$' "$WORK/probe.txt" || true)"
cp "$WORK/probe.txt" "$LOGS/probe.txt"
(( TOTAL >= 20 )) || die "zero-downtime probe only sent $TOTAL requests"
[[ "$FAILED" == "0" ]] || die "zero-downtime probe saw $FAILED non-200 responses out of $TOTAL"
ok "zero-downtime: $TOTAL requests through two blue/green swaps, 0 failures"

timeout 60 "${TS[@]}" logs e2e-box --node e2e-agent --tail 20 > "$LOGS/logs-box.txt"
[[ -s "$LOGS/logs-box.txt" ]] || die "ts-orch logs returned nothing for e2e-box"
ok "ts-orch logs streamed container output"
timeout 60 "${TS[@]}" exec e2e-agent e2e-box -- cat /www/readyz > "$LOGS/exec-box.txt"
grep -qx "ok" "$LOGS/exec-box.txt" || die "ts-orch exec did not run inside the container"
ok "ts-orch exec ran inside the container"
"${TS[@]}" node drain e2e-agent > "$LOGS/drain-agent.txt"
wait_for "e2e-agent drained" 120 node_is e2e-agent drained

log "E2E PASSED (backplane, Atlas, edge, CLI, MCP, chaos, real Docker agent)"
