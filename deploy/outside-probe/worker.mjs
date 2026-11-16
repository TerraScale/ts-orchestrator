import { DurableObject } from "cloudflare:workers";
import { connect } from "cloudflare:sockets";
import inventory from "../m1/regions.json" with { type: "json" };

const minute = 60_000;
const window = 10 * minute;
const regions = inventory.map(({ region }) => region);
const targets = [
  ["api", "api"], ["dash", "dash"], ["auth", "auth"], ["pg", "pg"],
  ...regions.flatMap(region => [[`${region}.api`, "api", region], [`${region}.pg`, "pg", region]]),
];

async function body(response, limit) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let bytes = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) return text + decoder.decode();
      bytes += chunk.value.byteLength;
      if (bytes > limit) throw new Error("body limit");
      text += decoder.decode(chunk.value, { stream: true });
    }
  } finally {
    await reader.cancel();
  }
}

async function request(url, options = {}, limit = 65_536) {
  const response = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(5_000), ...options });
  const text = await body(response, limit);
  if (response.status !== 200) throw new Error(`status ${response.status}`);
  return text;
}

async function endpoint([name, kind, region]) {
  const host = `${name}.terrascale.tech`;
  try {
    if (kind === "pg") {
      const socket = connect({ hostname: host, port: 5432 }, { secureTransport: "on" });
      try {
        const signal = AbortSignal.timeout(3_000);
        await Promise.race([socket.opened, new Promise((_, reject) => {
          signal.addEventListener("abort", () => reject(new Error("TLS deadline")), { once: true });
        })]);
      } finally {
        await socket.close();
      }
    } else {
      const value = JSON.parse(await request(`https://${host}/readyz`, { signal: AbortSignal.timeout(3_000) }, 16_384));
      const ready = kind === "dash"
        ? value.status === "ok" && value.dependencies?.["ts-auth"] === "ok" && value.dependencies?.terrabase === "ok"
        : value.status === "ready" && (kind === "auth" || regions.includes(value.region) && (!region || value.region === region));
      if (!ready) return { key: host, reason: "not ready" };
    }
    return { key: host, reason: "" };
  } catch {
    return { key: host, reason: "unreachable or invalid response" };
  }
}

async function heartbeat(secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("terrascale-alert-delivery-probe-v1")));
  const topic = "ts-probe-" + btoa(String.fromCharCode(...signature)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  try {
    const text = await request(`https://ntfy.sh/${topic}/json?poll=1&since=latest`);
    const messages = text.split("\n").filter(Boolean).map(line => JSON.parse(line));
    const newest = Math.max(0, ...messages.filter(m => m.event === "message" && m.topic === topic && m.time > 0).map(m => m.time * 1_000));
    return { key: "monitoring heartbeat", reason: newest === 0 ? "missing" : Date.now() - newest >= window ? "stale" : "", newest };
  } catch {
    return { key: "monitoring heartbeat", reason: "unreadable", newest: 0 };
  }
}

async function publish(secret, title, priority, message) {
  try {
    const text = await request(`https://ntfy.sh/${secret}`, { method: "POST", headers: { Title: title, Priority: priority }, body: message });
    const result = JSON.parse(text);
    if (!result.id || result.event !== "message" || result.topic !== secret || result.message !== message) throw new Error("push rejected");
  } catch {
    throw new Error("push delivery failed");
  }
}

export class Probe extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.ctx = ctx;
    this.env = env;
    ctx.blockConcurrencyWhile(async () => {
      if (!await ctx.storage.get("state")) {
        const now = Date.now();
        await ctx.storage.put("state", { open: {}, runs: [], reported: now });
        await ctx.storage.setAlarm(now + window);
      }
    });
  }

  async notify(state, outcomes, now) {
    const current = outcomes.filter(item => item.reason);
    const checked = new Set(outcomes.map(item => item.key));
    const next = Object.fromEntries(Object.entries(state.open).filter(([key]) => !checked.has(key)));
    const pages = [];
    const recovered = [];
    for (const item of current) {
      const prior = state.open[item.key];
      const entry = { since: prior?.since ?? now, paged: prior?.paged ?? 0 };
      next[item.key] = entry;
      const confirmed = item.key === "outside probe" || item.key === "monitoring heartbeat" && item.newest > 0
        ? now - (item.key === "outside probe" ? state.reported : item.newest) >= window
        : prior && now - entry.since >= (item.key === "monitoring heartbeat" ? window : 4 * minute);
      if (confirmed && (!entry.paged || now - entry.paged >= 30 * minute)) pages.push(item);
    }
    for (const [key, entry] of Object.entries(state.open)) {
      if (checked.has(key) && !next[key] && entry.paged) recovered.push(key);
    }
    if (pages.length) {
      await publish(this.env.TS_ALERTS_NTFY_TOPIC, "TerraScale outside probe", "urgent", pages.map(item => `${item.key}: ${item.reason}`).join("\n"));
      for (const item of pages) next[item.key].paged = Date.now();
      state.open = { ...state.open, ...next };
      await this.ctx.storage.put("state", state);
    }
    if (recovered.length) await publish(this.env.TS_ALERTS_NTFY_TOPIC, "TerraScale outside probe recovered", "default", recovered.join("\n"));
    state.open = next;
  }

  async run(scheduled) {
    return this.ctx.blockConcurrencyWhile(async () => {
      const secret = this.env.TS_ALERTS_NTFY_TOPIC;
      if (!/^[A-Za-z0-9_-]{43,64}$/.test(secret ?? "")) throw new Error("TS_ALERTS_NTFY_TOPIC missing or invalid");
      const started = Date.now();
      const state = await this.ctx.storage.get("state") ?? { open: {}, runs: [], reported: started };
      if (state.runs.some(run => run.scheduled === scheduled)) return;
      const outcomes = await Promise.all([...targets.map(endpoint), heartbeat(secret), { key: "outside probe", reason: "" }]);
      const completed = Date.now();
      const sample = { scheduled, started, completed, outcomes };
      state.reported = completed;
      state.runs = [...state.runs, sample].slice(-24);
      await this.ctx.storage.put("state", state);
      await this.notify(state, outcomes, completed);
      await this.ctx.storage.put("state", state);
      await this.ctx.storage.setAlarm(completed + window);
      console.log(JSON.stringify(sample));
    });
  }

  async alarm() {
    await this.ctx.blockConcurrencyWhile(async () => {
      const state = await this.ctx.storage.get("state");
      if (!state) throw new Error("probe state missing");
      const now = Date.now();
      await this.ctx.storage.setAlarm(now + 5 * minute);
      if (now - state.reported >= window) {
        await this.notify(state, [{ key: "outside probe", reason: "no completed report for ten minutes" }], now);
        await this.ctx.storage.put("state", state);
      }
    });
  }

  async status() {
    return await this.ctx.storage.get("state") ?? { open: {}, runs: [], reported: 0 };
  }
}

export default {
  async scheduled(event, env) {
    await env.PROBE.getByName("outside").run(event.scheduledTime);
  },
  async fetch(request, env) {
    if (request.method !== "GET" || new URL(request.url).pathname !== "/") return new Response("Not found", { status: 404 });
    const state = await env.PROBE.getByName("outside").status();
    return Response.json(state, { headers: { "Cache-Control": "no-store" } });
  },
};
