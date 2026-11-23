import type { Env } from "./env";
import type { ErrorResponse } from "./protocol";

export { AtlasDO } from "./atlas-do";
export { FleetDO } from "./fleet-do";

const ATLAS_PATHS: ReadonlySet<string> = new Set(["/v1/discovery", "/v1/resolve", "/v1/keys", "/v1/publish"]);

function error(code: string, message: string, status: number): Response {
  const body: ErrorResponse = { error: { code, message } };
  return Response.json(body, { status, headers: { "Cache-Control": "no-store" } });
}

function atlasRequest(url: URL, env: Env): boolean {
  return url.hostname === env.ATLAS_HOST || (env.LOCAL_DEV === "true" && url.pathname.startsWith("/atlas/"));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (atlasRequest(url, env)) {
      const path = url.hostname === env.ATLAS_HOST ? url.pathname : url.pathname.slice("/atlas".length);
      if (!ATLAS_PATHS.has(path)) return error("not_found", "Not found", 404);
      return error("unavailable", "Atlas is not implemented yet", 503);
    }
    if (url.hostname !== env.ORCH_HOST && env.LOCAL_DEV !== "true") return error("not_found", "Not found", 404);
    return error("unavailable", "The orchestrator backplane is not implemented yet", 503);
  },

  async scheduled(_controller: ScheduledController, _env: Env, _ctx: ExecutionContext): Promise<void> {},
} satisfies ExportedHandler<Env>;
