import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env";

export class AtlasDO extends DurableObject<Env> {
  override async fetch(_request: Request): Promise<Response> {
    return Response.json({ error: { code: "unavailable", message: "AtlasDO is not implemented yet" } }, { status: 503 });
  }
}
