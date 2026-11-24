import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env";
import type { AtlasPlacement, AtlasPublishRequest, AtlasTopology } from "./protocol";

export const ATLAS_DO_NAME = "atlas";
export const TOPOLOGY_KEY = "topology";

export function placementKey(project: string, database: string): string {
  return `placement:${project}:${database}`;
}

export interface AtlasCacheRecord<T> {
  at: number;
  doc: T | null;
}

export function cacheRecord<T>(doc: T | null): AtlasCacheRecord<T> {
  return { at: Date.now(), doc };
}

export function atlasStub(env: Env): DurableObjectStub {
  return env.ATLAS_DO.get(env.ATLAS_DO.idFromName(ATLAS_DO_NAME), { locationHint: env.FLEET_DO_LOCATION_HINT });
}

type WriteResult = "updated" | "stale" | "skipped";

type TopologyRow = { updated: number; doc: string };
type PlacementRow = { project: string; database: string; region: string | null; version: number; updated_at: number };
type CountRow = { region: string; count: number };

export interface AtlasPublishResult {
  topology?: WriteResult;
  placements: { project: string; database: string; result: "updated" | "stale" }[];
}

export interface AtlasExport {
  topology: AtlasTopology | null;
  placements: AtlasPlacement[];
}

function failure(code: string, message: string, fix: string, status: number): Response {
  return Response.json({ error: { code, message, fix } }, { status });
}

export class AtlasDO extends DurableObject<Env> {
  private readonly sql: SqlStorage;
  private pending: Promise<void> = Promise.resolve();

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS topology (id INTEGER PRIMARY KEY CHECK (id = 1), updated INTEGER NOT NULL, doc TEXT NOT NULL)",
    );
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS db_placements (project TEXT NOT NULL, database TEXT NOT NULL, region TEXT, version INTEGER NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (project, database))",
    );
    this.sql.exec("CREATE INDEX IF NOT EXISTS db_placements_region ON db_placements (region)");
  }

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (request.method === "POST" && url.pathname === "/publish") return await this.publish(request);
      if (request.method === "GET" && url.pathname === "/topology") return Response.json(this.topology());
      if (request.method === "GET" && url.pathname === "/placement") {
        const project = url.searchParams.get("project") ?? "";
        const database = url.searchParams.get("database") ?? "";
        return Response.json(this.placement(project, database));
      }
      if (request.method === "GET" && url.pathname === "/counts") return Response.json({ counts: this.regionDatabaseCounts() });
      if (request.method === "GET" && url.pathname === "/export") return Response.json(this.exportState());
      return failure("not_found", "No such route", "Use an AtlasDO route.", 404);
    } catch (error) {
      console.error("atlas store request failed", error);
      return failure("store_unavailable", "The Atlas store failed", "Retry after the store recovers.", 502);
    }
  }

  topology(): AtlasTopology | null {
    const row = this.sql.exec<TopologyRow>("SELECT updated, doc FROM topology WHERE id = 1").toArray()[0];
    return row === undefined ? null : (JSON.parse(row.doc) as AtlasTopology);
  }

  placement(project: string, database: string): AtlasPlacement | null {
    const row = this.sql
      .exec<PlacementRow>(
        "SELECT project, database, region, version, updated_at FROM db_placements WHERE project = ? AND database = ?",
        project,
        database,
      )
      .toArray()[0];
    return row === undefined ? null : { v: 1, project, database, region: row.region, updated: row.version };
  }

  regionDatabaseCounts(): Record<string, number> {
    const counts: Record<string, number> = {};
    for (const row of this.sql
      .exec<CountRow>("SELECT region, COUNT(*) AS count FROM db_placements WHERE region IS NOT NULL GROUP BY region")
      .toArray()) {
      counts[row.region] = row.count;
    }
    return counts;
  }

  exportState(): AtlasExport {
    const placements = this.sql
      .exec<PlacementRow>("SELECT project, database, region, version, updated_at FROM db_placements ORDER BY project, database")
      .toArray()
      .map((row): AtlasPlacement => ({ v: 1, project: row.project, database: row.database, region: row.region, updated: row.version }));
    return { topology: this.topology(), placements };
  }

  private async publish(request: Request): Promise<Response> {
    const previous = this.pending;
    let release!: () => void;
    this.pending = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      const body = await request.json<AtlasPublishRequest>();
      const result: AtlasPublishResult = { placements: [] };
      const writes: Promise<void>[] = [];
      if (body.topology !== undefined) result.topology = this.writeTopology(body.topology, writes);
      for (const placement of body.placements ?? []) {
        result.placements.push({
          project: placement.project,
          database: placement.database,
          result: this.writePlacement(placement, writes),
        });
      }
      await Promise.all(writes);
      return Response.json(result);
    } catch (error) {
      console.error("atlas SQLite write failed", error);
      return failure(
        "store_unavailable",
        "The Atlas store refused the write",
        "Publish again; earlier items may have landed.",
        502,
      );
    } finally {
      release();
    }
  }

  private writeTopology(topology: AtlasTopology, writes: Promise<void>[]): WriteResult {
    const doc = JSON.stringify(topology);
    const stored = this.sql.exec<TopologyRow>("SELECT updated, doc FROM topology WHERE id = 1").toArray()[0];
    if (stored !== undefined && stored.updated >= topology.updated) {
      if (stored.updated === topology.updated && stored.doc === doc) {
        writes.push(this.refreshCache(TOPOLOGY_KEY, topology));
        return "skipped";
      }
      return "stale";
    }
    this.sql.exec(
      "INSERT INTO topology (id, updated, doc) VALUES (1, ?, ?) ON CONFLICT(id) DO UPDATE SET updated = excluded.updated, doc = excluded.doc",
      topology.updated,
      doc,
    );
    writes.push(this.refreshCache(TOPOLOGY_KEY, topology));
    return "updated";
  }

  private writePlacement(placement: AtlasPlacement, writes: Promise<void>[]): "updated" | "stale" {
    const { project, database, region, updated } = placement;
    const doc: AtlasPlacement = { v: 1, project, database, region, updated };
    const stored = this.sql
      .exec<PlacementRow>(
        "SELECT project, database, region, version, updated_at FROM db_placements WHERE project = ? AND database = ?",
        project,
        database,
      )
      .toArray()[0];
    if (stored !== undefined && stored.version >= updated) {
      if (stored.version === updated && stored.region === region) {
        writes.push(this.refreshCache(placementKey(project, database), doc));
        return "updated";
      }
      return "stale";
    }
    this.sql.exec(
      "INSERT INTO db_placements (project, database, region, version, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(project, database) DO UPDATE SET region = excluded.region, version = excluded.version, updated_at = excluded.updated_at",
      project,
      database,
      region,
      updated,
      Date.now(),
    );
    writes.push(this.refreshCache(placementKey(project, database), doc));
    return "updated";
  }

  private async refreshCache(key: string, doc: AtlasTopology | AtlasPlacement): Promise<void> {
    try {
      await this.env.ATLAS_KV.put(key, JSON.stringify(cacheRecord(doc)), { expirationTtl: 86_400 });
    } catch (error) {
      console.error("atlas KV refresh failed after SQLite accepted the write", error);
    }
  }
}
