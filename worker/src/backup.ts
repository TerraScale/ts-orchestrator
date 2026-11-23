export interface NightlySnapshot {
  exportedAt: string;
  fleet: unknown;
  atlas: unknown;
}

export function backupKey(exportedAt: string, fallbackMs = Date.now()): string {
  const parsed = Date.parse(exportedAt);
  const ms = Number.isFinite(parsed) ? parsed : fallbackMs;
  const day = new Date(ms).toISOString().slice(0, 10);
  return `backups/${day}/snapshot-${ms}.json`;
}

export async function writeNightlyBackup(bucket: R2Bucket, snapshot: NightlySnapshot): Promise<string> {
  const key = backupKey(snapshot.exportedAt);
  await bucket.put(key, JSON.stringify(snapshot), {
    httpMetadata: { contentType: "application/json" },
    customMetadata: { exportedAt: snapshot.exportedAt },
  });
  return key;
}
