export interface Env {
  FLEET_DO: DurableObjectNamespace;
  ATLAS_DO: DurableObjectNamespace;
  ATLAS_KV: KVNamespace;
  FLEET_BACKUPS: R2Bucket;
  FLEET_DO_LOCATION_HINT: DurableObjectLocationHint;
  ORCH_HOST: string;
  ATLAS_HOST: string;
  LOCAL_DEV: string;
}
