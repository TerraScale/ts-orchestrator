import { bindings, defineConfig, defineWorker, exports, triggers } from "cf/config";

const worker = defineWorker({
  name: "ts-orchestrator-outside-probe",
  compatibilityDate: "2026-11-16",
  entrypoint: "./worker.mjs",
  workersDev: true,
  triggers: [triggers.scheduled({ schedule: "*/5 * * * *" })],
  env: {
    PROBE: bindings.durableObject({ worker: "ts-orchestrator-outside-probe", exportName: "Probe" }),
    TS_ALERTS_NTFY_TOPIC: bindings.secret(),
  },
  exports: { Probe: exports.durableObject({ storage: "sqlite" }) },
});

export default defineConfig({ worker });
