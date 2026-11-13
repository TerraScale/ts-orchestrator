package app

import (
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

const runtimeWorkerTransportFilename = "host-runtime-worker.json"

type runtimeWorkerBinding struct {
	Query   swarmruntime.WorkerRegistrationQuery `json:"query"`
	Binding hostenroll.SwarmNodeBinding          `json:"binding"`
}
