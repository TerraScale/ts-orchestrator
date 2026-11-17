package app

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
	"github.com/moby/swarmkit/v2/api"
)

func replicaTelemetryAddress(node *api.Node) (string, error) {
	const path = "/run/ts-orch-observability/storage.json"
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if time.Since(info.ModTime()) > 15*time.Second || node.Description == nil {
		return "", errors.New("regional telemetry discovery is stale")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var targets []swarmruntime.SLOTarget
	if err := json.Unmarshal(data, &targets); err != nil {
		return "", err
	}
	for _, target := range targets {
		if target.Labels["host"] == node.Description.Hostname && len(target.Targets) == 1 {
			host, _, err := net.SplitHostPort(target.Targets[0])
			return host, err
		}
	}
	return "", errors.New("regional node has no discovered telemetry address")
}

type AutoscaleConfig struct {
	Services []workload.ServiceSpec `json:"services,omitempty"`
}
