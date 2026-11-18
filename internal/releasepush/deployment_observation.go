package releasepush

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
)

type DeploymentTask struct {
	Image    string `json:"image"`
	Host     string `json:"host"`
	Revision string `json:"revision"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
}

type AppDeployment struct {
	Complete bool             `json:"complete"`
	Replicas uint64           `json:"replicas"`
	Tasks    []DeploymentTask `json:"tasks"`
	Host     string           `json:"host"`
	Reason   string           `json:"reason,omitempty"`
	Error    string           `json:"error,omitempty"`
	Failed   bool             `json:"failed"`
}

type DeploymentObservation struct {
	Targets map[string]DeploymentTarget `json:"targets"`
	Region  string                      `json:"region"`
	Host    string                      `json:"host"`
	Hosts   []HostVersion               `json:"hosts"`
	Apps    map[string]AppDeployment    `json:"apps"`
	Pull    json.RawMessage             `json:"pull"`
	Error   string                      `json:"error,omitempty"`
}

type DeploymentTarget struct {
	Seq         uint64    `json:"seq"`
	Attempt     uint64    `json:"attempt"`
	Image       string    `json:"image"`
	Revision    string    `json:"revision"`
	RunID       string    `json:"run_id"`
	PublishedAt time.Time `json:"published_at"`
	Error       string    `json:"error,omitempty"`
}

func (h *Handler) observeDeployments(ctx context.Context, w http.ResponseWriter) {
	if h.Deployments == nil {
		http.Error(w, "deployment observation unavailable", http.StatusServiceUnavailable)
		return
	}
	report, err := h.Deployments(ctx)
	if err != nil {
		report.Error = secretpreflight.Scrub(err.Error())
	}
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(report)
}
