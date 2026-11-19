package app

import (
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
)

// OciReconcileConfig carries signed resource amendments beside the always-on
// regional foundation. Its absence never disables foundation reconciliation.
type OciReconcileConfig struct {
	// PublicNLB keeps the public API NLB's backend set in step with the
	// RUNNING member hosts placement observes.
	PublicNLB *OciReconcileNLBConfig `json:"public_nlb,omitempty"`
	// PublicLB keeps the public API load balancer's TerraBase backend set
	// equal to the seats the signed terrabase profile names (TS-571).
	PublicLB *OciReconcileLBConfig `json:"public_lb,omitempty"`
	// Desired publishes desired specs listed in this controller
	// configuration (bound to the signed controller manifest on baked
	// controllers) into the protected foundation journal before every pass.
	Desired *cellspec.OCIDesired `json:"desired,omitempty"`
}

// OciReconcileNLBConfig names the NLB backend set synced to placement.
type OciReconcileNLBConfig struct {
	Name       string `json:"name"`
	NLBID      string `json:"nlb_id"`
	BackendSet string `json:"backend_set"`
	Port       int    `json:"port"`
}

// OciReconcileLBConfig names the L7 load balancer backend set synced to the
// TerraBase seats: every member TERRABASE_PEERS names, at the profile's
// client port. Its desired-state key is always lb.PublicTerraBase, the one
// public-api apply stamps ownership for.
type OciReconcileLBConfig struct {
	LoadBalancerID string `json:"load_balancer_id"`
	BackendSet     string `json:"backend_set"`
	// Seats limits the backends to these seats; empty means every seat.
	//
	// ponytail: gru-1 lists gru-1-db-1 only. Members serve diverging
	// catalogs until TS-561 replicates them; drop the list then.
	Seats []string `json:"seats,omitempty"`
}
