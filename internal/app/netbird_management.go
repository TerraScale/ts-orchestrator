package app

import (
	"context"
	"errors"
	"log"
	"maps"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
)

// netbirdManagementLoop returns the loop through which the controller holding
// cell authority reconciles the NetBird manager, or nil and the reason the
// feature is off. It is off unless the image's public netbird.json names the
// admin PAT secret, so deployments without the secret keep working.
func netbirdManagementLoop(path string, leader func() bool) (*manager.Loop, string) {
	cfg, err := netbird.LoadControllerConfig(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, "no public NetBird configuration"
	case err != nil:
		return nil, err.Error()
	case cfg.AdminPATSecretID == "":
		return nil, "admin_pat_secret_id is not configured"
	}
	// The desired state is cell gru-1's: another cell's controller would
	// reconcile, and prune, its servers.
	desired := manager.GRU()
	if cfg.Region != desired.Region {
		return nil, "no desired NetBird state for region " + cfg.Region
	}
	if !maps.Equal(cfg.PeerNames, desired.PeerNames()) {
		return nil, "peer_names do not match the desired NetBird cell " + desired.Cell
	}
	return &manager.Loop{
		Leader:        leader,
		Token:         func(ctx context.Context) ([]byte, error) { return netbird.ReadAdminPAT(ctx, cfg) },
		ManagementURL: cfg.ManagementURL,
		Desired:       desired,
		Logf:          log.Printf,
	}, ""
}

// runNetBirdManagement runs until ctx ends. It is not a controller worker:
// it never reports an error, so NetBird trouble cannot stop the controller.
func runNetBirdManagement(ctx context.Context, path string, leader func() bool) {
	loop, reason := netbirdManagementLoop(path, leader)
	if loop == nil {
		log.Printf("NetBird manager reconciliation disabled: %s", reason)
		return
	}
	log.Printf("NetBird manager reconciliation enabled on the cell authority holder")
	loop.Run(ctx)
}
