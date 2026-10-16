package app

import (
	"context"
	"log"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func netbirdManagementLoop(control authority.Fencer) manager.Loop {
	return manager.Automatic(control, func(ctx context.Context) (vaultsecret.Ref, error) {
		local, err := foundationDiscovery(ctx)
		if err != nil {
			return vaultsecret.Ref{}, err
		}
		foundation, err := local.foundations.Resolve(ctx, "GRU")
		if err != nil {
			return vaultsecret.Ref{}, err
		}
		target, err := foundation.VaultTarget()
		if err != nil {
			return vaultsecret.Ref{}, err
		}
		return vaultsecret.Ref{Vault: target.VaultID, Name: "gru-1-netbird-admin-pat"}, nil
	}, log.Printf)
}

// Foundation and Vault outages are retried without stopping the regional broker.
func runNetBirdManagement(ctx context.Context, control authority.Fencer) {
	netbirdManagementLoop(control).Run(ctx)
}
