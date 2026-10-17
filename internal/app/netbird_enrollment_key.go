package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// readNetBirdSetupKey resolves only the current signed regional foundation.
func readNetBirdSetupKey(ctx context.Context, cfg netbird.Config) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	if cfg.Region != local.factory.Region() {
		return nil, errors.New("NetBird enrollment configuration differs from the observed OCI region")
	}
	local.foundations, err = region.DiscoverCurrentFoundation(ctx, local.factory)
	if err != nil {
		return nil, err
	}
	record, err := local.foundations.Resolve(ctx, local.cell)
	if err != nil {
		return nil, err
	}
	target, err := record.VaultTarget()
	if err != nil {
		return nil, err
	}
	bundles, err := vaultsecret.SecretsClient(local.factory)
	if err != nil {
		return nil, err
	}
	current, err := vaultsecret.ReadVersioned(ctx, bundles, target.VaultID, strings.ToLower(local.cell)+"-1-netbird-setup-key")
	if err != nil {
		return nil, err
	}
	// Resolve again after delivery so a withdrawn/replaced regional record cannot enroll.
	currentSource, err := region.DiscoverCurrentFoundation(ctx, local.factory)
	if err != nil {
		return nil, err
	}
	latest, err := currentSource.Resolve(ctx, local.cell)
	if err != nil {
		return nil, err
	}
	latestTarget, err := latest.VaultTarget()
	if err != nil || latest.OperationID != record.OperationID || latest.Generation != record.Generation || latestTarget != target {
		return nil, errors.New("NetBird regional enrollment foundation changed during delivery")
	}
	return netbird.ReadSetupKey(ctx, cfg.Region, current.SecretID)
}
