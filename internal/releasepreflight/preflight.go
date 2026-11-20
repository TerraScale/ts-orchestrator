package releasepreflight

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func Run(ctx context.Context) error {
	if err := vaultsecret.CheckServiceSecrets(ctx); err != nil {
		return err
	}
	return pairUnit(ctx)
}

func Secrets(ctx context.Context) error {
	return vaultsecret.CheckRegionalSecrets(ctx)
}
