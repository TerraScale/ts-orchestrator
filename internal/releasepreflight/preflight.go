package releasepreflight

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func Run(ctx context.Context) error {
	return vaultsecret.CheckServiceSecrets(ctx)
}
