package bootstrapstart

import (
	"context"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"time"
)

// PublicSource reads this exact founder's public source inventory through the
// same authenticated OCI provider; it never opens founder escrow.
func (proof VerifiedSourceFounder) PublicSource(ctx context.Context) (bootstrap.VerifiedRegionalSource, error) {
	if err := proof.VerifyCurrent(ctx); err != nil {
		return bootstrap.VerifiedRegionalSource{}, err
	}
	objects, err := proof.factory.ObjectStorage()
	if err != nil {
		return bootstrap.VerifiedRegionalSource{}, err
	}
	return bootstrap.LoadRegionalSource(ctx, proof.template, &objects, time.Now().UTC())
}
