package app

import (
	"context"
	"log/slog"
	"time"
)

func (controller functionController) retireMaterial(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	count, err := controller.config.Material.Issuer.RetireExpiredFunctionMaterial(ctx)
	if count > 0 {
		slog.InfoContext(ctx, "expired function material retirement confirmed", "count", count)
	}
	return err
}
