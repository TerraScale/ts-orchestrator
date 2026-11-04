package app

import (
	"context"
	"errors"
)

func fixtureManagedNativeAuthority(cell, environment string) managedNativeAdmissionAuthority {
	return func(ctx context.Context, requestedCell, requestedEnvironment string) error {
		if requestedCell != cell || requestedEnvironment != environment {
			return errors.New("fixture native lineage differs from the independent cell and environment")
		}
		return ctx.Err()
	}
}
