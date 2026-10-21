package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

func provisionOriginalFoundationFromFile(ctx context.Context, args []string, out io.Writer) error {
	factory, roots, bundle, schema, err := region.ReadOriginalFoundationProvision(ctx, args)
	if err != nil {
		return err
	}
	lowerErr := region.ProvisionOriginalFoundationPrerequisites(ctx, factory, roots, bundle)
	if schema == 3 {
		// Each stage authenticates its own retained and current prerequisites.
		// A lower error is neither success nor authority for a later stage.
		managerErr := region.ProvisionOriginalNetBirdFoundation(ctx, factory, roots, bundle)
		sourceIAMErr := region.ProvisionOriginalFoundationSourceIAM(ctx, factory, roots, bundle)
		issuerErr := foundation.EnsureOriginalNetBirdPullCredentials(ctx, factory, roots, bundle)
		if err := errors.Join(lowerErr, managerErr, sourceIAMErr, issuerErr); err != nil {
			return err
		}
	} else if lowerErr != nil {
		return lowerErr
	}
	_, err = fmt.Fprintln(out, "provisioned exact signed foundation footprint")
	return err
}
