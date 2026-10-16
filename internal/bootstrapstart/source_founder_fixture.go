//go:build fixturetest

package bootstrapstart

import (
	"context"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// VerifySourceFounderWithSources substitutes offline metadata/provider protocol
// endpoints while retaining the production signed template, binary and identity checks.
func VerifySourceFounderWithSources(ctx context.Context, factory *ociclient.Factory, template bootstrap.VerifiedStartupTemplate, imds DescriptorSource, observer InstanceObserver) (VerifiedSourceFounder, error) {
	return verifySourceFounderWithSources(ctx, factory, template, imds, observer)
}
