//go:build fixturetest

package bootstrapstart

import (
	"context"
	"net/http"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

// VerifyRuntimeIAM verifies the fixture's current signed selection, running
// executable, instance principal, fixed IMDS fields and independently read OCI VM.
func (fixture *ControllerManagerStartupFixture) VerifyRuntimeIAM(ctx context.Context, factory *ociclient.Factory,
	imds IMDSClient, layout selfupdate.Layout,
) (VerifiedRuntimeIAM, error) {
	if fixture == nil || layout.Root == "" {
		return VerifiedRuntimeIAM{}, ErrSourceFounder
	}
	return verifyRuntimeIAMWithSources(ctx, fixture.Reader, fixture.Accepted, factory, fixture.Observer, imds,
		Gate{SelfUpdate: layout})
}

// NewIMDSClientWithHTTPClient substitutes the offline transport while retaining
// fixed IMDS endpoints and the production response checks.
func NewIMDSClientWithHTTPClient(client *http.Client) IMDSClient {
	return IMDSClient{client: client}
}
