//go:build fixturetest

package swarmruntime

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/moby/swarmkit/v2/agent/exec"
)

// StartAcceptedRootNodeFixture retains the actual root service, home IAM and
// original protected creation permit while isolating the local runtime state.
func StartAcceptedRootNodeFixture(ctx context.Context, stateDir string,
	reader *bootstrapstart.CurrentFounderAuthorityReader, accepted bootstrapstart.AcceptedIdentity,
	foundations region.FoundationResolver, vault vaultsecret.VaultClient, bundles vaultsecret.BundleClient,
	executor exec.Executor, observer *bootstrapstart.OCIInstanceObserver, hostEnrollment []byte,
	root *rootoci.Service, permit *region.RuntimeCreationPermit,
) (*Node, error) {
	if ctx == nil || root == nil || permit == nil {
		return nil, errors.New("root manager fixture requires concrete root, home IAM and original creation authority")
	}
	homeIAM, err := permit.GuardedHomeIAM(ctx)
	if err != nil {
		return nil, err
	}
	client, err := root.RootClient(ctx)
	if err != nil {
		return nil, err
	}
	if err := client.Close(); err != nil {
		return nil, err
	}
	return startAcceptedNodeFixture(ctx, stateDir, reader, accepted, foundations, vault, bundles, executor, observer, hostEnrollment, root, homeIAM, permit)
}
