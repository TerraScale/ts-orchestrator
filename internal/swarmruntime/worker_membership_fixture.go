//go:build fixturetest

package swarmruntime

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
)

// ReadWorkerMembershipFixture substitutes only the service-account child route.
// The concrete source and the production current-authority verifier still run.
func (n *Node) ReadWorkerMembershipFixture(ctx context.Context, nodeID string, source *hostenroll.WorkerMembershipSource) (VerifiedWorkerMembership, error) {
	if source == nil {
		return VerifiedWorkerMembership{}, errors.New("worker membership fixture requires the concrete ordered source")
	}
	return n.readWorkerMembership(ctx, nodeID, source)
}
