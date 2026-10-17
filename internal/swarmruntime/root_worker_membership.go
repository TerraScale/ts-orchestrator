package swarmruntime

import (
	"context"
	"errors"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
)

// ReadRootWorkerMembership uses root's concrete ordered registration source.
func (n *Node) ReadRootWorkerMembership(ctx context.Context, nodeID string, source *hostenroll.WorkerMembershipSource) (VerifiedWorkerMembership, error) {
	if os.Geteuid() != 0 || ctx == nil || source == nil {
		return VerifiedWorkerMembership{}, errors.New("root worker membership requires a concrete root source")
	}
	return n.readWorkerMembership(ctx, nodeID, source)
}
