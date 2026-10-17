//go:build linux && fixturetest

package swarmruntime

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

// RetireControllerManagerNativeFixture exercises the private native consumer.
// It provides no installed-source, leaseholder or public-forwarding coverage.
func (n *Node) RetireControllerManagerNativeFixture(ctx context.Context, proof *bootstrapstart.ManagerRetirement, nodeID string, version, epoch uint64) (*ManagerRetirementResult, error) {
	return n.retireControllerManager(ctx, proof, nodeID, version, epoch, nil)
}
