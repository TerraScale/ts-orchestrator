package seatrollout

import (
	"context"

	"github.com/TerraScale/ts-orchestrator/internal/host"
)

// Hosts reads desired state and host reports.
type Hosts interface {
	ListHosts(ctx context.Context) ([]host.HostStatus, error)
	ListDesired(ctx context.Context, role string) ([]host.Desired, error)
}
