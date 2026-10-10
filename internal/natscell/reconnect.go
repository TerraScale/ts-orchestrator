package natscell

import (
	"context"
	"errors"
	"fmt"

	"github.com/nats-io/nats-server/v2/server"
)

// ReconnectInterRegion kicks connected leaves of the link account, the pinned
// interregion account or, under a link, the cell account, without touching
// regional routes, clients or JetStream. NATS retains the
// existing TLS/account configuration and native retries; inbound leaves rely on
// the peer's retry. The count reports successful kicks, not recovered links.
// With no connected leaves it returns ErrUnavailable and leaves native retries
// running. Callers must probe the authenticated contract again to verify recovery.
func (r *Runtime) ReconnectInterRegion(ctx context.Context) (int, error) {
	if ctx == nil {
		return 0, errors.New("interregion reconnect requires a context")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if r == nil || r.server == nil {
		return 0, errors.New("interregion reconnect requires an embedded broker")
	}
	if !r.server.Running() {
		return 0, ErrEmbeddedServerStopped
	}
	if r.resolver == nil || r.resolver.interregion == "" {
		return 0, errors.New("interregion reconnect requires a pinned link account")
	}
	leafz, err := r.server.Leafz(&server.LeafzOptions{Account: r.resolver.interregion})
	if err != nil {
		return 0, fmt.Errorf("inspect interregion leaves: %w", err)
	}
	if len(leafz.Leafs) == 0 {
		return 0, fmt.Errorf("%w: no connected interregion leaves; native retries continue", ErrUnavailable)
	}
	kicked := 0
	var failures error
	for _, leaf := range leafz.Leafs {
		if err := ctx.Err(); err != nil {
			return kicked, errors.Join(failures, err)
		}
		if !r.server.Running() {
			return kicked, errors.Join(failures, ErrEmbeddedServerStopped)
		}
		if err := r.server.DisconnectClientByID(leaf.ID); err != nil {
			failures = errors.Join(failures, fmt.Errorf("disconnect interregion leaf %d: %w", leaf.ID, err))
			continue
		}
		kicked++
	}
	return kicked, failures
}
