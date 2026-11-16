package host

import (
	"context"
)

// Reader gives operator and placement callers a read-only host view without
// requiring the controller's private response signing key.
type Reader struct{ controller *Controller }

func (r *Reader) ListHosts(ctx context.Context) ([]HostStatus, error) {
	return r.controller.ListHosts(ctx)
}
