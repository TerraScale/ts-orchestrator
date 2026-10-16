package app

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
)

// Retry after enrollment or address changes; never delay the OCI control path.
func (n *netbirdRollout) meshListener(ctx context.Context) {
	n.meshListenerLoop(ctx, func() netip.Addr {
		addresses, _ := localNetBirdAddresses()
		return addresses[0]
	}, n.runtime.ListenNetBird, 2*time.Second)
}

func (n *netbirdRollout) meshListenerLoop(ctx context.Context, localAddress func() netip.Addr, listen func(netip.Addr) (net.Listener, error), interval time.Duration) {
	var listener net.Listener
	var bound netip.Addr
	defer func() {
		if listener != nil {
			_ = listener.Close()
		}
	}()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	last := ""
	for ctx.Err() == nil {
		address := localAddress()
		var err error
		if address != bound {
			if listener != nil {
				_ = listener.Close()
			}
			listener, bound = nil, netip.Addr{}
		}
		if address.IsValid() && listener == nil {
			listener, err = listen(address)
			if err == nil {
				bound = address
			}
		}
		if errors.Is(err, natscell.ErrBridgeClosed) {
			return
		}
		if err != nil && err.Error() != last {
			slog.WarnContext(ctx, "NetBird NATS listener held; retrying", "error", err)
		}
		last = ""
		if err != nil {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
