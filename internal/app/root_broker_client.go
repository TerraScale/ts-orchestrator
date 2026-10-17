package app

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootociwire"
)

func openControllerClientRuntime(ctx context.Context, cfg Config, _ func() error) (*natscell.Runtime, error) {
	if ctx == nil || ctx.Err() != nil || cfg.NATS.Embedded == nil {
		return nil, rootoci.ErrUnauthorized
	}
	probe, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	connection, err := new(net.Dialer).DialContext(probe, "unix", rootBrokerStartupSocket)
	if err != nil {
		return nil, err
	}
	socket, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, rootoci.ErrUnauthorized
	}
	peer, err := rootociwire.PeerCredential(socket)
	if err != nil || peer.UID != 0 || peer.GID != 0 {
		_ = socket.Close()
		return nil, rootoci.ErrUnauthorized
	}
	witness, err := rootoci.CaptureProcess(peer.PID)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	defer witness.Close()
	binding, err := rootBrokerPeerBinding(socket, witness, rootBrokerStartupSocket)
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	stop := context.AfterFunc(probe, func() { _ = socket.Close() })
	dialer := &rootControllerDialer{ctx: ctx, address: net.JoinHostPort(cfg.NATS.Embedded.Host, fmt.Sprint(cfg.NATS.Embedded.Port)), rootBinding: witness.Binding(), initial: socket}
	runtime, err := natscell.StartRootControllerClient(probe, cfg.NATS, dialer)
	stop()
	if err != nil {
		_ = socket.Close()
		return nil, err
	}
	current, err := rootBrokerPeerBinding(socket, witness, rootBrokerStartupSocket)
	if err != nil || binding != current || probe.Err() != nil {
		_ = runtime.Close()
		return nil, rootoci.ErrUnauthorized
	}
	return runtime, nil
}
