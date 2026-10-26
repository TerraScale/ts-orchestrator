package edge

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func (e *Edge) runListener(ctx context.Context, protocol string) {
	address := map[string]string{"http": ":80", "https": ":443", "postgres": ":5432", "wire": ":7464"}[protocol]
	for ctx.Err() == nil {
		observability.SetEdgeListenerReady(protocol, false)
		var err error
		if protocol == "wire" {
			err = e.wireFirewall(ctx, false)
			if err == nil && !e.wireReady(ctx) {
				err = errors.New("private TerraBase wire listener not ready")
			}
		}
		if err == nil {
			var ln net.Listener
			ln, err = e.listen("tcp", address)
			if err == nil {
				err = e.serveListener(ctx, protocol, ln)
			}
		}
		if ctx.Err() != nil {
			return
		}
		slog.WarnContext(ctx, "edge listener unavailable; other protocols keep serving", "protocol", protocol, "error", err)
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (e *Edge) serveListener(ctx context.Context, protocol string, ln net.Listener) error {
	// Withdraw public admission before releasing the socket, including on
	// backend loss, so a legacy native listener cannot inherit an open port.
	stop := func() {
		if protocol == "wire" {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := e.wireFirewall(cleanup, false); err != nil {
				slog.Error("edge wire firewall cleanup failed", "error", err)
			}
		}
		ln.Close()
	}
	defer stop()
	defer observability.SetEdgeListenerReady(protocol, false)
	if protocol == "wire" {
		if err := e.wireFirewall(ctx, true); err != nil {
			return err
		}
	}
	observability.SetEdgeListenerReady(protocol, true)
	served := make(chan error, 1)
	go func() {
		switch protocol {
		case "http", "https":
			plain, public := e.httpServers()
			if protocol == "http" {
				defer plain.Close()
				served <- plain.Serve(ln)
			} else {
				defer public.Close()
				served <- public.ServeTLS(ln, "", "")
			}
		case "postgres":
			served <- e.servePostgres(ln)
		case "wire":
			served <- e.serveWire(ln)
		}
	}()
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			stop()
			<-served
			return ctx.Err()
		case err := <-served:
			return err
		case <-tick.C:
			if protocol == "wire" && !e.wireReady(ctx) {
				stop()
				<-served
				return errors.New("private TerraBase wire listener became unavailable")
			}
		}
	}
}
