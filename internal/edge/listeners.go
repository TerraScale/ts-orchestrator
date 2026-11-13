package edge

import (
	"context"
	"log/slog"
	"net"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func (e *Edge) runListener(ctx context.Context, protocol string) {
	address := map[string]string{"http": ":80", "https": ":443", "postgres": ":5432", "terrabase": terrabaseLoopback}[protocol]
	for ctx.Err() == nil {
		observability.SetEdgeListenerReady(protocol, false)
		ln, err := e.listen("tcp", address)
		if protocol == "terrabase" && err != nil {
			err = terrabaseBindError(err)
		}
		if err == nil {
			err = e.serveListener(ctx, protocol, ln)
		}
		if ctx.Err() != nil {
			return
		}
		level := slog.LevelWarn
		if protocol == "terrabase" {
			level = slog.LevelError // ts-auth and ts-dashboard have no other path to TerraBase
		}
		slog.Log(ctx, level, "edge listener unavailable; other protocols keep serving", "protocol", protocol, "error", err)
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
	defer observability.SetEdgeListenerReady(protocol, false)
	defer e.listeners.And(^listenerBit(protocol))
	e.listeners.Or(listenerBit(protocol))
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
		case "terrabase":
			served <- e.serveRegionalInternal(ln)
		}
	}()
	select {
	case <-ctx.Done():
		ln.Close()
		<-served
		return ctx.Err()
	case err := <-served:
		ln.Close()
		return err
	}
}
