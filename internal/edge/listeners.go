package edge

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/plannedstop"
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
	tracked := &shutdownListener{Listener: ln}
	ln = tracked
	defer tracked.closeConnections()
	defer observability.SetEdgeListenerReady(protocol, false)
	bit := listenerBit(protocol)
	e.listeners.Or(bit)
	defer e.listeners.And(^bit)
	observability.SetEdgeListenerReady(protocol, true)
	var server *http.Server
	if protocol == "http" || protocol == "https" {
		plain, public := e.httpServers()
		server = plain
		if protocol == "https" {
			server = public
		}
		defer func() {
			observability.SetEdgeListenerReady(protocol, false)
			shutdown, cancel := context.WithTimeout(plannedstop.Begin(ctx), shutdownGrace)
			defer cancel()
			err := server.Shutdown(shutdown)
			remaining := tracked.closeConnections()
			server.Close()
			if err != nil || remaining != 0 {
				slog.Warn("edge connections abandoned", "protocol", protocol, "connections", remaining, "error", err)
			}
		}()
	}
	served := make(chan struct{})
	var serveErr error
	go func() {
		defer close(served)
		switch protocol {
		case "http":
			serveErr = server.Serve(limitedListener{Listener: ln, edge: e, protocol: protocol})
		case "https":
			config := server.TLSConfig.Clone()
			config.NextProtos = []string{"h2", "http/1.1"}
			serveErr = server.ServeTLS(limitedListener{Listener: ln, edge: e, protocol: protocol, config: config}, "", "")
		case "postgres":
			serveErr = e.servePostgres(ln)
		case "terrabase":
			serveErr = e.serveRegionalInternal(ln)
		}
	}()
	select {
	case <-ctx.Done():
		ln.Close()
		plannedstop.Wait(ctx, "edge "+protocol+" accept loop", served)
		return ctx.Err()
	case <-served:
		ln.Close()
		return serveErr
	}
}
