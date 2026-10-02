//go:build dashboardpreview

// Command ts-dashboard-preview serves the operator dashboard over a fake,
// moving three-region world for local design work and screenshots. It is a
// development tool only: it builds only with the dashboardpreview tag, it is
// not part of the orchestrator binary, and it listens on loopback without a
// token (the dashboard refuses DNS names there, as on a tokenless private
// listener).
//
//	go run -tags dashboardpreview ./cmd/ts-dashboard-preview -addr 127.0.0.1:8099
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/dashboard"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/dashboard/devfake"
)

func main() {
	address := flag.String("addr", "127.0.0.1:8099", "loopback address to listen on")
	flag.Parse()
	host, _, err := net.SplitHostPort(*address)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		slog.Error("the preview listens on a loopback address only", "addr", *address)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	slog.Info("generating the fake three-region world (a day of history)")
	world := devfake.New()
	go world.Run(ctx)
	options := world.Options()
	options.RequireLiteralHost = true
	board := dashboard.New(options)
	server := &http.Server{Addr: *address, Handler: board.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	slog.Info("dashboard preview with FAKE data", "url", "http://"+*address+"/")
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("preview server failed", "error", err)
		os.Exit(1)
	}
}
