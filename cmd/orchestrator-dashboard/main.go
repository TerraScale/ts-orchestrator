// Command orchestrator-dashboard serves the read-only operator view of a
// TerraScale orchestrator. It has no mutation routes and may be bound to a
// Tailscale address without placing a proxy in front of the control loop.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/dashboard"
)

const (
	listenEnvironment = "TS_ORCH_DASHBOARD_LISTEN"
	stateEnvironment  = "TS_ORCH_DASHBOARD_STATE_FILE"
	defaultListen     = "0.0.0.0:18447"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	listen := os.Getenv(listenEnvironment)
	if listen == "" {
		listen = defaultListen
	}
	state := dashboard.State{}
	stateFile := os.Getenv(stateEnvironment)
	if stateFile != "" {
		loaded, err := dashboard.LoadFile(stateFile)
		if err != nil {
			fatal(fmt.Errorf("load dashboard state: %w", err))
		}
		state = loaded
	}
	store := dashboard.NewStore(state)
	if stateFile != "" {
		go watchFile(ctx, store, stateFile)
	}
	server := &http.Server{Addr: listen, Handler: dashboard.NewServer(store).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 0, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	fmt.Printf("orchestrator dashboard listening on http://%s (read-only)\n", listen)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fatal(err)
	}
}

func watchFile(ctx context.Context, store *dashboard.Store, path string) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			next, err := dashboard.LoadFile(path)
			if err == nil {
				store.Set(next)
			}
		}
	}
}
func fatal(err error) { _, _ = fmt.Fprintln(os.Stderr, err); os.Exit(1) }
