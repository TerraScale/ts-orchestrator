package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostmetrics"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer cancel()
	if os.Args[1] == "push" {
		if err := servePush(ctx, os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] == "ackdrop" {
		if err := dropFirstAck(ctx, os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] == "budget" {
		if err := mesh.JourneyAlertBudget(ctx, os.Args[2], os.Args[3], os.Args[4], os.Args[5:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	go func() {
		if err := mesh.JourneyMonitoring(ctx, os.Args[1]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()
	server := &http.Server{Addr: "127.0.0.1:9108", Handler: hostmetrics.Handler("sjc", "127.0.0.1:9108", nil), ReadHeaderTimeout: time.Second}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	if err := server.ListenAndServe(); err != nil && ctx.Err() == nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
