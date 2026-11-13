package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	port := os.Getenv("PORT")
	if port == "" {
		port = "18083"
	}
	boots, err := os.OpenFile("/tmp/boots", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		panic(err)
	}
	if _, err := fmt.Fprintln(boots, os.Getpid()); err != nil {
		panic(err)
	}
	if err := boots.Close(); err != nil {
		panic(err)
	}
	var slowReady atomic.Bool
	var failed atomic.Int64
	var failOnce atomic.Bool
	server := &http.Server{Addr: ":" + port, ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow-ready" {
			slowReady.Store(true)
			return
		}
		if r.URL.Path == "/fast-ready" {
			slowReady.Store(false)
			return
		}
		if r.URL.Path == "/healthy" {
			fmt.Fprint(w, port)
			return
		}
		if r.URL.Path == "/failures" {
			fmt.Fprint(w, failed.Load())
			return
		}
		if r.URL.Path == "/fail-once" {
			failOnce.Store(true)
			return
		}
		if r.URL.Path != "/ready" {
			http.NotFound(w, r)
			return
		}
		if failOnce.CompareAndSwap(true, false) {
			<-r.Context().Done()
			failed.Add(1)
			return
		}
		if slowReady.Load() {
			timer := time.NewTimer(4 * time.Second)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-r.Context().Done():
				return
			}
		}
		fmt.Fprint(w, port)
	})}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
