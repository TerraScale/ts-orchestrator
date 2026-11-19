package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
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
	fmt.Fprintln(os.Stdout, "service-log-stdout")
	fmt.Fprintln(os.Stderr, "service-log-stderr")
	var slowReady atomic.Bool
	var notReady atomic.Bool
	server := &http.Server{Addr: ":" + port, ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/log-burst" {
			io.WriteString(os.Stdout, strings.Repeat("service-log-burst\n", 128<<10)+"service-log-burst-end\n")
			return
		}
		if r.URL.Path == "/log-follow" {
			fmt.Fprintln(os.Stdout, "service-log-follow")
			return
		}
		if r.URL.Path == "/load" {
			until := time.Now().Add(100 * time.Millisecond)
			for time.Now().Before(until) {
				_ = time.Now().UnixNano()
			}
			return
		}
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
		if r.URL.Path == "/not-ready" {
			notReady.Store(true)
			return
		}
		if r.URL.Path != "/ready" {
			http.NotFound(w, r)
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
		if notReady.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
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
