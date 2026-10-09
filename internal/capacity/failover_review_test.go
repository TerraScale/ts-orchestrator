package capacity

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestUsageQueriesHealthyThirdControllerWithinCallerDeadline(t *testing.T) {
	_, from, to := fixture(t)
	started := make(chan struct{}, 2)
	var canceled atomic.Int32
	stall := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		started <- struct{}{}
		<-r.Context().Done()
		canceled.Add(1)
	})
	first, second := httptest.NewServer(stall), httptest.NewServer(stall)
	defer first.Close()
	defer second.Close()
	third := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range 2 {
			select {
			case <-started:
			case <-r.Context().Done():
				return
			}
		}
		_ = json.NewEncoder(w).Encode(Usage{Region: "gru", From: from, To: to, Complete: true})
	}))
	defer third.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	client := Client{URLs: []string{first.URL, second.URL, third.URL}, Token: strings.Repeat("a", 32)}
	usage, err := client.Query(ctx, "gru", from, to)
	if err != nil || !usage.Complete || ctx.Err() != nil {
		t.Fatalf("healthy third controller was blocked by earlier attempts: %+v %v", usage, err)
	}
	first.Close()
	second.Close()
	if canceled.Load() != 2 {
		t.Fatalf("remaining controller requests were not canceled: %d", canceled.Load())
	}
}

func TestConcurrentUsageSelectsBestPartialAndHonorsCancellation(t *testing.T) {
	_, from, to := fixture(t)
	for _, mode := range []string{"partial", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			var servers []*httptest.Server
			client := Client{Token: strings.Repeat("a", 32)}
			for count := 1; count <= 3; count++ {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if mode == "canceled" {
						<-r.Context().Done()
						return
					}
					_ = json.NewEncoder(w).Encode(Usage{Region: "gru", From: from, To: to, Replicas: make([]Row, count)})
				}))
				servers = append(servers, server)
				client.URLs = append(client.URLs, server.URL)
			}
			defer func() {
				for _, server := range servers {
					server.Close()
				}
			}()
			timeout := time.Second
			if mode == "canceled" {
				timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			usage, err := client.Query(ctx, "gru", from, to)
			if mode == "partial" && (err != nil || usage.Complete || len(usage.Replicas) != 3) {
				t.Fatalf("best partial answer was lost: %+v %v", usage, err)
			}
			if mode == "canceled" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("caller deadline was lost: %v", err)
			}
		})
	}
}
