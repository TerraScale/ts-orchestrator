package manager_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
)

func TestManagementInventoryRejectsRedirectsAndSecretErrorBodies(t *testing.T) {
	const pat = "nbp_abcdefghijklmnopqrstuvwxyzABCD012345"
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	t.Run("redirect", func(t *testing.T) {
		var destinationCalls, originCalls atomic.Int32
		destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			destinationCalls.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer destination.Close()
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			originCalls.Add(1)
			if r.Method != http.MethodGet || r.URL.Path != "/api/groups" || r.Header.Get("Authorization") != "Token "+pat {
				t.Error("inventory request did not use authenticated GET /api/groups")
			}
			http.Redirect(w, r, destination.URL+"/api/groups", http.StatusFound)
		}))
		defer origin.Close()
		api, err := manager.NewAPI(origin.URL, pat)
		if err != nil {
			t.Fatal(err)
		}
		defer api.Close()
		requestCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		_, err = manager.ReadInventory(requestCtx, api)
		status, ok := errors.AsType[*manager.StatusError](err)
		if !ok || status.Status != http.StatusFound {
			t.Fatalf("redirect: %v", err)
		}
		if originCalls.Load() != 1 || destinationCalls.Load() != 0 {
			t.Fatalf("redirect requests: origin=%d destination=%d", originCalls.Load(), destinationCalls.Load())
		}
	})

	t.Run("error-body", func(t *testing.T) {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			if r.Method != http.MethodGet || r.URL.Path != "/api/groups" || r.Header.Get("Authorization") != "Token "+pat {
				t.Error("inventory request did not use authenticated GET /api/groups")
			}
			http.Error(w, "secret-ish body that must not leak: "+pat, http.StatusInternalServerError)
		}))
		defer server.Close()
		api, err := manager.NewAPI(server.URL, pat)
		if err != nil {
			t.Fatal(err)
		}
		defer api.Close()
		requestCtx, stop := context.WithTimeout(ctx, 2*time.Second)
		defer stop()
		_, err = manager.ReadInventory(requestCtx, api)
		status, ok := errors.AsType[*manager.StatusError](err)
		if !ok || status.Status != http.StatusInternalServerError || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), pat) {
			t.Fatalf("error status or redaction: %v", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("inventory requests: got %d, want 1", calls.Load())
		}
	})

	t.Run("rejected-origins", func(t *testing.T) {
		for _, origin := range []string{"http://netbird.terrascale.tech", "ftp://127.0.0.1", "https://x/api", "https://u:p@x", "https://x?q"} {
			if api, err := manager.NewAPI(origin, pat); err == nil {
				api.Close()
				t.Errorf("accepted %s", origin)
			}
		}
	})

	t.Run("accepted-origins", func(t *testing.T) {
		for _, origin := range []string{"http://127.0.0.1:8080", "http://[::1]:1", "https://netbird.terrascale.tech"} {
			api, err := manager.NewAPI(origin, pat)
			if err != nil {
				t.Errorf("refused %s: %v", origin, err)
				continue
			}
			api.Close()
		}
	})
}
