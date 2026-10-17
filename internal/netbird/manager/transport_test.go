package manager

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

type mutationWriteFailure struct {
	net.Conn
	fail   *atomic.Bool
	writes *atomic.Int32
}

func (c mutationWriteFailure) Write(wire []byte) (int, error) {
	if c.fail.Load() {
		c.writes.Add(1)
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(wire)
}

func TestAPIDoesNotRetryMutationAfterConnectionWriteFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	api, err := NewAPI(server.URL, testPAT)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	var fail atomic.Bool
	var writes atomic.Int32
	transport := api.http.Transport.(*http.Transport)
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		connection, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return mutationWriteFailure{connection, &fail, &writes}, nil
	}
	if err := api.do(t.Context(), http.MethodGet, "/groups", nil, nil); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := api.do(t.Context(), http.MethodDelete, "/groups/original", nil, nil); err == nil {
		t.Fatal("failed mutation write was reported as success")
	}
	if writes.Load() != 1 {
		t.Fatalf("mutation attempted %d writes", writes.Load())
	}
}

func TestAPIDoesNotReplayAmbiguousEmptyMutation(t *testing.T) {
	var writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		writes.Add(1)
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = connection.Close()
	}))
	defer server.Close()
	api, err := NewAPI(server.URL, testPAT)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	if err := api.do(t.Context(), http.MethodGet, "/groups", nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := api.do(t.Context(), http.MethodDelete, "/groups/original", nil, nil); err == nil {
		t.Fatal("lost response was reported as success")
	}
	if writes.Load() != 1 {
		t.Fatalf("ambiguous mutation dispatched %d times", writes.Load())
	}
}

func TestAPIDoesNotCompleteAcceptedMutation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	api, err := NewAPI(server.URL, testPAT)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	err = api.do(t.Context(), http.MethodPost, "/groups", groupRequest{Name: "original"}, nil)
	status, ok := errors.AsType[*StatusError](err)
	if !ok || status.Status != http.StatusAccepted {
		t.Fatalf("expected pending HTTP 202, got %v", err)
	}
}
