package manager

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagementAuthorityCancelsCommittedWriteAndRecoversFromSnapshot(t *testing.T) {
	for _, stage := range []string{"response headers", "response body"} {
		t.Run(stage, func(t *testing.T) {
			f := newFakeManager(t)
			var leader, interrupt atomic.Bool
			leader.Store(true)
			interrupt.Store(true)
			cancelled := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/api/groups" && interrupt.CompareAndSwap(true, false) {
					// Commit externally, but lose the response as authority transfers.
					f.serve(httptest.NewRecorder(), r)
					if stage == "response body" {
						w.Header().Set("Content-Length", "100")
						w.WriteHeader(http.StatusCreated)
						_, _ = w.Write([]byte("{"))
						w.(http.Flusher).Flush()
					}
					leader.Store(false)
					<-r.Context().Done()
					close(cancelled)
					return
				}
				f.serve(w, r)
			}))
			t.Cleanup(server.Close)
			loop := Loop{Leader: leader.Load, Desired: GRU(), ManagementURL: server.URL,
				Token: func(context.Context) ([]byte, error) { return []byte(testPAT), nil }}.withDefaults()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var tokenReads atomic.Int32
			follower := Loop{ManagementURL: server.URL, Desired: GRU(), Token: func(context.Context) ([]byte, error) {
				tokenReads.Add(1)
				return []byte(testPAT), nil
			}}.withDefaults()
			if err := follower.cycle(ctx, map[string]bool{}); !errors.Is(err, errAuthorityLost) {
				t.Fatalf("missing authority did not refuse cycle: %v", err)
			}
			followerCtx, stopFollower := context.WithTimeout(ctx, 20*time.Millisecond)
			Loop{initialDelay: time.Millisecond, Interval: time.Millisecond}.Run(followerCtx)
			stopFollower()
			if tokenReads.Load() != 0 || len(f.mutations) != 0 {
				t.Fatal("missing authority read credentials or mutated the manager")
			}
			if err := loop.cycle(ctx, map[string]bool{}); !errors.Is(err, errAuthorityLost) {
				t.Fatalf("authority transfer did not cancel active request: %v", err)
			}
			select {
			case <-cancelled:
			case <-ctx.Done():
				t.Fatal("external request did not observe cancellation")
			}
			if len(f.groups) != 1 || len(f.mutations) != 1 {
				t.Fatalf("stale cycle continued after committed write: groups=%d mutations=%v", len(f.groups), f.mutations)
			}
			createdID := f.groups[0].ID
			leader.Store(true)
			if err := loop.cycle(ctx, map[string]bool{}); err != nil {
				t.Fatal(err)
			}
			if len(f.groups) != len(GRU().Groups) || f.groups[0].ID != createdID {
				t.Fatalf("recovery duplicated or replaced committed identity: %+v", f.groups)
			}
			f.mutations = nil
			if err := loop.cycle(ctx, map[string]bool{}); err != nil || len(f.mutations) != 0 {
				t.Fatalf("recovered manager did not converge: %v %v", err, f.mutations)
			}
		})
	}
}

func TestManagementAuthorityFencesEveryPeerRenameWriteAndRecovers(t *testing.T) {
	f := newFakeManager(t)
	ids := f.seedLegacy(t)
	if _, err := Sync(t.Context(), f.api(t), GRU(), true); err != nil {
		t.Fatal(err)
	}
	name := GRU().PeerName(GRU().Slots[0])
	id := ids.server1
	f.peer(id).DNSLabel = name + "-conflict." + f.dnsDomain
	f.mutations = nil
	var leader, interrupt atomic.Bool
	leader.Store(true)
	interrupt.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.serve(w, r)
		if r.Method == http.MethodPut && r.URL.Path == "/api/peers/"+id && interrupt.CompareAndSwap(true, false) {
			leader.Store(false)
		}
	}))
	t.Cleanup(server.Close)
	loop := Loop{Leader: leader.Load, Desired: GRU(), ManagementURL: server.URL,
		Token: func(context.Context) ([]byte, error) { return []byte(testPAT), nil }}.withDefaults()
	if err := loop.cycle(t.Context(), map[string]bool{}); !errors.Is(err, errAuthorityLost) {
		t.Fatalf("second write was not fenced: %v", err)
	}
	if len(f.mutations) != 1 || f.peer(id).Name != name+"-renaming" {
		t.Fatalf("stale authority finished multi-write rename: %v %+v", f.mutations, f.peer(id))
	}
	leader.Store(true)
	if err := loop.cycle(t.Context(), map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if peer := f.peer(id); peer == nil || peer.Name != name || !strings.HasPrefix(peer.DNSLabel, name+".") {
		t.Fatalf("new authority did not recover intermediate rename: %+v", peer)
	}
}
