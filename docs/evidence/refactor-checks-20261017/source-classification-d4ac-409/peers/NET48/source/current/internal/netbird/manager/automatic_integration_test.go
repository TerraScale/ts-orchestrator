package manager

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type accountAuthority struct {
	current atomic.Pointer[authority.Runtime]
}

func (a *accountAuthority) Current() authority.Snapshot { return a.current.Load().Current() }
func (a *accountAuthority) Guard(ctx context.Context, epoch uint64) error {
	return a.current.Load().Guard(ctx, epoch)
}

func accountAuthorityStore(t *testing.T) (jetstream.JetStream, *server.Server) {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("account authority NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	return js, srv
}

func accountAuthorityConfig(scope string) authority.Config {
	return authority.Config{Scope: scope, DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		CandidateID: "0000000000C66H81REBS854264", Replicas: 1}
}

func TestAutomaticAccountAuthorityRecoversAcrossOwnerRestart(t *testing.T) {
	for _, response := range []string{"returned", "lost"} {
		t.Run(response, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			js, _ := accountAuthorityStore(t)
			first, err := authority.Start(ctx, js, accountAuthorityConfig("gru"))
			if err != nil {
				t.Fatal(err)
			}
			fencer := &accountAuthority{}
			fencer.current.Store(first)
			t.Cleanup(func() { _ = fencer.current.Load().Close() })
			f := newFakeManager(t)
			var interrupt atomic.Bool
			interrupt.Store(true)
			handoff := make(chan error, 1)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/api/groups" && interrupt.CompareAndSwap(true, false) {
					committed := httptest.NewRecorder()
					f.serve(committed, r)
					if err := first.Close(); err != nil {
						handoff <- err
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					next, err := authority.Start(ctx, js, accountAuthorityConfig("gru"))
					if err != nil {
						handoff <- err
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					fencer.current.Store(next)
					handoff <- nil
					if response == "lost" {
						<-r.Context().Done()
						return
					}
					w.WriteHeader(committed.Code)
					_, _ = w.Write(committed.Body.Bytes())
					return
				}
				f.serve(w, r)
			}))
			t.Cleanup(api.Close)
			loop := Automatic(fencer, nil, nil).withDefaults()
			loop.ManagementURL = api.URL
			loop.Token = func(context.Context) ([]byte, error) { return []byte(testPAT), nil }
			if err := loop.cycle(ctx, map[string]bool{}); !errors.Is(err, errAuthorityLost) {
				t.Fatalf("old owner continued across restart: %v", err)
			}
			if err := <-handoff; err != nil {
				t.Fatal(err)
			}
			if len(f.groups) != 1 || len(f.mutations) != 1 {
				t.Fatalf("old owner wrote after handoff: groups=%d writes=%v", len(f.groups), f.mutations)
			}
			created := f.groups[0].ID
			if err := loop.cycle(ctx, map[string]bool{}); err != nil {
				t.Fatal(err)
			}
			if f.groups[0].ID != created || len(f.groups) != len(GRU().Groups) {
				t.Fatal("new owner did not recover the committed group identity")
			}
			f.mutations = nil
			if err := loop.cycle(ctx, map[string]bool{}); err != nil || len(f.mutations) != 0 {
				t.Fatalf("recovered account did not converge: %v %v", err, f.mutations)
			}
		})
	}
}

func TestAutomaticManagementWaitsForFoundationWithoutExiting(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	js, _ := accountAuthorityStore(t)
	fencer, err := authority.Start(ctx, js, accountAuthorityConfig("gru"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fencer.Close() })
	pending := make(chan struct{}, 1)
	loop := Automatic(fencer, func(context.Context) (vaultsecret.Ref, error) {
		return vaultsecret.Ref{}, errors.New("foundation unavailable")
	}, func(string, ...any) { pending <- struct{}{} })
	loop.initialDelay = time.Millisecond
	done := make(chan struct{})
	go func() { loop.Run(ctx); close(done) }()
	select {
	case <-pending:
	case <-ctx.Done():
		t.Fatal("missing foundation was not reported")
	}
	select {
	case <-done:
		t.Fatal("missing foundation stopped automatic management")
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	<-done
}

func TestAutomaticManagementRefusesForeignRegionalAuthority(t *testing.T) {
	js, _ := accountAuthorityStore(t)
	fencer, err := authority.Start(t.Context(), js, accountAuthorityConfig("fra"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fencer.Close() })
	var reads atomic.Int32
	loop := Automatic(fencer, func(context.Context) (vaultsecret.Ref, error) {
		reads.Add(1)
		return vaultsecret.Ref{}, nil
	}, nil).withDefaults()
	if err := loop.cycle(t.Context(), map[string]bool{}); !errors.Is(err, errAuthorityLost) || reads.Load() != 0 {
		t.Fatalf("foreign authority fetched account credentials: reads=%d error=%v", reads.Load(), err)
	}
}

func TestAutomaticManagementGuardsWritesDuringAuthorityStoreLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	js, store := accountAuthorityStore(t)
	fencer, err := authority.Start(ctx, js, accountAuthorityConfig("gru"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fencer.Close() })
	f := newFakeManager(t)
	store.Shutdown()
	store.WaitForShutdown()
	if !fencer.Current().CanMutate() {
		t.Fatal("scenario needs a locally live lease after losing the authority store")
	}
	loop := Automatic(fencer, nil, nil).withDefaults()
	loop.ManagementURL = f.server.URL
	loop.Token = func(context.Context) ([]byte, error) { return []byte(testPAT), nil }
	if err := loop.cycle(ctx, map[string]bool{}); !errors.Is(err, errAuthorityLost) && !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("authority store loss did not fence writes: %v", err)
	}
	if len(f.mutations) != 0 {
		t.Fatalf("stale local authority mutated the account: %v", f.mutations)
	}
}
