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
			var requests atomic.Int32
			interrupt.Store(true)
			handoff := make(chan error, 1)
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
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
			for _, cidr := range []string{"100.64.0.0/10", "10.251.0.0/16", "10.0.0.0/8"} {
				t.Run("address plan/"+cidr, func(t *testing.T) {
					if snapshot := fencer.Current(); ctx.Err() != nil || snapshot.Scope != "gru" || !snapshot.CanMutate() {
						t.Fatal("invalid-plan scenario requires live GRU authority and context")
					}
					d := GRU()
					d.NetworkRange = cidr
					rejected := loop
					rejected.Desired = d
					err := rejected.cycle(ctx, map[string]bool{})
					if err == nil || !strings.Contains(err.Error(), "address plan:") ||
						errors.Is(err, errAuthorityLost) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
						strings.Contains(err.Error(), "panicked:") {
						t.Fatalf("expected address-plan rejection, got %v", err)
					}
					if snapshot := fencer.Current(); ctx.Err() != nil || snapshot.Scope != "gru" || !snapshot.CanMutate() {
						t.Fatal("invalid-plan refusal lost GRU authority or context")
					}
					if requests.Load() != 0 || len(f.mutations) != 0 || len(f.groups) != 0 {
						t.Fatalf("invalid plan reached the manager: requests=%d writes=%v groups=%d", requests.Load(), f.mutations, len(f.groups))
					}
				})
			}
			for name, test := range map[string]struct {
				mutate func(*Desired)
				want   string
			}{
				"slot outside the cell subnet": {
					mutate: func(d *Desired) { d.Slots[0].IP = "10.251.0.200" },
					want:   "not a private address inside the cell subnet",
				},
				"slot in another private range": {
					mutate: func(d *Desired) { d.Slots[0].IP = "192.168.0.11" },
					want:   "not a private address inside the cell subnet",
				},
				"public slot in a public subnet": {
					mutate: func(d *Desired) {
						d.Network.Resource.Address = "203.0.113.0/24"
						for i := range d.Slots {
							d.Slots[i].IP = "203.0.113." + strings.TrimPrefix(d.Slots[i].IP, "10.251.0.")
						}
					},
					want: "address plan:",
				},
				"alias to an unknown role": {
					mutate: func(d *Desired) { d.RoleAliases["nats"] = "controllers" },
					want:   `targets unknown role "controllers"`,
				},
				"alias to an empty role": {
					mutate: func(d *Desired) { d.RoleAliases["nats"] = "" },
					want:   `targets unknown role ""`,
				},
				"policy source by former group name": {
					mutate: func(d *Desired) { d.Policies[0].Sources = []string{"gateway"} },
					want:   `references unknown group "gateway"`,
				},
				"servers group by former name": {
					mutate: func(d *Desired) { d.ServersGroup = "ts-orch-servers" },
					want:   `references unknown group "ts-orch-servers"`,
				},
				"DNS disabled group by former name": {
					mutate: func(d *Desired) { d.DNSDisabledGroups = []string{"ts-orch-servers"} },
					want:   `references unknown group "ts-orch-servers"`,
				},
				"former name repeats a current name": {
					mutate: func(d *Desired) { d.Groups[0].RenamedFrom = []string{d.Groups[1].Name} },
					want:   "is empty or repeated",
				},
			} {
				t.Run("desired state/"+name, func(t *testing.T) {
					if snapshot := fencer.Current(); ctx.Err() != nil || snapshot.Scope != "gru" || !snapshot.CanMutate() {
						t.Fatal("invalid-state scenario requires live GRU authority and context")
					}
					d := GRU()
					test.mutate(&d)
					rejected := loop
					rejected.Desired = d
					err := rejected.cycle(ctx, map[string]bool{})
					if err == nil || !strings.Contains(err.Error(), test.want) ||
						errors.Is(err, errAuthorityLost) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
						strings.Contains(err.Error(), "panicked:") {
						t.Fatalf("expected desired-state rejection containing %q, got %v", test.want, err)
					}
					if snapshot := fencer.Current(); ctx.Err() != nil || snapshot.Scope != "gru" || !snapshot.CanMutate() {
						t.Fatal("invalid-state refusal lost GRU authority or context")
					}
					if requests.Load() != 0 || len(f.mutations) != 0 || len(f.groups) != 0 {
						t.Fatalf("invalid state reached the manager: requests=%d writes=%v groups=%d", requests.Load(), f.mutations, len(f.groups))
					}
				})
			}
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
