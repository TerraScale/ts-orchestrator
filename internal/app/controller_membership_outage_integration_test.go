package app

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/membership"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/nats.go"
)

func TestMembershipProviderOutageKeepsRegionalNATSServing(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	broker, err := natscell.Start(ctx, natscell.Config{Cell: "gru", Instance: "membership-outage", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "nats")}})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	control, err := authority.Start(ctx, broker.JetStream(), authority.Config{DeploymentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scope: "gru", CandidateID: entityid.New(), LeaseDuration: 5 * time.Second, RenewInterval: time.Second, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	if _, err := broker.Conn().Subscribe("regional.serving", func(message *nats.Msg) {
		_ = message.Respond([]byte("gru"))
	}); err != nil {
		t.Fatal(err)
	}
	if err := broker.Conn().FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	probe := func() {
		t.Helper()
		reply, err := broker.Conn().RequestWithContext(ctx, "regional.serving", nil)
		if err != nil || string(reply.Data) != "gru" {
			t.Fatalf("regional serving during membership recovery: %v, %v", reply, err)
		}
	}
	var available atomic.Bool
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !available.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer provider.Close()
	attempted := make(chan struct{}, 1)
	recovered := make(chan *controllerMembership, 1)
	supervisor := &controllerMembership{open: func(openCtx context.Context) (*controllerMembership, error) {
		request, err := http.NewRequestWithContext(openCtx, http.MethodGet, provider.URL, nil)
		if err != nil {
			return nil, err
		}
		response, err := provider.Client().Do(request)
		if err != nil {
			return nil, err
		}
		response.Body.Close()
		if response.StatusCode != http.StatusOK {
			select {
			case attempted <- struct{}{}:
			default:
			}
			return nil, errors.New("OCI identity service unavailable")
		}
		source := &fakeSlotOCI{}
		reconciler, err := membership.New(membership.Topology{Cell: "gru", Slots: []string{"controller-a", "controller-b", "controller-c"},
			SeedSlot: "controller-a", SelfSlot: "controller-a"}, membership.Dependencies{Leadership: control,
			Peers: natsMembershipPeers{runtime: broker}, Ledger: source, Instances: source, Evidence: source})
		if err != nil {
			return nil, err
		}
		opened := &controllerMembership{reconciler: reconciler}
		recovered <- opened
		return opened, nil
	}}
	runCtx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(runCtx) }()
	defer func() {
		stop()
		if err := <-done; err != nil {
			t.Errorf("membership supervision stopped: %v", err)
		}
	}()
	select {
	case <-attempted:
	case <-ctx.Done():
		t.Fatal("membership never reached the unavailable provider")
	}
	probe()
	available.Store(true)
	select {
	case opened := <-recovered:
		waitMembership(t, ctx, "membership observation after provider recovery", func() bool {
			return len(opened.reconciler.Statuses()) == 3
		})
	case <-ctx.Done():
		t.Fatal("membership did not recover automatically")
	}
	probe()
}
