package runtimecostsnapshot

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/controlaccess"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

func TestCostSnapshotThroughAuthenticatedControllerHTTP(t *testing.T) {
	token := strings.Repeat("private", 8)
	view := &ocicost.View{Cell: "gru", OCIRegion: "sa-saopaulo-1",
		Forecast: ocicost.Forecast{Currency: "USD", ObservedAt: time.Now().UTC().Add(-time.Minute).Truncate(time.Second),
			MonthToDateCents: 123, MonthEndCents: 456, PendingDailyCents: 17},
		Services: []ocicost.Line{{Name: "compute", Cents: 120}}, Components: []ocicost.Line{{Name: "node-pool", Cents: 90}}}
	controller, err := observability.NewTokenServer(observability.Config{ListenAddress: "127.0.0.1:9463"}, token,
		observability.ServerDeps{Registry: observability.NewRegistry(false), Health: new(observability.Health)})
	if err != nil {
		t.Fatal(err)
	}
	var mode atomic.Int32
	controller.HandleAuthenticated("GET "+Path, Handler("gru", func(context.Context) *ocicost.View {
		switch mode.Load() {
		case 1:
			return nil
		case 2:
			partial := *view
			partial.Missing = "current pool pricing is pending"
			return &partial
		case 3:
			wrong := *view
			wrong.Cell = "sfo"
			return &wrong
		default:
			return view
		}
	}))
	server := httptest.NewTLSServer(controller)
	t.Cleanup(server.Close)
	response, err := server.Client().Get(server.URL + Path)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status %d", response.StatusCode)
	}
	client := Client{Access: controlaccess.Access{URLs: []string{server.URL}, Token: token}, HTTP: server.Client()}
	snapshot, err := client.Read(t.Context(), "GRU")
	if err != nil || snapshot.SchemaVersion != 1 || snapshot.Region != "gru" || !snapshot.ObservedAt.Equal(view.Forecast.ObservedAt) || !reflect.DeepEqual(snapshot.Cost, view) {
		t.Fatalf("source observation changed: %+v, %v", snapshot, err)
	}
	wire, err := json.Marshal(snapshot)
	if err != nil || strings.Contains(string(wire)+fmt.Sprintf("%v %#v %+v", client, client, client), token) {
		t.Fatal("snapshot or client formatting exposed the bearer")
	}
	mode.Store(1)
	snapshot, err = client.Read(t.Context(), "gru")
	if !errors.Is(err, ErrPending) || snapshot.Cost != nil || !snapshot.ObservedAt.IsZero() {
		t.Fatalf("missing report became a price or timestamp: %+v %v", snapshot, err)
	}
	mode.Store(2)
	snapshot, err = client.Read(t.Context(), "gru")
	if !errors.Is(err, ErrPending) || snapshot.Cost == nil || snapshot.Cost.Missing == "" || !snapshot.ObservedAt.Equal(view.Forecast.ObservedAt) || snapshot.Cost.Forecast.PendingDailyCents != 17 {
		t.Fatalf("pending price lost its source observation: %+v %v", snapshot, err)
	}
	mode.Store(3)
	if _, err := client.Read(t.Context(), "gru"); err == nil {
		t.Fatal("accepted a different source region")
	}
}

func TestCostSnapshotHTTPFailoverCancellationAndRefusals(t *testing.T) {
	token := strings.Repeat("secret", 8)
	at := time.Now().UTC().Truncate(time.Second)
	good := Snapshot{SchemaVersion: 1, Region: "gru", ObservedAt: at,
		Cost: &ocicost.View{Cell: "gru", Forecast: ocicost.Forecast{Currency: "USD", ObservedAt: at, MonthEndCents: 42}}}
	var mode, destinationCalls atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { destinationCalls.Add(1) }))
	t.Cleanup(destination.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != Path || r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("snapshot client changed the authenticated read request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		snapshot := good
		switch mode.Load() {
		case 1:
			http.Redirect(w, r, destination.URL, http.StatusFound)
			return
		case 2:
			snapshot.SchemaVersion = 2
		case 3:
			snapshot.Region = "sfo"
		case 4:
			snapshot.ObservedAt = at.Add(time.Second)
		case 5:
			fmt.Fprint(w, strings.Repeat(" ", (8<<20)+1))
			return
		case 6:
			<-r.Context().Done()
			return
		}
		wire, err := json.Marshal(snapshot)
		if err != nil {
			t.Error(err)
			return
		}
		w.Write(wire)
	}))
	t.Cleanup(server.Close)
	client := Client{Access: controlaccess.Access{URLs: []string{server.URL}, Token: token}}
	blockedStarted, blockedEnded := make(chan struct{}), make(chan struct{})
	blocked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(blockedStarted)
		<-r.Context().Done()
		close(blockedEnded)
	}))
	t.Cleanup(blocked.Close)
	// Ensure the healthy answer follows an actual outstanding request.
	gate := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-blockedStarted:
		case <-r.Context().Done():
			return
		}
		wire, _ := json.Marshal(good)
		w.Write(wire)
	}))
	t.Cleanup(gate.Close)
	failover := Client{Access: controlaccess.Access{URLs: []string{blocked.URL, gate.URL}, Token: token}}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if snapshot, err := failover.Read(ctx, "gru"); err != nil || snapshot.Cost.Forecast.MonthEndCents != 42 {
		t.Fatalf("healthy admitted controller was unavailable: %+v %v", snapshot, err)
	}
	select {
	case <-blockedEnded:
	case <-ctx.Done():
		t.Fatal("complete snapshot did not cancel the other request")
	}
	for scenario := int32(1); scenario <= 5; scenario++ {
		mode.Store(scenario)
		if _, err := client.Read(t.Context(), "gru"); err == nil || strings.Contains(err.Error(), token) {
			t.Fatalf("refusal %d returned success or exposed bearer: %v", scenario, err)
		}
	}
	if destinationCalls.Load() != 0 {
		t.Fatal("cost client followed a redirect")
	}
	mode.Store(6)
	deadline, stop := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer stop()
	if _, err := client.Read(deadline, "gru"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled snapshot read: %v", err)
	}
	mode.Store(0)
	for _, origin := range []string{"http://remote.example.test", server.URL + "/other", server.URL + "?token=x", "https://user:password@example.test"} {
		invalid := Client{Access: controlaccess.Access{URLs: []string{origin}, Token: token}}
		if _, err := invalid.Read(t.Context(), "gru"); err == nil {
			t.Fatalf("accepted invalid cost origin %s", origin)
		}
	}
}
