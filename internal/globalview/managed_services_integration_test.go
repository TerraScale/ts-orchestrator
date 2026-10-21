package globalview

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestManagedServicesCrossSourceNATSAndHTTP(t *testing.T) {
	now := time.Now().UTC()
	remote, conn := followedTestView(t, "gru", nil, func() time.Time { return now })
	local := NewView("gru", nil, func() time.Time { return now })
	source := Sources{Cell: "gru", Now: func() time.Time { return now }, Services: func(context.Context) ([]swarmruntime.ServiceObservation, error) {
		return []swarmruntime.ServiceObservation{{ServiceID: "unplaced", IntentID: "intent-a", Role: "api", RequestedReplicas: 2, Readiness: "unknown", ObservedAt: now, Tasks: []swarmruntime.TaskObservation{{TaskID: "task-a", State: "PENDING"}}}}, nil
	}}
	publish := func() {
		t.Helper()
		changed := remote.Changed()
		publishOnce(t.Context(), conn, "gru", func(ctx context.Context) Rollup { return Build(source.Collect(ctx)) }, local)
		waitClosed(t, changed)
	}
	server := httptest.NewServer(Handler(remote))
	defer server.Close()
	read := func(path string, status int, state string) ResourceView {
		t.Helper()
		response, err := server.Client().Get(server.URL + "/v1/regions/gru/services" + path)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result ResourceView
		if err := json.UnmarshalRead(response.Body, &result); err != nil || response.StatusCode != status || result.State != state {
			t.Fatalf("status=%d state=%s error=%v", response.StatusCode, result.State, err)
		}
		return result
	}
	publish()
	result := read("/unplaced", 200, "current")
	wire, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatal(err)
	}
	var service swarmruntime.ServiceObservation
	if err := json.Unmarshal(wire, &service); err != nil || service.Readiness != "unknown" || service.RequestedReplicas != 2 || len(service.Tasks) != 1 || service.Tasks[0].NodeID != "" {
		t.Fatalf("unplaced observation lost: %+v %v", service, err)
	}
	read("/absent", 404, "not_found")
	now = now.Add(time.Second)
	source.Services = func(context.Context) ([]swarmruntime.ServiceObservation, error) {
		return nil, errors.New("manager unavailable")
	}
	publish()
	read("", 503, "unavailable")
	read("/unplaced", 503, "unavailable")
	now = now.Add(time.Second)
	source.Services = func(context.Context) ([]swarmruntime.ServiceObservation, error) {
		return []swarmruntime.ServiceObservation{{ServiceID: "retained", ObservedAt: now.Add(-time.Minute)}}, nil
	}
	publish()
	read("/retained", 200, "stale")
	read("", 200, "stale")
	now = now.Add(time.Second)
	source.Services = func(context.Context) ([]swarmruntime.ServiceObservation, error) {
		var services []swarmruntime.ServiceObservation
		for range 40 {
			services = append(services, swarmruntime.ServiceObservation{ServiceID: "bounded", ObservedAt: now})
		}
		return services, nil
	}
	publish()
	read("/absent", 503, "truncated")

	// Keep the listed-region fixture independent of the mutable service clock.
	{
		now := time.Now().UTC()
		listedView, listedConn := followedTestView(t, "gru", func() []string { return []string{"sfo"} }, func() time.Time { return now })
		listedLocal := NewView("gru", func() []string { return []string{"sfo"} }, func() time.Time { return now })
		changed := listedView.Changed()
		publishOnce(t.Context(), listedConn, "gru", func(context.Context) Rollup {
			return Rollup{Version: Version, Cell: "gru", ObservedAt: now, Health: Health{Status: Healthy}}
		}, listedLocal)
		waitClosed(t, changed)
		listedServer := httptest.NewServer(Handler(listedView))
		defer listedServer.Close()

		response, err := listedServer.Client().Get(listedServer.URL + "/v1/regions")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("list body: read=%v close=%v", err, closeErr)
		}
		var entries []Region
		if response.StatusCode != http.StatusOK || json.Unmarshal(body, &entries) != nil {
			t.Fatalf("list = %d %s", response.StatusCode, body)
		}
		if len(entries) != 2 || entries[0].Cell != "gru" || entries[0].Rollup == nil || entries[1].Cell != "sfo" || entries[1].Rollup != nil {
			t.Fatalf("entries = %+v", entries)
		}
		rollup := entries[0].Rollup
		if rollup.Version != Version || rollup.Cell != "gru" || !rollup.ObservedAt.Equal(now) || rollup.Health.Status != Healthy {
			t.Fatalf("received rollup = %+v", rollup)
		}
		for path, want := range map[string]int{"/v1/regions/GRU": http.StatusOK, "/v1/regions/sfo": http.StatusOK,
			"/v1/regions/fra": http.StatusNotFound} {
			response, err := listedServer.Client().Get(listedServer.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			closeErr := response.Body.Close()
			if err != nil || closeErr != nil {
				t.Fatalf("%s body: read=%v close=%v", path, err, closeErr)
			}
			if response.StatusCode != want {
				t.Fatalf("%s = %d, want %d: %s", path, response.StatusCode, want, body)
			}
		}
	}
}
