package globalview

import (
	"context"
	"encoding/json/v2"
	"errors"
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
}
