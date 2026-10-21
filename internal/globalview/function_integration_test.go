package globalview

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/functions"
)

func TestFunctionObservationsCrossNATSAndHTTP(t *testing.T) {
	now := time.Now().UTC()
	remote, conn := followedTestView(t, "gru", nil, func() time.Time { return now })
	local := NewView("gru", nil, func() time.Time { return now })
	source := Sources{Cell: "gru", Now: func() time.Time { return now }, Functions: func(context.Context) ([]FunctionObservation, error) {
		return []FunctionObservation{{TenantID: "tenant-a", FunctionID: "echo", State: "observed", ObservedAt: now,
			Snapshot: &functions.Snapshot{SchemaVersion: 1, ObservedAt: now, Succeeded: 4}},
			{TenantID: "tenant-b", FunctionID: "unplaced", State: "unplaced", ObservedAt: now}}, nil
	}}
	publish := func() {
		t.Helper()
		changed := remote.Changed()
		publishOnce(t.Context(), conn, "gru", func(ctx context.Context) Rollup { return Build(source.Collect(ctx)) }, local)
		waitClosed(t, changed)
	}
	server := httptest.NewServer(Handler(remote))
	defer server.Close()
	read := func(path, state string, status int) ResourceView {
		t.Helper()
		response, err := server.Client().Get(server.URL + "/v1/regions/gru/functions" + path)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result ResourceView
		if err := json.UnmarshalRead(response.Body, &result); err != nil || result.State != state || response.StatusCode != status {
			t.Fatalf("status=%d result=%+v err=%v", response.StatusCode, result, err)
		}
		return result
	}
	publish()
	read("", "current", 200)
	read("/tenant-a/echo", "current", 200)
	read("/tenant-b/unplaced", "current", 200)
	read("/tenant-b/echo", "not_found", 404)
	now = now.Add(time.Second)
	source.Functions = func(context.Context) ([]FunctionObservation, error) { return nil, errors.New("manager unavailable") }
	publish()
	read("/tenant-a/echo", "unavailable", 503)
	now = now.Add(time.Second)
	source.Functions = func(context.Context) ([]FunctionObservation, error) {
		return []FunctionObservation{{TenantID: "tenant-a", FunctionID: "echo", State: "unavailable"}}, nil
	}
	publish()
	read("/tenant-a/echo", "unavailable", 200)
	read("", "unavailable", 200)
}
