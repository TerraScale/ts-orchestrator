package globalview

import (
	"context"
	"encoding/json/v2"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

func followedTestView(t *testing.T, local string, cells func() []string, now func() time.Time) (*View, *nats.Conn) {
	t.Helper()
	conn, _ := startNATS(t)
	view := NewView(local, cells, now)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- view.Follow(ctx, conn) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("follow: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("rollup follower did not stop")
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for conn.NumSubscriptions() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("rollup subscriber did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	return view, conn
}

func readTestRegion(t *testing.T, view *View, cell string) Region {
	t.Helper()
	server := httptest.NewServer(Handler(view))
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/v1/regions/" + cell)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var region Region
	if err := json.UnmarshalRead(response.Body, &region); err != nil || response.StatusCode != 200 {
		t.Fatalf("region status=%d result=%+v error=%v", response.StatusCode, region, err)
	}
	return region
}

// The production builder publishes across NATS; assertions read the remote API.
func observedRollup(t *testing.T, in Inputs) Rollup {
	t.Helper()
	cell := normalize(in.Cell)
	remote, conn := followedTestView(t, cell, nil, func() time.Time { return in.Now })
	changed := remote.Changed()
	local := NewView(cell, nil, func() time.Time { return in.Now })
	publishOnce(t.Context(), conn, cell, func(context.Context) Rollup { return Build(in) }, local)
	waitClosed(t, changed)
	region := readTestRegion(t, remote, cell)
	if region.Rollup == nil {
		t.Fatal("published rollup missing from regional API")
	}
	return *region.Rollup
}

func publishTestRaw(t *testing.T, conn *nats.Conn, subject string, data []byte) {
	t.Helper()
	if err := conn.Publish(subject, data); err != nil {
		t.Fatal(err)
	}
	if err := conn.FlushTimeout(3 * time.Second); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	if err := conn.Barrier(func() { close(done) }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("regional observation dispatch stalled")
	}
}

func publishTestRollup(t *testing.T, conn *nats.Conn, rollup Rollup) {
	t.Helper()
	data, err := json.Marshal(rollup)
	if err != nil {
		t.Fatal(err)
	}
	publishTestRaw(t, conn, protocol.RegionRollupSubject(normalize(rollup.Cell)), data)
}

func readTestRegions(t *testing.T, view *View) []Region {
	t.Helper()
	server := httptest.NewServer(Handler(view))
	defer server.Close()
	response, err := server.Client().Get(server.URL + "/v1/regions")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var regions []Region
	if err := json.UnmarshalRead(response.Body, &regions); err != nil || response.StatusCode != 200 {
		t.Fatalf("regional list status=%d error=%v", response.StatusCode, err)
	}
	return regions
}
