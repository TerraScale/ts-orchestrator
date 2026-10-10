package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionlifecycle"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/regionplanner"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/rollout"
)

// noLifecycleRecords is a region lifecycle store with no record: only the
// global home occupies a region slot.
type noLifecycleRecords struct{}

func (noLifecycleRecords) List(context.Context) ([]regionlifecycle.Record, error) { return nil, nil }

// A controller with the rollout store and the region planner's budgets
// attached: a rollout past its phase deadline and a budget at its ceiling
// reach the insight engine through the controller wiring, and the dashboard
// shows them on the needs-attention page, the rollouts page and the
// rollout's own detail page with its journaled decisions.
func TestControllerRolloutsAndBudgetsReachInsightsAndTheDashboard(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	nats, err := natscell.Start(ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nats.Close() })
	address := freeLoopbackAddress(t)
	cfg := Config{NATS: natscell.Config{Cell: "lab", Instance: "one"},
		Observability: observability.Config{ListenAddress: address, Dashboard: true}}
	telemetry, err := startRuntimeObservability(ctx, cfg, "controller", "one")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(telemetry.close)
	if telemetry.server == nil {
		t.Skipf("loopback port %s was taken before the listener bound", address)
	}

	// The real rollout store, with a rollout whose preflight deadline
	// passed two hours ago. Begin and Commit journal their decisions.
	lease := observedAuthority{snapshot: authority.Snapshot{Leader: true, Ready: true, OwnerID: "0000000000DV8998ZCQW1J2V2R", Epoch: 3,
		ExpiresAt: time.Now().Add(time.Minute)}}
	store, err := rollout.OpenStore(ctx, nats.JetStream(), "lab", 1, lease)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now().Add(-3 * time.Hour)
	generation, err := store.PublishRelease(ctx, 3, rollout.Release{Digest: strings.Repeat("b", 64), Actor: "ci", CreatedAt: started})
	if err != nil {
		t.Fatal(err)
	}
	record, revision, err := store.Begin(ctx, rollout.Spec{RolloutID: entityid.Derive(rollout.ControllerReleaseDomain, rollout.ReleaseRolloutID(generation.Generation)), Kind: rollout.KindController,
		Cell: "lab", FromDigest: strings.Repeat("a", 64), ToDigest: strings.Repeat("b", 64),
		Units:  []rollout.Unit{{ID: "one", Group: "controllers", Seed: true}, {ID: "two", Group: "controllers"}},
		Policy: rollout.DefaultPolicy(), AuthorityEpoch: 3}, started)
	if err != nil {
		t.Fatal(err)
	}
	preflight, err := rollout.Apply(record, rollout.Event{Kind: rollout.EventStart, At: started})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, revision, preflight); err != nil {
		t.Fatal(err)
	}
	// The planner's budgets: the global home alone fills a one-region
	// ceiling.
	budgets := regionplanner.Budgets{Records: noLifecycleRecords{}, Policy: regionplanner.Policy{MaxRegions: 1,
		Home: regionlifecycle.Home{Cell: "lab", MonthlyCents: 1000}}}

	if err := telemetry.attachController(ctx, controllerObservation{nats: nats, replicas: 1,
		brokerIDs: []string{"one"}, authority: lease, rollouts: store, budgets: budgets}, nil); err != nil {
		t.Fatal(err)
	}
	telemetry.markStarted()
	browse := func(path string) (int, string) {
		t.Helper()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(data)
	}
	// The engine evaluates as soon as it starts; the journal attaches
	// asynchronously, so poll until the insights are listed.
	want := map[string][]string{
		"/insights":                     {"Rollout " + record.RolloutID[:12] + " is past its preflight deadline", "Budget regions is 100% used"},
		"/rollouts":                     {record.RolloutID, "preflight", `href="/rollouts/` + record.RolloutID + `"`},
		"/rollouts/" + record.RolloutID: {"preflight", "Rollout " + record.RolloutID[:12] + " is past its preflight deadline", "Admitted controller rollout " + record.RolloutID},
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		missing := ""
		for path, wants := range want {
			status, page := browse(path)
			for _, text := range wants {
				if status != http.StatusOK || !strings.Contains(page, text) {
					missing = path + " lacks " + text
				}
			}
		}
		if missing == "" {
			break
		}
		if time.Now().After(deadline) {
			_, page := browse("/insights")
			t.Fatalf("%s\n/insights:\n%s", missing, page)
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}
