package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/insights"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/nats-io/nats.go/jetstream"
)

func TestDashboardRolloutHistoryRetainsTerminalRecords(t *testing.T) {
	original := slog.Default()
	t.Cleanup(func() { slog.SetDefault(original) })
	for _, phase := range []rollout.Phase{rollout.PhaseComplete, rollout.PhaseAborted, rollout.PhaseRolledBack, rollout.PhaseFrozen} {
		t.Run(string(phase), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
			defer cancel()
			auth := newAuthenticatedNATS(t, "lab")
			broker, err := auth.start(t, ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1,
				Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = broker.Close() })
			lease := observedAuthority{snapshot: authority.Snapshot{Leader: true, Ready: true, Epoch: 3, ExpiresAt: time.Now().Add(time.Hour)}}
			store, err := rollout.OpenStore(ctx, broker.JetStream(), "lab", 1, lease)
			if err != nil {
				t.Fatal(err)
			}
			token := strings.Repeat("d", 40)
			tokenFile := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(tokenFile, []byte(token), 0600); err != nil {
				t.Fatal(err)
			}
			telemetry, err := startRuntimeObservability(ctx, Config{NATS: natscell.Config{Cell: "lab", Instance: "one"},
				Observability: observability.Config{ListenAddress: freeLoopbackAddress(t), BearerTokenFile: tokenFile}}, "controller", "one")
			if err != nil || telemetry.server == nil {
				t.Fatalf("observability: %v", err)
			}
			defer telemetry.close()
			started := time.Now().UTC().Truncate(time.Second).Add(-48 * time.Hour)
			generation, err := store.PublishRelease(ctx, 3, rollout.Release{Digest: strings.Repeat("b", 64), Actor: "ci", CreatedAt: started})
			if err != nil {
				t.Fatal(err)
			}
			id := entityid.Derive(rollout.ControllerReleaseDomain, rollout.ReleaseRolloutID(generation.Generation))
			record, revision, err := store.Begin(ctx, rollout.Spec{RolloutID: id, Kind: rollout.KindController, Cell: "lab",
				FromDigest: strings.Repeat("a", 64), ToDigest: generation.Digest,
				Units:  []rollout.Unit{{ID: "one", Group: "controllers", Seed: true}, {ID: "two", Group: "controllers"}},
				Policy: rollout.DefaultPolicy(), AuthorityEpoch: 3}, started)
			if err != nil {
				t.Fatal(err)
			}
			var cachedBoard *dashboard.Dashboard
			if phase == rollout.PhaseComplete {
				cachedBoard = dashboard.New(dashboard.Options{Journal: &dashboard.Journal{Rollouts: dashboardRollouts{store: store}}})
				for _, path := range []string{"/rollouts", "/rollouts/" + id} {
					response := httptest.NewRecorder()
					cachedBoard.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx))
					if !strings.Contains(response.Body.String(), `<span class="pill s-run">pending</span>`) {
						t.Fatal("real-store dashboard did not show the admitted active rollout")
					}
				}
			}
			at := started
			apply := func(event rollout.Event) {
				t.Helper()
				record, err = rollout.Apply(record, event)
				if err != nil {
					t.Fatal(err)
				}
				revision, err = store.Commit(ctx, revision, record)
				if err != nil {
					t.Fatal(err)
				}
			}
			apply(rollout.Event{Kind: rollout.EventStart, At: at})
			switch phase {
			case rollout.PhaseAborted:
				apply(rollout.Event{Kind: rollout.EventAbort, At: at.Add(time.Second)})
			case rollout.PhaseFrozen:
				apply(rollout.Event{Kind: rollout.EventFreeze, At: at.Add(time.Second)})
			default:
				apply(rollout.Event{Kind: rollout.EventPreflightPassed, At: at})
				if phase == rollout.PhaseRolledBack {
					apply(rollout.Event{Kind: rollout.EventAbort, At: at})
					for _, unit := range record.RollbackOrder {
						apply(rollout.Event{Kind: rollout.EventRollbackServing, Unit: unit, At: at.Add(time.Second)})
					}
				} else {
					for !record.Phase.Terminal() {
						wave := slices.Clone(record.Waves[record.WaveIndex])
						for _, unit := range wave {
							apply(rollout.Event{Kind: rollout.EventPrepared, Unit: unit, At: at})
						}
						soak := record.Policy.BatchSoakSeconds
						if record.WaveIndex == 0 {
							soak = record.Policy.CanarySoakSeconds
						}
						for report := range record.Policy.MinHealthyReports {
							observed := at.Add(time.Duration(report) * time.Duration(soak) * time.Second / time.Duration(record.Policy.MinHealthyReports-1))
							for _, unit := range wave {
								apply(rollout.Event{Kind: rollout.EventHealthy, Unit: unit, At: observed,
									Health: rollout.Health{Digest: record.ToDigest, ProcessID: 1, StartNonce: strings.Repeat("1", 32), ObservedAt: observed}})
							}
						}
						at = record.PhaseStartedAt
					}
				}
			}
			state, _, err := store.Cell(ctx)
			if err != nil || (state.ActiveRolloutID == "") != phase.Terminal() || record.Phase != phase {
				t.Fatalf("terminal slot/phase: %+v %s %v", state, record.Phase, err)
			}
			active, err := store.Rollouts(ctx)
			if err != nil || phase.Terminal() && len(active) != 0 {
				t.Fatalf("insight provider: %+v %v", active, err)
			}

			// Reconnect and reopen: the dashboard must read persisted outcomes, not an executor's memory.
			reconnected, err := auth.start(t, ctx, natscell.Config{URL: broker.Conn().ConnectedUrl()})
			if err != nil {
				t.Fatal(err)
			}
			defer reconnected.Close()
			js, err := jetstream.New(reconnected.Conn())
			if err != nil {
				t.Fatal(err)
			}
			store, err = rollout.OpenStore(ctx, js, "lab", 1, lease)
			if err != nil {
				t.Fatal(err)
			}
			loaded, _, err := store.Load(ctx, id)
			if err != nil || loaded.Phase != phase {
				t.Fatalf("persisted record: %s %v", loaded.Phase, err)
			}

			if err := telemetry.attachController(ctx, controllerObservation{nats: broker, replicas: 1, brokerIDs: []string{"one"}, authority: lease, rollouts: store}, nil); err != nil {
				t.Fatal(err)
			}
			browse := func(path string, authorized bool) *httptest.ResponseRecorder {
				t.Helper()
				request := httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx)
				if authorized {
					request.Header.Set("Authorization", "Bearer "+token)
				}
				response := httptest.NewRecorder()
				telemetry.server.ServeHTTP(response, request)
				return response
			}
			for _, path := range []string{"/rollouts", "/rollouts/" + id} {
				page := browse(path, true)
				pill := map[rollout.Phase]string{rollout.PhaseComplete: "ok", rollout.PhaseAborted: "bad", rollout.PhaseRolledBack: "serious", rollout.PhaseFrozen: "warn"}[phase]
				for _, want := range []string{id, `<span class="pill s-` + pill + `">` + string(phase) + `</span>`, `class="phase-row"`, record.PhaseStartedAt.Format(time.RFC3339)} {
					if page.Code != http.StatusOK || !strings.Contains(page.Body.String(), want) {
						t.Errorf("%s lost retained %s: missing %s (HTTP %d)", path, phase, want, page.Code)
					}
				}
				if response := browse(path, false); response.Code != http.StatusUnauthorized {
					t.Errorf("unauthorized %s = %d", path, response.Code)
				}
			}
			if response := browse("/v1/decisions", false); response.Code != http.StatusUnauthorized {
				t.Errorf("unauthorized decisions = %d", response.Code)
			}
			if cachedBoard != nil {
				select {
				case <-time.After(5 * time.Second):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				for _, path := range []string{"/rollouts", "/rollouts/" + id} {
					response := httptest.NewRecorder()
					cachedBoard.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx))
					if !strings.Contains(response.Body.String(), `<span class="pill s-ok">complete</span>`) {
						t.Error("real-store completion stayed active after cache expiry")
					}
				}
			}
			engine := insights.NewEngine(insights.Config{Region: "lab", Rollouts: store})
			for _, insight := range engine.Evaluate(ctx).Insights {
				if phase.Terminal() && insight.Entity.Kind == "rollout" {
					t.Errorf("historical rollout raised an insight: %+v", insight)
				}
			}
			query := "/v1/decisions?region=lab&subject_id=" + record.ToDigest + "&limit=100"
			var result decisionlog.Result
			// The attached stream replays asynchronously; memory can already hold the terminal decision.
			for {
				response := browse(query, true)
				result = decisionlog.Result{}
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &result) != nil || result.Truncated {
					t.Fatalf("regional decisions unavailable: %d %s", response.Code, response.Body.String())
				}
				if !result.Partial {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatalf("regional decisions stayed partial: %v; %s", ctx.Err(), response.Body.String())
				case <-time.After(20 * time.Millisecond):
				}
			}
			found := false
			for _, decision := range result.Decisions {
				if decision.Attrs["rollout"] == id && decision.Attrs["phase"] == string(phase) {
					found = true
					status := map[rollout.Phase]decisionlog.Status{rollout.PhaseComplete: decisionlog.StatusSucceeded,
						rollout.PhaseAborted: decisionlog.StatusFailed, rollout.PhaseRolledBack: decisionlog.StatusRolledBack, rollout.PhaseFrozen: decisionlog.StatusPending}[phase]
					if decision.Status != status || decision.Region != "lab" {
						t.Errorf("terminal decision identity: %+v", decision)
					}
					chainResponse := browse("/v1/decisions/"+decision.ID, true)
					var chain decisionlog.Chain
					if chainResponse.Code != http.StatusOK || json.Unmarshal(chainResponse.Body.Bytes(), &chain) != nil || len(chain.Decisions) < 2 {
						t.Errorf("terminal decision chain lost: %d %s", chainResponse.Code, chainResponse.Body.String())
					}
				}
			}
			if !found {
				t.Errorf("regional journal lost %s decision identity", phase)
			}
			if phase.Terminal() {
				for index := range rollout.ReleaseHistory {
					_, err := store.PublishRelease(ctx, 3, rollout.Release{Digest: fmt.Sprintf("%064x", index+3), Actor: "ci", CreatedAt: time.Now()})
					if err != nil {
						t.Fatal(err)
					}
				}
				board := dashboard.New(dashboard.Options{})
				telemetry.addBoard(board, nil)
				for _, path := range []string{"/rollouts", "/rollouts/" + id} {
					response := httptest.NewRecorder()
					board.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil).WithContext(ctx))
					pill := `<span class="pill s-` + map[rollout.Phase]string{rollout.PhaseComplete: "ok", rollout.PhaseAborted: "bad", rollout.PhaseRolledBack: "serious"}[phase] + `">` + string(phase) + `</span>`
					if path == "/rollouts" && strings.Contains(response.Body.String(), `href="/rollouts/`+id+`"`) {
						t.Error("old record leaked into recent window")
					}
					if path != "/rollouts" && !strings.Contains(response.Body.String(), pill) {
						t.Error("exact older-than-window detail lost terminal phase")
					}
				}
			}
		})
	}
}

func TestDashboardRolloutStoreFailuresStayUnavailable(t *testing.T) {
	ctx := t.Context()
	auth := newAuthenticatedNATS(t, "lab")
	broker, err := auth.start(t, ctx, natscell.Config{Cell: "lab", Instance: "one", Replicas: 1,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "js")}})
	if err != nil {
		t.Fatal(err)
	}
	defer broker.Close()
	lease := observedAuthority{snapshot: authority.Snapshot{Leader: true, Ready: true, Epoch: 3, ExpiresAt: time.Now().Add(time.Hour)}}
	reconnected, err := auth.start(t, ctx, natscell.Config{URL: broker.Conn().ConnectedUrl()})
	if err != nil {
		t.Fatal(err)
	}
	defer reconnected.Close()
	js, err := jetstream.New(reconnected.Conn())
	if err != nil {
		t.Fatal(err)
	}
	store, err := rollout.OpenStore(ctx, js, "lab", 1, lease)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := store.PublishRelease(ctx, 3, rollout.Release{Digest: strings.Repeat("b", 64), Actor: "ci", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	id := entityid.Derive(rollout.ControllerReleaseDomain, rollout.ReleaseRolloutID(generation.Generation))
	record, revision, err := store.Begin(ctx, rollout.Spec{RolloutID: id, Kind: rollout.KindController, Cell: "lab",
		FromDigest: strings.Repeat("a", 64), ToDigest: generation.Digest, Units: []rollout.Unit{{ID: "one", Group: "controllers", Seed: true}, {ID: "two", Group: "controllers"}},
		Policy: rollout.DefaultPolicy(), AuthorityEpoch: 3}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	record, err = rollout.Apply(record, rollout.Event{Kind: rollout.EventAbort, At: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(ctx, revision, record); err != nil {
		t.Fatal(err)
	}
	source := dashboardRollouts{store: store}
	missing := entityid.Derive(rollout.HostReleaseDomain, rollout.ReleaseRolloutID(generation.Generation))
	if _, err := source.Rollout(ctx, missing); !errors.Is(err, dashboard.ErrRolloutNotFound) {
		t.Fatal("missing record was not classified:", err)
	}
	kv, err := js.KeyValue(ctx, rollout.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	// A record-free reservation recovered by the store produces a genuine abandonment marker.
	state, _, err := store.Cell(ctx)
	if err != nil {
		t.Fatal(err)
	}
	state.ActiveRolloutID = missing
	if state.Attempts == nil {
		state.Attempts = make(map[string]int)
	}
	state.Attempts[generation.Digest]++
	wire, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(ctx, "cell", wire); err != nil {
		t.Fatal(err)
	}
	if err := store.RecoverReservation(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Rollout(ctx, missing); !errors.Is(err, dashboard.ErrRolloutNotFound) {
		t.Fatal("abandonment was not classified:", err)
	}
	for _, failure := range []string{"malformed", "wrong-cell", "wrong-id", "canceled", "disconnected"} {
		t.Run(failure, func(t *testing.T) {
			readCtx := t.Context()
			altered := record.Clone()
			if failure == "wrong-cell" {
				altered.Cell = "sfo"
			}
			if failure == "wrong-id" {
				altered.RolloutID = missing
			}
			wire, err := json.Marshal(altered)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "malformed" {
				wire = []byte("{secret upstream detail")
			}
			written, err := kv.Put(ctx, id, wire)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "canceled" {
				var cancel context.CancelFunc
				readCtx, cancel = context.WithCancel(readCtx)
				cancel()
			}
			if failure == "disconnected" {
				reconnected.Conn().Close()
			}
			if _, err := source.Rollout(readCtx, id); err == nil || errors.Is(err, dashboard.ErrRolloutNotFound) {
				t.Fatalf("failed exact read became absence/success: %v", err)
			}
			if rows, err := source.Rollouts(readCtx); err == nil || len(rows) != 0 {
				t.Fatalf("failed list became success: %+v %v", rows, err)
			}
			if failure != "canceled" {
				board := dashboard.New(dashboard.Options{Journal: &dashboard.Journal{Rollouts: source}})
				for _, path := range []string{"/rollouts", "/rollouts/" + id} {
					response := httptest.NewRecorder()
					board.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
					body := response.Body.String()
					if !strings.Contains(body, "unavailable") || strings.Contains(body, "No recorded release rollout") || strings.Contains(body, "No retained rollout record") || strings.Contains(body, "secret upstream") || strings.Contains(body, `<span class="pill s-bad">aborted</span>`) {
						t.Errorf("%s hid or leaked store failure", path)
					}
				}
			}
			if failure != "disconnected" {
				entry, err := kv.Get(ctx, id)
				if err != nil || entry.Revision() != written {
					t.Fatal("dashboard read mutated the record")
				}
			}
		})
	}
	// An invalid ID is rejected before reaching even a disconnected store.
	if _, err := source.Rollout(ctx, "invalid-id"); !errors.Is(err, rollout.ErrInvalid) {
		t.Fatal("ID validation reached disconnected storage:", err)
	}
}
