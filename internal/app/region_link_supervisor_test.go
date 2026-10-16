package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionlink"
	"github.com/TerraScale/ts-orchestrator/internal/regionview"
)

func wanTestSummary(region string, now time.Time) regionview.Summary {
	return regionview.Summary{Version: 1, Region: region, ObservedAt: now, TerraBase: regionview.TerraBase{NativeRegion: region + "-1"},
		Nodes: []regionview.Node{{Name: region + "-1", Services: []regionview.Service{{Role: "terrabase"}}},
			{Name: region + "-2", Services: []regionview.Service{{Role: "terrabase"}}}}}
}

func TestLinkRecoveryRequiresFreshWANAndPublishesMetrics(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	remote := wanTestSummary("sfo", now)
	recorder := new(linkTestRecorder)
	history := observability.NewHistory(observability.HistoryConfig{})
	provider := &regionview.Provider{Cell: "gru", Now: func() time.Time { return now }, History: history, NativeRegion: func() string { return "gru-1" },
		Nodes: func(context.Context) []regionview.Node { return wanTestSummary("gru", now).Nodes }}
	fail := true
	provider.Links = regionlink.Static{LocalRegion: "gru", All: []string{"gru", "sfo"},
		Handler: func(context.Context, string, string, []byte) ([]byte, error) {
			if fail {
				return nil, context.DeadlineExceeded
			}
			remote.ObservedAt = now
			return json.Marshal(remote)
		}}
	supervisor := &regionLinkSupervisor{cell: "gru", member: "a", source: provider, recorder: recorder,
		now: func() time.Time { return now }, reconnect: func(context.Context) (int, error) { return 1, nil }}
	supervisor.round(t.Context())
	failure := supervisor.failures["sfo"]
	fail = false
	now = now.Add(time.Minute)
	supervisor.round(t.Context())
	if supervisor.failures["sfo"] != failure || !supervisor.snapshot()[0].LastSuccessAt.IsZero() {
		t.Fatal("successful NATS with missing WAN claimed recovery")
	}
	for _, node := range remote.Nodes {
		remote.TerraBase.WAN = append(remote.TerraBase.WAN, regionview.WANPeer{SourceRegion: "gru-1",
			Node: node.Name, ObservedAt: now, Members: 2, StalenessSeconds: 1})
	}
	supervisor.round(t.Context())
	if supervisor.failures["sfo"] != "" || !supervisor.snapshot()[0].LastSuccessAt.Equal(now) {
		t.Fatal("fresh authenticated telemetry and complete WAN did not recover")
	}
	last := recorder.decisions[len(recorder.decisions)-1]
	if last.Kind != "region_link_recovered" || last.ParentID != failure || last.Status != decisionlog.StatusSucceeded {
		t.Fatalf("recovery has no causal journal chain: %+v", last)
	}
	var metrics bytes.Buffer
	supervisor.writeMetrics(&metrics)
	for _, want := range []string{`ts_orch_region_link_probe_success{peer="sfo",member="a"} 1`,
		`ts_orch_region_wan_healthy{peer="sfo",member="a"} 1`, `ts_orch_region_wan_lag_groups{peer="sfo",member="a"} 0`} {
		if !strings.Contains(metrics.String(), want) {
			t.Fatalf("metrics omit %q: %s", want, &metrics)
		}
	}
	now = now.Add(3 * time.Minute)
	metrics.Reset()
	supervisor.writeMetrics(&metrics)
	if strings.Contains(metrics.String(), "ts_orch_region_wan_lag_groups{") ||
		!strings.Contains(metrics.String(), `ts_orch_region_link_probe_success{peer="sfo",member="a"} 0`) {
		t.Fatalf("stopped probe metrics retained health: %s", &metrics)
	}
}

func TestWANAheadFailuresRequireNewCounterEvidence(t *testing.T) {
	now := time.Now().UTC()
	supervisor := &regionLinkSupervisor{cell: "gru"}
	remote := wanTestSummary("sfo", now)
	remote.TerraBase.WAN = []regionview.WANPeer{{SourceRegion: "gru-1", Node: "sfo-1", ObservedAt: now,
		AheadFailures: new(5.0)}}
	if supervisor.newAheadFailures(remote, "gru-1", now) {
		t.Fatal("historical counter was treated as a new failure")
	}
	for _, test := range []struct {
		value   float64
		advance bool
		failed  bool
	}{
		{6, true, true}, {6, false, true}, {6, true, false}, {0, true, false}, {2, true, true}, {1, true, true},
	} {
		if test.advance {
			now = now.Add(time.Second)
		}
		remote.TerraBase.WAN[0].ObservedAt = now
		remote.TerraBase.WAN[0].AheadFailures = new(test.value)
		if failed := supervisor.newAheadFailures(remote, "gru-1", now); failed != test.failed {
			t.Fatalf("counter %g advanced=%v failed=%v want=%v", test.value, test.advance, failed, test.failed)
		}
	}
}

func TestWANRequiresEveryReceiverAndExactSourceCoverage(t *testing.T) {
	now := time.Now().UTC()
	local, remote := wanTestSummary("gru", now), wanTestSummary("sfo", now)
	rows := []regionview.WANPeer{{SourceRegion: "gru-1", Node: "sfo-1", ObservedAt: now,
		Members: 2, StalenessSeconds: 1}, {SourceRegion: "gru-1", Node: "sfo-2", ObservedAt: now,
		Members: 2, StalenessSeconds: 1}}
	for name, change := range map[string]func([]regionview.WANPeer) []regionview.WANPeer{
		"healthy":            func(rows []regionview.WANPeer) []regionview.WANPeer { return rows },
		"missing receiver":   func(rows []regionview.WANPeer) []regionview.WANPeer { return rows[:1] },
		"duplicate receiver": func(rows []regionview.WANPeer) []regionview.WANPeer { rows[1] = rows[0]; return rows },
		"zero members":       func(rows []regionview.WANPeer) []regionview.WANPeer { rows[1].Members = 0; return rows },
		"partial members":    func(rows []regionview.WANPeer) []regionview.WANPeer { rows[1].Members = 1; return rows },
		"wrong direction":    func(rows []regionview.WANPeer) []regionview.WANPeer { rows[1].SourceRegion = "fra-1"; return rows },
		"stale": func(rows []regionview.WANPeer) []regionview.WANPeer {
			rows[1].ObservedAt = now.Add(-3 * time.Minute)
			return rows
		},
		"future": func(rows []regionview.WANPeer) []regionview.WANPeer {
			rows[1].ObservedAt = now.Add(3 * time.Minute)
			return rows
		},
		"nonfinite":    func(rows []regionview.WANPeer) []regionview.WANPeer { rows[1].Lag = math.NaN(); return rows },
		"unknown node": func(rows []regionview.WANPeer) []regionview.WANPeer { rows[1].Node = "foreign"; return rows },
	} {
		t.Run(name, func(t *testing.T) {
			remote.TerraBase.WAN = change(append([]regionview.WANPeer(nil), rows...))
			state, lag, _ := checkRegionWAN(local, remote, now)
			if (state == "ok") != (name == "healthy") || (lag != nil) != (name == "healthy") {
				t.Fatalf("WAN accepted incomplete or invalid evidence: state=%s lag=%v", state, lag)
			}
		})
	}
	remote.TerraBase.WAN = append([]regionview.WANPeer(nil), rows...)
	remote.TerraBase.WAN[1].Lag = 7
	if state, lag, _ := checkRegionWAN(local, remote, now); state != "catching_up" || lag == nil || *lag != 7 {
		t.Fatalf("WAN must report worst change-group lag: %s %v", state, lag)
	}
	remote.TerraBase.WAN[1].StalenessSeconds = 61
	if state, _, _ := checkRegionWAN(local, remote, now); state != "failed" {
		t.Fatalf("stalled WAN was not failed: %s", state)
	}
	local.NodesIncomplete = true
	if state, lag, _ := checkRegionWAN(local, remote, now); state != "unknown" || lag != nil {
		t.Fatal("truncated node roster claimed complete WAN coverage")
	}
	local.NodesIncomplete = false
	local.TerraBase.NativeRegion = ""
	if state, lag, _ := checkRegionWAN(local, remote, now); state != "unknown" || lag != nil {
		t.Fatal("missing native identity guessed a source binding")
	}
}

func TestWANArchiveAgeDoesNotEstablishReplicationFailure(t *testing.T) {
	now := time.Now().UTC()
	local, remote := wanTestSummary("gru", now), wanTestSummary("sfo", now)
	for _, node := range remote.Nodes {
		remote.TerraBase.WAN = append(remote.TerraBase.WAN, regionview.WANPeer{SourceRegion: "gru-1",
			Node: node.Name, ObservedAt: now.Add(-65 * time.Second), Members: 2, StalenessSeconds: 1})
	}
	if state, lag, _ := checkRegionWAN(local, remote, now); state != "ok" || lag == nil || *lag != 0 {
		t.Fatalf("healthy archived scrape authorized repair: %s %v", state, lag)
	}
	remote.TerraBase.WAN[0].StalenessSeconds = 61
	if state, _, _ := checkRegionWAN(local, remote, now); state != "failed" {
		t.Fatalf("measured stalled replication did not fail: %s", state)
	}
	if state, lag, _ := checkRegionWAN(local, remote, now.Add(time.Minute)); state != "unknown" || lag != nil {
		t.Fatalf("expired evidence authorized repair: %s %v", state, lag)
	}
}

type linkTestRecorder struct {
	mu        sync.Mutex
	decisions []decisionlog.Decision
}

func (recorder *linkTestRecorder) Record(_ context.Context, decision decisionlog.Decision) string {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	decision.ID = decisionlog.NewID()
	recorder.decisions = append(recorder.decisions, decision)
	return decision.ID
}

func TestLinkSupervisorRunsEveryMinuteWithoutDashboardReaders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var calls atomic.Int32
		provider := &regionview.Provider{Cell: "gru", Links: regionlink.Static{LocalRegion: "gru", All: []string{"gru", "sfo"},
			Handler: func(_ context.Context, _, _ string, _ []byte) ([]byte, error) {
				calls.Add(1)
				return json.Marshal(wanTestSummary("sfo", time.Now().UTC()))
			}}}
		supervisor := &regionLinkSupervisor{cell: "gru", member: "a", source: provider, recorder: decisionlog.Discard{},
			reconnect: func(context.Context) (int, error) {
				t.Fatal("unknown WAN does not authorize a reconnect")
				return 0, nil
			}}
		done := make(chan struct{})
		go func() { _ = supervisor.Run(ctx); close(done) }()
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("startup did not perform a real request")
		}
		time.Sleep(59 * time.Second)
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatal("probe cadence is shorter than one minute")
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatal("probe did not repeat after one minute")
		}
		cancel()
		synctest.Wait()
		<-done
		time.Sleep(time.Minute)
		if calls.Load() != 2 {
			t.Fatal("probe survived controller cancellation")
		}
	})
}

func TestLinkRepairIsCoalescedAndDoesNotClaimRecovery(t *testing.T) {
	now := time.Now().UTC()
	var repairs int
	recorder := new(linkTestRecorder)
	provider := &regionview.Provider{Cell: "gru", Now: func() time.Time { return now }}
	supervisor := &regionLinkSupervisor{cell: "gru", member: "a", source: provider, recorder: recorder,
		now: func() time.Time { return now }, reconnect: func(context.Context) (int, error) { repairs++; return 1, nil }}
	// Requests are concurrent, so count them atomically in the fixture.
	var requests atomic.Int32
	provider.Links = regionlink.Static{LocalRegion: "gru", All: []string{"gru", "sfo", "fra"},
		Handler: func(context.Context, string, string, []byte) ([]byte, error) {
			requests.Add(1)
			return nil, context.DeadlineExceeded
		}}
	supervisor.round(t.Context())
	if repairs != 1 || requests.Load() != 2 {
		t.Fatalf("repair/request counts=%d/%d", repairs, requests.Load())
	}
	for _, probe := range supervisor.snapshot() {
		if probe.Reach == "ok" || !probe.LastSuccessAt.IsZero() || probe.Recovery == "" {
			t.Fatalf("reconnect claimed health: %+v", probe)
		}
	}
	for _, decision := range recorder.decisions {
		if decision.Status == decisionlog.StatusSucceeded {
			t.Fatalf("reconnect was journaled as recovery: %+v", decision)
		}
		if decision.Kind == "region_link_reconnect" && decision.ParentID == "" {
			t.Fatal("repair is not linked to its failed probe")
		}
	}
	now = now.Add(time.Minute)
	supervisor.round(t.Context())
	if repairs != 1 {
		t.Fatal("shared leaf was repeatedly disconnected inside the repair interval")
	}
	if supervisor.snapshot()[0].Recovery == "" {
		t.Fatal("pending repair disappeared during the retry interval")
	}
	now = now.Add(3 * time.Minute)
	if supervisor.snapshot()[0].Reach != "stale" {
		t.Fatal("stopped probe retained fresh health")
	}
}

func TestLinkRepairCooldownSurvivesInterveningRounds(t *testing.T) {
	for _, intermediateWAN := range []string{"unknown", "ok"} {
		t.Run(intermediateWAN, func(t *testing.T) {
			now := time.Now().UTC()
			start := now
			failed := true
			repairs := 0
			provider := &regionview.Provider{Cell: "gru", Now: func() time.Time { return now },
				NativeRegion: func() string { return "gru-1" },
				Nodes:        func(context.Context) []regionview.Node { return wanTestSummary("gru", now).Nodes }}
			provider.Links = regionlink.Static{LocalRegion: "gru", All: []string{"gru", "sfo"},
				Handler: func(context.Context, string, string, []byte) ([]byte, error) {
					if failed {
						return nil, context.DeadlineExceeded
					}
					remote := wanTestSummary("sfo", now)
					if intermediateWAN == "ok" {
						for _, node := range remote.Nodes {
							remote.TerraBase.WAN = append(remote.TerraBase.WAN, regionview.WANPeer{SourceRegion: "gru-1",
								Node: node.Name, ObservedAt: now, Members: 2, StalenessSeconds: 1})
						}
					}
					return json.Marshal(remote)
				}}
			supervisor := &regionLinkSupervisor{cell: "gru", source: provider, recorder: decisionlog.Discard{},
				now: func() time.Time { return now }, reconnect: func(context.Context) (int, error) { repairs++; return 1, nil }}
			supervisor.round(t.Context())
			deadline := supervisor.nextRepair
			failed, now = false, start.Add(time.Minute)
			supervisor.round(t.Context())
			if supervisor.snapshot()[0].WAN != intermediateWAN {
				t.Fatalf("intervening WAN state = %s", supervisor.snapshot()[0].WAN)
			}
			failed, now = true, start.Add(2*time.Minute)
			supervisor.round(t.Context())
			if repairs != 1 || !supervisor.nextRepair.Equal(deadline) {
				t.Fatalf("intervening %s round reset the repair bound: repairs=%d deadline=%s", intermediateWAN, repairs, supervisor.nextRepair)
			}
			now = deadline
			supervisor.round(t.Context())
			if repairs != 2 {
				t.Fatalf("repair did not retry at its deadline: %d", repairs)
			}
		})
	}
}

type partiallyLinkedTestRegions struct{ regionlink.Static }

func (links partiallyLinkedTestRegions) Linked(region string) bool { return region == "sfo" }

func TestLinkRepairJournalNamesTheFailedAdmittedPeer(t *testing.T) {
	now := time.Now().UTC()
	recorder := new(linkTestRecorder)
	provider := &regionview.Provider{Cell: "gru", Links: partiallyLinkedTestRegions{regionlink.Static{
		LocalRegion: "gru", All: []string{"gru", "fra", "sfo"},
		Handler: func(_ context.Context, region, _ string, _ []byte) ([]byte, error) {
			if region == "fra" {
				return nil, regionlink.ErrNotLinked
			}
			return nil, context.DeadlineExceeded
		},
	}}}
	supervisor := &regionLinkSupervisor{cell: "gru", source: provider, recorder: recorder, now: func() time.Time { return now },
		reconnect: func(context.Context) (int, error) { return 1, nil }}
	supervisor.round(t.Context())
	for _, decision := range recorder.decisions {
		if decision.Subject.ID != "sfo" {
			t.Fatalf("failure or repair attributed to an unlinked peer: %+v", decision)
		}
	}
	if probes := supervisor.snapshot(); probes[0].Recovery != "" || probes[1].Recovery == "" {
		t.Fatalf("repair outcome attributed to wrong probe: %+v", probes)
	}
	if probe := supervisor.snapshot()[0]; probe.Reach != decisionlog.RegionNotLinked || strings.Contains(probe.Detail, "request failed") {
		t.Fatalf("unlinked region reported a failed authenticated request: %+v", probe)
	}
	now = now.Add(3 * time.Minute)
	if probe := supervisor.snapshot()[0]; probe.Reach != decisionlog.RegionNotLinked {
		t.Fatalf("unlinked region became an outage when the worker stopped: %+v", probe)
	}
}

func TestIncompleteOrCatchingUpWANDoesNotStartFailureEpisode(t *testing.T) {
	now := time.Now().UTC()
	for _, state := range []string{regionlink.WANUnknown, regionlink.WANCatchingUp} {
		t.Run(state, func(t *testing.T) {
			recorder := new(linkTestRecorder)
			provider := &regionview.Provider{Cell: "gru", Now: func() time.Time { return now },
				NativeRegion: func() string { return "gru-1" },
				Nodes:        func(context.Context) []regionview.Node { return wanTestSummary("gru", now).Nodes }}
			provider.Links = regionlink.Static{LocalRegion: "gru", All: []string{"gru", "sfo"},
				Handler: func(context.Context, string, string, []byte) ([]byte, error) {
					remote := wanTestSummary("sfo", now)
					if state == regionlink.WANCatchingUp {
						for _, node := range remote.Nodes {
							remote.TerraBase.WAN = append(remote.TerraBase.WAN, regionview.WANPeer{SourceRegion: "gru-1",
								Node: node.Name, ObservedAt: now, Members: 2, Lag: 7, StalenessSeconds: 1})
						}
					}
					return json.Marshal(remote)
				}}
			supervisor := &regionLinkSupervisor{cell: "gru", source: provider, recorder: recorder, now: func() time.Time { return now },
				reconnect: func(context.Context) (int, error) { t.Fatal("non-failed WAN authorized repair"); return 0, nil }}
			supervisor.round(t.Context())
			if len(recorder.decisions) != 0 || len(supervisor.failures) != 0 || supervisor.snapshot()[0].WAN != state {
				t.Fatalf("normal or incomplete evidence became a failed episode: probes=%+v decisions=%+v", supervisor.snapshot(), recorder.decisions)
			}
		})
	}
}

type changingLinkedTestRegions struct {
	regionlink.Static
	linked atomic.Bool
}

func (links *changingLinkedTestRegions) Linked(string) bool { return links.linked.Load() }

func TestLinkRepairRequiresCurrentPeerAdmission(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		linked bool
		repair bool
	}{
		{name: "removed peer with failed WAN"},
		{name: "removed peer with failed request", err: context.DeadlineExceeded},
		{name: "removed peer before dispatch", err: regionlink.ErrUnknownRegion},
		{name: "removed peer readded before decision", err: regionlink.ErrUnknownRegion, linked: true},
		{name: "admitted peer without physical leaf", err: nats.ErrNoResponders, linked: true, repair: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC()
			recorder := new(linkTestRecorder)
			links := &changingLinkedTestRegions{Static: regionlink.Static{LocalRegion: "gru", All: []string{"gru", "sfo"}}}
			links.linked.Store(true)
			links.Handler = func(context.Context, string, string, []byte) ([]byte, error) {
				remote := wanTestSummary("sfo", now)
				for _, node := range remote.Nodes {
					remote.TerraBase.WAN = append(remote.TerraBase.WAN, regionview.WANPeer{SourceRegion: "gru-1",
						Node: node.Name, ObservedAt: now, Members: 2, StalenessSeconds: 61})
				}
				data, err := json.Marshal(remote)
				if err != nil {
					return nil, err
				}
				// Membership can change after the round snapshots peers and before its decisions.
				links.linked.Store(false)
				links.linked.Store(test.linked)
				return data, test.err
			}
			provider := &regionview.Provider{Cell: "gru", Links: links, Now: func() time.Time { return now },
				NativeRegion: func() string { return "gru-1" },
				Nodes:        func(context.Context) []regionview.Node { return wanTestSummary("gru", now).Nodes }}
			repairs := 0
			supervisor := &regionLinkSupervisor{cell: "gru", source: provider, recorder: recorder, now: func() time.Time { return now },
				reconnect: func(context.Context) (int, error) { repairs++; return 0, natscell.ErrUnavailable }}
			supervisor.round(t.Context())
			if (repairs == 1) != test.repair {
				t.Fatalf("current admission did not control repair: repairs=%d decisions=%+v", repairs, recorder.decisions)
			}
			probe := supervisor.snapshot()[0]
			if errors.Is(test.err, regionlink.ErrUnknownRegion) && (probe.Reach != decisionlog.RegionNotLinked || strings.Contains(probe.Detail, "request failed")) {
				t.Fatalf("pre-dispatch removal became an authenticated request outage: %+v", probe)
			}
			if !test.repair {
				if len(recorder.decisions) != 0 || len(supervisor.failures) != 0 || probe.Recovery != "" {
					t.Fatalf("ineligible peer started a failure or repair episode: probe=%+v decisions=%+v", probe, recorder.decisions)
				}
				return
			}
			if len(recorder.decisions) != 3 {
				t.Fatalf("admitted outage lost its causal journal: %+v", recorder.decisions)
			}
			failed, repair, outcome := recorder.decisions[0], recorder.decisions[1], recorder.decisions[2]
			if failed.Kind != "region_link_failed" || repair.ParentID != failed.ID || outcome.ParentID != repair.ID ||
				outcome.Status != decisionlog.StatusFailed || supervisor.failures["sfo"] != failed.ID || !probe.LastSuccessAt.IsZero() {
				t.Fatalf("zero physical leaves lost the failure chain or claimed recovery: probe=%+v decisions=%+v", probe, recorder.decisions)
			}
		})
	}
}

func TestWANAheadFailuresPreserveUnknownEvidence(t *testing.T) {
	for _, evidence := range []string{"unregistered", "incomplete", "complete"} {
		t.Run(evidence, func(t *testing.T) {
			now := time.Now().UTC()
			recorder := new(linkTestRecorder)
			counter := 5.0
			provider := &regionview.Provider{Cell: "gru", Now: func() time.Time { return now },
				NativeRegion: func() string { return "gru-1" },
				Nodes:        func(context.Context) []regionview.Node { return wanTestSummary("gru", now).Nodes }}
			provider.Links = regionlink.Static{LocalRegion: "gru", All: []string{"gru", "sfo"},
				Handler: func(context.Context, string, string, []byte) ([]byte, error) {
					remote := wanTestSummary("sfo", now)
					for _, node := range remote.Nodes {
						remote.TerraBase.WAN = append(remote.TerraBase.WAN, regionview.WANPeer{SourceRegion: "gru-1",
							Node: node.Name, ObservedAt: now, Members: 2, StalenessSeconds: 1, AheadFailures: new(counter)})
					}
					if counter > 5 {
						switch evidence {
						case "unregistered":
							remote.TerraBase.WAN[0].Unregistered = 1
						case "incomplete":
							remote.TerraBase.WAN = remote.TerraBase.WAN[:1]
						}
					}
					return json.Marshal(remote)
				}}
			repairs := 0
			supervisor := &regionLinkSupervisor{cell: "gru", source: provider, recorder: recorder, now: func() time.Time { return now },
				reconnect: func(context.Context) (int, error) { repairs++; return 1, nil }}
			supervisor.round(t.Context())
			if supervisor.snapshot()[0].WAN != regionlink.WANOK || len(recorder.decisions) != 0 {
				t.Fatal("historical ahead counter was treated as a new failure")
			}
			now, counter = now.Add(time.Minute), 6
			supervisor.round(t.Context())
			probe := supervisor.snapshot()[0]
			if evidence == "complete" {
				if probe.WAN != regionlink.WANFailed || repairs != 1 || len(recorder.decisions) != 3 {
					t.Fatalf("coherent new ahead failures did not authorize repair: probe=%+v decisions=%+v", probe, recorder.decisions)
				}
			} else if probe.WAN != regionlink.WANUnknown || repairs != 0 || len(recorder.decisions) != 0 || len(supervisor.failures) != 0 {
				t.Fatalf("new ahead failures promoted unknown WAN evidence: probe=%+v decisions=%+v", probe, recorder.decisions)
			}
		})
	}
}
