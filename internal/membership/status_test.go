package membership

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

var expectedBrokers = []string{"cell-controller-a", "cell-controller-b", "cell-controller-c"}

func healthyObservation() Observation {
	return Observation{ServerName: "cell-controller-a", Running: true, Expected: expectedBrokers,
		Routes:     []string{"cell-controller-b", "cell-controller-c"},
		MetaLeader: "cell-controller-b", MetaSize: 3, MetaQuorum: 2,
		Peers: []Peer{{Name: "cell-controller-c", Current: true}, {Name: "cell-controller-b", Current: true}}}
}

func TestEvaluateClassifiesClusterStates(t *testing.T) {
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		mutate func(*Observation)
		check  func(*testing.T, Status)
	}{
		{"healthy", func(*Observation) {}, func(t *testing.T, status Status) {
			if status.Phase != PhaseHealthy || !slices.Equal(status.Online, expectedBrokers) ||
				status.Offline != nil || status.Missing != nil || status.Unknown != nil {
				t.Fatalf("status = %+v", status)
			}
		}},
		{"stopped", func(observation *Observation) { observation.Running = false }, func(t *testing.T, status Status) {
			if status.Phase != PhaseStopped {
				t.Fatalf("status = %+v", status)
			}
		}},
		{"offline peer", func(observation *Observation) {
			observation.Peers[0] = Peer{Name: "cell-controller-c", Offline: true}
			observation.Routes = observation.Routes[:1]
		}, func(t *testing.T, status Status) {
			if status.Phase != PhaseDegraded || !slices.Equal(status.Offline, []string{"cell-controller-c"}) ||
				!slices.Equal(status.Unrouted, []string{"cell-controller-c"}) {
				t.Fatalf("status = %+v", status)
			}
		}},
		{"never joined", func(observation *Observation) {
			observation.Peers = observation.Peers[1:]
			observation.MetaSize = 2
		}, func(t *testing.T, status Status) {
			if status.Phase != PhaseDegraded || !slices.Equal(status.Missing, []string{"cell-controller-c"}) {
				t.Fatalf("status = %+v", status)
			}
		}},
		{"unknown peer", func(observation *Observation) {
			observation.Peers = append(observation.Peers, Peer{Name: "cell-controller-z", Current: true})
			observation.MetaSize = 4
		}, func(t *testing.T, status Status) {
			if status.Phase != PhaseDegraded || !slices.Equal(status.Unknown, []string{"cell-controller-z"}) {
				t.Fatalf("status = %+v", status)
			}
		}},
		{"lagging peer", func(observation *Observation) {
			observation.Peers[0].Lag = 5000
		}, func(t *testing.T, status Status) {
			if status.Phase != PhaseDegraded || len(status.Lagging) != 1 || status.Lagging[0].Name != "cell-controller-c" {
				t.Fatalf("status = %+v", status)
			}
		}},
		{"not current", func(observation *Observation) {
			observation.Peers[1].Current = false
		}, func(t *testing.T, status Status) {
			if status.Phase != PhaseDegraded || len(status.Lagging) != 1 || status.Lagging[0].Name != "cell-controller-b" {
				t.Fatalf("status = %+v", status)
			}
		}},
		{"size mismatch", func(observation *Observation) { observation.MetaSize = 2 }, func(t *testing.T, status Status) {
			if status.Phase != PhaseDegraded {
				t.Fatalf("status = %+v", status)
			}
		}},
		{"no leader", func(observation *Observation) { observation.MetaLeader = "" }, func(t *testing.T, status Status) {
			if status.Phase != PhaseNoLeader {
				t.Fatalf("status = %+v", status)
			}
		}},
		{"lab without signed set", func(observation *Observation) {
			observation.Expected = nil
			observation.MetaSize = 5
		}, func(t *testing.T, status Status) {
			if status.Phase != PhaseHealthy || status.Unknown != nil || status.Missing != nil {
				t.Fatalf("status = %+v", status)
			}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			observation := healthyObservation()
			observation.Peers = slices.Clone(observation.Peers)
			test.mutate(&observation)
			status := Evaluate(observation, DefaultLagThreshold, now)
			if !status.ObservedAt.Equal(now) {
				t.Fatalf("observed at = %s", status.ObservedAt)
			}
			test.check(t, status)
		})
	}
}

type recordingReporter struct {
	mu       sync.Mutex
	statuses []Status
}

func (reporter *recordingReporter) ReportClusterHealth(status Status) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	reporter.statuses = append(reporter.statuses, status)
}

func TestSupervisorLogsTransitionsAndReportsEveryTick(t *testing.T) {
	var logs bytes.Buffer
	observation := healthyObservation()
	var observeErr error
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	reporter := &recordingReporter{}
	supervisor := &Supervisor{
		Observe:  func() (Observation, error) { return observation, observeErr },
		Interval: time.Second, Remind: time.Hour,
		Logger:   slog.New(slog.NewTextHandler(&logs, nil)),
		Reporter: reporter, Now: func() time.Time { return now },
	}
	if _, ok := supervisor.Current(); ok {
		t.Fatal("supervisor reported status before observing")
	}
	supervisor.Tick()
	supervisor.Tick()
	if count := strings.Count(logs.String(), "msg="); count != 1 {
		t.Fatalf("steady healthy cluster logged %d lines:\n%s", count, logs.String())
	}
	observation.Peers = []Peer{{Name: "cell-controller-b", Current: true}, {Name: "cell-controller-c", Offline: true}}
	status := supervisor.Tick()
	if status.Phase != PhaseDegraded || !strings.Contains(logs.String(), "level=WARN") ||
		!strings.Contains(logs.String(), "offline=[cell-controller-c]") {
		t.Fatalf("degraded transition not logged: %+v\n%s", status, logs.String())
	}
	observeErr = errors.New("jsz unavailable")
	if status := supervisor.Tick(); status.Phase != PhaseUnknown || status.Error == "" {
		t.Fatalf("observation error status = %+v", status)
	}
	current, ok := supervisor.Current()
	if !ok || current.Phase != PhaseUnknown {
		t.Fatalf("current = %+v %v", current, ok)
	}
	if len(reporter.statuses) != 4 {
		t.Fatalf("reporter saw %d statuses", len(reporter.statuses))
	}
}

func TestSupervisorRemindsWhileDegraded(t *testing.T) {
	var logs bytes.Buffer
	observation := healthyObservation()
	observation.MetaLeader = ""
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	supervisor := &Supervisor{Observe: func() (Observation, error) { return observation, nil },
		Interval: time.Second, Remind: time.Minute,
		Logger: slog.New(slog.NewTextHandler(&logs, nil)), Now: func() time.Time { return now }}
	supervisor.Tick()
	now = now.Add(30 * time.Second)
	supervisor.Tick()
	now = now.Add(31 * time.Second)
	supervisor.Tick()
	if count := strings.Count(logs.String(), "msg="); count != 2 {
		t.Fatalf("degraded cluster logged %d lines, want transition plus one reminder:\n%s", count, logs.String())
	}
}

func TestSupervisorRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	ticks := make(chan struct{}, 8)
	supervisor := &Supervisor{Interval: 10 * time.Millisecond, Logger: slog.New(slog.DiscardHandler),
		Observe: func() (Observation, error) {
			select {
			case ticks <- struct{}{}:
			default:
			}
			return healthyObservation(), nil
		}}
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	<-ticks
	<-ticks
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("supervisor did not stop after cancellation")
	}
	if err := (&Supervisor{}).Run(t.Context()); err == nil {
		t.Fatal("supervisor without an observer started")
	}
}
