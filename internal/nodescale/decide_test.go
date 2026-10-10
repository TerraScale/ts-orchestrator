package nodescale

import (
	"math/rand/v2"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func ago(d time.Duration) time.Time { return t0.Add(-d) }

func uniform(u float64) map[Signal]float64 {
	m := make(map[Signal]float64, len(Signals))
	for _, sig := range Signals {
		m[sig] = u
	}
	return m
}

// flat returns one complete sample every Interval from `from` through `to`, every signal at u.
func flat(from, to time.Time, nodes int, u float64) []Sample {
	var out []Sample
	for at := from; !at.After(to); at = at.Add(Interval) {
		out = append(out, Sample{At: at, Nodes: nodes, Reporting: nodes, Utilization: uniform(u)})
	}
	return out
}

// partial makes sample i report one node fewer than the region has.
func partial(samples []Sample, i int) []Sample {
	samples[i].Reporting--
	return samples
}

func TestDecide(t *testing.T) {
	tests := []struct {
		name      string
		state     State
		action    Action
		want      int
		saturated bool
		reason    string
	}{
		{
			name:   "up after 5m of cpu 0.8",
			state:  State{Nodes: 4, Allowance: 12, Samples: flat(ago(5*time.Minute), t0, 4, 0.8)},
			action: Up, want: 5, reason: "cpu 0.80 >= 0.75 for 5m0s",
		},
		{
			name:   "no up at 4m",
			state:  State{Nodes: 4, Allowance: 12, Samples: flat(ago(4*time.Minute), t0, 4, 0.8)},
			action: Hold, want: 4, reason: "load within band",
		},
		{
			name: "2m spike holds",
			state: State{Nodes: 4, Allowance: 12, Samples: append(
				flat(ago(10*time.Minute), ago(2*time.Minute+30*time.Second), 4, 0.3),
				flat(ago(2*time.Minute), t0, 4, 0.8)...)},
			action: Hold, want: 4, reason: "load within band",
		},
		{
			name:   "budget blocks up",
			state:  State{Nodes: 4, Allowance: 4, Samples: flat(ago(5*time.Minute), t0, 4, 0.8)},
			action: Hold, want: 5, reason: "the budget allows 4 nodes",
		},
		{
			name:   "budget admits up",
			state:  State{Nodes: 4, Allowance: 5, Samples: flat(ago(5*time.Minute), t0, 4, 0.8)},
			action: Up, want: 5, reason: "cpu 0.80 >= 0.75 for 5m0s",
		},
		{
			name:   "saturated at 12",
			state:  State{Nodes: 12, Allowance: 12, Samples: flat(ago(5*time.Minute), t0, 12, 0.8)},
			action: Hold, want: 13, saturated: true, reason: "at the maximum of 12 nodes",
		},
		{
			name:   "up cooldown holds",
			state:  State{Nodes: 4, Allowance: 12, LastChange: ago(9 * time.Minute), Samples: flat(ago(5*time.Minute), t0, 4, 0.8)},
			action: Hold, want: 5, reason: "cooldown after the last change",
		},
		{
			name:   "up after up cooldown",
			state:  State{Nodes: 4, Allowance: 12, LastChange: ago(10 * time.Minute), Samples: flat(ago(5*time.Minute), t0, 4, 0.8)},
			action: Up, want: 5, reason: "cpu 0.80 >= 0.75 for 5m0s",
		},
		{
			name:   "down at 4 nodes after 30m at 0.3",
			state:  State{Nodes: 4, Allowance: 12, Samples: flat(ago(30*time.Minute), t0, 4, 0.3)},
			action: Down, want: 3, reason: "every signal <= 0.55 on 3 nodes for 30m0s",
		},
		{
			name:   "no down with 29m of history",
			state:  State{Nodes: 4, Allowance: 12, Samples: flat(ago(29*time.Minute), t0, 4, 0.3)},
			action: Hold, want: 4, reason: "load within band",
		},
		{
			name:   "hold at 0.45 on 4 nodes",
			state:  State{Nodes: 4, Allowance: 12, Samples: flat(ago(30*time.Minute), t0, 4, 0.45)},
			action: Hold, want: 4, reason: "load within band",
		},
		{
			name:   "never down at 3 nodes",
			state:  State{Nodes: 3, Allowance: 12, Samples: flat(ago(30*time.Minute), t0, 3, 0.1)},
			action: Hold, want: 3, reason: "load within band",
		},
		{
			name:   "down cooldown holds",
			state:  State{Nodes: 4, Allowance: 12, LastChange: ago(29 * time.Minute), Samples: flat(ago(30*time.Minute), t0, 4, 0.3)},
			action: Hold, want: 3, reason: "cooldown after the last change",
		},
		{
			name:   "down after down cooldown",
			state:  State{Nodes: 4, Allowance: 12, LastChange: ago(30 * time.Minute), Samples: flat(ago(30*time.Minute), t0, 4, 0.3)},
			action: Down, want: 3, reason: "every signal <= 0.55 on 3 nodes for 30m0s",
		},
		{
			name:   "busy holds hot load",
			state:  State{Nodes: 4, Allowance: 12, Busy: true, Samples: flat(ago(5*time.Minute), t0, 4, 0.8)},
			action: Hold, want: 4, reason: "a scale action or node operation is running",
		},
		{
			name:   "above max goes down to max",
			state:  State{Nodes: 13, Allowance: 13},
			action: Down, want: 12, reason: "above the maximum of 12 nodes",
		},
		{
			name:   "below min holds",
			state:  State{Nodes: 2, Allowance: 12},
			action: Hold, want: 2, reason: "fewer than 3 nodes",
		},
		{
			name:   "no samples hold",
			state:  State{Nodes: 4, Allowance: 12},
			action: Hold, want: 4, reason: "missing load samples",
		},
		{
			name:   "stale latest sample holds",
			state:  State{Nodes: 4, Allowance: 12, Samples: flat(ago(5*time.Minute), ago(2*time.Minute), 4, 0.8)},
			action: Hold, want: 4, reason: "missing load samples",
		},
		{
			name:   "incomplete latest sample holds",
			state:  State{Nodes: 4, Allowance: 12, Samples: partial(flat(ago(5*time.Minute), t0, 4, 0.8), 10)},
			action: Hold, want: 4, reason: "missing load samples",
		},
		{
			name:   "incomplete sample inside the window blocks up",
			state:  State{Nodes: 4, Allowance: 12, Samples: partial(flat(ago(5*time.Minute), t0, 4, 0.8), 3)},
			action: Hold, want: 4, reason: "load within band",
		},
		{
			name: "gap of 90s blocks up",
			state: State{Nodes: 4, Allowance: 12, Samples: append(
				flat(ago(5*time.Minute), ago(3*time.Minute+30*time.Second), 4, 0.8),
				flat(ago(2*time.Minute), t0, 4, 0.8)...)},
			action: Hold, want: 4, reason: "load within band",
		},
		{
			name: "gap of 2m blocks down",
			state: State{Nodes: 4, Allowance: 12, Samples: append(
				flat(ago(30*time.Minute), ago(10*time.Minute), 4, 0.3),
				flat(ago(8*time.Minute), t0, 4, 0.3)...)},
			action: Hold, want: 4, reason: "load within band",
		},
		{
			name: "samples from before a size change do not count",
			state: State{Nodes: 4, Allowance: 12, Samples: append(
				flat(ago(30*time.Minute), ago(2*time.Minute+30*time.Second), 3, 0.8),
				flat(ago(2*time.Minute), t0, 4, 0.8)...)},
			action: Hold, want: 4, reason: "load within band",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Decide(tt.state, t0)
			if got.Action != tt.action || got.Want != tt.want || got.Saturated != tt.saturated {
				t.Fatalf("Decide = %s want %d saturated %t, want %s want %d saturated %t (reason %q)",
					got.Action, got.Want, got.Saturated, tt.action, tt.want, tt.saturated, got.Reason)
			}
			if !strings.Contains(got.Reason, tt.reason) {
				t.Fatalf("reason = %q, want it to contain %q", got.Reason, tt.reason)
			}
		})
	}
}

func TestDecidePressure(t *testing.T) {
	tests := []struct {
		name     string
		util     map[Signal]float64
		signal   Signal
		pressure float64
	}{
		{"memory is the highest", map[Signal]float64{SignalCPU: 0.2, SignalMemory: 0.9, SignalDisk: 0.1, SignalRequests: 0.3}, SignalMemory, 0.9},
		{"ties go to the earlier signal", uniform(0.5), SignalCPU, 0.5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			samples := []Sample{{At: t0, Nodes: 4, Reporting: 4, Utilization: tt.util}}
			got := Decide(State{Nodes: 4, Allowance: 12, Samples: samples}, t0)
			if got.Signal != tt.signal || got.Pressure != tt.pressure {
				t.Fatalf("Signal %s Pressure %.2f, want %s %.2f", got.Signal, got.Pressure, tt.signal, tt.pressure)
			}
		})
	}
}

func TestHistoryAdd(t *testing.T) {
	var h History
	h.Add(Sample{At: t0, Nodes: 4})
	h.Add(Sample{At: t0, Nodes: 5})
	h.Add(Sample{At: t0.Add(-time.Second), Nodes: 6})
	if got := h.Samples(); len(got) != 1 || got[0].Nodes != 4 {
		t.Fatalf("Samples = %+v, want only the first sample", got)
	}

	var long History
	for at := ago(3 * time.Hour); !at.After(t0); at = at.Add(Interval) {
		long.Add(Sample{At: at, Nodes: 4})
	}
	got := long.Samples()
	// Kept: DownWindow plus 2*Interval back from the newest, both ends included.
	wantLen := int((DownWindow+2*Interval)/Interval) + 1
	if len(got) != wantLen || !got[0].At.Equal(ago(DownWindow+2*Interval)) {
		t.Fatalf("kept %d samples from %s, want %d from %s", len(got), got[0].At, wantLen, ago(DownWindow+2*Interval))
	}
}

// TestNoFlap runs constant total loads through the leader loop and checks it never reverses direction.
func TestNoFlap(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	changes := 0
	for range 200 {
		total := r.Float64() * 12 * 0.9
		nodes := MinNodes + r.IntN(MaxNodes-MinNodes+1)
		var history History
		var lastChange time.Time
		var last Action
		for at := ago(8 * time.Hour); !at.After(t0); at = at.Add(Interval) {
			history.Add(Sample{At: at, Nodes: nodes, Reporting: nodes, Utilization: uniform(total / float64(nodes))})
			d := Decide(State{Nodes: nodes, Allowance: MaxNodes, LastChange: lastChange, Samples: history.Samples()}, at)
			if d.Action == Hold {
				continue
			}
			if last != "" && d.Action != last {
				t.Fatalf("total %.2f from %d nodes: %s after %s at %s", total, nodes, d.Action, last, at)
			}
			last = d.Action
			changes++
			lastChange = at
			if d.Action == Up {
				nodes++
			} else {
				nodes--
			}
			if nodes < MinNodes || nodes > MaxNodes {
				t.Fatalf("total %.2f: nodes %d outside %d..%d at %s", total, nodes, MinNodes, MaxNodes, at)
			}
		}
	}
	if changes == 0 {
		t.Fatal("no scaling in any run; the property checked nothing")
	}
}

func TestSampleComplete(t *testing.T) {
	tests := []struct {
		name   string
		sample Sample
		want   bool
	}{
		{"complete", Sample{Nodes: 3, Reporting: 3, Utilization: uniform(0.5)}, true},
		{"reporting short", Sample{Nodes: 3, Reporting: 2, Utilization: uniform(0.5)}, false},
		{"no utilization", Sample{Nodes: 3, Reporting: 3}, false},
		{"no nodes", Sample{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.sample.Complete(); got != tt.want {
				t.Fatalf("Complete = %t, want %t", got, tt.want)
			}
		})
	}
}
