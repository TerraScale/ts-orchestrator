package nodescale

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeClock is the prober's clock. A fake connect advances it by the latency it simulates.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeNet simulates the OCI endpoints. Each address lists the latency of its successive connects; a connect past
// the end of the list, or to an address not listed, is refused.
type fakeNet struct {
	clock   *fakeClock
	latency map[string][]time.Duration

	mu     sync.Mutex
	dialed []string
	calls  map[string]int
	active int
	peak   int
	open   int
}

func (n *fakeNet) Dial(_ context.Context, _, address string) (net.Conn, error) {
	n.mu.Lock()
	n.dialed = append(n.dialed, address)
	call := n.calls[address]
	n.calls[address]++
	n.active++
	n.peak = max(n.peak, n.active)
	n.mu.Unlock()

	time.Sleep(time.Millisecond) // real time, so concurrent probes overlap

	n.mu.Lock()
	n.active--
	steps := n.latency[address]
	if call >= len(steps) {
		n.mu.Unlock()
		return nil, errors.New("connection refused")
	}
	n.open++
	n.mu.Unlock()
	n.clock.advance(steps[call])
	return &fakeConn{fake: n}, nil
}

// fakeConn counts itself open until it is closed.
type fakeConn struct {
	net.Conn
	fake *fakeNet
}

func (c *fakeConn) Close() error {
	c.fake.mu.Lock()
	defer c.fake.mu.Unlock()
	c.fake.open--
	return nil
}

// newTestProber probes regions over a fake network that connects with the given latencies.
func newTestProber(regions []string, latency map[string][]time.Duration) (*Prober, *fakeNet) {
	clock := &fakeClock{now: t0}
	fake := &fakeNet{clock: clock, latency: latency, calls: map[string]int{}}
	prober := &Prober{
		Regions: func(context.Context) ([]string, error) { return regions, nil },
		Dial:    fake.Dial,
		Now:     clock.Now,
	}
	return prober, fake
}

func endpoint(region string) string {
	return "objectstorage." + region + ".oraclecloud.com:443"
}

func TestProbeTakesTheMedianOfTheConnects(t *testing.T) {
	t.Parallel()

	prober, fake := newTestProber([]string{"us-ashburn-1"}, map[string][]time.Duration{
		endpoint("us-ashburn-1"): {30 * time.Millisecond, 10 * time.Millisecond, 50 * time.Millisecond},
	})
	if err := prober.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	rtt, at := prober.Latest()
	if rtt["us-ashburn-1"] != 30*time.Millisecond || !at.Equal(t0.Add(90*time.Millisecond)) {
		t.Fatalf("Latest = %v at %s; want 30ms at the end of the round", rtt, at)
	}
	if fake.open != 0 {
		t.Fatalf("%d connections left open", fake.open)
	}
}

func TestProbeLeavesOutARegionThatNeverConnects(t *testing.T) {
	t.Parallel()

	prober, _ := newTestProber([]string{"us-ashburn-1", "eu-zurich-1"}, map[string][]time.Duration{
		endpoint("us-ashburn-1"): {20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond},
	})
	if err := prober.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	rtt, _ := prober.Latest()
	if len(rtt) != 1 || rtt["us-ashburn-1"] != 20*time.Millisecond {
		t.Fatalf("Latest = %v; want only us-ashburn-1", rtt)
	}
}

func TestProbeNeverDialsAnInvalidRegionName(t *testing.T) {
	t.Parallel()

	prober, fake := newTestProber([]string{"us-ashburn-1", "../../etc", "US-ASHBURN-1", "us-ashburn-1.evil.com",
		"us-ashburn-1/x", ""}, map[string][]time.Duration{
		endpoint("us-ashburn-1"): {time.Millisecond, time.Millisecond, time.Millisecond},
	})
	if err := prober.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(fake.dialed) != RTTSamples {
		t.Fatalf("dialed %v; want only the valid region, %d times", fake.dialed, RTTSamples)
	}
	for _, address := range fake.dialed {
		if address != endpoint("us-ashburn-1") {
			t.Fatalf("dialed %q; want only %q", address, endpoint("us-ashburn-1"))
		}
	}
}

func TestProbeBoundsConcurrency(t *testing.T) {
	t.Parallel()

	var regions []string
	latency := map[string][]time.Duration{}
	for i := range 20 {
		region := fmt.Sprintf("us-test-%d", i+1)
		regions = append(regions, region)
		latency[endpoint(region)] = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	}
	prober, fake := newTestProber(regions, latency)
	if err := prober.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	if rtt, _ := prober.Latest(); len(rtt) != len(regions) {
		t.Fatalf("Latest has %d regions, want %d", len(rtt), len(regions))
	}
	if fake.peak > rttWorkers {
		t.Fatalf("%d connects at once, want at most %d", fake.peak, rttWorkers)
	}
}

func TestLatestIsACopyAndACancelledRoundKeepsTheLast(t *testing.T) {
	t.Parallel()

	prober, _ := newTestProber([]string{"us-ashburn-1"}, map[string][]time.Duration{
		endpoint("us-ashburn-1"): {10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond},
	})
	if err := prober.Probe(t.Context()); err != nil {
		t.Fatal(err)
	}
	rtt, _ := prober.Latest()
	maps.DeleteFunc(rtt, func(string, time.Duration) bool { return true })
	if again, _ := prober.Latest(); again["us-ashburn-1"] != 10*time.Millisecond {
		t.Fatalf("Latest after the caller emptied its copy = %v; want the probe's own map", again)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := prober.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Probe = %v; want context.Canceled", err)
	}
	if again, _ := prober.Latest(); again["us-ashburn-1"] != 10*time.Millisecond {
		t.Fatalf("cancelled round replaced the map with %v", again)
	}
}

func TestStatusValidatesRoundTrips(t *testing.T) {
	t.Parallel()

	valid := Status{Schema: StatusSchema, Cell: "gru", At: t0, Reason: "load within band",
		RTTMillis: map[string]int{"us-sanjose-1": 171, "eu-frankfurt-1": maxRoundTripMillis}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("status with round trips: %v", err)
	}
	tooMany := map[string]int{}
	for i := range maxRoundTrips + 1 {
		tooMany[fmt.Sprintf("us-test-%d", i+1)] = 1
	}
	tests := []struct {
		name  string
		rtt   map[string]int
		valid bool
	}{
		{"zero", map[string]int{"us-sanjose-1": 0}, false},
		{"negative", map[string]int{"us-sanjose-1": -5}, false},
		{"over a minute", map[string]int{"us-sanjose-1": maxRoundTripMillis + 1}, false},
		{"upper-case name", map[string]int{"US-SANJOSE-1": 171}, false},
		{"name with a path", map[string]int{"us-sanjose-1/../x": 171}, false},
		{"too many", tooMany, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status := valid
			status.RTTMillis = tc.rtt
			if err := status.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate = %v; want valid=%t", err, tc.valid)
			}
		})
	}
}
