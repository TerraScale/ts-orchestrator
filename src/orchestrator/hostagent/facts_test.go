package hostagent

import (
	"context"
	"encoding/json"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/hostplatform"
	"testing"
	"time"
)

// fakeClock is the injectable clock source of the facts tests.
type fakeClock struct {
	offset time.Duration
	err    error
}

func (f fakeClock) Offset(ctx context.Context) (time.Duration, error) {
	return f.offset, f.err
}

// fakeStatfs is the injectable statfs of the facts tests.
func fakeStatfs(total, available int64) StatfsPath {
	return func(path string) (int64, int64, error) { return total, available, nil }
}

func newTestFactsSource(t *testing.T, clock hostplatform.ClockSource, systemd SystemdController) *HostFactsSource {
	t.Helper()
	source, err := NewHostFactsSource(HostFactsSourceConfig{
		Clock:          clock,
		Statfs:         fakeStatfs(1000<<30, 400<<30),
		DataVolumeRoot: "/var/lib/terrascale",
		Systemd:        systemd,
		InstallRoot:    t.TempDir(),
		Installer:      &Installer{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// TestHeartbeatPayloadCarriesHostFacts asserts the D-69 heartbeat facts:
// clock offset and health, disk figures, agent version, and per-component
// desired/current/installed/active state.
func TestHeartbeatPayloadCarriesHostFacts(t *testing.T) {
	harness := newTestHarness(t)
	spec := harness.publish(t, "terrabase", "1.2.3")
	harness.applyDesired(t, spec)
	if err := FlipCurrent(harness.root, "terrabase", "1.2.3"); err != nil {
		t.Fatal(err)
	}
	systemd := newFakeSystemd(UnitName("terrabase"))
	source, err := NewHostFactsSource(HostFactsSourceConfig{
		Clock:          fakeClock{offset: 750 * time.Millisecond},
		Statfs:         fakeStatfs(1000<<30, 400<<30),
		DataVolumeRoot: "/var/lib/terrascale",
		Systemd:        systemd,
		InstallRoot:    harness.root,
		Installer:      harness.lifecycle.installer,
	})
	if err != nil {
		t.Fatal(err)
	}
	facts, err := source.Sample(context.Background(), NodeStateServing, []hostmanifest.ComponentSpec{spec})
	if err != nil {
		t.Fatalf("sample failed: %v", err)
	}
	if facts.ClockOffsetMillis != 750 || !facts.ClockMeasured {
		t.Fatalf("clock facts are %+v", facts)
	}
	if !facts.ClockUnhealthy {
		t.Fatal("750 ms offset not marked unhealthy")
	}
	if facts.Disk.Path != "/var/lib/terrascale" ||
		facts.Disk.TotalBytes != 1000<<30 || facts.Disk.AvailableBytes != 400<<30 {
		t.Fatalf("disk facts are %+v", facts.Disk)
	}
	if facts.TsNodeVersion != TsNodeVersion {
		t.Fatalf("agent version is %q", facts.TsNodeVersion)
	}
	if len(facts.Components) != 1 {
		t.Fatalf("components are %+v", facts.Components)
	}
	component := facts.Components[0]
	if component.Name != "terrabase" || component.Desired != "1.2.3" ||
		component.Version != "1.2.3" || !component.Installed || !component.UnitActive {
		t.Fatalf("component facts are %+v", component)
	}
	// The wire shape stays camelCase and closed.
	encoded, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"clockOffsetMillis":750`, `"clockUnhealthy":true`,
		`"tsNodeVersion":"dev"`, `"unitActive":true`} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("wire payload %s misses %s", encoded, field)
		}
	}
}

// TestHeartbeatFailsClosedOnUnreadableClock asserts a chrony failure marks
// the host unhealthy with Measured=false, never healthy.
func TestHeartbeatFailsClosedOnUnreadableClock(t *testing.T) {
	source := newTestFactsSource(t,
		fakeClock{err: &InvalidDataError{Message: "chrony down"}}, newFakeSystemd())
	facts, err := source.Sample(context.Background(), NodeStateServing, nil)
	if err != nil {
		t.Fatalf("sample failed: %v", err)
	}
	if facts.ClockMeasured || !facts.ClockUnhealthy {
		t.Fatalf("unreadable clock is %+v", facts)
	}
}
