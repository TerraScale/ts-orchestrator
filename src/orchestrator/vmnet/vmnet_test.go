package vmnet

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	commands []Command
	failAt   int
	checkCtx bool
}

type fakeJournalWriter struct {
	writes int
	plan   Journal
}

func (f *fakeJournalWriter) WriteJournal(_ context.Context, journal Journal) error {
	f.writes++
	f.plan = journal
	return nil
}

func (f *fakeRunner) Run(ctx context.Context, executable string, args []string) error {
	if f.checkCtx && ctx.Err() != nil {
		return ctx.Err()
	}
	f.commands = append(f.commands, Command{Executable: executable, Args: append([]string(nil), args...)})
	if f.failAt >= 0 && len(f.commands)-1 == f.failAt {
		return errors.New("injected runner failure")
	}
	return nil
}

func TestDefaultPlanIsStableAndCoversNetworkSurfaces(t *testing.T) {
	if StableCIDR(GRU) != "10.77.0.0/24" || StableGateway(SFO) != "10.77.1.1" {
		t.Fatal("launch address allocation changed")
	}
	address, err := StableGuestAddress(FRA, 2)
	if err != nil || address != "10.77.2.11" {
		t.Fatalf("stable guest address = %q, %v", address, err)
	}
	first, err := Plan(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultConfig()
	config.Regions[0], config.Regions[2] = config.Regions[2], config.Regions[0]
	config.Regions[0].Guests[0], config.Regions[0].Guests[1] = config.Regions[0].Guests[1], config.Regions[0].Guests[0]
	second, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != second.Fingerprint || !reflect.DeepEqual(first.Commands, second.Commands) {
		t.Fatal("declaration order changed the network plan")
	}
	if len(first.Regions) != 3 || len(first.Regions[0].Guests)+len(first.Regions[1].Guests)+len(first.Regions[2].Guests) != 6 {
		t.Fatalf("unexpected launch topology: %+v", first.Regions)
	}
	joined := ""
	for _, c := range first.Commands {
		joined += c.Executable + " " + strings.Join(c.Args, " ") + "\n"
	}
	for _, want := range []string{"netns", "tuntap", "bridge", "nft", "forward", "veth", "route"} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan lacks %s operations", want)
		}
	}
	if len(first.Cleanup.Commands) == 0 || first.Journal.Fingerprint != first.Fingerprint {
		t.Fatal("missing crash cleanup journal")
	}
}

func TestFaultsAreDirectionalNetemAndPartition(t *testing.T) {
	config := DefaultConfig()
	config.Faults = []FaultSpec{{
		From: GRU, To: FRA, Latency: 120 * time.Millisecond, Jitter: 15 * time.Millisecond,
		LossPercent: 2.5, BandwidthKbit: 512, Partition: true,
	}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	foundTC, foundDrop := false, false
	for _, c := range plan.Commands {
		if c.Executable == "ip" && len(c.Args) > 2 && c.Args[0] == "-n" && c.Args[2] == "tc" {
			foundTC = true
			if !contains(c.Args, "120ms") || !contains(c.Args, "15ms") || !contains(c.Args, "2.5%") || !contains(c.Args, "512kbit") {
				t.Errorf("incomplete tc netem args: %v", c.Args)
			}
		}
		if contains(c.Args, "drop") {
			foundDrop = true
		}
	}
	if !foundTC || !foundDrop {
		t.Fatalf("fault plan tc=%v drop=%v", foundTC, foundDrop)
	}
}

func TestApplyFailureRunsBestEffortCleanup(t *testing.T) {
	plan, err := Plan(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: 3}
	if err := plan.Apply(context.Background(), runner); err == nil {
		t.Fatal("Apply succeeded despite injected failure")
	}
	if len(runner.commands) != 4+len(plan.Cleanup.Commands) {
		t.Fatalf("commands after failed apply = %d, want %d", len(runner.commands), 4+len(plan.Cleanup.Commands))
	}
	// Cleanup proceeds in reverse ownership order and can be replayed.
	before := len(runner.commands)
	_ = plan.Rollback(context.Background(), runner)
	if len(runner.commands) != before+len(plan.Cleanup.Commands) {
		t.Fatal("rollback did not replay the complete idempotent cleanup plan")
	}
}

func TestCancellationUsesCleanupContext(t *testing.T) {
	plan, err := Plan(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &fakeRunner{failAt: -1, checkCtx: true}
	if err := plan.Apply(ctx, runner); err == nil {
		t.Fatal("Apply did not report cancellation")
	}
	if len(runner.commands) != len(plan.Cleanup.Commands) {
		t.Fatalf("cancellation cleanup commands = %d, want %d", len(runner.commands), len(plan.Cleanup.Commands))
	}
}

func TestApplyWithJournalWritesBeforeRunner(t *testing.T) {
	plan, err := Plan(Config{Regions: []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "member"}}}}})
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeJournalWriter{}
	runner := &fakeRunner{failAt: -1}
	if err := plan.ApplyWithJournal(context.Background(), runner, writer); err != nil {
		t.Fatal(err)
	}
	if writer.writes != 1 || writer.plan.Fingerprint != plan.Fingerprint || len(runner.commands) != len(plan.Commands) {
		t.Fatalf("journal/apply ordering state: writes=%d fingerprint=%q commands=%d", writer.writes, writer.plan.Fingerprint, len(runner.commands))
	}
}

func TestValidationRejectsUnsafeDeclarations(t *testing.T) {
	tests := []Config{
		{Prefix: "bad;rm", Regions: []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "guest"}}}}},
		{Regions: []RegionSpec{{Code: GRU, CIDR: "10.1.0.1/24", Guests: []GuestSpec{{ID: "guest"}}}}},
		{Regions: []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "guest", Address: "192.0.2.1"}}}}},
		{Regions: []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "guest", TAP: "tap;bad"}}}}},
	}
	for i, config := range tests {
		if _, err := Plan(config); err == nil {
			t.Errorf("case %d accepted unsafe declaration", i)
		}
	}
}

func TestCleanupContinuesAfterError(t *testing.T) {
	plan, err := Plan(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: 0}
	if err := plan.Cleanup.Run(context.Background(), runner); err == nil {
		t.Fatal("cleanup hid runner error")
	}
	if len(runner.commands) != len(plan.Cleanup.Commands) {
		t.Fatalf("cleanup stopped after first error: %d/%d", len(runner.commands), len(plan.Cleanup.Commands))
	}
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
