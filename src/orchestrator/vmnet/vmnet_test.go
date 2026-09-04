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

type fakeCleanupRunner struct {
	runs     int
	cleanups int
}

func (f *fakeCleanupRunner) Run(context.Context, string, []string) error {
	f.runs++
	return errors.New("ordinary Run must not handle cleanup")
}

func (f *fakeCleanupRunner) RunCleanup(context.Context, string, []string) error {
	f.cleanups++
	return nil
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
	mac, err := StableGuestMAC(FRA, 2)
	if err != nil || mac != "02:fc:77:03:02:01" {
		t.Fatalf("stable guest MAC = %q, %v", mac, err)
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
	for _, want := range []string{"netns", "tuntap", "bridge", "nft", "forward", "veth", "route", "sysctl"} {
		if !strings.Contains(joined, want) {
			t.Errorf("plan lacks %s operations", want)
		}
	}
	if len(first.Cleanup.Commands) == 0 || first.Journal.Fingerprint != first.Fingerprint {
		t.Fatal("missing crash cleanup journal")
	}
	for _, region := range first.Regions {
		if region.NamespacePath != "/run/netns/"+region.Namespace {
			t.Fatalf("namespace path = %q for %s", region.NamespacePath, region.Code)
		}
		for _, guest := range region.Guests {
			if !strings.HasPrefix(guest.ID, strings.ToLower(string(region.Code))+"-") || guest.MAC == "" {
				t.Fatalf("unresolved guest identity: %+v", guest)
			}
			for _, command := range first.Commands {
				line := strings.Join(command.Args, " ")
				if strings.Contains(line, guest.Address+"/32") && strings.Contains(line, "dev "+guest.TAP) {
					t.Fatalf("guest address was assigned to host TAP: %s", line)
				}
			}
		}
	}
	for _, command := range first.Commands {
		line := strings.Join(command.Args, " ")
		if strings.Contains(line, " link set ts-v-") && strings.Contains(line, " master ") {
			t.Fatalf("transit veth was bridged instead of routed: %s", line)
		}
	}
}

func TestTAPOwnershipIsExplicitWhenConfigured(t *testing.T) {
	config := Config{TAPUID: 1234, TAPGID: 5678, Regions: []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "gru-member-1"}}}}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, command := range plan.Commands {
		if contains(command.Args, "tuntap") {
			found = contains(command.Args, "user") && contains(command.Args, "1234") && contains(command.Args, "group") && contains(command.Args, "5678")
		}
	}
	if !found {
		t.Fatal("TAP owner and group were not emitted")
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
		if c.Executable == "ip" && len(c.Args) > 3 && c.Args[0] == "netns" && c.Args[1] == "exec" && c.Args[3] == "tc" {
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

func TestCleanupUsesIdempotentRunnerWhenAvailable(t *testing.T) {
	plan, err := Plan(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeCleanupRunner{}
	if err := plan.Cleanup.Run(context.Background(), runner); err != nil {
		t.Fatal(err)
	}
	if runner.runs != 0 || runner.cleanups != len(plan.Cleanup.Commands) {
		t.Fatalf("cleanup dispatch runs=%d cleanups=%d", runner.runs, runner.cleanups)
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
