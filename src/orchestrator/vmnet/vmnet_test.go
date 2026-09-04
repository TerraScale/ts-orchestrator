package vmnet

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const testRunID = "0123456789abcdef0123456789abcdef"

func qualifiedConfig(t *testing.T) Config {
	t.Helper()
	config := DefaultConfig()
	config.RunID = testRunID
	config.Tools = testToolPaths(t)
	return config
}

func testToolPaths(t *testing.T) ToolPaths {
	t.Helper()
	directory := t.TempDir()
	paths := make(map[string]string, 4)
	for _, name := range []string{"ip", "tc", "nft", "sysctl"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("test executable"), 0700); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	return ToolPaths{IP: paths["ip"], TC: paths["tc"], NFT: paths["nft"], Sysctl: paths["sysctl"]}
}

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

type observingCleanupRunner struct {
	runs             int
	cleanups         []Command
	cancelledContext bool
	missingDeadline  bool
}

type boundFakeRunner struct {
	fakeRunner
	tools ToolPaths
}

func (r *boundFakeRunner) ToolPaths() ToolPaths { return r.tools }

func (f *fakeCleanupRunner) Run(context.Context, string, []string) error {
	f.runs++
	return errors.New("ordinary Run must not handle cleanup")
}

func (f *fakeCleanupRunner) RunCleanup(context.Context, string, []string) error {
	f.cleanups++
	return nil
}

func (f *observingCleanupRunner) Run(context.Context, string, []string) error {
	f.runs++
	return errors.New("ordinary Run must not handle cleanup")
}

func (f *observingCleanupRunner) RunCleanup(ctx context.Context, executable string, args []string) error {
	if ctx.Err() != nil {
		f.cancelledContext = true
	}
	if _, ok := ctx.Deadline(); !ok {
		f.missingDeadline = true
	}
	f.cleanups = append(f.cleanups, Command{Executable: executable, Args: append([]string(nil), args...)})
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
	config := qualifiedConfig(t)
	first, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
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

func TestPlanRequiresSafeRunIDAndPinnedTools(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(Config) Config
	}{
		{name: "short run ID", mutate: func(config Config) Config { config.RunID = "0123456789abcdef"; return config }},
		{name: "uppercase run ID", mutate: func(config Config) Config { config.RunID = "0123456789ABCDEF0123456789ABCDEF"; return config }},
		{name: "non-hex run ID", mutate: func(config Config) Config { config.RunID = "gggggggggggggggggggggggggggggggg"; return config }},
		{name: "missing ip", mutate: func(config Config) Config { config.Tools.IP = ""; return config }},
		{name: "relative tc", mutate: func(config Config) Config { config.Tools.TC = "tc"; return config }},
		{name: "unclean nft", mutate: func(config Config) Config { config.Tools.NFT = "/opt/../usr/bin/nft"; return config }},
		{name: "missing sysctl", mutate: func(config Config) Config { config.Tools.Sysctl = ""; return config }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Plan(test.mutate(qualifiedConfig(t))); err == nil {
				t.Fatal("Plan accepted an unsafe run identity or tool path")
			}
		})
	}
}

func TestPlanUsesOneProcessScopedDefaultRunID(t *testing.T) {
	config := qualifiedConfig(t)
	config.RunID = ""
	first, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunID == "" || first.RunID != second.RunID {
		t.Fatalf("default run ID is empty or changed within one process: %q, %q", first.RunID, second.RunID)
	}
	if len(first.RunID) != 32 {
		t.Fatalf("default run ID length = %d, want 32", len(first.RunID))
	}
	for _, character := range first.RunID {
		if !strings.ContainsRune("0123456789abcdef", character) {
			t.Fatalf("default run ID contains unsafe character %q: %q", character, first.RunID)
		}
	}
}

func TestPlanPinsEveryHostExecutable(t *testing.T) {
	config := qualifiedConfig(t)
	config.Faults = []FaultSpec{{From: GRU, To: SFO, Latency: 25 * time.Millisecond}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}

	seenNested := map[string]bool{}
	commands := append([]Command(nil), plan.Commands...)
	commands = append(commands, plan.Cleanup.Commands...)
	for _, command := range commands {
		if !filepath.IsAbs(command.Executable) || filepath.Clean(command.Executable) != command.Executable {
			t.Fatalf("command executable is not clean and absolute: %+v", command)
		}
		if command.Executable != config.Tools.IP {
			t.Fatalf("command uses unpinned top-level executable %q", command.Executable)
		}
		for _, argument := range command.Args {
			switch argument {
			case "ip", "tc", "nft", "sysctl":
				t.Fatalf("command contains unresolved executable %q: %+v", argument, command)
			}
		}
		if len(command.Args) >= 4 && command.Args[0] == "netns" && command.Args[1] == "exec" {
			nested := command.Args[3]
			if !filepath.IsAbs(nested) || filepath.Clean(nested) != nested {
				t.Fatalf("nested executable is not clean and absolute: %+v", command)
			}
			seenNested[nested] = true
		}
	}
	for name, path := range map[string]string{"nft": config.Tools.NFT, "sysctl": config.Tools.Sysctl, "tc": config.Tools.TC} {
		if !seenNested[path] {
			t.Errorf("plan never used pinned %s executable %q", name, path)
		}
	}
}

func TestPlanHandlesCanonicalPrivateSubnetBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		cidr        string
		address     string
		wantGateway string
	}{
		{name: "slash 24 last usable", cidr: "10.91.0.0/24", address: "10.91.0.254", wantGateway: "10.91.0.1"},
		{name: "nonzero slash 25", cidr: "10.91.0.128/25", address: "10.91.0.254", wantGateway: "10.91.0.129"},
		{name: "slash 30 only guest", cidr: "10.91.0.0/30", address: "10.91.0.2", wantGateway: "10.91.0.1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := qualifiedConfig(t)
			config.Regions = []RegionSpec{{Code: GRU, CIDR: test.cidr, Guests: []GuestSpec{{ID: "guest", Address: test.address}}}}
			plan, err := Plan(config)
			if err != nil {
				t.Fatal(err)
			}
			if got := plan.Regions[0].Gateway; got != test.wantGateway {
				t.Fatalf("gateway = %q, want %q", got, test.wantGateway)
			}
			if got := plan.Regions[0].Guests[0].Address; got != test.address {
				t.Fatalf("guest address = %q, want %q", got, test.address)
			}
		})
	}
}

func TestPlanRejectsBroadcastAndNonPrivateSubnets(t *testing.T) {
	tests := []struct {
		name    string
		cidr    string
		address string
	}{
		{name: "slash 24 broadcast", cidr: "10.91.0.0/24", address: "10.91.0.255"},
		{name: "slash 30 broadcast", cidr: "10.91.0.0/30", address: "10.91.0.3"},
		{name: "public", cidr: "192.0.2.0/24", address: "192.0.2.10"},
		{name: "loopback", cidr: "127.0.0.0/24", address: "127.0.0.10"},
		{name: "link local transit", cidr: "169.254.240.0/24", address: "169.254.240.10"},
		{name: "reserved private transit", cidr: "10.78.255.0/24", address: "10.78.255.10"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := qualifiedConfig(t)
			config.Regions = []RegionSpec{{Code: GRU, CIDR: test.cidr, Guests: []GuestSpec{{ID: "guest", Address: test.address}}}}
			if _, err := Plan(config); err == nil {
				t.Fatal("Plan accepted an unusable or reserved Region subnet")
			}
		})
	}
}

func TestTransitLinksAreRoutedAndGuestAddressesRemainGuestOwned(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}

	transit := transitNames(plan.Commands)
	if len(transit) != 6 {
		t.Fatalf("transit endpoints = %d, want six directed endpoints for three Region pairs", len(transit))
	}

	forwarding := make(map[string]bool)
	transitAddresses := make(map[string]bool)
	routes := 0
	faultDispatches := 0
	for _, command := range plan.Commands {
		args := command.Args
		if contains(args, "master") {
			for endpoint := range transit {
				if contains(args, endpoint) {
					t.Fatalf("transit endpoint %q was attached to a bridge: %+v", endpoint, command)
				}
			}
		}
		if len(args) >= 6 && args[0] == "netns" && args[1] == "exec" && args[3] == config.Tools.Sysctl && contains(args, "net.ipv4.ip_forward=1") {
			forwarding[args[2]] = true
		}
		if contains(args, "route") && contains(args, "via") {
			routes++
		}
		if contains(args, "jump") {
			faultDispatches++
			if !contains(args, "insert") {
				t.Fatalf("fault dispatch does not precede conntrack acceptance: %+v", command)
			}
		}
		for endpoint := range transit {
			if contains(args, endpoint) && contains(args, "addr") {
				for _, argument := range args {
					if strings.HasSuffix(argument, "/30") {
						transitAddresses[endpoint] = true
					}
				}
			}
		}
		for _, region := range plan.Regions {
			for _, guest := range region.Guests {
				if contains(args, "addr") && contains(args, "dev") && contains(args, guest.TAP) {
					for _, argument := range args {
						if argument == guest.Address || strings.HasPrefix(argument, guest.Address+"/") {
							t.Fatalf("guest address %s was assigned to host TAP %s: %+v", guest.Address, guest.TAP, command)
						}
					}
				}
			}
		}
	}
	if len(forwarding) != len(plan.Regions) {
		t.Fatalf("forwarding enabled in %d/%d Region namespaces", len(forwarding), len(plan.Regions))
	}
	if len(transitAddresses) != len(transit) {
		t.Fatalf("routed /30 addresses cover %d/%d transit endpoints", len(transitAddresses), len(transit))
	}
	joined := joinedCommands(plan.Commands)
	for _, address := range []string{"10.78.255.1/30", "10.78.255.2/30", "10.78.255.5/30", "10.78.255.6/30", "10.78.255.9/30", "10.78.255.10/30"} {
		if !strings.Contains(joined, address) {
			t.Errorf("transit plan lacks %s", address)
		}
	}
	if routes < len(transit) {
		t.Fatalf("cross-Region routes = %d, want at least %d", routes, len(transit))
	}
	if faultDispatches != len(transit) {
		t.Fatalf("fault dispatches = %d, want one for each of %d directed links", faultDispatches, len(transit))
	}
}

func TestRunIDScopesEveryOwnedNetworkResource(t *testing.T) {
	firstConfig := qualifiedConfig(t)
	secondConfig := firstConfig
	// Keep the first 12 hexadecimal characters identical so this test catches
	// accidental prefix truncation instead of proving only the easy case.
	secondConfig.RunID = "0123456789abffffffffffffffffffff"
	first, err := Plan(firstConfig)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Plan(secondConfig)
	if err != nil {
		t.Fatal(err)
	}
	if first.RunID != firstConfig.RunID || second.RunID != secondConfig.RunID {
		t.Fatalf("plans lost run identity: %q, %q", first.RunID, second.RunID)
	}
	if first.Fingerprint == second.Fingerprint {
		t.Fatal("distinct run IDs produced the same fingerprint")
	}

	owned := ownedResourceNames(first)
	foreign := ownedResourceNames(second)
	for name := range owned {
		if foreign[name] {
			t.Fatalf("owned network resource %q is shared by distinct run IDs", name)
		}
	}
	for _, command := range first.Cleanup.Commands {
		ownedTarget := false
		for _, argument := range command.Args {
			ownedTarget = ownedTarget || owned[argument]
			if foreign[argument] {
				t.Fatalf("cleanup for run %s targets resource %q owned by run %s: %+v", first.RunID, argument, second.RunID, command)
			}
		}
		if !ownedTarget {
			t.Fatalf("cleanup command has no resource owned by run %s: %+v", first.RunID, command)
		}
	}
	for index := range first.Regions {
		a, b := first.Regions[index], second.Regions[index]
		if a.Namespace == b.Namespace || a.Bridge == b.Bridge || a.NamespacePath == b.NamespacePath {
			t.Fatalf("Region resources are not run-scoped: first=%+v second=%+v", a, b)
		}
		for guestIndex := range a.Guests {
			if a.Guests[guestIndex].TAP == b.Guests[guestIndex].TAP {
				t.Fatalf("guest TAP is not run-scoped: %q", a.Guests[guestIndex].TAP)
			}
		}
	}
	firstTransit, secondTransit := transitNames(first.Commands), transitNames(second.Commands)
	if len(firstTransit) == 0 || len(firstTransit) != len(secondTransit) {
		t.Fatalf("unexpected transit resources: first=%v second=%v", firstTransit, secondTransit)
	}
	for name := range firstTransit {
		if secondTransit[name] {
			t.Fatalf("transit endpoint %q is shared by distinct runs", name)
		}
	}
}

func TestCleanupIsBoundedReplaySafeAndIgnoresCallerCancellation(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := &observingCleanupRunner{}
	for replay := 0; replay < 2; replay++ {
		if err := plan.Cleanup.Run(ctx, runner); err != nil {
			t.Fatalf("cleanup replay %d failed: %v", replay+1, err)
		}
	}
	if runner.runs != 0 {
		t.Fatalf("cleanup used ordinary Run %d times", runner.runs)
	}
	if runner.cancelledContext {
		t.Fatal("caller cancellation prevented a cleanup command")
	}
	if runner.missingDeadline {
		t.Fatal("a cleanup command ran without a deadline")
	}
	want := 2 * len(plan.Cleanup.Commands)
	if len(runner.cleanups) != want {
		t.Fatalf("cleanup commands across two replays = %d, want %d", len(runner.cleanups), want)
	}
}

func TestCleanupRejectsCrossRunTargetsBeforeMutation(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	foreignConfig := config
	foreignConfig.RunID = "0123456789abffffffffffffffffffff"
	foreign, err := Plan(foreignConfig)
	if err != nil {
		t.Fatal(err)
	}

	cleanup := plan.CleanupPlan()
	cleanup.Commands[0].Args[2] = foreign.Regions[0].Namespace
	runner := &fakeCleanupRunner{}
	if err := cleanup.Run(context.Background(), runner); err == nil {
		t.Fatal("cleanup accepted a namespace owned by another run")
	}
	if runner.runs != 0 || runner.cleanups != 0 {
		t.Fatalf("invalid cleanup reached runner: runs=%d cleanups=%d", runner.runs, runner.cleanups)
	}

	journal := plan.Journal
	journal.RunID = foreign.RunID
	if err := journal.Validate(); err == nil {
		t.Fatal("journal accepted mismatched cleanup ownership")
	}
}

func TestApplyRejectsTamperedPlanBeforeJournalOrMutation(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*NetworkPlan)
	}{
		{name: "foreign setup command", mutate: func(plan *NetworkPlan) {
			plan.Commands[0] = command(plan.Tools.IP, "netns", "del", "default")
		}},
		{name: "foreign cleanup command", mutate: func(plan *NetworkPlan) {
			plan.Cleanup.Commands[0] = command(plan.Tools.IP, "netns", "del", "default")
		}},
		{name: "journal ownership", mutate: func(plan *NetworkPlan) {
			plan.Journal.RunID = "ffffffffffffffffffffffffffffffff"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tampered := plan.copy()
			test.mutate(&tampered)
			runner := &fakeRunner{failAt: -1}
			writer := &fakeJournalWriter{}
			if err := tampered.ApplyWithJournal(context.Background(), runner, writer); err == nil {
				t.Fatal("ApplyWithJournal accepted a tampered network plan")
			}
			if writer.writes != 0 || len(runner.commands) != 0 {
				t.Fatalf("tampered plan reached privileged boundary: writes=%d commands=%+v", writer.writes, runner.commands)
			}
		})
	}
}

func TestPlanRejectsRunnerWithDifferentPinnedTools(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	runner := &boundFakeRunner{fakeRunner: fakeRunner{failAt: -1}, tools: testToolPaths(t)}
	if err := plan.Apply(context.Background(), runner); err == nil {
		t.Fatal("Apply accepted a runner bound to different host executables")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("mismatched runner received commands: %+v", runner.commands)
	}
}

func TestCleanupNeedsOnlyItsPinnedIPBinary(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(config.Tools.TC); err != nil {
		t.Fatal(err)
	}
	runner := &fakeCleanupRunner{}
	if err := plan.Cleanup.Run(context.Background(), runner); err != nil {
		t.Fatalf("cleanup depended on an unrelated removed tc binary: %v", err)
	}
	if runner.cleanups != len(plan.Regions) {
		t.Fatalf("cleanup commands = %d, want %d", runner.cleanups, len(plan.Regions))
	}
}

func TestCleanupRegionManifestIsCompleteAndCanonical(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CleanupPlan){
		func(cleanup *CleanupPlan) { cleanup.Regions = cleanup.Regions[:len(cleanup.Regions)-1] },
		func(cleanup *CleanupPlan) {
			cleanup.Regions[0], cleanup.Regions[1] = cleanup.Regions[1], cleanup.Regions[0]
		},
		func(cleanup *CleanupPlan) { cleanup.Commands = cleanup.Commands[:len(cleanup.Commands)-1] },
	} {
		cleanup := plan.CleanupPlan()
		mutate(&cleanup)
		runner := &fakeCleanupRunner{}
		if err := cleanup.Run(context.Background(), runner); err == nil {
			t.Fatal("cleanup accepted an incomplete or noncanonical Region manifest")
		}
		if runner.cleanups != 0 {
			t.Fatalf("invalid cleanup reached runner %d times", runner.cleanups)
		}
	}
}

func TestTAPOwnershipIsExplicitWhenConfigured(t *testing.T) {
	config := qualifiedConfig(t)
	config.TAPUID = 1234
	config.TAPGID = 5678
	config.Regions = []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "gru-member-1"}}}}
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
	config := qualifiedConfig(t)
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
		if c.Executable == config.Tools.IP && len(c.Args) > 3 && c.Args[0] == "netns" && c.Args[1] == "exec" && c.Args[3] == config.Tools.TC {
			if contains(c.Args, "120ms") && contains(c.Args, "15ms") && contains(c.Args, "2.5%") && contains(c.Args, "512kbit") {
				foundTC = true
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
	plan, err := Plan(qualifiedConfig(t))
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
	plan, err := Plan(qualifiedConfig(t))
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
	config := qualifiedConfig(t)
	config.Regions = []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "member"}}}}
	plan, err := Plan(config)
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
	if writer.plan.RunID != config.RunID || writer.plan.Cleanup.RunID != config.RunID {
		t.Fatalf("journal lost run identity: journal=%q cleanup=%q", writer.plan.RunID, writer.plan.Cleanup.RunID)
	}
	if !reflect.DeepEqual(writer.plan.Tools, config.Tools) || !reflect.DeepEqual(writer.plan.Cleanup.Tools, config.Tools) {
		t.Fatalf("journal lost pinned tools: journal=%+v cleanup=%+v want=%+v", writer.plan.Tools, writer.plan.Cleanup.Tools, config.Tools)
	}
}

func TestValidationRejectsUnsafeDeclarations(t *testing.T) {
	tests := []func(Config) Config{
		func(config Config) Config { config.Prefix = "bad;rm"; return config },
		func(config Config) Config {
			config.Regions = []RegionSpec{{Code: GRU, CIDR: "10.1.0.1/24", Guests: []GuestSpec{{ID: "guest"}}}}
			return config
		},
		func(config Config) Config {
			config.Regions = []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "guest", Address: "192.0.2.1"}}}}
			return config
		},
		func(config Config) Config {
			config.Regions = []RegionSpec{{Code: GRU, Guests: []GuestSpec{{ID: "guest", TAP: "tap;bad"}}}}
			return config
		},
	}
	for i, mutate := range tests {
		config := mutate(qualifiedConfig(t))
		if _, err := Plan(config); err == nil {
			t.Errorf("case %d accepted unsafe declaration", i)
		}
	}
}

func TestCleanupContinuesAfterError(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
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
	plan, err := Plan(qualifiedConfig(t))
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

func transitNames(commands []Command) map[string]bool {
	result := make(map[string]bool)
	for _, command := range commands {
		args := command.Args
		for index := 0; index+7 < len(args); index++ {
			if args[index] == "link" && args[index+1] == "add" && args[index+3] == "type" && args[index+4] == "veth" && args[index+5] == "peer" && args[index+6] == "name" {
				result[args[index+2]] = true
				result[args[index+7]] = true
			}
		}
	}
	return result
}

func ownedResourceNames(plan NetworkPlan) map[string]bool {
	result := transitNames(plan.Commands)
	for _, region := range plan.Regions {
		result[region.Namespace] = true
		result[region.NamespacePath] = true
		result[region.Bridge] = true
		for _, guest := range region.Guests {
			result[guest.TAP] = true
		}
	}
	for _, command := range plan.Commands {
		for index, argument := range command.Args {
			if argument == "table" && index+2 < len(command.Args) && command.Args[index+1] == "inet" {
				result[command.Args[index+2]] = true
			}
		}
	}
	return result
}
