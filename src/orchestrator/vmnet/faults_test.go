package vmnet

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type indexedFailureRunner struct {
	commands []Command
	failures map[int]error
}

type blockingFaultRunner struct {
	mu      sync.Mutex
	calls   int
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (*indexedFailureRunner) vmnetNonHostRunner() {}
func (*blockingFaultRunner) vmnetNonHostRunner()  {}

func (r *blockingFaultRunner) Run(context.Context, string, []string) error {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	r.started <- struct{}{}
	r.once.Do(func() { <-r.release })
	return nil
}

func (r *blockingFaultRunner) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func applyFaultTestPlan(t *testing.T, plan NetworkPlan) {
	t.Helper()
	if err := plan.ApplyWithJournal(context.Background(), &fakeRunner{failAt: -1}, &fakeJournalWriter{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := plan.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
			t.Errorf("clean applied fault plan: %v", err)
		}
	})
}

func (r *indexedFailureRunner) Run(_ context.Context, executable string, args []string) error {
	index := len(r.commands)
	r.commands = append(r.commands, command(executable, args...))
	return r.failures[index]
}

func TestNetworkPlanPartitionsHealsAndShapesLiveLinks(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	applyFaultTestPlan(t, plan)
	runner := &fakeRunner{failAt: -1}

	if err := plan.Partition(context.Background(), runner, GRU, FRA); err != nil {
		t.Fatal(err)
	}
	assertDynamicCommandsUsePinnedTools(t, runner.commands, config.Tools.IP, config.Tools.NFT)
	partition := joinedCommands(runner.commands)
	for _, want := range []string{regionNamespace(t, plan, GRU), regionNamespace(t, plan, FRA), config.Tools.NFT, " drop"} {
		if !strings.Contains(partition, want) {
			t.Fatalf("partition commands lack %q:\n%s", want, partition)
		}
	}

	runner.commands = nil
	if err := plan.Heal(context.Background(), runner, GRU, FRA); err != nil {
		t.Fatal(err)
	}
	assertDynamicCommandsUsePinnedTools(t, runner.commands, config.Tools.IP, config.Tools.NFT)
	heal := joinedCommands(runner.commands)
	if !strings.Contains(heal, " flush chain ") || strings.Contains(heal, " drop") {
		t.Fatalf("heal did not flush only the owned fault chains:\n%s", heal)
	}

	runner.commands = nil
	profile := FaultSpec{From: SFO, To: FRA, Latency: 80 * time.Millisecond, Jitter: 5 * time.Millisecond, LossPercent: 1.25, BandwidthKbit: 256}
	if err := plan.SetNetem(context.Background(), runner, profile); err != nil {
		t.Fatal(err)
	}
	assertDynamicCommandsUsePinnedTools(t, runner.commands, config.Tools.IP, config.Tools.TC)
	netem := joinedCommands(runner.commands)
	for _, want := range []string{regionNamespace(t, plan, SFO), config.Tools.TC, " qdisc replace ", "80ms", "5ms", "1.25%", "256kbit"} {
		if !strings.Contains(netem, want) {
			t.Fatalf("netem commands lack %q:\n%s", want, netem)
		}
	}

	runner.commands = nil
	if err := plan.ClearNetem(context.Background(), runner, SFO, FRA); err != nil {
		t.Fatal(err)
	}
	assertDynamicCommandsUsePinnedTools(t, runner.commands, config.Tools.IP, config.Tools.TC)
	clear := joinedCommands(runner.commands)
	if !strings.Contains(clear, " qdisc ") || !strings.Contains(clear, " root") {
		t.Fatalf("clear netem did not reset the owned root qdisc:\n%s", clear)
	}
	for _, impairment := range []string{" delay ", " loss ", " reorder ", " duplicate ", " rate "} {
		if strings.Contains(clear, impairment) {
			t.Fatalf("clear netem retained impairment %q:\n%s", impairment, clear)
		}
	}
}

func TestNetworkPlanRollsBackPartialPartition(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	applyFaultTestPlan(t, plan)
	runner := &fakeRunner{failAt: 2}
	if err := plan.Partition(context.Background(), runner, GRU, SFO); err == nil {
		t.Fatal("partition succeeded despite injected failure")
	}
	if len(runner.commands) < 4 {
		t.Fatalf("failed partition did not attempt a deterministic heal: %+v", runner.commands)
	}
	for _, command := range runner.commands[3:] {
		if !contains(command.Args, "flush") {
			t.Fatalf("partition rollback did not heal the pair: %+v", command)
		}
	}
}

func TestRepeatedPartitionFailureRestoresPartitionedState(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	applyFaultTestPlan(t, plan)
	if err := plan.Partition(context.Background(), &fakeRunner{failAt: -1}, GRU, SFO); err != nil {
		t.Fatal(err)
	}

	runner := &fakeRunner{failAt: 2}
	if err := plan.Partition(context.Background(), runner, GRU, SFO); err == nil {
		t.Fatal("repeated partition succeeded despite injected failure")
	}
	if len(runner.commands) != 7 {
		t.Fatalf("repeated partition made %d calls, want three attempted and four rollback calls", len(runner.commands))
	}
	rollback := runner.commands[3:]
	drops := 0
	for _, command := range rollback {
		if contains(command.Args, "drop") {
			drops++
		}
	}
	if drops != 2 {
		t.Fatalf("rollback restored a healed state instead of both drop rules: %+v", rollback)
	}
}

func TestSameRunFaultControllersSerializeMutations(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	applyFaultTestPlan(t, plan)
	runner := &blockingFaultRunner{started: make(chan struct{}, 16), release: make(chan struct{})}
	results := make(chan error, 2)
	go func() { results <- plan.Partition(context.Background(), runner, GRU, SFO) }()
	<-runner.started
	go func() { results <- plan.Heal(context.Background(), runner, GRU, SFO) }()
	select {
	case <-runner.started:
		t.Fatal("a second fault controller mutated the same run concurrently")
	case <-time.After(50 * time.Millisecond):
	}
	close(runner.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if calls := runner.callCount(); calls != 6 {
		t.Fatalf("serialized partition and heal calls = %d, want six", calls)
	}
}

func TestFaultMutationRequiresJournaledApply(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: -1}
	if err := plan.Partition(context.Background(), runner, GRU, SFO); err == nil || !strings.Contains(err.Error(), "journaled applied network") {
		t.Fatalf("unapplied fault error = %v", err)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("unapplied fault reached runner: %+v", runner.commands)
	}
}

func TestNetworkPlanFaultRecoveryTriesBothDirections(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	applyFaultTestPlan(t, plan)

	healFailure := errors.New("first heal failed")
	healRunner := &indexedFailureRunner{failures: map[int]error{0: healFailure}}
	if err := plan.Heal(context.Background(), healRunner, GRU, SFO); !errors.Is(err, healFailure) {
		t.Fatalf("heal error = %v, want first directional failure", err)
	}
	if len(healRunner.commands) != 4 {
		t.Fatalf("heal attempted %d commands, want both directions plus exact rollback", len(healRunner.commands))
	}

	partitionFailure := errors.New("partition failed")
	rollbackFailure := errors.New("rollback failed")
	partitionRunner := &indexedFailureRunner{failures: map[int]error{0: partitionFailure, 1: rollbackFailure}}
	err = plan.Partition(context.Background(), partitionRunner, GRU, SFO)
	if !errors.Is(err, partitionFailure) || !errors.Is(err, rollbackFailure) || !strings.Contains(err.Error(), "prior partition state") {
		t.Fatalf("partition error does not preserve apply and rollback failures: %v", err)
	}
	if len(partitionRunner.commands) != 3 {
		t.Fatalf("partition failure attempted %d commands, want one apply and two rollback commands", len(partitionRunner.commands))
	}
}

func TestHealFailureRestoresPriorPartitionInBothDirections(t *testing.T) {
	for _, failureIndex := range []int{0, 1} {
		t.Run(strconv.Itoa(failureIndex), func(t *testing.T) {
			plan, err := Plan(qualifiedConfig(t))
			if err != nil {
				t.Fatal(err)
			}
			applyFaultTestPlan(t, plan)
			if err := plan.Partition(context.Background(), &fakeRunner{failAt: -1}, GRU, SFO); err != nil {
				t.Fatal(err)
			}

			runner := &fakeRunner{failAt: failureIndex}
			if err := plan.Heal(context.Background(), runner, GRU, SFO); err == nil {
				t.Fatal("Heal succeeded despite injected directional failure")
			}
			if len(runner.commands) != 6 {
				t.Fatalf("Heal calls = %d, want two attempts and four rollback calls", len(runner.commands))
			}
			drops := 0
			for _, command := range runner.commands[2:] {
				if contains(command.Args, "drop") {
					drops++
				}
			}
			if drops != 2 {
				t.Fatalf("Heal rollback did not restore both drop rules: %+v", runner.commands[2:])
			}
		})
	}
}

func TestNetworkPlanRejectsInvalidDynamicFaults(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	applyFaultTestPlan(t, plan)
	runner := &fakeRunner{failAt: -1}
	if err := plan.Partition(context.Background(), runner, GRU, GRU); err == nil {
		t.Fatal("accepted a same-Region partition")
	}
	if err := plan.Partition(nil, runner, GRU, SFO); err == nil {
		t.Fatal("accepted a nil partition context")
	}
	if err := plan.Heal(context.Background(), nil, GRU, SFO); err == nil {
		t.Fatal("accepted a nil heal runner")
	}
	if err := plan.SetNetem(context.Background(), runner, FaultSpec{From: GRU, To: SFO, LossPercent: -1}); err == nil {
		t.Fatal("accepted invalid netem")
	}
	if err := plan.SetNetem(context.Background(), runner, FaultSpec{From: GRU, To: SFO, Partition: true}); err == nil {
		t.Fatal("accepted partition through SetNetem")
	}
	if err := plan.ClearNetem(context.Background(), runner, GRU, GRU); err == nil {
		t.Fatal("accepted same-Region netem clear")
	}
	for _, fault := range []FaultSpec{
		{From: GRU, To: SFO, Latency: 500 * time.Nanosecond},
		{From: GRU, To: SFO, Latency: maxNetemDelay + time.Microsecond},
		{From: GRU, To: SFO, BandwidthKbit: maxNetemBandwidthKbit + 1},
	} {
		if err := plan.SetNetem(context.Background(), runner, fault); err == nil {
			t.Fatalf("accepted unbounded or tc-inexpressible fault: %+v", fault)
		}
	}
	if len(runner.commands) != 0 {
		t.Fatalf("invalid dynamic faults mutated the runner: %+v", runner.commands)
	}
}

func TestNetworkPlanNetemUsesASCIIUnits(t *testing.T) {
	config := qualifiedConfig(t)
	config.Faults = []FaultSpec{{From: GRU, To: SFO, Latency: 500 * time.Microsecond, Jitter: 25 * time.Microsecond}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	applyFaultTestPlan(t, plan)
	joined := joinedCommands(plan.Commands)
	if !strings.Contains(joined, "delay 500us 25us") || strings.Contains(joined, "µ") {
		t.Fatalf("static netem duration is not valid tc ASCII: %s", joined)
	}

	runner := &fakeRunner{failAt: -1}
	if err := plan.SetNetem(context.Background(), runner, FaultSpec{From: SFO, To: FRA, Latency: 750 * time.Microsecond}); err != nil {
		t.Fatal(err)
	}
	dynamic := joinedCommands(runner.commands)
	if !strings.Contains(dynamic, "delay 750us") || strings.Contains(dynamic, "µ") {
		t.Fatalf("dynamic netem duration is not valid tc ASCII: %s", dynamic)
	}
}

func TestFaultControllerRejectsForeignRunNamespace(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	foreignConfig := config
	foreignConfig.RunID = "ffffffffffffffffffffffffffffffff"
	foreign, err := Plan(foreignConfig)
	if err != nil {
		t.Fatal(err)
	}
	tampered := plan.copy()
	tampered.Regions[0].Namespace = foreign.Regions[0].Namespace
	tampered.Regions[0].NamespacePath = foreign.Regions[0].NamespacePath
	runner := &fakeRunner{failAt: -1}
	if _, err := NewFaultController(tampered, runner); err == nil {
		t.Fatal("fault controller accepted a Region namespace owned by another run")
	}
	if len(runner.commands) != 0 {
		t.Fatalf("foreign dynamic fault reached runner: %+v", runner.commands)
	}
}

func assertDynamicCommandsUsePinnedTools(t *testing.T, commands []Command, ip, nested string) {
	t.Helper()
	if len(commands) == 0 {
		t.Fatal("dynamic operation emitted no commands")
	}
	for _, command := range commands {
		if command.Executable != ip {
			t.Fatalf("dynamic command executable = %q, want %q", command.Executable, ip)
		}
		if len(command.Args) < 4 || command.Args[0] != "netns" || command.Args[1] != "exec" || command.Args[3] != nested {
			t.Fatalf("dynamic command does not pin nested executable %q: %+v", nested, command)
		}
	}
}

func joinedCommands(commands []Command) string {
	var joined strings.Builder
	for _, command := range commands {
		joined.WriteString(command.Executable)
		joined.WriteByte(' ')
		joined.WriteString(strings.Join(command.Args, " "))
		joined.WriteByte('\n')
	}
	return joined.String()
}

func regionNamespace(t *testing.T, plan NetworkPlan, code RegionCode) string {
	t.Helper()
	for _, region := range plan.Regions {
		if region.Code == code {
			return region.Namespace
		}
	}
	t.Fatalf("plan lacks Region %s", code)
	return ""
}
