package vmnet

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestFaultControllerPartitionsHealsAndShapesLiveLinks(t *testing.T) {
	plan, err := Plan(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: -1}
	controller, err := NewFaultController(plan, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Partition(context.Background(), GRU, FRA); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 4 {
		t.Fatalf("partition commands = %d, want 4", len(runner.commands))
	}
	for index, command := range runner.commands {
		line := strings.Join(command.Args, " ")
		if index < 2 && !strings.Contains(line, "nft flush chain inet ts_vmnet") {
			t.Fatalf("partition did not clear owned chain first: %s", line)
		}
		if index >= 2 && !strings.HasSuffix(line, " drop") {
			t.Fatalf("partition did not install drop rule: %s", line)
		}
	}
	if err := controller.Partition(context.Background(), GRU, FRA); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 8 {
		t.Fatalf("repeated partition did not converge through owned chains: %d", len(runner.commands))
	}
	if err := controller.Heal(context.Background(), GRU, FRA); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 10 {
		t.Fatalf("heal commands = %d, want 2 additional", len(runner.commands))
	}

	profile := FaultSpec{From: SFO, To: FRA, Latency: 80 * time.Millisecond, Jitter: 5 * time.Millisecond, LossPercent: 1.25, BandwidthKbit: 256}
	if err := controller.SetNetem(context.Background(), profile); err != nil {
		t.Fatal(err)
	}
	line := strings.Join(runner.commands[len(runner.commands)-1].Args, " ")
	for _, want := range []string{"netns exec ts-n-sfo tc qdisc replace", "ts-v-sfo-fra", "80ms", "5ms", "1.25%", "256kbit"} {
		if !strings.Contains(line, want) {
			t.Fatalf("netem command %q lacks %q", line, want)
		}
	}
	if err := controller.ClearNetem(context.Background(), SFO, FRA); err != nil {
		t.Fatal(err)
	}
	cleared := len(runner.commands)
	if line := strings.Join(runner.commands[cleared-1].Args, " "); !strings.Contains(line, "tc qdisc del dev ts-v-sfo-fra root") {
		t.Fatalf("clear netem command = %q", line)
	}
	if err := controller.ClearNetem(context.Background(), SFO, FRA); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != cleared {
		t.Fatal("repeated ClearNetem mutated an already-clear link")
	}
}

func TestFaultControllerRollsBackPartialPartition(t *testing.T) {
	plan, err := Plan(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: 2}
	controller, err := NewFaultController(plan, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Partition(context.Background(), GRU, SFO); err == nil {
		t.Fatal("partition succeeded despite injected failure")
	}
	if len(runner.commands) != 5 {
		t.Fatalf("commands after failed partition = %d, want three attempts and two rollback flushes", len(runner.commands))
	}
	for _, command := range runner.commands[3:] {
		if !contains(command.Args, "flush") {
			t.Fatalf("rollback command did not heal the pair: %v", command.Args)
		}
	}
}

func TestFaultControllerTracksInitiallyAppliedNetem(t *testing.T) {
	config := DefaultConfig()
	config.Faults = []FaultSpec{{From: GRU, To: SFO, Latency: time.Millisecond}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{failAt: -1}
	controller, err := NewFaultController(plan, runner)
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.ClearNetem(context.Background(), GRU, SFO); err != nil {
		t.Fatal(err)
	}
	if len(runner.commands) != 1 || !contains(runner.commands[0].Args, "del") {
		t.Fatalf("initial netem was not cleared: %+v", runner.commands)
	}
}

func TestFaultControllerRejectsInvalidOperations(t *testing.T) {
	if _, err := NewFaultController(NetworkPlan{}, &fakeRunner{}); err == nil {
		t.Fatal("accepted an empty plan")
	}
	plan, err := Plan(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFaultController(plan, nil); err == nil {
		t.Fatal("accepted a nil runner")
	}
	controller, err := NewFaultController(plan, &fakeRunner{failAt: -1})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Partition(context.Background(), GRU, GRU); err == nil {
		t.Fatal("accepted a same-Region partition")
	}
	if err := controller.SetNetem(context.Background(), FaultSpec{From: GRU, To: SFO, LossPercent: -1}); err == nil {
		t.Fatal("accepted invalid netem")
	}
	if err := controller.SetNetem(context.Background(), FaultSpec{From: GRU, To: SFO, Partition: true}); err == nil {
		t.Fatal("accepted partition through SetNetem")
	}
	if err := (*FaultController)(nil).Heal(context.Background(), GRU, SFO); err == nil {
		t.Fatal("accepted a nil controller")
	}
	if err := controller.Heal(nil, GRU, SFO); err == nil {
		t.Fatal("accepted a nil context")
	}
}
