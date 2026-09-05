package vmqualruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
)

func TestNetworkCleanupWaitsForRemovalAndRejectsPersistentResource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned-link")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- awaitNetworkResourceRemoval(ctx, path) }()
	select {
	case err := <-result:
		t.Fatalf("cleanup returned while resource existed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := awaitNetworkResourceRemoval(ctx, path); !errors.Is(err, context.Canceled) {
		t.Fatalf("persistent resource error = %v", err)
	}
}

func TestNewNetworkControllerUsesPinnedToolsAndWritesValidJournal(t *testing.T) {
	config := networkTestConfig(t)
	runner := &vmnet.RecordingRunner{}
	journalPath := filepath.Join(t.TempDir(), "network.json")
	controller, err := NewNetworkController(config, runner, journalPath)
	if err != nil {
		t.Fatal(err)
	}
	concrete, ok := controller.(*networkController)
	if !ok {
		t.Fatalf("controller type = %T, want *networkController", controller)
	}
	if concrete.Plan().RunID != config.RunID || concrete.Plan().Tools != config.Tools {
		t.Fatalf("controller plan lost ownership inputs: run=%q tools=%+v", concrete.Plan().RunID, concrete.Plan().Tools)
	}
	if err := controller.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(runner.Calls()) != len(concrete.Plan().Commands) {
		t.Fatalf("setup calls = %d, want %d", len(runner.Calls()), len(concrete.Plan().Commands))
	}
	for _, call := range runner.Calls() {
		if !filepath.IsAbs(call.Command.Executable) {
			t.Fatalf("setup used non-absolute executable %q", call.Command.Executable)
		}
		if len(call.Command.Args) >= 4 && call.Command.Args[0] == "netns" && call.Command.Args[1] == "exec" && !filepath.IsAbs(call.Command.Args[3]) {
			t.Fatalf("namespace setup used non-absolute nested executable %q", call.Command.Args[3])
		}
	}

	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	var journal vmnet.Journal
	if err := json.Unmarshal(data, &journal); err != nil {
		t.Fatal(err)
	}
	if err := vmqual.ValidateNetworkJournal(journal); err != nil {
		t.Fatalf("controller wrote an invalid journal: %v", err)
	}
	if journal.Fingerprint != concrete.Journal().Fingerprint {
		t.Fatalf("journal fingerprint = %q, want %q", journal.Fingerprint, concrete.Journal().Fingerprint)
	}
}

func TestNetworkControllerDelegatesDynamicFaults(t *testing.T) {
	config := networkTestConfig(t)
	runner := &vmnet.RecordingRunner{}
	controller, err := NewNetworkController(config, runner, "")
	if err != nil {
		t.Fatal(err)
	}
	dynamic, ok := controller.(interface {
		Partition(context.Context, vmnet.RegionCode, vmnet.RegionCode) error
		Heal(context.Context, vmnet.RegionCode, vmnet.RegionCode) error
		SetNetem(context.Context, vmnet.FaultSpec) error
		ClearNetem(context.Context, vmnet.RegionCode, vmnet.RegionCode) error
	})
	if !ok {
		t.Fatalf("controller type %T does not expose dynamic network faults", controller)
	}
	if err := controller.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}

	if err := dynamic.Partition(context.Background(), vmnet.GRU, vmnet.SFO); err != nil {
		t.Fatal(err)
	}
	partitionEnd := len(runner.Calls())
	if partitionEnd == 0 || !callsContain(runner.Calls(), "nft", "drop") {
		t.Fatalf("partition calls did not install an nft drop rule: %+v", runner.Calls())
	}
	if err := dynamic.Heal(context.Background(), vmnet.GRU, vmnet.SFO); err != nil {
		t.Fatal(err)
	}
	if !callsContain(runner.Calls()[partitionEnd:], "nft", "flush") || callsContain(runner.Calls()[partitionEnd:], "nft", "drop") {
		t.Fatalf("heal calls did not flush only the owned nft chains: %+v", runner.Calls()[partitionEnd:])
	}

	fault := vmnet.FaultSpec{
		From:          vmnet.SFO,
		To:            vmnet.FRA,
		Latency:       37 * time.Millisecond,
		Jitter:        3 * time.Millisecond,
		LossPercent:   1.25,
		BandwidthKbit: 512,
	}
	if err := dynamic.SetNetem(context.Background(), fault); err != nil {
		t.Fatal(err)
	}
	setEnd := len(runner.Calls())
	if setEnd == 0 {
		t.Fatal("SetNetem made no runner call")
	}
	if !callContains(runner.Calls()[setEnd-1], "tc", "replace", "37ms", "3ms", "1.25%", "512kbit") {
		t.Fatalf("SetNetem call = %+v", runner.Calls()[setEnd-1])
	}
	if err := dynamic.ClearNetem(context.Background(), vmnet.SFO, vmnet.FRA); err != nil {
		t.Fatal(err)
	}
	if len(runner.Calls()) != setEnd+1 || !callContains(runner.Calls()[len(runner.Calls())-1], "tc", "qdisc", "replace", "root", "netem") {
		t.Fatalf("ClearNetem calls = %+v", runner.Calls()[setEnd:])
	}
}

func TestValidateNetworkJournalRejectsToolAndRunOwnershipChanges(t *testing.T) {
	config := networkTestConfig(t)
	plan, err := vmnet.Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := vmqual.ValidateNetworkJournal(plan.Journal); err != nil {
		t.Fatalf("generated journal is invalid: %v", err)
	}

	t.Run("non-absolute top-level tool", func(t *testing.T) {
		journal := cloneNetworkJournal(t, plan.Journal)
		if len(journal.Cleanup.Commands) == 0 {
			t.Fatal("generated journal has no cleanup commands")
		}
		journal.Cleanup.Commands[0].Executable = "ip"
		if err := vmqual.ValidateNetworkJournal(journal); err == nil {
			t.Fatal("accepted a non-absolute cleanup executable")
		}
	})

	t.Run("non-absolute nested tool", func(t *testing.T) {
		journal := cloneNetworkJournal(t, plan.Journal)
		journal.Tools.NFT = "nft"
		journal.Cleanup.Tools.NFT = "nft"
		if err := vmqual.ValidateNetworkJournal(journal); err == nil {
			t.Fatal("accepted a non-absolute nested tool")
		}
	})

	t.Run("mismatched cleanup tools", func(t *testing.T) {
		journal := cloneNetworkJournal(t, plan.Journal)
		journal.Cleanup.Tools.NFT = filepath.Join(t.TempDir(), "nft")
		if err := vmqual.ValidateNetworkJournal(journal); err == nil {
			t.Fatal("accepted cleanup tools that do not match the journal tool paths")
		}
	})

	t.Run("different run ownership", func(t *testing.T) {
		journal := cloneNetworkJournal(t, plan.Journal)
		changed := false
		for index := range journal.Cleanup.Commands {
			args := journal.Cleanup.Commands[index].Args
			if len(args) == 3 && args[0] == "netns" && args[1] == "del" {
				args[2] = "ts-fedcba9876543210fedcba9876543210-n-gru"
				changed = true
				break
			}
		}
		if !changed {
			t.Fatal("generated journal has no namespace cleanup command")
		}
		if err := vmqual.ValidateNetworkJournal(journal); err == nil {
			t.Fatal("accepted cleanup ownership from a different run")
		}
	})
}

func TestNetworkControllerCleanupIgnoresCallerCancellationButBoundsCommands(t *testing.T) {
	config := networkTestConfig(t)
	runner := &vmnet.RecordingRunner{}
	controller, err := NewNetworkController(config, runner, "")
	if err != nil {
		t.Fatal(err)
	}
	concrete := controller.(*networkController)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	if err := controller.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	if len(runner.Calls()) != len(concrete.Plan().Cleanup.Commands) {
		t.Fatalf("cleanup calls = %d, want %d", len(runner.Calls()), len(concrete.Plan().Cleanup.Commands))
	}
	for _, call := range runner.Calls() {
		if !call.Cleanup {
			t.Fatalf("cleanup used ordinary runner entry point: %+v", call)
		}
		if call.Canceled {
			t.Fatalf("cleanup inherited caller cancellation: %+v", call)
		}
		if !call.HasDeadline || call.Deadline.Before(started) || call.Deadline.After(started.Add(11*time.Second)) {
			t.Fatalf("cleanup command deadline = %v, started %v", call.Deadline, started)
		}
	}
}

func networkTestConfig(t *testing.T) vmnet.Config {
	t.Helper()
	directory := t.TempDir()
	paths := make(map[string]string, 4)
	for _, name := range []string{"ip", "nft", "tc", "sysctl"} {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("fake executable"), 0700); err != nil {
			t.Fatal(err)
		}
		paths[name] = path
	}
	config := vmnet.DefaultConfig()
	digest := sha256.Sum256([]byte(t.Name()))
	config.RunID = hex.EncodeToString(digest[:16])
	config.CoordinationRoot = filepath.Join(directory, "coordination")
	config.Tools = vmnet.ToolPaths{IP: paths["ip"], NFT: paths["nft"], TC: paths["tc"], Sysctl: paths["sysctl"]}
	return config
}

func cloneNetworkJournal(t *testing.T, journal vmnet.Journal) vmnet.Journal {
	t.Helper()
	data, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	var clone vmnet.Journal
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func callsContain(calls []vmnet.RecordingCall, values ...string) bool {
	for _, call := range calls {
		if callContains(call, values...) {
			return true
		}
	}
	return false
}

func callContains(call vmnet.RecordingCall, values ...string) bool {
	line := call.Command.Executable + "\x00" + strings.Join(call.Command.Args, "\x00")
	for _, value := range values {
		if !strings.Contains(line, value) {
			return false
		}
	}
	return true
}

var _ vmnet.CleanupRunner = (*vmnet.RecordingRunner)(nil)
