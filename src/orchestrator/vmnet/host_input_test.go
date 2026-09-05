package vmnet

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestHostInputWithoutDNSReplaysSerializedCleanup(t *testing.T) {
	config := qualifiedConfig(t)
	config.Regions = config.Regions[:1]
	config.Endpoints = []EndpointSpec{{Name: "ntp", Region: GRU, Protocol: UDP, GuestPort: 123, HostPort: 18123}}
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeJournalWriter{}
	if err := plan.ApplyWithJournal(context.Background(), &fakeRunner{failAt: -1}, writer); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(writer.plan)
	if err != nil {
		t.Fatal(err)
	}
	var recovered Journal
	if err := json.Unmarshal(data, &recovered); err != nil {
		t.Fatal(err)
	}
	if err := recovered.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := recovered.Cleanup.Run(context.Background(), &fakeCleanupRunner{}); err != nil {
		t.Fatal(err)
	}
}

func TestHostInputAdmissionMatchesOnlyJournaledEndpointTuples(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewHostRunner(plan.Tools)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Cleanup.HostInput) != len(plan.Forwards) {
		t.Fatal("cleanup omitted an endpoint")
	}
	for _, command := range plan.Cleanup.HostInput {
		if !runner.admittedCleanup(command.Executable, command.Args) {
			t.Fatalf("rejected owned cleanup: %+v", command)
		}
	}
	for _, mutate := range []func([]string){
		func(a []string) { a[4] = "-F" },
		func(a []string) { a[5] = "FORWARD" },
		func(a []string) { a[7] = "eth0" },
		func(a []string) { a[9] = "198.18.0.0/16" },
		func(a []string) { a[11] = "0.0.0.0/0" },
		func(a []string) { a[13] = "all" },
		func(a []string) { a[15] = "0" },
		func(a []string) { a[19] = "unrelated" },
		func(a []string) { a[21] = "DROP" },
	} {
		command := plan.Cleanup.HostInput[0].copy()
		mutate(command.Args)
		if runner.admittedCleanup(command.Executable, command.Args) {
			t.Fatalf("admitted unowned command: %v", command.Args)
		}
		cleanup := plan.Cleanup.copy()
		cleanup.HostInput[0] = command
		if err := cleanup.Validate(); err == nil {
			t.Fatal("journal admitted changed tuple")
		}
	}
	cleanup := plan.Cleanup.copy()
	cleanup.HostInput = cleanup.HostInput[1:]
	if err := cleanup.Validate(); err == nil {
		t.Fatal("journal admitted a missing cleanup obligation")
	}
}

type hostInputStateRunner struct {
	fakeRunner
	rules      map[string]bool
	writer     *fakeJournalWriter
	failInsert int
	inserts    int
	denyDelete bool
}

func (r *hostInputStateRunner) Run(ctx context.Context, executable string, args []string) error {
	if !admittedHostInput(args) {
		return r.fakeRunner.Run(ctx, executable, args)
	}
	if r.writer.writes == 0 {
		return errors.New("firewall mutation preceded durable journal")
	}
	start := 6
	if args[4] == "-I" {
		start = 7
		r.inserts++
		if r.failInsert == r.inserts {
			return errors.New("injected firewall insertion failure")
		}
	}
	key := strings.Join(args[start:], " ")
	if args[4] == "-D" {
		if r.denyDelete {
			return errors.New("injected firewall deletion failure")
		}
		delete(r.rules, key)
	} else {
		r.rules[key] = true
	}
	return nil
}

func TestHostInputJournalPartialApplyCleanupAndLeaseRetention(t *testing.T) {
	config := qualifiedConfig(t)
	plan, err := Plan(config)
	if err != nil {
		t.Fatal(err)
	}
	writer := &fakeJournalWriter{}
	runner := &hostInputStateRunner{fakeRunner: fakeRunner{failAt: -1}, rules: map[string]bool{"unrelated ambient deny": true}, writer: writer, failInsert: 2, denyDelete: true}
	if err := plan.ApplyWithJournal(context.Background(), runner, writer); err == nil {
		t.Fatal("partial insertion unexpectedly succeeded")
	}
	if len(runner.rules) != 2 || !runner.rules["unrelated ambient deny"] {
		t.Fatalf("partial insertion or unrelated rule lost: %v", runner.rules)
	}
	if err := plan.Cleanup.Run(context.Background(), runner); err == nil {
		t.Fatal("failed deletion reported complete")
	}
	coordinator, unlock := lockRunCoordinator(plan.RunID)
	retained := coordinator.hostLease != nil && coordinator.cleanupRequired
	unlock()
	if !retained {
		t.Fatal("failed deletion released host ownership")
	}
	runner.denyDelete = false
	for i := 0; i < 2; i++ {
		if err := writer.plan.Cleanup.Run(context.Background(), runner); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(runner.rules, map[string]bool{"unrelated ambient deny": true}) {
		t.Fatalf("cleanup changed unrelated rules: %v", runner.rules)
	}
}

func writeIPTablesScript(t *testing.T, path, body string) {
	t.Helper()
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("#!"+shell+"\n"+body+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
}

type hostInputTestRunner struct{ *HostRunner }

func (*hostInputTestRunner) vmnetNonHostRunner() {}

func TestHostInputCollisionAndCleanupErrorClassification(t *testing.T) {
	plan, err := Plan(qualifiedConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewHostRunner(plan.Tools)
	if err != nil {
		t.Fatal(err)
	}
	writeIPTablesScript(t, plan.Tools.IPTables, "exit 0")
	writer := &fakeJournalWriter{}
	if err := plan.ApplyWithJournal(context.Background(), &hostInputTestRunner{runner}, writer); err == nil || !strings.Contains(err.Error(), "existing owned host input rule") || writer.writes != 0 {
		t.Fatalf("collision was not refused before journaling: writes=%d err=%v", writer.writes, err)
	}
	for _, test := range []struct {
		body    string
		missing bool
	}{
		{"echo 'iptables: Bad rule (does a matching rule exist in that chain?)' >&2; exit 1", true},
		{"echo 'Permission denied' >&2; exit 1", false},
		{"echo 'Bad rule (does a matching rule exist in that chain?)' >&2; exit 4", false},
	} {
		writeIPTablesScript(t, plan.Tools.IPTables, test.body)
		command := plan.Cleanup.HostInput[0]
		err := runner.RunCleanup(context.Background(), command.Executable, command.Args)
		if (err == nil) != test.missing {
			t.Fatalf("missing=%v err=%v", test.missing, err)
		}
	}
}

func TestIPTablesMulticallUsesExplicitDispatch(t *testing.T) {
	for _, name := range []string{"xtables-nft-multi", "xtables-legacy-multi"} {
		path := "/trusted/" + name
		if err := validateHostToolPath("iptables", path); err != nil {
			t.Fatal(err)
		}
		if got := iptablesArguments(path, []string{"-w", "5"}); !reflect.DeepEqual(got, []string{"iptables", "-w", "5"}) {
			t.Fatalf("multicall dispatch=%v", got)
		}
		if err := validateHostToolPath("ip", path); err == nil {
			t.Fatal("multicall broadened unrelated executable admission")
		}
	}
}
