package agent

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

func completedTargetLedger() ledger {
	transaction := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	hash := strings.Repeat("a", 64)
	return ledger{Generation: 2, Epoch: 3, Transaction: transaction, Action: "confirm", ActionID: network.CommandID(transaction, "confirm"),
		TargetHash: hash, InstalledTargetHash: hash, AppliedTargetHash: hash}
}

func TestCompletedTargetRejectsUnfinishedOrDifferentTarget(t *testing.T) {
	last := completedTargetLedger()
	view, err := completedTarget(last)
	if err != nil || view.Generation != last.Generation || view.Epoch != last.Epoch || view.Transaction != last.Transaction ||
		view.Action != last.Action || view.ActionID != last.ActionID || view.TargetHash != last.TargetHash ||
		view.InstalledTargetHash != last.InstalledTargetHash || view.AppliedTargetHash != last.AppliedTargetHash {
		t.Fatalf("confirmed checkpoint: %+v %v", view, err)
	}
	for name, change := range map[string]func(*ledger){
		"pre-effect confirm": func(last *ledger) { last.ActionID = network.CommandID(last.Transaction, "install") },
		"failed confirm":     func(last *ledger) { last.Error = "confirmation failed" },
		"installed differs":  func(last *ledger) { last.InstalledTargetHash = strings.Repeat("b", 64) },
		"applied differs":    func(last *ledger) { last.AppliedTargetHash = strings.Repeat("b", 64) },
		"missing installed":  func(last *ledger) { last.InstalledTargetHash = "" },
		"missing applied":    func(last *ledger) { last.AppliedTargetHash = "" },
		"noncanonical hash":  func(last *ledger) { last.TargetHash = strings.Repeat("A", 64) },
		"invalid transaction": func(last *ledger) {
			last.Transaction = "not-a-transaction"
			last.ActionID = network.CommandID(last.Transaction, "confirm")
		},
		"zero generation": func(last *ledger) { last.Generation = 0 },
		"zero epoch":      func(last *ledger) { last.Epoch = 0 },
		"install":         func(last *ledger) { last.Action = "install" },
		"rollback":        func(last *ledger) { last.Action = "rollback"; last.InstalledTargetHash = "" },
		"absent":          func(last *ledger) { *last = ledger{} },
	} {
		t.Run(name, func(t *testing.T) {
			last := completedTargetLedger()
			change(&last)
			if view, err := completedTarget(last); err == nil || view != (CompletedTargetView{}) {
				t.Fatalf("unfinished checkpoint accepted: %+v %v", view, err)
			}
		})
	}
}

func TestReadCompletedTargetRejectsNoncanonicalIdentity(t *testing.T) {
	for _, identity := range [][2]string{{"GRU", "gru-1-ctl-1"}, {"unknown", "ts-gru-1"}, {"gru", "../ts-gru-1"}, {"gru", "gru-1-controller-a"}} {
		if view, err := ReadCompletedTarget(identity[0], identity[1]); err == nil || view != (CompletedTargetView{}) {
			t.Fatalf("invalid identity accepted: %q %+v %v", identity, view, err)
		}
	}
	if os.Geteuid() != 0 {
		if _, err := ReadCompletedTarget("gru", "gru-1-ctl-1"); err == nil {
			t.Fatal("unprivileged caller accepted")
		}
	}
}

func TestCompletedTargetDirectoryRejectsUnprotectedOwnerOrMode(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0770); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := checkCompletedTargetDirectory(int(file.Fd()), false); err == nil {
		t.Fatal("writable ancestor accepted")
	}
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if err := checkCompletedTargetDirectory(int(file.Fd()), true); err == nil {
		t.Fatal("nonprivate final directory accepted")
	}
	if os.Geteuid() != 0 {
		if err := os.Chmod(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := checkCompletedTargetDirectory(int(file.Fd()), true); err == nil {
			t.Fatal("nonroot final directory accepted")
		}
	}
}

func TestCompletedTargetDescriptorAndStrictLedger(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("protected worker-ledger fixture requires root ownership")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(completedTargetLedger())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "ledger.json")
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := os.Rename(directory, directory+".moved"); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory + ".moved")
	if err := os.Symlink(t.TempDir(), directory); err != nil {
		t.Fatal(err)
	}
	if _, err := readCompletedTarget(file); err != nil {
		t.Fatalf("held ledger descriptor followed replaced path: %v", err)
	}
	path = filepath.Join(directory+".moved", "ledger.json")
	for name, change := range map[string]func() error{
		"unknown field": func() error {
			return os.WriteFile(path, append(append([]byte(nil), wire[:len(wire)-1]...), []byte(",\"unknown\":true}")...), 0600)
		},
		"duplicate field": func() error {
			return os.WriteFile(path, append(append([]byte(nil), wire[:len(wire)-1]...), []byte(",\"epoch\":3}")...), 0600)
		},
		"public mode": func() error { return os.Chmod(path, 0644) },
		"hard link": func() error {
			alias := filepath.Join(directory+".moved", "alias")
			return os.Link(path, alias)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Cleanup(func() { _ = os.Remove(filepath.Join(directory+".moved", "alias")) })
			if err := os.WriteFile(path, wire, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := change(); err != nil {
				t.Fatal(err)
			}
			if _, err := readCompletedTarget(file); err == nil {
				t.Fatal("unsafe ledger accepted")
			}
		})
	}
}
