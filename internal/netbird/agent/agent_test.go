package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

func signedCommand(t *testing.T, action string) (Config, []byte) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pin, err := client.LoadPin("../../../deploy/image/image-inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Cell: "gru", Node: "node-a", Directory: t.TempDir(), Controller: public}
	command := network.Command{ID: network.CommandID("1XSA1KQFHZFFN74D9VXYVJGJE6", action), Transaction: "1XSA1KQFHZFFN74D9VXYVJGJE6", Generation: 1, Action: action, Target: network.Target{Pin: pin,
		Enrollment: netbird.Config{ManagementURL: netbird.DefaultManagementURL, Region: "sa-saopaulo-1", SetupKeySecretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.example.valid"}}}
	return cfg, signCommand(t, cfg, key, command, 3)
}

func signCommand(t *testing.T, cfg Config, key ed25519.PrivateKey, command network.Command, epoch uint64) []byte {
	t.Helper()
	payload, err := json.Marshal(command)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	step, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: cfg.Cell, Kind: "netbird.step", Actor: cfg.Node, OperationID: command.ID, Epoch: epoch, Generation: command.Generation}, now, now.Add(StepLifetime), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(step)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func workerFixture(t *testing.T) (Config, network.Command, ed25519.PrivateKey) {
	t.Helper()
	cfg, wire := signedCommand(t, "install")
	command, _, err := Verify(cfg, wire)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Controller = public
	cfg.StateDirectory = t.TempDir()
	if err := os.Chmod(cfg.StateDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := stateDirectory(cfg); err != nil {
		t.Fatal(err)
	}
	return cfg, command, key
}

func TestSignedNetBirdStepRejectsRetargetingAndTampering(t *testing.T) {
	cfg, wire := signedCommand(t, "confirm")
	if _, _, err := Verify(cfg, wire); err != nil {
		t.Fatal(err)
	}
	other := cfg
	other.Node = "node-b"
	if _, _, err := Verify(other, wire); err == nil {
		t.Fatal("accepted command signed for another node")
	}
	var step protocol.Envelope
	if err := json.Unmarshal(wire, &step); err != nil {
		t.Fatal(err)
	}
	step.Generation++
	tampered, err := json.Marshal(step)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Verify(cfg, tampered); err == nil {
		t.Fatal("accepted modified transaction generation")
	}
}

func TestRelayRejectsWrongArtifactBeforeSpoolingInstall(t *testing.T) {
	cfg, wire := signedCommand(t, "install")
	err := Relay(t.Context(), cfg, wire, func(_ context.Context, _ string, out io.Writer) error {
		_, err := out.Write([]byte("untrusted executable"))
		return err
	})
	if err == nil {
		t.Fatal("accepted unverified network-agent bytes")
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, "step.json")); !os.IsNotExist(err) {
		t.Fatalf("installation command became visible: %v", err)
	}
}

func TestRelaySpoolsConfirmationWithoutFetchingBinary(t *testing.T) {
	cfg, wire := signedCommand(t, "confirm")
	if err := Relay(t.Context(), cfg, wire, func(context.Context, string, io.Writer) error { t.Fatal("confirmation fetched a binary"); return nil }); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(cfg.Directory, "step.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(stored) != string(wire) {
		t.Fatal("relay changed signed command bytes")
	}
	link := filepath.Join(t.TempDir(), "spool")
	if err := os.Symlink(cfg.Directory, link); err != nil {
		t.Fatal(err)
	}
	if err := Write(link, "step.json", wire); err == nil {
		t.Fatal("spooled through a symlink")
	}
}

func TestSpoolReadRejectsUnsafeFilesWithoutBlocking(t *testing.T) {
	for _, kind := range []string{"regular", "symlink", "fifo", "directory", "writable", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "step.json")
			wire := []byte("signed command")
			switch kind {
			case "symlink":
				target := filepath.Join(t.TempDir(), "private")
				if err := os.WriteFile(target, wire, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := syscall.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				if kind == "oversize" {
					wire = make([]byte, 16385)
				}
				if err := os.WriteFile(path, wire, 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "writable" {
					if err := os.Chmod(path, 0620); err != nil {
						t.Fatal(err)
					}
				}
			}
			done := make(chan error, 1)
			go func() {
				got, err := read(directory, "step.json", 16384)
				if kind == "regular" && (err != nil || string(got) != string(wire)) {
					err = errors.New("regular spool file was not read")
				} else if kind != "regular" && err == nil {
					err = errors.New("unsafe spool file was accepted")
				} else {
					err = nil
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("spool read blocked")
			}
		})
	}
}

func TestWorkerRejectsReplayedTransactionsAcrossLeaderFailover(t *testing.T) {
	last := ledger{Generation: 20, Epoch: 3, Transaction: "2S68NEPB3AF7KVEFYXRZVNNGRJ", Action: "confirm", ActionID: network.CommandID("2S68NEPB3AF7KVEFYXRZVNNGRJ", "confirm")}
	for _, test := range []struct {
		name, transaction, action string
		generation, epoch         uint64
		accepted                  bool
	}{
		{"old transaction signed by new leader", "3WFCQVW916SRRSWMQAV8D0MHZE", "install", 19, 4, false},
		{"generation reused for another transaction", "2VP7F78J0ZNFE8BE3RYC7BNX9T", "install", 20, 4, false},
		{"install replay after confirm", "2S68NEPB3AF7KVEFYXRZVNNGRJ", "install", 20, 4, false},
		{"duplicate confirmation", "2S68NEPB3AF7KVEFYXRZVNNGRJ", "confirm", 20, 4, false},
		{"old leader", "7WVH811H6PKN5FZS9M96YYWYMF", "install", 21, 2, false},
		{"failover rollback", "2S68NEPB3AF7KVEFYXRZVNNGRJ", "rollback", 20, 4, true},
		{"next transaction", "7WVH811H6PKN5FZS9M96YYWYMF", "install", 21, 4, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := network.Command{ID: test.transaction + "." + test.action, Transaction: test.transaction, Action: test.action, Generation: test.generation}
			step := protocol.Envelope{Generation: test.generation, Epoch: test.epoch}
			if accepted := last.accepts(command, step); accepted != test.accepted {
				t.Fatalf("accepted=%v, want %v", accepted, test.accepted)
			}
		})
	}
	// A crash after journaling authority, before recording the effect's
	// result, must still allow the same idempotent install to resume.
	interrupted := ledger{Generation: 21, Epoch: 4, Transaction: "7WVH811H6PKN5FZS9M96YYWYMF", Action: "install", ActionID: network.CommandID("2S68NEPB3AF7KVEFYXRZVNNGRJ", "confirm")}
	if !interrupted.accepts(network.Command{ID: network.CommandID("7WVH811H6PKN5FZS9M96YYWYMF", "install"), Transaction: "7WVH811H6PKN5FZS9M96YYWYMF", Action: "install", Generation: 21}, protocol.Envelope{Generation: 21, Epoch: 4}) {
		t.Fatal("interrupted installation cannot resume")
	}
}

func TestWorkerPrivateLedgerSurvivesForgedDeletedRelayResultAndRestart(t *testing.T) {
	cfg, command, key := workerFixture(t)
	targetHash := network.Hash(command.Target)
	last := ledger{Generation: 20, Epoch: 4, Transaction: "6A9DXA113MF6SB6HF7QT199XK4", Action: "confirm", ActionID: network.CommandID("6A9DXA113MF6SB6HF7QT199XK4", "confirm"),
		TargetHash: targetHash, InstalledTargetHash: targetHash, AppliedTargetHash: targetHash}
	if err := saveLedger(cfg.StateDirectory, last); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []string{"forge", "delete", "corrupt"} {
		t.Run(mutation, func(t *testing.T) {
			resultPath := filepath.Join(cfg.Directory, "result.json")
			switch mutation {
			case "forge":
				if err := Write(cfg.Directory, "result.json", []byte(`{"generation":0,"epoch":0}`)); err != nil {
					t.Fatal(err)
				}
			case "delete":
				if err := os.Remove(resultPath); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			case "corrupt":
				if err := Write(cfg.Directory, "result.json", []byte("invalid JSON")); err != nil {
					t.Fatal(err)
				}
			}
			// A restarted worker reads its private ledger, never result.json.
			restarted, err := loadLedger(cfg.StateDirectory)
			if err != nil || restarted != last {
				t.Fatalf("restart lost worker authority: %+v, %v", restarted, err)
			}
			for _, stale := range []network.Command{
				{ID: network.CommandID("3WFCQVW916SRRSWMQAV8D0MHZE", "install"), Transaction: "3WFCQVW916SRRSWMQAV8D0MHZE", Generation: 19, Action: "install", Target: command.Target},
				{ID: network.CommandID("6A9DXA113MF6SB6HF7QT199XK4", "install"), Transaction: "6A9DXA113MF6SB6HF7QT199XK4", Generation: 20, Action: "install", Target: command.Target},
			} {
				wire := signCommand(t, cfg, key, stale, 5)
				if err := applyStep(t.Context(), cfg, &restarted, wire, func(context.Context, network.Command) error {
					t.Fatal("replayed command reached privileged effects")
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestWorkerAppliedTargetRequiresSuccessfulInstallAndConfirmation(t *testing.T) {
	cfg, command, key := workerFixture(t)
	previous := command.Target
	previous.Enrollment.ManagementIP = "10.250.10.155"
	previousHash := network.Hash(previous)
	targetHash := network.Hash(command.Target)
	last := ledger{AppliedTargetHash: previousHash}
	apply := func(action string, effectErr error) {
		t.Helper()
		command.Action, command.ID = action, network.CommandID(command.Transaction, action)
		if err := applyStep(t.Context(), cfg, &last, signCommand(t, cfg, key, command, 3), func(context.Context, network.Command) error { return effectErr }); err != nil {
			t.Fatal(err)
		}
		var err error
		last, err = loadLedger(cfg.StateDirectory)
		if err != nil {
			t.Fatal(err)
		}
	}
	apply("install", nil)
	if last.AppliedTargetHash != previousHash || last.InstalledTargetHash != targetHash {
		t.Fatal("unconfirmed install was reported as applied")
	}
	apply("confirm", errors.New("confirmation failed"))
	if last.AppliedTargetHash != previousHash || last.Error == "" {
		t.Fatal("failed confirmation changed applied target")
	}
	apply("confirm", nil)
	if last.AppliedTargetHash != targetHash || last.Error != "" {
		t.Fatal("successful confirmation did not publish applied target")
	}
	apply("rollback", errors.New("rollback failed"))
	if last.AppliedTargetHash != targetHash || last.Error == "" {
		t.Fatal("failed rollback reported previous target as restored")
	}
	apply("rollback", nil)
	if last.AppliedTargetHash != previousHash || last.Error != "" {
		t.Fatal("successful rollback did not preserve previous target identity")
	}
}

func TestWorkerRejectsConfirmationForAnUninstalledTarget(t *testing.T) {
	cfg, command, key := workerFixture(t)
	last := ledger{}
	if err := applyStep(t.Context(), cfg, &last, signCommand(t, cfg, key, command, 3), func(context.Context, network.Command) error { return nil }); err != nil {
		t.Fatal(err)
	}
	command.Action, command.ID = "confirm", network.CommandID(command.Transaction, "confirm")
	command.Target.Enrollment.ManagementIP = "10.250.10.155"
	if err := applyStep(t.Context(), cfg, &last, signCommand(t, cfg, key, command, 3), func(context.Context, network.Command) error {
		t.Fatal("confirmation acknowledged a different enrollment target")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if last.AppliedTargetHash != "" {
		t.Fatal("uninstalled target became applied")
	}
}

func TestWorkerFailedInstallCannotBeConfirmed(t *testing.T) {
	cfg, command, key := workerFixture(t)
	last := ledger{}
	if err := applyStep(t.Context(), cfg, &last, signCommand(t, cfg, key, command, 3), func(context.Context, network.Command) error {
		return errors.New("install failed")
	}); err != nil {
		t.Fatal(err)
	}
	command.Action, command.ID = "confirm", network.CommandID(command.Transaction, "confirm")
	if err := applyStep(t.Context(), cfg, &last, signCommand(t, cfg, key, command, 3), func(context.Context, network.Command) error {
		t.Fatal("failed installation was confirmed")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if last.InstalledTargetHash != "" || last.AppliedTargetHash != "" {
		t.Fatal("failed installation published an applied target")
	}
}

func TestWorkerPrivateStateRejectsSpoolOverlapSymlinksAndUnsafePermissions(t *testing.T) {
	cfg, _, _ := workerFixture(t)
	for _, directory := range []string{cfg.Directory, filepath.Join(cfg.Directory, "private")} {
		other := cfg
		other.StateDirectory = directory
		if _, err := stateDirectory(other); err == nil {
			t.Fatal("authority state allowed inside relay spool")
		}
	}
	link := filepath.Join(t.TempDir(), "private")
	if err := os.Symlink(cfg.StateDirectory, link); err != nil {
		t.Fatal(err)
	}
	other := cfg
	other.StateDirectory = link
	if _, err := stateDirectory(other); err == nil {
		t.Fatal("authority state traversed symlink")
	}
	if err := os.Chmod(cfg.StateDirectory, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := stateDirectory(cfg); err == nil {
		t.Fatal("authority directory was not private")
	}
	if err := os.Chmod(cfg.StateDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(cfg.Directory, "result.json"), filepath.Join(cfg.StateDirectory, "ledger.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLedger(cfg.StateDirectory); err == nil {
		t.Fatal("authority ledger accepted relay symlink")
	}
	if err := os.Remove(filepath.Join(cfg.StateDirectory, "ledger.json")); err != nil {
		t.Fatal(err)
	}
	if err := saveLedger(cfg.StateDirectory, ledger{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(cfg.StateDirectory, "ledger.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLedger(cfg.StateDirectory); err == nil {
		t.Fatal("authority ledger accepted non-private file permissions")
	}
}

func TestWorkerMissingRequiresExecutableAbsence(t *testing.T) {
	path := t.TempDir()
	t.Setenv("PATH", path)
	if !executableMissing() {
		t.Fatal("absent executable was not marked missing")
	}
	for _, mode := range []os.FileMode{0600, 0700} {
		if err := os.WriteFile(filepath.Join(path, "netbird"), []byte("#!/bin/sh\nexit 1\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(path, "netbird"), mode); err != nil {
			t.Fatal(err)
		}
		if executableMissing() {
			t.Fatalf("present executable failure mode %o was marked missing", mode)
		}
	}
	t.Setenv("PATH", strings.Join([]string{t.TempDir(), path}, string(os.PathListSeparator)))
	if executableMissing() {
		t.Fatal("executable in later PATH directory was marked missing")
	}
}

func TestVerifyRejectsSignedOldTransactionID(t *testing.T) {
	cfg, command, key := workerFixture(t)
	command.Transaction = "old-transaction"
	command.ID = network.CommandID(command.Transaction, command.Action)
	if _, _, err := Verify(cfg, signCommand(t, cfg, key, command, 3)); err == nil {
		t.Fatal("signed command accepted an old transaction ID")
	}
}
