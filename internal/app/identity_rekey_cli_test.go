package app

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/selfupdate"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
)

func TestIdentityRekeyRecoveryChecksClockBeforeSigningAndPublication(t *testing.T) {
	js := testRolloutJetStream(t)
	for _, bucket := range []string{"TS_SERVICE_SET", "TS_TRUST_ROOTS"} {
		if _, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: bucket, Storage: jetstream.FileStorage, Replicas: 1}); err != nil {
			t.Fatal(err)
		}
	}
	control, err := authority.Start(t.Context(), js, authority.Config{DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	epoch := control.Current().Epoch
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	floor, err := authority.ObserveIdentityResetFloor(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(public)
	if err != nil {
		t.Fatal(err)
	}
	reset := authority.IdentityReset{Version: 1, OperationID: entityid.New(), DeploymentID: entityid.New(), ClusterID: entityid.New(),
		Scope: "gru", Environment: "production", CheckpointSHA256: controllerSHA256([]byte("checkpoint")),
		HostStatePlanSHA256: controllerSHA256([]byte("host plan")), LastSequence: floor.LastSequence,
		PreviousSequence: floor.PreviousSequence, PreviousSHA256: floor.PreviousSHA256, EpochFloor: epoch, Epoch: epoch + 1,
		Records: []authority.IdentityResetRecord{{Action: authority.IdentityResetReplaceKV, Bucket: "TS_SERVICE_SET", Key: "current", SHA256: controllerSHA256([]byte("services"))},
			{Action: authority.IdentityResetReplaceKV, Bucket: "TS_TRUST_ROOTS", Key: "chain", SHA256: controllerSHA256([]byte("roots"))},
			{Action: authority.IdentityResetReplaceKV, Bucket: "TS_TRUST_ROOTS", Key: "material-generations", SHA256: controllerSHA256([]byte("material"))}}}
	target := authority.IdentityResetTarget{OperationID: reset.OperationID, DeploymentID: reset.DeploymentID, ClusterID: reset.ClusterID,
		Scope: reset.Scope, Environment: reset.Environment, CheckpointSHA256: reset.CheckpointSHA256, HostStatePlanSHA256: reset.HostStatePlanSHA256, Replicas: 1}
	issued := time.Now().Add(-2 * time.Hour)
	envelope, err := authority.SignIdentityReset(reset, issued, issued.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.ResetIdentityLease(t.Context(), js, envelope, roots, target, issued.Add(time.Minute)); !errors.Is(err, authority.ErrOutcomeUnknown) {
		t.Fatalf("fixture must hold an out-of-window committed transaction: %v", err)
	}
	stream, err := js.Stream(t.Context(), authority.ControlStreamName)
	if err != nil {
		t.Fatal(err)
	}
	before, err := stream.Info(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	clockErr := errors.New("controller clock unsynchronized")
	for _, failedCheck := range []int{1, 2} {
		calls := 0
		clock := func() error {
			calls++
			if calls == failedCheck {
				return clockErr
			}
			return nil
		}
		if err := authorizeIdentityRekeyRecovery(t.Context(), js, envelope, roots, target, key, clock); !errors.Is(err, clockErr) || calls != failedCheck {
			t.Fatalf("clock failure at boundary %d: %d calls, %v", failedCheck, calls, err)
		}
		after, err := stream.Info(t.Context())
		if err != nil || after.State.LastSeq != before.State.LastSeq {
			t.Fatal("unhealthy recovery clock published shared authority")
		}
	}
	if err := authorizeIdentityRekeyRecovery(t.Context(), js, envelope, roots, target, key, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.VerifyCommittedIdentityReset(t.Context(), js, envelope, roots, target); err != nil {
		t.Fatalf("healthy-clock authorization cannot resume exact hold: %v", err)
	}
}

func TestIdentityRekeyCLIRejectsUnreviewedArguments(t *testing.T) {
	var output bytes.Buffer
	if err := Run(t.Context(), []string{"identity-rekey", "--help"}, &output); err != nil ||
		!strings.Contains(output.String(), "stage|install") || !strings.Contains(output.String(), "shared completion") {
		t.Fatalf("help is not reachable: %v %s", err, output.String())
	}
	for _, args := range [][]string{{"unstage"}, {"stage"}, {"recover-inputs", "--inputs", "/root/reviewed"}, {"install", "--destination", "/tmp"},
		{"stage", "--inputs", "/root/reviewed", "extra"}, {"cleanup", "--inputs", "/root/reviewed"}} {
		if err := runIdentityRekey(t.Context(), args, io.Discard); err == nil {
			t.Fatalf("unreviewed arguments accepted: %v", args)
		}
	}
	for _, path := range []string{"relative", "/", "/root/../root", "/tmp"} {
		if dir, err := openIdentityRekeyInputs(path); err == nil {
			unix.Close(dir)
			t.Fatalf("unsafe inputs directory accepted: %q", path)
		}
	}
}

func TestIdentityRekeyFinalInputsRecoverAfterInterruptedPublication(t *testing.T) {
	directory := t.TempDir()
	dir, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dir)
	proposal := bootstrapstart.IdentityRekeyJournal{Version: 1, AcceptedWire: []byte("reviewed acceptance"),
		ResetWire: []byte("reviewed floor"), CheckpointWire: []byte("reviewed checkpoint"), Values: [][]byte{[]byte("reviewed material")}}
	final := proposal
	final.AcceptedWire, final.ResetWire = []byte("final acceptance"), []byte("final signed floor")
	original, err := protocol.EncodeJSON(proposal)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"identity-rekey.json", ".identity-rekey.final.json", ".identity-rekey.final.abandoned.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), original, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	expected, err := protocol.EncodeJSON(final)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := recoverFinalIdentityRekeyInput(dir, proposal, final); err != nil {
			t.Fatal(err)
		}
		actual, err := readExactControllerFile(dir, "identity-rekey.json", uint32(os.Getuid()), uint32(os.Getgid()), 0o600, bootstrapstart.MaxIdentityRekeyJournalBytes)
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("finalized journal not recovered exactly: %v", err)
		}
	}
	for _, fault := range []string{"checkpoint", "material"} {
		changed := final
		if fault == "checkpoint" {
			changed.CheckpointWire = []byte("another checkpoint")
		} else {
			changed.Values = [][]byte{[]byte("another material")}
		}
		if err := recoverFinalIdentityRekeyInput(dir, proposal, changed); !errors.Is(err, bootstrapstart.ErrIdentityRekeyJournal) {
			t.Fatalf("different %s recovered: %v", fault, err)
		}
		actual, err := os.ReadFile(filepath.Join(directory, "identity-rekey.json"))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatal("refused recovery changed finalized journal")
		}
	}
}

func TestIdentityRekeyInputReaderRefusesIndirectFilesAndChangedReset(t *testing.T) {
	for _, fault := range []string{"none", "old version", "noncanonical", "unknown field", "different chain", "symlink", "hardlink", "fifo", "wrong mode", "missing public file"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			chain := []byte("exact root-pinned chain")
			journal := bootstrapstart.IdentityRekeyJournal{Version: 1, Values: [][]byte{[]byte("spec"), []byte("roots"), chain}}
			if fault == "old version" {
				journal.Version = 2
			}
			wire, err := protocol.EncodeJSON(journal)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "noncanonical" {
				wire = append([]byte(" "), wire...)
			} else if fault == "unknown field" {
				wire = append(wire[:len(wire)-1], []byte(`,"unknown":true}`)...)
			}
			files := map[string][]byte{"identity-rekey.json": wire, bootstrapstart.MaterialGenerationsFile: chain,
				"receipt.json": []byte("receipt"), "delegation.json": []byte("delegation"), controllerConfigFilename: []byte("config")}
			for _, name := range bootstrap.ControllerConfigFileNames {
				files[name] = []byte(name)
			}
			for _, name := range identityRekeyLaunchFiles {
				files[name] = []byte(name)
			}
			if fault == "different chain" {
				files[bootstrapstart.MaterialGenerationsFile] = []byte("different chain")
			}
			for name, content := range files {
				if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join(directory, "receipt.json")
			if fault == "symlink" || fault == "fifo" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "symlink":
				err = os.Symlink("delegation.json", path)
			case "hardlink":
				err = os.Link(path, filepath.Join(directory, "receipt-copy"))
			case "fifo":
				err = unix.Mkfifo(path, 0o600)
			case "wrong mode":
				err = os.Chmod(path, 0o644)
			case "missing public file":
				err = os.Remove(filepath.Join(directory, identityRekeyLaunchFiles[0]))
			}
			if err != nil {
				t.Fatal(err)
			}
			dir, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(dir)
			inputs, err := readIdentityRekeyInputs(dir, directory, uint32(os.Getuid()), uint32(os.Getgid()))
			if fault != "none" {
				if err == nil {
					t.Fatal("unsafe input reached installation")
				}
				return
			}
			if err != nil || len(inputs.files) != 8 || !bytes.Equal(inputs.chain, chain) ||
				inputs.candidate != filepath.Join(directory, selfupdate.BinaryName) {
				t.Fatalf("exact inputs changed: %+v %v", inputs, err)
			}
		})
	}
}
