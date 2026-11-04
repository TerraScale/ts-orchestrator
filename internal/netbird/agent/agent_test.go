package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	network "github.com/TerraScale/ts-orchestrator/internal/netbird/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
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
