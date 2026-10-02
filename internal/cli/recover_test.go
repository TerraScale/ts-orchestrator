package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

type recordingRefound struct{ slots []string }

func (r *recordingRefound) Replace(_ context.Context, slot string, _ []byte) error {
	r.slots = append(r.slots, slot)
	return nil
}

func recoveryFixture(t *testing.T) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	store := filepath.Join(root, "nats")
	if err := os.MkdirAll(filepath.Join(store, "jetstream", "ACCOUNT", "streams", "TS_CONTROL_LOG"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store, "jetstream", "ACCOUNT", "streams", "TS_CONTROL_LOG", "meta.inf"),
		[]byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "controller.json")
	if err := os.WriteFile(config, []byte(`{"nats":{"cell":"gru","instance":"controller-a","replicas":3,`+
		`"embedded":{"host":"127.0.0.1","port":0,"store_dir":"`+store+`"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	envelope, err := bootstrap.SignSlotRetirement(bootstrap.RetirementEvidence{SchemaVersion: 1,
		DeploymentID: "deployment-1", Cell: "GRU", Environment: "production", Role: "controller",
		Slot: "controller-b", PreviousAttempt: 1, PreviousGeneration: 1,
		PreviousResultDigest: strings.Repeat("c", 64), PriorInstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1.b",
		PriorCreateKey: "founder-controller-b-key", Disposition: bootstrap.SlotRetirementDisposition,
		ObservedEvidenceDigest: strings.Repeat("e", 64), FencingAuthority: "authority-epoch-1", ObservedAt: now},
		now, now.Add(time.Hour), key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	retirement := filepath.Join(root, "controller-b.retirement")
	if err := os.WriteFile(retirement, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	return config, retirement, root
}

func TestRecoverQuorumRefoundRequiresBackupAndConfirmation(t *testing.T) {
	config, retirement, root := recoveryFixture(t)
	recorder := &recordingRefound{}
	previousInput, previousReplacer := recoveryInput, refoundReplacer
	t.Cleanup(func() { recoveryInput, refoundReplacer = previousInput, previousReplacer })
	refoundReplacer = func(context.Context) (interface {
		Replace(context.Context, string, []byte) error
	}, error) {
		return recorder, nil
	}
	backup := filepath.Join(root, "backup")
	run := func(input string, args ...string) (string, error) {
		recoveryInput = strings.NewReader(input)
		var output bytes.Buffer
		err := Run(t.Context(), append([]string{"cluster", "recover-quorum"}, args...), &output)
		return output.String(), err
	}
	if out, err := run("", "--help"); err != nil || !strings.Contains(out, "refound") {
		t.Fatalf("help = %q, %v", out, err)
	}
	refoundArgs := []string{"refound", "--config", config, "--slot", "controller-b",
		"--retirement", retirement, "--backup", backup}
	if _, err := run("re-found gru/controller-b\n", refoundArgs...); err == nil {
		t.Fatal("refound ran without a verified backup")
	}
	if _, err := run("back up gru/controller-a\n", "backup", "--config", config, "--out", backup); err != nil {
		t.Fatal(err)
	}
	if out, err := run("", "verify-backup", "--dir", backup); err != nil || !strings.Contains(out, "verified") {
		t.Fatalf("verify = %q, %v", out, err)
	}
	wrongSlot := append([]string(nil), refoundArgs...)
	wrongSlot[4] = "controller-c"
	if _, err := run("re-found gru/controller-c\n", wrongSlot...); err == nil {
		t.Fatal("refound accepted evidence for another slot")
	}
	if _, err := run("yes\n", refoundArgs...); err == nil || len(recorder.slots) != 0 {
		t.Fatalf("refound without confirmation: %v %v", err, recorder.slots)
	}
	out, err := run("re-found gru/controller-b\n", refoundArgs...)
	if err != nil || len(recorder.slots) != 1 || recorder.slots[0] != "controller-b" ||
		!strings.Contains(out, "attempt 2") {
		t.Fatalf("refound = %q, %v, %v", out, err, recorder.slots)
	}
	survivor := append([]string(nil), refoundArgs...)
	survivor[4] = "controller-a"
	if _, err := run("re-found gru/controller-a\n", survivor...); err == nil {
		t.Fatal("refound relaunched the local survivor")
	}
	if out, err := run("", "runbook", "--config", config); err != nil || !strings.Contains(out, "verify-backup") {
		t.Fatalf("runbook = %q, %v", out, err)
	}
}
