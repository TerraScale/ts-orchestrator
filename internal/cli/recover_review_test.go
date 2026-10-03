package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
)

func runRecover(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var output bytes.Buffer
	err := Run(t.Context(), append([]string{"cluster", "recover-quorum"}, args...), &output)
	return output.String(), err
}

func TestRecoverQuorumSubcommandHelpAndIrrelevantFlags(t *testing.T) {
	config, _, root := recoveryFixture(t)
	for _, help := range []string{"--help", "-h"} {
		if out, err := runRecover(t, "backup", help); err != nil || !strings.Contains(out, "refound") {
			t.Fatalf("backup %s = %q, %v", help, out, err)
		}
	}
	if _, err := runRecover(t, "verify-backup", "--dir", root, "--slot", "controller-b"); err == nil ||
		!strings.Contains(err.Error(), "--slot") {
		t.Fatalf("verify-backup accepted --slot: %v", err)
	}
	if _, err := runRecover(t, "backup", "--config", config, "--dir", root); err == nil ||
		!strings.Contains(err.Error(), "--dir") {
		t.Fatalf("backup accepted --dir: %v", err)
	}
	if _, err := runRecover(t, "nonsense"); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func TestRecoverQuorumBindsConfigToTheAdmittedController(t *testing.T) {
	config, retirement, root := recoveryFixture(t)
	localAdmittedInstall = func() (bootstrapstart.AcceptedInstall, error) {
		return bootstrapstart.AcceptedInstall{Cell: "GRU", Slot: "controller-c", SeedSlot: "controller-c",
			PrimaryPrivateIP: "10.0.0.9"}, nil
	}
	recoveryInput = strings.NewReader("back up gru/controller-a\n")
	t.Cleanup(func() { recoveryInput = os.Stdin })
	if _, err := runRecover(t, "backup", "--config", config, "--out", filepath.Join(root, "backup")); err == nil ||
		!strings.Contains(err.Error(), "not the controller admitted on this host") {
		t.Fatalf("backup for another controller's config = %v", err)
	}
	if _, err := runRecover(t, "refound", "--config", config, "--slot", "controller-b", "--retirement", retirement,
		"--backup", filepath.Join(root, "backup")); err == nil ||
		!strings.Contains(err.Error(), "not the controller admitted on this host") {
		t.Fatalf("refound for another controller's config = %v", err)
	}
}

func TestRecoveryTargetRequiresFixedListeners(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "controller.json")
	if err := os.WriteFile(config, []byte(`{"nats":{"cell":"gru","instance":"controller-a","replicas":3,`+
		`"embedded":{"host":"127.0.0.1","port":-1,"store_dir":"/var/lib/x"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runRecover(t, "preflight", "--config", config); err == nil ||
		!strings.Contains(err.Error(), "fixed client and route listeners") {
		t.Fatalf("preflight with a random port = %v", err)
	}
}

func TestReadRetirementEvidenceRejectsSymlinksAndFIFOs(t *testing.T) {
	root := t.TempDir()
	regular := filepath.Join(root, "evidence")
	if err := os.WriteFile(regular, []byte("envelope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if wire, err := readRetirementEvidence(regular); err != nil || string(wire) != "envelope" {
		t.Fatalf("regular evidence = %q, %v", wire, err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRetirementEvidence(link); err == nil {
		t.Fatal("symlinked evidence was read")
	}
	fifo := filepath.Join(root, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if _, err := readRetirementEvidence(fifo); err == nil {
		t.Fatal("FIFO evidence was read")
	}
	large := filepath.Join(root, "large")
	if err := os.WriteFile(large, bytes.Repeat([]byte("x"), maxRetirementEvidenceBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRetirementEvidence(large); err == nil {
		t.Fatal("oversized evidence was read")
	}
}
