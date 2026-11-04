package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
)

type managedFixture struct {
	m       managedClient
	pin     Pin
	cfg     netbird.Config
	options ManagedOptions
	old     []byte
	next    []byte
	calls   []string
}

func managedELF(body string) []byte {
	wire := make([]byte, 64)
	copy(wire, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(wire[16:], 2)
	binary.LittleEndian.PutUint16(wire[18:], 62)
	binary.LittleEndian.PutUint32(wire[20:], 1)
	binary.LittleEndian.PutUint16(wire[52:], 64)
	return append(wire, body...)
}

func managedDigest(wire []byte) string {
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:])
}

func newManagedFixture(t *testing.T) *managedFixture {
	t.Helper()
	f := &managedFixture{old: managedELF("old agent"), next: managedELF("new agent")}
	f.m = managedClient{root: t.TempDir(), architecture: "amd64", executable: "/usr/local/bin/ts-orch"}
	f.options = ManagedOptions{TransactionID: "7ZZ773YKB490QT19V3PQ57H4DP", BinaryPath: filepath.Join(t.TempDir(), "staged")}
	if err := os.WriteFile(f.options.BinaryPath, f.next, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := directDirectory(f.m.root, "/usr/local/bin", 0755, false); err != nil {
		t.Fatal(err)
	}
	f.m.executable = f.m.path("/usr/local/bin/ts-orch")
	if err := os.WriteFile(f.m.executable, managedELF("rollback worker"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.m.path(managedBinary), f.old, 0755); err != nil {
		t.Fatal(err)
	}
	f.pin.Version = "0.80.0"
	for _, arch := range []string{"arm64", "amd64"} {
		a := Archive{URL: "https://github.com/netbirdio/netbird/releases/download/v0.80.0/netbird_0.80.0_linux_" + arch + ".tar.gz",
			Bytes: 100, SHA256: strings.Repeat("a", 64), BinarySHA256: managedDigest(f.next)}
		if arch == "arm64" {
			f.pin.Archives.Arm64 = a
		} else {
			f.pin.Archives.AMD64 = a
		}
	}
	f.cfg = netbird.Config{ManagementURL: netbird.DefaultManagementURL, Region: netbird.DefaultRegion,
		SetupKeySecretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaa.testsecret"}
	version := "0.79.0"
	f.m.status = func(context.Context) (netbird.LocalStatus, error) {
		return netbird.LocalStatus{Version: version}, nil
	}
	f.m.systemctl = func(_ context.Context, args ...string) error {
		f.calls = append(f.calls, strings.Join(args, " "))
		if slices.Equal(args, []string{"restart", "netbird.service"}) {
			wire, err := os.ReadFile(f.m.path(managedBinary))
			if err != nil {
				return err
			}
			if bytes.Equal(wire, f.next) {
				version = "0.80.0"
			} else {
				version = "0.79.0"
			}
		}
		return nil
	}
	f.m.enroll = func(context.Context, netbird.Config) error { return nil }
	return f
}

func assertManagedFile(t *testing.T, path string, want []byte) {
	t.Helper()
	wire, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(wire, want) {
		t.Fatalf("%s does not retain expected bytes: %v", path, err)
	}
}

func managedBackup(t *testing.T, f *managedFixture) string {
	t.Helper()
	transaction, err := f.m.readTransaction()
	if err != nil {
		t.Fatal(err)
	}
	return f.m.previousBinary(transaction)
}

func TestManagedInstallArmsRollbackBeforeRestartAndPreservesBackup(t *testing.T) {
	f := newManagedFixture(t)
	result, err := f.m.install(t.Context(), f.pin, f.cfg, f.options)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Pending || result.PreviousVersion != "0.79.0" || result.Version != "0.80.0" || result.TransactionID != f.options.TransactionID {
		t.Fatalf("incorrect transaction: %#v", result)
	}
	if result.RollbackDeadline.Before(time.Now()) || result.RollbackDeadline.After(time.Now().Add(rollbackWindow)) {
		t.Fatalf("incorrect rollback deadline %s", result.RollbackDeadline)
	}
	armed := slices.Index(f.calls, "restart "+rollbackUnit+".timer")
	restarted := slices.Index(f.calls, "restart netbird.service")
	if armed < 0 || restarted <= armed {
		t.Fatalf("agent changed before watchdog: %v", f.calls)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.next)
	assertManagedFile(t, managedBackup(t, f), f.old)
	service, err := os.ReadFile(f.m.path("/etc/systemd/system/" + rollbackUnit + ".service"))
	if err != nil || !strings.Contains(string(service), "netbird agent rollback --transaction "+f.options.TransactionID) {
		t.Fatalf("watchdog does not bind transaction: %s %v", service, err)
	}
	if err = f.m.finish(t.Context(), result.TransactionID, false); err != nil {
		t.Fatal(err)
	}
	transaction, err := f.m.readTransaction()
	if err != nil || transaction.Pending {
		t.Fatalf("confirmation not durable: %#v %v", transaction, err)
	}
	assertManagedFile(t, managedBackup(t, f), f.old)
}

func TestManagedRollbackSurvivesInstallerRestartAndDoesNotNeedVault(t *testing.T) {
	f := newManagedFixture(t)
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
		t.Fatal(err)
	}
	restarted := f.m
	restarted.enroll = func(context.Context, netbird.Config) error {
		t.Fatal("rollback consumed an OCI Vault setup key")
		return nil
	}
	if err := restarted.finish(t.Context(), f.options.TransactionID, true); err != nil {
		t.Fatal(err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.old)
	transaction, err := restarted.readTransaction()
	if err != nil || transaction.Pending || !transaction.RolledBack || transaction.Version != "0.79.0" {
		t.Fatalf("rollback not durable: %#v %v", transaction, err)
	}
	before := len(f.calls)
	if err := restarted.finish(t.Context(), f.options.TransactionID, true); err != nil || len(f.calls) != before {
		t.Fatalf("duplicate rollback mutated service: %v", err)
	}
}
