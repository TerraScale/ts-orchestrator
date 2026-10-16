package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
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

func TestValidateManagedVersion(t *testing.T) {
	for _, version := range []string{"0.80.0", "0.80.12"} {
		if err := ValidateManagedVersion(version); err != nil {
			t.Errorf("managed version %q rejected: %v", version, err)
		}
	}
	for _, version := range []string{"", "0.79.0", "0.81.0", "0.80.", "0.80.0-rc1", "v0.80.0", "0.80.1\n"} {
		if err := ValidateManagedVersion(version); err == nil {
			t.Errorf("invalid managed version %q accepted", version)
		}
	}
}

func TestManagedInstallRejectsChecksumBeforeServiceMutation(t *testing.T) {
	f := newManagedFixture(t)
	f.pin.Archives.AMD64.BinarySHA256 = strings.Repeat("0", 64)
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err == nil || !strings.Contains(err.Error(), "pinned SHA-256") {
		t.Fatalf("unverified binary accepted: %v", err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.old)
	if len(f.calls) != 0 {
		t.Fatalf("checksum failure mutated service: %v", f.calls)
	}
}

func TestManagedBinaryCopyRejectsCorruptionBeforeReplacingLiveBinary(t *testing.T) {
	f := newManagedFixture(t)
	if err := os.WriteFile(f.options.BinaryPath, managedELF("changed staged bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := installManagedBinary(f.options.BinaryPath, f.m.path(managedBinary), managedDigest(f.next), "amd64"); err == nil || !strings.Contains(err.Error(), "pinned SHA-256") {
		t.Fatalf("copied corruption was accepted: %v", err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.old)
}

func TestManagedBinaryCopyRejectsHostileStagedFiles(t *testing.T) {
	for _, kind := range []string{"fifo", "oversized", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			f := newManagedFixture(t)
			path := filepath.Join(t.TempDir(), "hostile-source")
			var err error
			switch kind {
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "oversized":
				var file *os.File
				file, err = os.Create(path)
				if err == nil {
					err = errors.Join(file.Truncate(MaxBinaryBytes+1), file.Close())
				}
			case "symlink":
				err = os.Symlink(f.options.BinaryPath, path)
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				done <- installManagedBinary(path, f.m.path(managedBinary), managedDigest(f.next), "amd64")
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("hostile source was installed")
				}
			case <-time.After(2 * time.Second):
				// Release a regressed blocking FIFO open before reporting it.
				if kind == "fifo" {
					fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
					if err == nil {
						syscall.Close(fd)
					}
				}
				t.Fatal("hostile staged source blocked the installer")
			}
			assertManagedFile(t, f.m.path(managedBinary), f.old)
			if err := VerifyBinary(path, managedDigest(f.next), "amd64"); err == nil {
				t.Fatal("hostile source passed binary verification")
			}
		})
	}
}

func TestManagedInstallRestartsChangedUnitAtMatchingVersionAndRetriesFailedRestart(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(failFirst), func(t *testing.T) {
			f := newManagedFixture(t)
			if err := os.WriteFile(f.m.path(managedBinary), f.next, 0755); err != nil {
				t.Fatal(err)
			}
			f.m.status = func(context.Context) (netbird.LocalStatus, error) {
				return netbird.LocalStatus{Version: f.pin.Version}, nil
			}
			if _, err := directDirectory(f.m.root, "/etc/systemd/system", 0755, false); err != nil {
				t.Fatal(err)
			}
			oldUnit := strings.Replace(managedService, "Environment=NB_FORCE_RELAY=true\n", "", 1)
			if err := os.WriteFile(f.m.path("/etc/systemd/system/netbird.service"), []byte(oldUnit), 0644); err != nil {
				t.Fatal(err)
			}
			restarts, reloadedNewUnit := 0, false
			control := f.m.systemctl
			f.m.systemctl = func(ctx context.Context, args ...string) error {
				if slices.Equal(args, []string{"daemon-reload"}) {
					body, err := os.ReadFile(f.m.path("/etc/systemd/system/netbird.service"))
					reloadedNewUnit = err == nil && string(body) == managedService
				}
				if slices.Equal(args, []string{"restart", "netbird.service"}) {
					restarts++
					if !reloadedNewUnit {
						t.Fatal("restart ran before loading the changed unit")
					}
					transaction, err := f.m.readTransaction()
					if err != nil || !transaction.RestartRequired {
						t.Fatalf("restart had no durable retry marker: %+v %v", transaction, err)
					}
					if failFirst && restarts == 1 {
						return errors.New("restart failed after writing the unchanged-version unit")
					}
				}
				return control(ctx, args...)
			}
			_, err := f.m.install(t.Context(), f.pin, f.cfg, f.options)
			if (err != nil) != failFirst || restarts != 1 {
				t.Fatalf("matching-version unit update did not restart: restarts=%d error=%v", restarts, err)
			}
			if failFirst {
				if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil || restarts != 2 {
					t.Fatalf("failed restart was lost on retry: restarts=%d error=%v", restarts, err)
				}
			}
			before := restarts
			if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil || restarts != before {
				t.Fatalf("successful install retry restarted the daemon: restarts=%d error=%v", restarts, err)
			}
			transaction, err := f.m.readTransaction()
			if err != nil || transaction.RestartRequired {
				t.Fatalf("successful restart left a retry marker: %+v %v", transaction, err)
			}
		})
	}
}

func TestManagedServiceMatchesImageAndCommentOnlyChangesDoNotRestart(t *testing.T) {
	imageUnit, err := os.ReadFile("../../../deploy/systemd/netbird.service")
	if err != nil {
		t.Fatal(err)
	}
	if managedUnitSettings(string(imageUnit)) != managedUnitSettings(managedService) {
		t.Fatal("managed and image NetBird service settings differ")
	}
	for _, unit := range []string{string(imageUnit), "# changed comment\n; another comment\n\n" + managedService} {
		f := newManagedFixture(t)
		if err := os.WriteFile(f.m.path(managedBinary), f.next, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := directDirectory(f.m.root, "/etc/systemd/system", 0755, false); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.m.path("/etc/systemd/system/netbird.service"), []byte(unit), 0644); err != nil {
			t.Fatal(err)
		}
		f.m.status = func(context.Context) (netbird.LocalStatus, error) {
			return netbird.LocalStatus{Version: f.pin.Version}, nil
		}
		if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
			t.Fatal(err)
		}
		if slices.Contains(f.calls, "restart netbird.service") {
			t.Fatalf("comment-only unit difference restarted the matching client: %v", f.calls)
		}
	}
}

func TestManagedConfirmationSurvivesTimerCancellationFailure(t *testing.T) {
	f := newManagedFixture(t)
	result, err := f.m.install(t.Context(), f.pin, f.cfg, f.options)
	if err != nil {
		t.Fatal(err)
	}
	f.m.systemctl = func(context.Context, ...string) error { return errors.New("timer stop unavailable") }
	if err := f.m.finish(t.Context(), result.TransactionID, false); err != nil {
		t.Fatalf("durable confirmation failed: %v", err)
	}
	journal, err := f.m.readTransaction()
	if err != nil || journal.Pending {
		t.Fatalf("confirmation not persisted: %+v %v", journal, err)
	}
	if err := f.m.finishMode(t.Context(), result.TransactionID, true, true); err != nil {
		t.Fatal(err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.next)
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

func TestManagedInstallRetriesDoNotReplacePreviousBinaryOrAcceptOtherTransaction(t *testing.T) {
	f := newManagedFixture(t)
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
		t.Fatal(err)
	}
	before := len(f.calls)
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(f.calls[before:], "restart netbird.service") {
		t.Fatal("retry restarted the already updated daemon")
	}
	assertManagedFile(t, managedBackup(t, f), f.old)
	options := f.options
	options.TransactionID = "0SZR6Y74Z101950CY9J404XT21"
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, options); err == nil {
		t.Fatal("overlapping update accepted")
	}
	if err := f.m.finish(t.Context(), options.TransactionID, false); err == nil {
		t.Fatal("stale confirmation accepted")
	}
}

func TestManagedInstallEnrollsMissingAgentWithoutReadingOldDaemon(t *testing.T) {
	f := newManagedFixture(t)
	if err := os.Remove(f.m.path(managedBinary)); err != nil {
		t.Fatal(err)
	}
	enrolled := false
	f.m.enroll = func(_ context.Context, cfg netbird.Config) error {
		if cfg.SetupKeySecretID != f.cfg.SetupKeySecretID {
			t.Fatal("missing agent received wrong OCI Vault setup-key reference")
		}
		enrolled = true
		return nil
	}
	result, err := f.m.install(t.Context(), f.pin, f.cfg, f.options)
	if err != nil || !enrolled || !result.Pending || result.PreviousVersion != "" {
		t.Fatalf("missing agent did not enroll: %#v enrolled=%t error=%v", result, enrolled, err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.next)
	if err := f.m.finish(t.Context(), result.TransactionID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(f.m.path(managedBinary)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed first installation left executable: %v", err)
	}
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

func TestConfirmedUpdateOnlyRollsBackForAnExplicitControllerAction(t *testing.T) {
	f := newManagedFixture(t)
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
		t.Fatal(err)
	}
	if err := f.m.finish(t.Context(), f.options.TransactionID, false); err != nil {
		t.Fatal(err)
	}
	before := len(f.calls)
	if err := f.m.finishMode(t.Context(), f.options.TransactionID, true, true); err != nil || len(f.calls) != before {
		t.Fatalf("watchdog mutated confirmed update: %v", err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.next)
	if err := f.m.finish(t.Context(), f.options.TransactionID, true); err != nil {
		t.Fatal(err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.old)
	transaction, err := f.m.readTransaction()
	if err != nil || transaction.Pending || !transaction.RolledBack {
		t.Fatalf("signed post-confirmation rollback did not complete: %#v %v", transaction, err)
	}
}

func TestManagedWatchdogHonorsCurrentDeadlineAndIdentity(t *testing.T) {
	for _, when := range []string{"before", "at", "after", "stale-identity"} {
		t.Run(when, func(t *testing.T) {
			f := newManagedFixture(t)
			if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
				t.Fatal(err)
			}
			transaction, err := f.m.readTransaction()
			if err != nil {
				t.Fatal(err)
			}
			id := transaction.TransactionID
			switch when {
			case "before":
				transaction.RollbackDeadline = time.Now().Add(time.Minute)
			case "at":
				transaction.RollbackDeadline = time.Now()
			case "after", "stale-identity":
				transaction.RollbackDeadline = time.Now().Add(-time.Second)
			}
			if when == "stale-identity" {
				id = "superseded-transaction"
			}
			if err := f.m.writeTransaction(transaction); err != nil {
				t.Fatal(err)
			}
			before := len(f.calls)
			journal, err := os.ReadFile(f.m.path(managedDirectory + "/pending.json"))
			if err != nil {
				t.Fatal(err)
			}
			err = f.m.finishMode(t.Context(), id, true, true)
			if when == "stale-identity" {
				if err == nil {
					t.Fatal("stale watchdog identity accepted")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if when == "before" || when == "stale-identity" {
				if len(f.calls) != before {
					t.Fatalf("inactive watchdog mutated the service: %v", f.calls[before:])
				}
				assertManagedFile(t, f.m.path(managedBinary), f.next)
				assertManagedFile(t, f.m.path(managedDirectory+"/pending.json"), journal)
			} else {
				assertManagedFile(t, f.m.path(managedBinary), f.old)
				transaction, err := f.m.readTransaction()
				if err != nil || transaction.Pending || !transaction.RolledBack {
					t.Fatalf("expired watchdog did not complete rollback: %+v %v", transaction, err)
				}
			}
		})
	}
}

func TestManagedEnrollmentFailureDoesNotExposeSetupKeyAndCanRollback(t *testing.T) {
	f := newManagedFixture(t)
	secret := "884b8bcf-16bc-4d2c-8a3f-ae5f8b6b3ba3"
	f.m.enroll = func(context.Context, netbird.Config) error { return errors.New("rejected setup key " + secret) }
	result, err := f.m.install(t.Context(), f.pin, f.cfg, f.options)
	if err == nil || strings.Contains(err.Error(), secret) || !result.Pending {
		t.Fatalf("setup key failure was exposed or lost transaction: %#v %v", result, err)
	}
	if err := f.m.finish(t.Context(), result.TransactionID, true); err != nil {
		t.Fatal(err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.old)
}

func TestManagedRollbackRejectsCorruptBackupAndLateConfirmation(t *testing.T) {
	f := newManagedFixture(t)
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
		t.Fatal(err)
	}
	transaction, err := f.m.readTransaction()
	if err != nil {
		t.Fatal(err)
	}
	transaction.RollbackDeadline = time.Now().Add(-time.Second)
	if err := f.m.writeTransaction(transaction); err != nil {
		t.Fatal(err)
	}
	if err := f.m.finish(t.Context(), f.options.TransactionID, false); err == nil {
		t.Fatal("accepted confirmation after watchdog deadline")
	}
	if err := os.WriteFile(managedBackup(t, f), managedELF("corrupt previous"), 0755); err != nil {
		t.Fatal(err)
	}
	before := len(f.calls)
	if err := f.m.finish(t.Context(), f.options.TransactionID, true); err == nil || len(f.calls) != before {
		t.Fatalf("corrupt backup restored: %v", err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.next)
}

func TestManagedFileLockSerializesLocalOperations(t *testing.T) {
	f := newManagedFixture(t)
	lock, err := f.m.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err == nil || !strings.Contains(err.Error(), "another managed") {
		t.Fatalf("concurrent local install accepted: %v", err)
	}
}

func TestManagedRollbackRestoresEnrollmentBeforeOldDaemonRestart(t *testing.T) {
	f := newManagedFixture(t)
	prior := map[string][]byte{
		netbird.PublicConfigPath:              []byte(`{"management_url":"https://old-manager.invalid"}`),
		"/var/lib/netbird/config.json":        []byte(`{"PrivateKey":"saved-peer-identity","ManagementURL":"https://old-manager.invalid"}`),
		"/etc/systemd/system/netbird.service": []byte("[Service]\nExecStart=/usr/local/bin/netbird service run --config /var/lib/netbird/config.json\nEnvironment=OLD_SETTING=1\n"),
		"/etc/hosts":                          []byte("127.0.0.1 localhost\n10.250.10.155\tnetbird.terrascale.tech\t# terrascale-netbird-manager\n"),
	}
	for path, body := range prior {
		if _, err := directDirectory(f.m.root, filepath.Dir(path), 0755, false); err != nil {
			t.Fatal(err)
		}
		mode := os.FileMode(0644)
		if path == "/var/lib/netbird/config.json" {
			mode = 0600
		}
		if err := os.WriteFile(f.m.path(path), body, mode); err != nil {
			t.Fatal(err)
		}
	}
	f.m.enroll = func(context.Context, netbird.Config) error {
		if err := os.WriteFile(f.m.path("/var/lib/netbird/config.json"), []byte(`{"PrivateKey":"changed-identity","ManagementURL":"https://failed-manager.invalid"}`), 0600); err != nil {
			return err
		}
		if err := os.WriteFile(f.m.path("/etc/hosts"), []byte("127.0.0.1 localhost\n10.250.99.99\tnetbird.terrascale.tech\t# terrascale-netbird-manager\n10.251.0.99 unrelated-added-during-upgrade\n"), 0644); err != nil {
			return err
		}
		return errors.New("manager unreachable")
	}
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err == nil {
		t.Fatal("failed enrollment unexpectedly succeeded")
	}
	control := f.m.systemctl
	f.m.systemctl = func(ctx context.Context, args ...string) error {
		if slices.Equal(args, []string{"restart", "netbird.service"}) {
			for path, body := range prior {
				if path != "/etc/hosts" {
					assertManagedFile(t, f.m.path(path), body)
				}
			}
			assertManagedFile(t, f.m.path(managedBinary), f.old)
		}
		return control(ctx, args...)
	}
	f.m.enroll = func(context.Context, netbird.Config) error {
		t.Fatal("rollback requested Vault enrollment")
		return nil
	}
	if err := f.m.finish(t.Context(), f.options.TransactionID, true); err != nil {
		t.Fatal(err)
	}
	hosts, err := os.ReadFile(f.m.path("/etc/hosts"))
	if err != nil || bytes.Contains(hosts, []byte("10.250.99.99")) || !bytes.Contains(hosts, []byte("10.250.10.155")) || !bytes.Contains(hosts, []byte("unrelated-added-during-upgrade")) {
		t.Fatal("rollback did not restore the manager mapping while preserving unrelated hosts edits")
	}
	info, err := os.Stat(f.m.path("/var/lib/netbird/config.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("rollback did not preserve private enrollment file permissions")
	}
}

func TestManagedStartupRecoveryRepairsWatchdogOrRollsBackExpiredJournal(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			f := newManagedFixture(t)
			if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
				t.Fatal(err)
			}
			transaction, err := f.m.readTransaction()
			if err != nil {
				t.Fatal(err)
			}
			if expired {
				transaction.RollbackDeadline = time.Now().Add(-time.Second)
				if err := f.m.writeTransaction(transaction); err != nil {
					t.Fatal(err)
				}
			}
			for _, suffix := range []string{".service", ".timer"} {
				if err := os.Remove(f.m.path("/etc/systemd/system/" + rollbackUnit + suffix)); err != nil {
					t.Fatal(err)
				}
			}
			before := len(f.calls)
			restarted := f.m
			restarted.enroll = func(context.Context, netbird.Config) error { t.Fatal("startup rollback requested Vault"); return nil }
			recovered, err := restarted.recover(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if expired {
				if recovered.Pending || !recovered.RolledBack {
					t.Fatal("expired journal was left unprotected")
				}
				assertManagedFile(t, f.m.path(managedBinary), f.old)
			} else {
				if !recovered.Pending || !slices.Contains(f.calls[before:], "restart "+rollbackUnit+".timer") {
					t.Fatal("startup did not rearm an unexpired pending journal")
				}
				assertManagedFile(t, f.m.path(managedBinary), f.next)
			}
		})
	}
}

func TestManagedStartupRecoversFirstInstallBeforeServiceCreation(t *testing.T) {
	f := newManagedFixture(t)
	if err := os.Remove(f.m.path(managedBinary)); err != nil {
		t.Fatal(err)
	}
	lock, err := f.m.lock()
	if err != nil {
		t.Fatal(err)
	}
	lock.Close()
	transaction := managedTransaction{ManagedResult: ManagedResult{TransactionID: f.options.TransactionID,
		Version: f.pin.Version, Pending: true, RollbackDeadline: time.Now().Add(-time.Second)},
		BinarySHA256: f.pin.Archives.AMD64.BinarySHA256, Architecture: "amd64", StateBackup: true}
	if err := f.m.backupState(t.Context(), transaction); err != nil {
		t.Fatal(err)
	}
	if err := f.m.writeTransaction(transaction); err != nil {
		t.Fatal(err)
	}
	f.m.systemctl = func(_ context.Context, args ...string) error {
		if len(args) > 1 && args[1] == "netbird.service" {
			t.Error("recovery tried to operate on a service that was never created")
			return errors.New("unit not found")
		}
		return nil
	}
	if recovered, err := f.m.recover(t.Context()); err != nil || recovered.Pending || !recovered.RolledBack {
		t.Fatalf("pre-service startup recovery failed: %+v %v", recovered, err)
	}
}

func TestManagedNextPreparationFailurePreservesConfirmedRollback(t *testing.T) {
	f := newManagedFixture(t)
	control := f.m.systemctl
	f.m.systemctl = func(ctx context.Context, args ...string) error {
		if slices.Equal(args, []string{"restart", rollbackUnit + ".timer"}) {
			journal, err := f.m.readTransaction()
			if err != nil || journal.TransactionID == f.options.TransactionID {
				t.Fatal("new journal was committed before the watchdog was armed")
			}
		}
		return control(ctx, args...)
	}
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil {
		t.Fatal(err)
	}
	f.m.systemctl = control
	if err := f.m.finish(t.Context(), f.options.TransactionID, false); err != nil {
		t.Fatal(err)
	}
	first, err := f.m.readTransaction()
	if err != nil {
		t.Fatal(err)
	}
	options := f.options
	options.TransactionID = "0R37SFQWTMQNE2B6F1R8PE0GW3"
	f.m.systemctl = func(ctx context.Context, args ...string) error {
		if slices.Equal(args, []string{"restart", rollbackUnit + ".timer"}) {
			return errors.New("simulated crash before new journal commit")
		}
		return control(ctx, args...)
	}
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, options); err == nil {
		t.Fatal("preparation failure was ignored")
	}
	journal, err := f.m.readTransaction()
	if err != nil || journal.TransactionID != first.TransactionID || journal.Pending {
		t.Fatal("failed preparation replaced the confirmed journal")
	}
	assertManagedFile(t, f.m.previousBinary(first), f.old)
	f.m.systemctl = control
	before := len(f.calls)
	if err := f.m.finishMode(t.Context(), options.TransactionID, true, true); err != nil {
		t.Fatalf("orphaned watchdog retries forever against a completed journal: %v", err)
	}
	if !slices.Equal(f.calls[before:], []string{"stop " + rollbackUnit + ".timer " + rollbackUnit + ".service"}) {
		t.Fatalf("orphaned watchdog touched more than its own units: %v", f.calls[before:])
	}
	if current, err := f.m.readTransaction(); err != nil || current != first {
		t.Fatalf("orphaned watchdog changed the completed journal: %+v %v", current, err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.next)
	if err := f.m.finish(t.Context(), first.TransactionID, true); err != nil {
		t.Fatal(err)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.old)
}

func TestManagedTransactionIdentityAndBootstrapOwnership(t *testing.T) {
	f := newManagedFixture(t)
	f.options.TransactionID, f.options.Bootstrap = "", true
	result, err := f.m.install(t.Context(), f.pin, f.cfg, f.options)
	if err != nil || !entityid.Valid(result.TransactionID) || !result.Bootstrap {
		t.Fatalf("new bootstrap identity: %+v %v", result, err)
	}
	persisted, err := f.m.readTransaction()
	if err != nil || persisted.TransactionID != result.TransactionID || !persisted.Bootstrap {
		t.Fatalf("bootstrap ownership did not persist: %+v %v", persisted, err)
	}
	f.options.TransactionID, f.options.Bootstrap = result.TransactionID, false
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err == nil {
		t.Fatal("controller claimed bootstrap transaction")
	}
}

func TestManagedTransactionRejectsNoncanonicalIDs(t *testing.T) {
	for _, id := range []string{"bootstrap-old", "550e8400-e29b-41d4-a716-446655440000", "01m4eb0gdpphgjppvy77emzqkt"} {
		t.Run(id, func(t *testing.T) {
			f := newManagedFixture(t)
			f.options.TransactionID = id
			if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err == nil || len(f.calls) != 0 {
				t.Fatalf("invalid ID reached installation: %v %v", err, f.calls)
			}
			if err := f.m.finish(t.Context(), id, true); err == nil || len(f.calls) != 0 {
				t.Fatalf("invalid ID reached rollback: %v %v", err, f.calls)
			}
		})
	}
}
