package client

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird"
)

type canceledBootstrapPublication struct {
	context.Context
	calls, cancelAt int
}

func (ctx *canceledBootstrapPublication) Err() error {
	ctx.calls++
	if ctx.calls >= ctx.cancelAt {
		return context.Canceled
	}
	return nil
}

func TestManagedBootstrapEnrollmentRejectsEveryPendingTransaction(t *testing.T) {
	for _, id := range []string{"controller-transaction", "bootstrap-transaction"} {
		t.Run(id, func(t *testing.T) {
			f := newManagedFixture(t)
			root := managedBootstrapDefaults(t, f)
			if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); !written || err != nil {
				t.Fatalf("bootstrap fixture publication failed: written=%t error=%v", written, err)
			}
			if err := f.m.writeTransaction(managedTransaction{ManagedResult: ManagedResult{TransactionID: id,
				Version: f.pin.Version, Pending: true, RollbackDeadline: time.Now().Add(time.Minute)},
				BinarySHA256: f.pin.Archives.AMD64.BinarySHA256, Architecture: "amd64"}); err != nil {
				t.Fatal(err)
			}
			f.m.enroll = func(context.Context, netbird.Config) error {
				t.Fatal("bootstrap enrollment bypassed a pending transaction")
				return nil
			}
			if err := f.m.enrollBootstrap(t.Context(), filepath.Join(root, "netbird.json")); err == nil || !strings.Contains(err.Error(), "pending managed transaction") {
				t.Fatalf("pending transaction did not hold enrollment: %v", err)
			}
		})
	}
}

func TestManagedBootstrapEnrollmentRejectsIncompletePublication(t *testing.T) {
	f := newManagedFixture(t)
	root := managedBootstrapDefaults(t, f)
	if err := atomicManagedFile(filepath.Join(root, bootstrapPendingFile), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	f.m.enroll = func(context.Context, netbird.Config) error {
		t.Fatal("bootstrap enrolled an incomplete publication")
		return nil
	}
	if err := f.m.enrollBootstrap(t.Context(), filepath.Join(root, "netbird.json")); err == nil || !strings.Contains(err.Error(), "publication is incomplete") {
		t.Fatalf("incomplete publication did not hold final enrollment: %v", err)
	}
}

func TestManagedBootstrapEnrollmentLoadsCurrentConfigAndRetainsLock(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "enrollment-failure"}[failure], func(t *testing.T) {
			f := newManagedFixture(t)
			root := managedBootstrapDefaults(t, f)
			if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); !written || err != nil {
				t.Fatalf("prior publication failed: written=%t error=%v", written, err)
			}
			path := filepath.Join(root, "netbird.json")
			_, prior, err := f.m.readBootstrapConfig(t.Context(), path, false)
			if err != nil {
				t.Fatal(err)
			}
			f.cfg.SetupKeySecretID += ".current"
			if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); !written || err != nil {
				t.Fatalf("current publication failed: written=%t error=%v", written, err)
			}
			if err := os.Remove(filepath.Join(root, "netbird-pin.json")); err != nil {
				t.Fatal(err)
			}
			enrolled := false
			var enrollmentErr error
			if failure {
				enrollmentErr = errors.New("enrollment failed")
			}
			f.m.enroll = func(_ context.Context, cfg netbird.Config) error {
				if cfg.SetupKeySecretID != f.cfg.SetupKeySecretID || cfg.SetupKeySecretID == prior.SetupKeySecretID {
					t.Fatal("final enrollment used superseded bootstrap configuration")
				}
				if lock, err := f.m.lock(); err == nil {
					_ = lock.Close()
					t.Fatal("enrollment released the managed lock before mutation completed")
				}
				enrolled = true
				return enrollmentErr
			}
			if err := f.m.enrollBootstrap(t.Context(), path); !errors.Is(err, enrollmentErr) || !enrolled {
				t.Fatalf("final enrollment result differs: enrolled=%t error=%v", enrolled, err)
			}
			lock, err := f.m.lock()
			if err != nil {
				t.Fatalf("completed enrollment retained its lock: %v", err)
			}
			_ = lock.Close()
		})
	}
}

func TestManagedBootstrapPublicationCancellationHoldsReadersAndFreshSnapshots(t *testing.T) {
	for _, cancelAt := range []int{3, 4} {
		t.Run(map[int]string{3: "between-mirrors", 4: "before-commit"}[cancelAt], func(t *testing.T) {
			f := newManagedFixture(t)
			root := managedBootstrapDefaults(t, f)
			if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); !written || err != nil {
				t.Fatalf("prior publication failed: written=%t error=%v", written, err)
			}
			previous, err := os.ReadFile(filepath.Join(root, "netbird.json"))
			if err != nil {
				t.Fatal(err)
			}
			f.pin.Version = "0.80.1"
			f.pin.Archives.Arm64.URL = strings.ReplaceAll(f.pin.Archives.Arm64.URL, "0.80.0", "0.80.1")
			f.pin.Archives.AMD64.URL = strings.ReplaceAll(f.pin.Archives.AMD64.URL, "0.80.0", "0.80.1")
			f.cfg.SetupKeySecretID += ".next"
			ctx := &canceledBootstrapPublication{Context: t.Context(), cancelAt: cancelAt}
			if written, err := f.m.installBootstrapConfig(ctx, root, f.pin, f.cfg); written || !errors.Is(err, context.Canceled) {
				t.Fatalf("interrupted publication completed: written=%t error=%v", written, err)
			}
			if _, err := os.Stat(filepath.Join(root, bootstrapPendingFile)); err != nil {
				t.Fatalf("interrupted publication lacks durable marker: %v", err)
			}
			if cancelAt == 3 {
				assertManagedFile(t, filepath.Join(root, "netbird.json"), previous)
			}
			for _, requirePin := range []bool{false, true} {
				if _, _, err := f.m.readBootstrapConfig(t.Context(), filepath.Join(root, "netbird.json"), requirePin); err == nil || !strings.Contains(err.Error(), "publication is incomplete") {
					t.Fatalf("reader accepted interrupted publication: requirePin=%t error=%v", requirePin, err)
				}
			}
			if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err == nil || !strings.Contains(err.Error(), "publication is incomplete") {
				t.Fatalf("fresh snapshot accepted interrupted publication: %v", err)
			}
			if len(f.calls) != 0 {
				t.Fatalf("incomplete publication changed a service: %v", f.calls)
			}
			if transaction, err := f.m.readTransaction(); err != nil || transaction.TransactionID != "" {
				t.Fatalf("incomplete publication admitted an installation: %+v %v", transaction, err)
			}
			if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); err != nil || !written {
				t.Fatalf("publication retry did not repair mirrors: written=%t error=%v", written, err)
			}
			pin, cfg, err := f.m.readBootstrapConfig(t.Context(), filepath.Join(root, "netbird.json"), true)
			if err != nil || pin != f.pin || cfg.SetupKeySecretID != f.cfg.SetupKeySecretID {
				t.Fatalf("repaired publication differs: pin=%+v config=%+v error=%v", pin, cfg, err)
			}
			if _, err := os.Lstat(filepath.Join(root, bootstrapPendingFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("completed publication kept its hold: %v", err)
			}
		})
	}
}

func TestManagedBootstrapPublicationWriteFailureRemainsHeldUntilRetry(t *testing.T) {
	f := newManagedFixture(t)
	root := managedBootstrapDefaults(t, f)
	configPath := filepath.Join(root, "netbird.json")
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(configPath, 0700); err != nil {
		t.Fatal(err)
	}
	if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); written || err == nil {
		t.Fatalf("failed second mirror completed: written=%t error=%v", written, err)
	}
	if _, _, err := f.m.readBootstrapConfig(t.Context(), configPath, true); err == nil || !strings.Contains(err.Error(), "publication is incomplete") {
		t.Fatalf("reader accepted failed mirror publication: %v", err)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); !written || err != nil {
		t.Fatalf("failed publication could not resume: written=%t error=%v", written, err)
	}
}

func TestManagedBootstrapReaderSharesInstallationLock(t *testing.T) {
	f := newManagedFixture(t)
	root := managedBootstrapDefaults(t, f)
	lock, err := f.m.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if _, _, err := f.m.readBootstrapConfig(t.Context(), filepath.Join(root, "netbird.json"), true); err == nil || !strings.Contains(err.Error(), "another managed NetBird operation") {
		t.Fatalf("bootstrap reader bypassed publication lock: %v", err)
	}
}

func TestManagedBootstrapReaderRejectsUntrustedPins(t *testing.T) {
	for _, failure := range []string{"symlink", "writable", "checksum", "unknown-member", "oversized", "missing"} {
		t.Run(failure, func(t *testing.T) {
			f := newManagedFixture(t)
			root := managedBootstrapDefaults(t, f)
			if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); !written || err != nil {
				t.Fatalf("bootstrap fixture publication failed: written=%t error=%v", written, err)
			}
			path := filepath.Join(root, "netbird-pin.json")
			var err error
			switch failure {
			case "symlink":
				if err = os.Rename(path, path+".actual"); err == nil {
					err = os.Symlink(path+".actual", path)
				}
			case "writable":
				err = os.Chmod(path, 0666)
			case "checksum":
				f.pin.Archives.Arm64.SHA256 = ""
				var body []byte
				if body, err = json.Marshal(f.pin); err == nil {
					err = os.WriteFile(path, body, 0644)
				}
			case "unknown-member":
				var body []byte
				if body, err = os.ReadFile(path); err == nil {
					err = os.WriteFile(path, append([]byte(`{"unknown":true,`), body[1:]...), 0644)
				}
			case "oversized":
				err = os.WriteFile(path, []byte(strings.Repeat(" ", 16<<10+1)), 0644)
			case "missing":
				err = os.Remove(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := f.m.readBootstrapConfig(t.Context(), filepath.Join(root, "netbird.json"), true); err == nil {
				t.Fatal("bootstrap reader accepted untrusted pin")
			}
			if _, cfg, err := f.m.readBootstrapConfig(t.Context(), filepath.Join(root, "netbird.json"), false); err != nil || cfg.SetupKeySecretID != f.cfg.SetupKeySecretID {
				t.Fatalf("existing-client enrollment unnecessarily required pin: %+v %v", cfg, err)
			}
		})
	}
}

func TestManagedBootstrapReaderRejectsFIFOWithoutHoldingLock(t *testing.T) {
	for _, name := range []string{"netbird.json", "netbird-pin.json"} {
		t.Run(name, func(t *testing.T) {
			f := newManagedFixture(t)
			root := managedBootstrapDefaults(t, f)
			if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); !written || err != nil {
				t.Fatalf("bootstrap fixture publication failed: written=%t error=%v", written, err)
			}
			path := filepath.Join(root, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				_, _, err := f.m.readBootstrapConfig(t.Context(), filepath.Join(root, "netbird.json"), true)
				result <- err
			}()
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("FIFO bootstrap configuration was accepted")
				}
			case <-time.After(time.Second):
				if fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = syscall.Close(fd)
				}
				t.Fatal("bootstrap reader blocked on a FIFO while holding the managed lock")
			}
			lock, err := f.m.lock()
			if err != nil {
				t.Fatalf("bootstrap reader retained lock after rejecting FIFO: %v", err)
			}
			_ = lock.Close()
		})
	}
}

func managedBootstrapDefaults(t *testing.T, f *managedFixture) string {
	t.Helper()
	root, err := directDirectory(f.m.root, filepath.Dir(netbird.PublicConfigPath), 0755, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"netbird-pin.json", "netbird.json"} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("image default "+name), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestManagedBootstrapConfigReplacesImageDefaultsBeforeAdmission(t *testing.T) {
	f := newManagedFixture(t)
	root := managedBootstrapDefaults(t, f)
	if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); err != nil || !written {
		t.Fatalf("signed initial configuration did not replace image defaults: written=%t error=%v", written, err)
	}
	body, err := os.ReadFile(filepath.Join(root, "netbird-pin.json"))
	var pin Pin
	if err != nil || json.Unmarshal(body, &pin, json.RejectUnknownMembers(true)) != nil || ValidatePin(pin) != nil || pin != f.pin {
		t.Fatalf("initial pin differs: %v", err)
	}
	cfg, err := netbird.LoadConfig(filepath.Join(root, "netbird.json"))
	if err != nil || cfg.SetupKeySecretID != f.cfg.SetupKeySecretID {
		t.Fatalf("initial enrollment differs: %v", err)
	}
	if transaction, err := f.m.readTransaction(); err != nil || transaction.TransactionID != "" || len(f.calls) != 0 {
		t.Fatalf("bootstrap configuration admitted or changed the service: %+v %v calls=%v", transaction, err, f.calls)
	}
	assertManagedFile(t, f.m.path(managedBinary), f.old)
}

func TestManagedBootstrapConfigPreservesEveryDurableAdmission(t *testing.T) {
	for _, phase := range []string{"pending", "confirmed", "rolledback", "invalid"} {
		t.Run(phase, func(t *testing.T) {
			f := newManagedFixture(t)
			root := managedBootstrapDefaults(t, f)
			lock, err := f.m.lock()
			if err != nil {
				t.Fatal(err)
			}
			_ = lock.Close()
			transaction := managedTransaction{ManagedResult: ManagedResult{TransactionID: "admitted",
				Version: f.pin.Version, Pending: phase == "pending", RolledBack: phase == "rolledback",
				RollbackDeadline: time.Now().Add(time.Minute)},
				BinarySHA256: f.pin.Archives.AMD64.BinarySHA256, Architecture: "amd64"}
			if err := f.m.writeTransaction(transaction); err != nil {
				t.Fatal(err)
			}
			if phase == "invalid" {
				if err := os.WriteFile(f.m.path(managedDirectory+"/pending.json"), []byte("invalid journal"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg)
			if written || (err != nil) != (phase == "invalid") {
				t.Fatalf("bootstrap bypassed durable admission: written=%t error=%v", written, err)
			}
			for _, name := range []string{"netbird-pin.json", "netbird.json"} {
				assertManagedFile(t, filepath.Join(root, name), []byte("image default "+name))
			}
		})
	}
}

func TestManagedBootstrapConfigCannotChangeConcurrentInstallationSnapshot(t *testing.T) {
	f := newManagedFixture(t)
	root := managedBootstrapDefaults(t, f)
	prior := f.cfg
	prior.SetupKeySecretID += "-image"
	body, err := json.Marshal(prior)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.m.path(netbird.PublicConfigPath), body, 0644); err != nil {
		t.Fatal(err)
	}
	checked := false
	f.options.Prepare = func(ManagedResult) error {
		checked = true
		if written, err := f.m.installBootstrapConfig(t.Context(), root, f.pin, f.cfg); written || err == nil {
			t.Fatalf("bootstrap changed configuration while installation held the lock: written=%t error=%v", written, err)
		}
		return nil
	}
	if _, err := f.m.install(t.Context(), f.pin, f.cfg, f.options); err != nil || !checked {
		t.Fatalf("snapshot preparation was not checked: checked=%t error=%v", checked, err)
	}
	transaction, err := f.m.readTransaction()
	if err != nil {
		t.Fatal(err)
	}
	assertManagedFile(t, filepath.Join(f.m.backupDirectory(transaction), filepath.Base(netbird.PublicConfigPath)), body)
	if err := f.m.finish(t.Context(), transaction.TransactionID, true); err != nil {
		t.Fatal(err)
	}
	assertManagedFile(t, f.m.path(netbird.PublicConfigPath), body)
}

func TestManagedBootstrapConfigRejectsInvalidInputsBeforeWrites(t *testing.T) {
	for _, failure := range []string{"version", "pin", "configuration", "context"} {
		t.Run(failure, func(t *testing.T) {
			f := newManagedFixture(t)
			root := managedBootstrapDefaults(t, f)
			ctx := t.Context()
			switch failure {
			case "version":
				f.pin.Version = "0.79.0"
			case "pin":
				f.pin.Archives.AMD64.BinarySHA256 = "invalid"
			case "configuration":
				f.cfg.SetupKeySecretID = "invalid"
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			written, err := f.m.installBootstrapConfig(ctx, root, f.pin, f.cfg)
			if err == nil || written || failure == "context" && !errors.Is(err, context.Canceled) {
				t.Fatalf("invalid initial configuration was written: written=%t error=%v", written, err)
			}
			for _, name := range []string{"netbird-pin.json", "netbird.json"} {
				assertManagedFile(t, filepath.Join(root, name), []byte("image default "+name))
			}
		})
	}
}
