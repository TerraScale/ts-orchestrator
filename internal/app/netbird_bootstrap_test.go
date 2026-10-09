package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
)

type netbirdBootstrapFixture struct {
	configPath string
	config     netbird.Config
	runner     netbirdBootstrapRuntime
}

func newNetBirdBootstrapFixture(t *testing.T) netbirdBootstrapFixture {
	t.Helper()
	dir := t.TempDir()
	f := netbirdBootstrapFixture{configPath: filepath.Join(dir, "netbird.json"),
		config: netbird.Config{ManagementURL: netbird.DefaultManagementURL, Region: "sa-saopaulo-1",
			SetupKeySecretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.bootstrap"}}
	for name, value := range map[string]any{"netbird.json": f.config, "netbird-pin.json": netbirdArtifactTestPin(t)} {
		wire, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), wire, 0644); err != nil {
			t.Fatal(err)
		}
	}
	f.runner = netbirdBootstrapRuntime{binary: filepath.Join(dir, "netbird"), fallback: filepath.Join(dir, "fallback"),
		status: func(context.Context) (client.ManagedResult, error) { return client.ManagedResult{}, nil },
		defaults: func(_ context.Context, path string, requirePin bool) (client.Pin, netbird.Config, error) {
			cfg, err := netbird.LoadConfig(path)
			if err != nil || !requirePin {
				return client.Pin{}, cfg, err
			}
			body, err := os.ReadFile(filepath.Join(filepath.Dir(path), "netbird-pin.json"))
			if err != nil {
				return client.Pin{}, cfg, err
			}
			var pin client.Pin
			if err := json.Unmarshal(body, &pin, json.RejectUnknownMembers(true)); err != nil {
				return client.Pin{}, cfg, err
			}
			return pin, cfg, client.ValidatePin(pin)
		},
		install: func(context.Context, client.Pin, netbird.Config, client.ManagedOptions) (client.ManagedResult, error) {
			t.Fatal("unexpected bootstrap installation")
			return client.ManagedResult{}, nil
		},
		confirm: func(context.Context, string) error { t.Fatal("unexpected bootstrap confirmation"); return nil },
		enroll:  func(context.Context, netbird.Config) error { t.Fatal("unexpected bootstrap enrollment"); return nil },
	}
	if err := os.WriteFile(f.runner.fallback, netbirdArtifactELF(runtime.GOARCH), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestNetBirdBootstrapIncompletePublicationHoldsEveryEnrollment(t *testing.T) {
	for _, installed := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-client", true: "existing-client"}[installed], func(t *testing.T) {
			f := newNetBirdBootstrapFixture(t)
			if installed {
				if err := os.WriteFile(f.runner.binary, []byte("installed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			f.runner.defaults = func(_ context.Context, _ string, requirePin bool) (client.Pin, netbird.Config, error) {
				if requirePin == installed {
					t.Fatal("bootstrap requested the wrong pin requirement")
				}
				return client.Pin{}, netbird.Config{}, errors.New("NetBird bootstrap configuration publication is incomplete")
			}
			if err := enrollNetBirdBootstrap(t.Context(), f.configPath, io.Discard, f.runner); err == nil || !strings.Contains(err.Error(), "publication is incomplete") {
				t.Fatalf("incomplete publication escaped the reader boundary: %v", err)
			}
		})
	}
}

func TestNetBirdExistingClientEnrollmentDoesNotRequireBootstrapPin(t *testing.T) {
	f := newNetBirdBootstrapFixture(t)
	if err := os.WriteFile(f.runner.binary, []byte("installed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(f.configPath), "netbird-pin.json")); err != nil {
		t.Fatal(err)
	}
	enrolled := false
	f.runner.enroll = func(context.Context, netbird.Config) error { enrolled = true; return nil }
	if err := enrollNetBirdBootstrap(t.Context(), f.configPath, io.Discard, f.runner); err != nil || !enrolled {
		t.Fatalf("config-only existing-client enrollment failed: enrolled=%t error=%v", enrolled, err)
	}
}

func TestNetBirdBootstrapRetryResumesPersistedTransactionBeforeAndAfterReplacement(t *testing.T) {
	for _, test := range []struct {
		name              string
		replaced, confirm bool
	}{
		{name: "before-replacement"},
		{name: "after-replacement", replaced: true},
		{name: "during-confirmation", replaced: true, confirm: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newNetBirdBootstrapFixture(t)
			var pending client.ManagedResult
			installs, confirms, enrolls := 0, 0, 0
			f.runner.status = func(context.Context) (client.ManagedResult, error) { return pending, nil }
			f.runner.install = func(_ context.Context, _ client.Pin, _ netbird.Config, options client.ManagedOptions) (client.ManagedResult, error) {
				installs++
				if !entityid.Valid(options.TransactionID) || !options.Bootstrap || options.BinaryPath != f.runner.fallback ||
					pending.TransactionID != "" && pending.TransactionID != options.TransactionID {
					t.Fatalf("bootstrap retry changed persisted installation identity: %+v %+v", options, pending)
				}
				pending = client.ManagedResult{TransactionID: options.TransactionID, Bootstrap: options.Bootstrap, Pending: true}
				if test.replaced || installs > 1 {
					if err := os.WriteFile(f.runner.binary, []byte("installed"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if installs == 1 && !test.confirm {
					return pending, errors.New("simulated caller crash after journaling")
				}
				return pending, nil
			}
			f.runner.confirm = func(_ context.Context, id string) error {
				if id != pending.TransactionID || !pending.Pending {
					t.Fatalf("confirmed an unrelated or completed transaction: %s %+v", id, pending)
				}
				confirms++
				if test.confirm && confirms == 1 {
					return errors.New("simulated crash before confirmation committed")
				}
				pending.Pending = false
				return nil
			}
			f.runner.enroll = func(context.Context, netbird.Config) error { enrolls++; return nil }
			before := 0
			if test.confirm {
				before = 1
			}
			if err := enrollNetBirdBootstrap(t.Context(), f.configPath, io.Discard, f.runner); err == nil || confirms != before || enrolls != 0 {
				t.Fatalf("failed bootstrap escaped pending recovery: confirms=%d enrolls=%d err=%v", confirms, enrolls, err)
			}
			if err := enrollNetBirdBootstrap(t.Context(), f.configPath, io.Discard, f.runner); err != nil || installs != 2 || confirms != before+1 || enrolls != 1 || pending.Pending {
				t.Fatalf("retry skipped persisted transaction: installs=%d confirms=%d enrolls=%d pending=%+v err=%v", installs, confirms, enrolls, pending, err)
			}
		})
	}
}

func TestNetBirdBootstrapDoesNotConfirmControllerTransaction(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "completed", true: "pending"}[pending], func(t *testing.T) {
			f := newNetBirdBootstrapFixture(t)
			if err := os.WriteFile(f.runner.binary, []byte("installed"), 0600); err != nil {
				t.Fatal(err)
			}
			f.runner.status = func(context.Context) (client.ManagedResult, error) {
				return client.ManagedResult{TransactionID: "3QBR1KQT1HTTSCJ70S4NNBKM6R", Pending: pending}, nil
			}
			enrolls := 0
			f.runner.enroll = func(context.Context, netbird.Config) error { enrolls++; return nil }
			err := enrollNetBirdBootstrap(t.Context(), f.configPath, io.Discard, f.runner)
			if pending && (err == nil || !strings.Contains(err.Error(), "controller-owned") || enrolls != 0) ||
				!pending && (err != nil || enrolls != 1) {
				t.Fatalf("controller transaction ownership lost: pending=%t enrolls=%d err=%v", pending, enrolls, err)
			}
		})
	}
}

func TestNetBirdPendingBootstrapRequiresVerifiedFallback(t *testing.T) {
	f := newNetBirdBootstrapFixture(t)
	if err := os.WriteFile(f.runner.binary, []byte("installed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.runner.fallback); err != nil {
		t.Fatal(err)
	}
	f.runner.status = func(context.Context) (client.ManagedResult, error) {
		return client.ManagedResult{TransactionID: "6HY7VA1YZA2NVTY123SNDH514X", Bootstrap: true, Pending: true}, nil
	}
	if err := enrollNetBirdBootstrap(t.Context(), f.configPath, io.Discard, f.runner); err == nil || !strings.Contains(err.Error(), "bootstrap transaction") {
		t.Fatalf("pending bootstrap reported success without its verified artifact: %v", err)
	}
}

func TestNetBirdBootstrapCannotReplaceMissingControllerManagedBinary(t *testing.T) {
	for _, rolledBack := range []bool{false, true} {
		t.Run(map[bool]string{false: "confirmed", true: "rolled-back"}[rolledBack], func(t *testing.T) {
			f := newNetBirdBootstrapFixture(t)
			f.runner.status = func(context.Context) (client.ManagedResult, error) {
				return client.ManagedResult{TransactionID: "3QBR1KQT1HTTSCJ70S4NNBKM6R", RolledBack: rolledBack}, nil
			}
			if err := enrollNetBirdBootstrap(t.Context(), f.configPath, io.Discard, f.runner); err == nil || !strings.Contains(err.Error(), "fenced rollout") {
				t.Fatalf("missing managed binary bypassed controller history: rolledBack=%t err=%v", rolledBack, err)
			}
		})
	}
}

func TestNetBirdBootstrapLoadsConfigAfterRecoveryRestoresIt(t *testing.T) {
	f := newNetBirdBootstrapFixture(t)
	if err := os.WriteFile(f.runner.binary, []byte("restored previous binary"), 0600); err != nil {
		t.Fatal(err)
	}
	restored := f.config
	restored.SetupKeySecretID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.restored"
	f.runner.status = func(context.Context) (client.ManagedResult, error) {
		wire, err := json.Marshal(restored)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.configPath, wire, 0644); err != nil {
			t.Fatal(err)
		}
		return client.ManagedResult{TransactionID: "28VM3C1AVKQYWE7V44S6FPVBVS", Bootstrap: true, RolledBack: true}, nil
	}
	enrolled := false
	f.runner.enroll = func(_ context.Context, cfg netbird.Config) error {
		if cfg.SetupKeySecretID != restored.SetupKeySecretID {
			t.Fatal("enrollment used the config superseded by rollback")
		}
		enrolled = true
		return nil
	}
	if err := enrollNetBirdBootstrap(t.Context(), f.configPath, io.Discard, f.runner); err != nil || !enrolled {
		t.Fatalf("restored configuration was not enrolled: enrolled=%t err=%v", enrolled, err)
	}
}
