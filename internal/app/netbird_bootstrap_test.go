package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
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

func TestNetBirdBootstrapRetryResumesPersistedTransactionBeforeAndAfterReplacement(t *testing.T) {
	for _, test := range []struct {
		name              string
		replaced, confirm bool
	}{

		{name: "after-replacement", replaced: true},
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
