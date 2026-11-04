package client

import (
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/netbird"
)

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

	for _, test := range []struct{ name, failure, version string }{
		{name: "version", failure: "version", version: "0.79.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newManagedFixture(t)
			root := managedBootstrapDefaults(t, f)
			validPin, validConfig := f.pin, f.cfg
			before, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			switch test.failure {
			case "version":
				f.pin.Version = test.version
				if err := ValidateManagedVersion(test.version); err == nil {
					t.Fatalf("invalid managed version %q accepted", test.version)
				}
			case "pin":
				f.pin.Archives.AMD64.BinarySHA256 = "invalid"
			case "configuration":
				f.cfg.SetupKeySecretID = "invalid"
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			default:
				f.pin.Version = test.version
				f.pin.Archives.AMD64.URL = strings.ReplaceAll(validPin.Archives.AMD64.URL, validPin.Version, test.version)
				f.pin.Archives.Arm64.URL = strings.ReplaceAll(validPin.Archives.Arm64.URL, validPin.Version, test.version)
				if err := ValidateManagedVersion(test.version); err != nil {
					t.Fatalf("managed version %q rejected: %v", test.version, err)
				}
				if err := ValidatePin(f.pin); err != nil {
					t.Fatalf("supported patch fixture: %v", err)
				}
			}
			wantPin, wantConfig := f.pin, f.cfg
			written, err := f.m.installBootstrapConfig(ctx, root, f.pin, f.cfg)
			if test.failure != "" {
				if err == nil || written || test.failure == "context" && !errors.Is(err, context.Canceled) {
					t.Fatalf("invalid initial configuration was written: written=%t error=%v", written, err)
				}
				if test.failure == "version" && err.Error() != "managed NetBird pin must be a 0.80.x release" {
					t.Fatalf("version was rejected by another gate: %v", err)
				}
				for _, name := range []string{"netbird-pin.json", "netbird.json"} {
					assertManagedFile(t, filepath.Join(root, name), []byte("image default "+name))
				}
				if _, err := os.Lstat(filepath.Join(root, bootstrapPendingFile)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("invalid publication left a pending marker: %v", err)
				}
				after, readErr := os.ReadDir(root)
				if readErr != nil || len(after) != len(before) {
					t.Fatalf("invalid publication changed directory entries: %v", readErr)
				}
				for index, entry := range before {
					if after[index].Name() != entry.Name() {
						t.Fatal("invalid publication changed directory entry names")
					}
				}
				if transaction, err := f.m.readTransaction(); err != nil || transaction.TransactionID != "" || len(f.calls) != 0 {
					t.Fatalf("invalid publication admitted or changed the service: %+v %v calls=%v", transaction, err, f.calls)
				}
				wantPin, wantConfig = validPin, validConfig
				written, err = f.m.installBootstrapConfig(t.Context(), root, wantPin, wantConfig)
			}
			if err != nil || !written {
				t.Fatalf("valid publication after input gate: written=%t error=%v", written, err)
			}
			readPin, readConfig, err := f.m.readBootstrapConfig(t.Context(), filepath.Join(root, "netbird.json"), true)
			if err != nil || readPin != wantPin {
				t.Fatalf("independent publication pin readback: %+v %v", readPin, err)
			}
			expected, err := json.Marshal(wantConfig)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := json.Marshal(readConfig)
			if err != nil || string(actual) != string(expected) {
				t.Fatalf("independent publication configuration changed: %v", err)
			}
			if transaction, err := f.m.readTransaction(); err != nil || transaction.TransactionID != "" || len(f.calls) != 0 {
				t.Fatalf("publication readback admitted or changed the service: %+v %v calls=%v", transaction, err, f.calls)
			}
			assertManagedFile(t, f.m.path(managedBinary), f.old)
		})
	}
}
