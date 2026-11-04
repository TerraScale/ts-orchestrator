package netbird

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testSetupKey = "884b8bcf-16bc-4d2c-8a3f-ae5f8b6b3ba3"
const appliedConfigJSON = `{"managementUrl":"https://netbird.terrascale.tech","disableDns":false,"disableClientRoutes":true,"disableServerRoutes":true,"disableAutoConnect":false,` +
	`"serverSSHAllowed":true,"enableSSHRoot":true,"enableSSHSFTP":true,"enableSSHLocalPortForwarding":true,"enableSSHRemotePortForwarding":false,"disableSSHAuth":false}`

func testConfig() Config {
	return Config{ManagementURL: DefaultManagementURL, ManagementIP: "10.250.10.155", Region: DefaultRegion,
		SetupKeySecretID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaa.testsecret"}
}

func testEnroller(t *testing.T) enroller {
	t.Helper()
	directory := t.TempDir()
	hosts := filepath.Join(directory, "hosts")
	if err := os.WriteFile(hosts, []byte("127.0.0.1 localhost\n# keep this entry\n10.250.1.2 git.terrascale.tech\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return enroller{hostsPath: hosts, runtimePath: filepath.Join(directory, "run"), poll: time.Millisecond, pending: 50 * time.Millisecond,
		hostname: func() (string, error) { return "ts-gru-server-1", nil },
		readKey: func(context.Context, Config) ([]byte, error) {
			t.Fatal("unexpected OCI secret retrieval")
			return nil, nil
		}}
}

func statusJSON(state, manager string, connected bool) []byte {
	if connected {
		return []byte(`{"daemonStatus":"` + state + `","management":{"url":"` + manager + `","connected":true},"signal":{"connected":true},"publicKey":"not-a-credential","netbirdIp":"100.100.0.1/16"}`)
	}
	return []byte(`{"daemonStatus":"` + state + `","management":{"url":"` + manager + `","connected":false},"signal":{"connected":false}}`)
}

func TestEnrollmentKeyIsFileOnlyAndRemovedOnSuccessOrFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "failure"}[fail], func(t *testing.T) {
			e := testEnroller(t)
			key := []byte(testSetupKey)
			e.readKey = func(ctx context.Context, cfg Config) ([]byte, error) {
				if cfg.SetupKeySecretID != testConfig().SetupKeySecretID {
					t.Fatal("wrong Vault reference")
				}
				return key, nil
			}
			connected := false
			e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[0] == "debug" {
					return []byte(appliedConfigJSON), nil
				}
				if strings.Contains(strings.Join(args, " "), testSetupKey) {
					t.Fatal("setup key exposed in process arguments")
				}
				if args[0] == "up" {
					for _, flag := range append([]string{"--hostname", "--no-browser"}, upSettings()...) {
						if !slices.Contains(args, flag) {
							t.Fatalf("missing enrollment flag %s", flag)
						}
					}
					index := slices.Index(args, "--setup-key-file")
					if index < 0 {
						t.Fatal("missing setup-key-file")
					}
					path := args[index+1]
					info, err := os.Stat(path)
					if err != nil || info.Mode().Perm() != 0o600 || filepath.Dir(path) != e.runtimePath {
						t.Fatalf("setup key is not a private runtime file: %v %v", info, err)
					}
					body, err := os.ReadFile(path)
					if err != nil || string(body) != testSetupKey {
						t.Fatal("wrong setup key file content")
					}
					if fail {
						return []byte(testSetupKey), errors.New("subprocess leaked " + testSetupKey)
					}
					connected = true
					return nil, nil
				}
				if connected {
					return statusJSON("Connected", DefaultManagementURL, true), nil
				}
				return statusJSON("NeedsLogin", DefaultManagementURL, false), nil
			}
			err := e.enroll(t.Context(), testConfig())
			if (err != nil) != fail {
				t.Fatalf("enrollment returned %v; fail = %t", err, fail)
			}
			if err != nil && strings.Contains(err.Error(), testSetupKey) {
				t.Fatal("subprocess error exposed setup key")
			}
			if _, err := os.Lstat(filepath.Join(e.runtimePath, "setup-key")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("setup key survived enrollment: %v", err)
			}
			if !bytes.Equal(key, make([]byte, len(key))) {
				t.Fatal("retrieved key bytes were not cleared")
			}
		})
	}
}

func TestFirstRegistrationUsesStableSlotPeerName(t *testing.T) {
	for name, tc := range map[string]struct {
		ip, want string
	}{
		"mapped controller": {"10.251.0.12", "gru-1-ctl-2"},
	} {
		t.Run(name, func(t *testing.T) {
			e := testEnroller(t)
			e.primaryIP = func(context.Context) (netip.Addr, error) { return netip.MustParseAddr(tc.ip), nil }
			e.readKey = func(context.Context, Config) ([]byte, error) { return []byte(testSetupKey), nil }
			cfg := testConfig()
			cfg.PeerNames = map[string]string{"10.251.0.12": "gru-1-ctl-2", "10.251.0.21": "gru-1-db-1"}
			var registered string
			e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				switch args[0] {
				case "debug":
					return []byte(appliedConfigJSON), nil
				case "up":
					registered = args[slices.Index(args, "--hostname")+1]
					return nil, nil
				}
				if registered != "" {
					return statusJSON("Connected", DefaultManagementURL, true), nil
				}
				return statusJSON("NeedsLogin", DefaultManagementURL, false), nil
			}
			if err := e.enroll(t.Context(), cfg); err != nil {
				t.Fatal(err)
			}
			if registered != tc.want {
				t.Fatalf("registered as %q, want %q", registered, tc.want)
			}
		})
	}
}
