package netbird

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
)

const testSetupSecretID = "ocid1.vaultsecret.oc1.sa-saopaulo-1.aaaaaaaa.testsecret"

const testSetupKey = "884b8bcf-16bc-4d2c-8a3f-ae5f8b6b3ba3"
const appliedConfigJSON = `{"managementUrl":"https://netbird.terrascale.tech","disableDns":false,"disableClientRoutes":true,"disableServerRoutes":true,"disableAutoConnect":false,"serverSSHAllowed":true,"enableSSHRoot":true,"enableSSHSFTP":true,"enableSSHLocalPortForwarding":true,"enableSSHRemotePortForwarding":false,"disableSSHAuth":false}`

func testConfig() Config {
	return Config{ManagementURL: DefaultManagementURL, Region: DefaultRegion}
}

func statusJSON(state, manager string, connected bool) []byte {
	wire, _ := json.Marshal(map[string]any{"daemonStatus": state, "management": map[string]any{"url": manager, "connected": connected}, "signal": map[string]any{"connected": connected}})
	return wire
}

// The executable is a protocol simulator, with identity/settings surviving every CLI process.
func testEnroller(t *testing.T) enroller {
	t.Helper()
	directory := t.TempDir()
	writeIntegrationFile(t, filepath.Join(directory, "hosts"), "127.0.0.1 localhost\n# keep this entry\n10.250.1.2 git.terrascale.tech\n10.250.10.155 netbird.terrascale.tech "+hostsMarker+"\n", 0o644)
	writeIntegrationFile(t, filepath.Join(directory, "status"), string(statusJSON("NeedsLogin", DefaultManagementURL, false)), 0o600)
	writeIntegrationFile(t, filepath.Join(directory, "effective"), appliedConfigJSON, 0o600)
	writeIntegrationFile(t, filepath.Join(directory, "connected"), string(statusJSON("Connected", DefaultManagementURL, true)), 0o600)
	script := `#!/bin/sh
set -eu
cd "$(dirname "$0")"
printf '%s\n' "$*" >> commands
case "$1" in
 status)
  if [ -e socket-path ]; then test -S "$(cat socket-path)"; fi
  if [ -e unreachable ]; then rm unreachable; exit 1; fi
  if [ -e hang ]; then exec sleep 30; fi
  if [ -e boot ]; then rm boot; cat connecting; else cat status; fi;;
 debug) cat effective;;
 down)
  if [ -e require-key-before-down ]; then test -e vault-read; fi;;
 up)
  previous=''
  for argument do
   if [ "$previous" = '--setup-key-file' ]; then
    test "$(stat -c '%a' "$argument")" = 600
    test "$(stat -c '%a' "$(dirname "$argument")")" = 700
    test "$(cat "$argument")" = '884b8bcf-16bc-4d2c-8a3f-ae5f8b6b3ba3'
    printf '%s\n' "$argument" > key-path
   fi
   previous="$argument"
  done
  if [ -e fail ]; then
   echo '884b8bcf-16bc-4d2c-8a3f-ae5f8b6b3ba3'
   echo '884b8bcf-16bc-4d2c-8a3f-ae5f8b6b3ba3' >&2
   exit 1
  fi
  if [ -e repair ]; then cp desired effective; fi
  cp connected status;;
 *) exit 2;;
esac
`
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}
	script = strings.Replace(script, "set -eu\n", "set -eu\nPATH='"+strings.ReplaceAll(os.Getenv("PATH"), "'", "'\"'\"'")+"'\nexport PATH\n", 1)
	binary := filepath.Join(directory, "netbird")
	writeIntegrationFile(t, binary, script, 0o700)
	return enroller{hostsPath: filepath.Join(directory, "hosts"), runtimePath: filepath.Join(directory, "run"), poll: time.Millisecond, pending: 100 * time.Millisecond,
		hostname: os.Hostname, run: func(ctx context.Context, _ string, args ...string) ([]byte, error) {
			return runCommand(ctx, shell, append([]string{binary}, args...)...)
		},
		readKey: func(context.Context, Config) ([]byte, error) {
			t.Error("unexpected Vault read")
			return nil, errors.New("unexpected Vault read")
		}}
}

func writeIntegrationFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func enrollmentCommands(t *testing.T, e enroller) []string {
	t.Helper()
	wire, err := os.ReadFile(filepath.Join(filepath.Dir(e.hostsPath), "commands"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(testSetupKey)) {
		t.Fatal("secret reached executable arguments")
	}
	var commands []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(wire)), "\n") {
		commands = append(commands, strings.Fields(line)[0])
	}
	return commands
}

func TestEnrollmentIntegrationPersistsIdentityAcrossProcessesAndRestart(t *testing.T) {
	client, requests := vaultHTTPClient(t, func(attempt int) (int, map[string]any) {
		return 200, vaultBundle(testSetupSecretID, "\n"+testSetupKey+"\n")
	})
	e := testEnroller(t)
	e.readKey = func(ctx context.Context, cfg Config) ([]byte, error) {
		return readCurrentSetupKey(ctx, testSetupSecretID, client)
	}
	cfgPath := filepath.Join(filepath.Dir(e.hostsPath), "config.json")
	wire, err := json.Marshal(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	writeIntegrationFile(t, cfgPath, string(wire), 0o644)
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.enroll(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("Vault requests = %d", requests.Load())
	}
	if commands := enrollmentCommands(t, e); !slices.Equal(commands, []string{"status", "up", "status", "debug"}) {
		t.Fatalf("initial commands %v", commands)
	}
	if _, err := os.Lstat(filepath.Join(e.runtimePath, "setup-key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setup key survived: %v", err)
	}
	body, err := os.ReadFile(e.hostsPath)
	if err != nil || !bytes.Contains(body, []byte("10.250.1.2 git.terrascale.tech")) || bytes.Contains(body, []byte(hostsMarker)) || bytes.Contains(body, []byte("10.250.10.155")) {
		t.Fatalf("hosts: %q %v", body, err)
	}
	// Recreate the enroller while retaining the daemon's disk state.
	restarted := e
	restarted.readKey = func(context.Context, Config) ([]byte, error) {
		t.Error("restart consumed setup key")
		return nil, errors.New("unexpected read")
	}
	if err := restarted.enroll(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatal("connected restart read Vault")
	}
	directory := filepath.Dir(e.hostsPath)
	writeIntegrationFile(t, filepath.Join(directory, "status"), string(statusJSON("Idle", DefaultManagementURL, false)), 0o600)
	if err := restarted.enroll(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
	if commands := enrollmentCommands(t, e); !slices.Equal(commands, []string{"status", "up", "status", "debug", "status", "debug", "status", "up", "status", "debug"}) {
		t.Fatalf("restart commands %v", commands)
	}
}

func TestEnrollmentIntegrationFailureCleansKeyAndRedactsJournal(t *testing.T) {
	client, _ := vaultHTTPClient(t, func(int) (int, map[string]any) { return 200, vaultBundle(testSetupSecretID, testSetupKey) })
	e := testEnroller(t)
	e.readKey = func(ctx context.Context, cfg Config) ([]byte, error) {
		return readCurrentSetupKey(ctx, testSetupSecretID, client)
	}
	writeIntegrationFile(t, filepath.Join(filepath.Dir(e.hostsPath), "fail"), "", 0o600)
	journal := decisionlog.NewJournal(decisionlog.JournalConfig{Region: "gru"})
	t.Cleanup(decisionlog.SetDefault(journal))
	err := e.enroll(t.Context(), testConfig())
	if err == nil || strings.Contains(err.Error(), testSetupKey) {
		t.Fatalf("unsafe enrollment result: %v", err)
	}
	recordEnrollment(t.Context(), testConfig(), e.hostname, err)
	result, _ := journal.Query(t.Context(), decisionlog.Query{Kinds: []decisionlog.Kind{decisionlog.KindPeerEnrolled}})
	if len(result.Decisions) != 1 || result.Decisions[0].Status != decisionlog.StatusFailed || result.Decisions[0].Outcome == "not connected" {
		t.Fatalf("journal %+v", result.Decisions)
	}
	encoded, err := json.Marshal(result)
	if err != nil || bytes.Contains(encoded, []byte(testSetupKey)) {
		t.Fatalf("unsafe journal: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(e.runtimePath, "setup-key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("setup key survived failed process: %v", err)
	}
	enrollmentCommands(t, e)
}

func TestEnrollmentIntegrationSavedIdentityOutageAndUntrustedStatusNeverReadVault(t *testing.T) {
	for _, state := range []string{"Connecting", "LoginFailed", "invalid", "NewState"} {
		t.Run(state, func(t *testing.T) {
			e := testEnroller(t)
			directory := filepath.Dir(e.hostsPath)
			wire := statusJSON(state, DefaultManagementURL, false)
			if state == "invalid" {
				wire = []byte("invalid " + testSetupKey)
			}
			writeIntegrationFile(t, filepath.Join(directory, "status"), string(wire), 0o600)
			writeIntegrationFile(t, filepath.Join(directory, "fail"), "", 0o600)
			err := e.enroll(t.Context(), testConfig())
			if err == nil || strings.Contains(err.Error(), testSetupKey) {
				t.Fatalf("untrusted daemon result %v", err)
			}
			if slices.Contains(enrollmentCommands(t, e), "down") {
				t.Fatal("outage disconnected saved identity")
			}
		})
	}
}

func TestEnrollmentIntegrationReappliesSettingsAndRejectsMissingFields(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "stale", true: "missing"}[missing], func(t *testing.T) {
			e := testEnroller(t)
			directory := filepath.Dir(e.hostsPath)
			writeIntegrationFile(t, filepath.Join(directory, "status"), string(statusJSON("Connected", DefaultManagementURL, true)), 0o600)
			stale := strings.Replace(appliedConfigJSON, `"disableSSHAuth":false`, `"disableSSHAuth":true`, 1)
			if missing {
				stale = strings.Replace(appliedConfigJSON, `"enableSSHRoot":true,`, "", 1)
			}
			writeIntegrationFile(t, filepath.Join(directory, "effective"), stale, 0o600)
			writeIntegrationFile(t, filepath.Join(directory, "repair"), "", 0o600)
			writeIntegrationFile(t, filepath.Join(directory, "desired"), appliedConfigJSON, 0o600)
			err := e.enroll(t.Context(), testConfig())
			if missing {
				if err == nil {
					t.Fatal("missing SSH setting accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := enrollmentCommands(t, e); !slices.Equal(got, []string{"status", "debug", "down", "up", "status", "debug"}) {
				t.Fatalf("reapply commands %v", got)
			}
		})
	}
}

func TestEnrollmentIntegrationSubprocessRejectsEnvironmentOverrides(t *testing.T) {
	t.Setenv("NB_SETUP_KEY", testSetupKey)
	t.Setenv("WT_MANAGEMENT_URL", "https://attacker.invalid")
	wire, err := runCommand(t.Context(), "/usr/bin/env")
	if err != nil || bytes.Contains(wire, []byte("NB_SETUP_KEY")) || bytes.Contains(wire, []byte("WT_MANAGEMENT_URL")) {
		t.Fatalf("unsafe process environment: %v", err)
	}
}

func TestEnrollmentIntegrationRejectsOCIOverridesBeforeReadingIdentity(t *testing.T) {
	for _, name := range []string{"OCI_GO_SDK_DEBUG", "OCI_METADATA_BASE_URL", "OCI_SDK_AUTH_CLIENT_REGION_URL", "OCI_DEFAULT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PATH", "OCI_DEFAULT_CLIENT_CERTS_PRIVATE_KEY_PATH"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "forbidden")
			e := testEnroller(t)
			var vaultErr error
			e.readKey = func(ctx context.Context, cfg Config) ([]byte, error) {
				key, err := ReadSetupKey(ctx, cfg.Region, testSetupSecretID)
				vaultErr = err
				return key, err
			}
			err := e.enroll(t.Context(), testConfig())
			if err == nil || vaultErr == nil || !strings.Contains(vaultErr.Error(), "does not permit") {
				t.Fatalf("OCI override reached enrollment: %v", err)
			}
			if slices.Contains(enrollmentCommands(t, e), "up") {
				t.Fatal("OCI override reached client mutation")
			}
		})
	}
}

func TestEnrollmentIntegrationForeignManagerReadsKeyBeforeDisconnecting(t *testing.T) {
	for _, failVault := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "vault-unavailable"}[failVault], func(t *testing.T) {
			e := testEnroller(t)
			directory := filepath.Dir(e.hostsPath)
			writeIntegrationFile(t, filepath.Join(directory, "status"), string(statusJSON("Connected", "https://api.netbird.io", true)), 0600)
			writeIntegrationFile(t, filepath.Join(directory, "require-key-before-down"), "", 0600)
			client, requests := vaultHTTPClient(t, func(int) (int, map[string]any) { return 200, vaultBundle(testSetupSecretID, testSetupKey) })
			e.readKey = func(ctx context.Context, cfg Config) ([]byte, error) {
				if failVault {
					return nil, errors.New("Vault unavailable")
				}
				key, err := readCurrentSetupKey(ctx, testSetupSecretID, client)
				if err == nil {
					writeIntegrationFile(t, filepath.Join(directory, "vault-read"), "", 0600)
				}
				return key, err
			}
			err := e.enroll(t.Context(), testConfig())
			if failVault {
				if err == nil || !slices.Equal(enrollmentCommands(t, e), []string{"status"}) {
					t.Fatal("failed Vault read disconnected the previous identity")
				}
				return
			}
			if err != nil || requests.Load() != 1 || !slices.Equal(enrollmentCommands(t, e), []string{"status", "down", "up", "status", "debug"}) {
				t.Fatalf("foreign-manager transition failed: %v", err)
			}
		})
	}
}

func TestEnrollmentIntegrationWaitsForSocketAndTransientProcessFailure(t *testing.T) {
	e := testEnroller(t)
	directory := filepath.Dir(e.hostsPath)
	writeIntegrationFile(t, filepath.Join(directory, "status"), string(statusJSON("Connected", DefaultManagementURL, true)), 0600)
	writeIntegrationFile(t, filepath.Join(directory, "unreachable"), "", 0600)
	sockets, err := os.MkdirTemp("", "nb-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockets) })
	e.socketPath = filepath.Join(sockets, "daemon.sock")
	writeIntegrationFile(t, filepath.Join(directory, "socket-path"), e.socketPath, 0600)
	type socketResult struct {
		listener net.Listener
		err      error
	}
	ready := make(chan socketResult, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		listener, err := net.Listen("unix", e.socketPath)
		ready <- socketResult{listener, err}
	}()
	t.Cleanup(func() {
		result := <-ready
		if result.err != nil {
			t.Error(result.err)
		} else {
			result.listener.Close()
		}
	})
	if err := e.enroll(t.Context(), testConfig()); err != nil {
		t.Fatal(err)
	}
	if got := enrollmentCommands(t, e); !slices.Equal(got, []string{"status", "status", "debug"}) {
		t.Fatalf("daemon startup commands %v", got)
	}
}

func TestEnrollmentIntegrationBootReconnectVerifiesPinnedClientSettings(t *testing.T) {
	inputs, err := os.ReadFile("../../deploy/image/image-inputs.json")
	if err != nil {
		t.Fatal(err)
	}
	var pin struct {
		NetBird struct {
			Version string `json:"version"`
		} `json:"netbird"`
	}
	if err := json.Unmarshal(inputs, &pin); err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join("testdata", "debug-config-"+pin.NetBird.Version+".json"))
	if err != nil {
		t.Fatal(err)
	}
	e := testEnroller(t)
	directory := filepath.Dir(e.hostsPath)
	writeIntegrationFile(t, filepath.Join(directory, "effective"), string(fixture), 0600)
	writeIntegrationFile(t, filepath.Join(directory, "connecting"), string(statusJSON("Connecting", DefaultManagementURL, false)), 0600)
	writeIntegrationFile(t, filepath.Join(directory, "boot"), "", 0600)
	writeIntegrationFile(t, filepath.Join(directory, "status"), string(statusJSON("Connected", DefaultManagementURL, true)), 0600)
	if err := e.enroll(t.Context(), testConfig()); err != nil {
		t.Fatal(err)
	}
	if got := enrollmentCommands(t, e); !slices.Equal(got, []string{"status", "status", "debug"}) {
		t.Fatalf("saved boot identity was mutated: %v", got)
	}
}

func TestEnrollmentIntegrationRejectsUnsafeDisplayNameBeforeClientMutation(t *testing.T) {
	for _, hostname := range []string{"", "invalid name", "injected\nname", strings.Repeat("x", 254)} {
		e := testEnroller(t)
		e.hostname = func() (string, error) { return hostname, nil }
		if err := e.enroll(t.Context(), testConfig()); err == nil || !slices.Equal(enrollmentCommands(t, e), []string{"status"}) {
			t.Fatal("unsafe hostname reached client mutation")
		}
	}
}
