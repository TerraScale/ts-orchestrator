package netbird

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const testSetupKey = "884b8bcf-16bc-4d2c-8a3f-ae5f8b6b3ba3"
const appliedConfigJSON = `{"managementUrl":"https://netbird.terrascale.tech","disableDns":true,"disableClientRoutes":true,"disableServerRoutes":true,"disableAutoConnect":false,` +
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

func TestConnectedEnrollmentDoesNotReadVaultOrRunUp(t *testing.T) {
	e := testEnroller(t)
	var commands []string
	e.run = func(ctx context.Context, binary string, args ...string) ([]byte, error) {
		commands = append(commands, args[0])
		if args[0] == "debug" {
			return []byte(appliedConfigJSON), nil
		}
		if binary != netbirdBinary || args[0] != "status" || !slices.Contains(args, "--json") {
			t.Fatalf("unexpected command: %s %v", binary, args)
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > commandLimit {
			t.Fatal("subprocess did not receive a bounded context")
		}
		return statusJSON("Connected", DefaultManagementURL+":443", true), nil
	}
	if err := e.enroll(t.Context(), testConfig()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(commands, []string{"status", "debug"}) {
		t.Fatalf("commands = %v", commands)
	}
	body, err := os.ReadFile(e.hostsPath)
	if err != nil || !bytes.Contains(body, []byte("10.250.10.155\tnetbird.terrascale.tech\t"+hostsMarker)) || !bytes.Contains(body, []byte("10.250.1.2 git.terrascale.tech")) {
		t.Fatalf("manager resolution did not preserve hosts entries: %q %v", body, err)
	}
}

func TestSavedIdentityReconnectDoesNotReadSetupKey(t *testing.T) {
	e := testEnroller(t)
	connected := false
	var commands []string
	e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[0])
		if args[0] == "debug" {
			return []byte(appliedConfigJSON), nil
		}
		if args[0] == "up" {
			if slices.Contains(args, "--setup-key-file") || slices.Contains(args, "--setup-key") {
				t.Fatal("saved identity reconnect should not use a setup key")
			}
			connected = true
			return nil, nil
		}
		if connected {
			return statusJSON("Connected", DefaultManagementURL, true), nil
		}
		return statusJSON("Idle", DefaultManagementURL, false), nil
	}
	if err := e.enroll(t.Context(), testConfig()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(commands, "up") || slices.Contains(commands, "down") {
		t.Fatalf("commands = %v", commands)
	}
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

func TestEnrollmentDoesNotConsumeKeyDuringNetworkOutage(t *testing.T) {
	for _, state := range []string{"Connecting", "LoginFailed"} {
		t.Run(state, func(t *testing.T) {
			e := testEnroller(t)
			e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if args[0] == "up" {
					return nil, errors.New("network unreachable")
				}
				return statusJSON(state, DefaultManagementURL, false), nil
			}
			if err := e.enroll(t.Context(), testConfig()); err == nil {
				t.Fatal("network outage should fail readiness without reading a new key")
			}
		})
	}
}

func TestConnectedIdentityAppliesServerSettingsWithoutVault(t *testing.T) {
	for name, stale := range map[string]string{
		"ssh disabled": strings.Replace(appliedConfigJSON, `"serverSSHAllowed":true`, `"serverSSHAllowed":false`, 1),
		"dns enabled":  strings.Replace(appliedConfigJSON, `"disableDns":true`, `"disableDns":false`, 1),
		"ssh auth off": strings.Replace(appliedConfigJSON, `"disableSSHAuth":false`, `"disableSSHAuth":true`, 1),
		"remote forwarding": strings.Replace(appliedConfigJSON,
			`"enableSSHRemotePortForwarding":false`, `"enableSSHRemotePortForwarding":true`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			e := testEnroller(t)
			configured := false
			var commands []string
			e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
				commands = append(commands, args[0])
				switch args[0] {
				case "debug":
					if configured {
						return []byte(appliedConfigJSON), nil
					}
					return []byte(stale), nil
				case "down":
					return nil, nil
				case "up":
					if slices.Contains(args, "--setup-key-file") {
						t.Fatal("applying server settings consumed a setup key")
					}
					configured = true
					return nil, nil
				default:
					return statusJSON("Connected", DefaultManagementURL, true), nil
				}
			}
			if err := e.enroll(t.Context(), testConfig()); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(commands, []string{"status", "debug", "down", "up", "status", "debug"}) {
				t.Fatalf("configuration was not applied to existing identity: %v", commands)
			}
		})
	}
}

func TestEffectiveConfigurationWithoutSSHFieldsIsRejected(t *testing.T) {
	e := testEnroller(t)
	e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "debug" {
			return []byte(strings.Replace(appliedConfigJSON, `"enableSSHRoot":true,`, "", 1)), nil
		}
		return statusJSON("Connected", DefaultManagementURL, true), nil
	}
	if err := e.enroll(t.Context(), testConfig()); err == nil || !strings.Contains(err.Error(), "invalid effective configuration") {
		t.Fatalf("missing SSH setting was accepted: %v", err)
	}
}

func TestEnrollmentRejectsStatusFailureWithoutReadingKey(t *testing.T) {
	for _, wire := range [][]byte{[]byte("invalid json containing " + testSetupKey), statusJSON("NewState", DefaultManagementURL, false)} {
		e := testEnroller(t)
		e.run = func(context.Context, string, ...string) ([]byte, error) { return bytes.Clone(wire), nil }
		err := e.enroll(t.Context(), testConfig())
		if err == nil || strings.Contains(err.Error(), testSetupKey) {
			t.Fatalf("unexpected untrusted status error: %v", err)
		}
	}
}

func TestDifferentManagerRequiresFreshEnrollmentAndVerification(t *testing.T) {
	e := testEnroller(t)
	keyRead, connected := false, false
	e.readKey = func(context.Context, Config) ([]byte, error) {
		keyRead = true
		return []byte(testSetupKey), nil
	}
	var commands []string
	e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[0])
		switch args[0] {
		case "debug":
			return []byte(appliedConfigJSON), nil
		case "down":
			if !keyRead {
				t.Fatal("disconnected old manager before retrieving enrollment key")
			}
			return nil, nil
		case "up":
			connected = true
			return nil, nil
		default:
			if connected {
				return statusJSON("Connected", DefaultManagementURL, true), nil
			}
			return statusJSON("Connected", "https://api.netbird.io", true), nil
		}
	}
	if err := e.enroll(t.Context(), testConfig()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(commands, []string{"status", "down", "up", "status", "debug"}) {
		t.Fatalf("unexpected manager transition %v", commands)
	}
}

func TestSubprocessEnvironmentCannotOverrideFlags(t *testing.T) {
	t.Setenv("NB_SETUP_KEY", testSetupKey)
	t.Setenv("WT_MANAGEMENT_URL", "https://attacker.invalid")
	output, err := runCommand(t.Context(), "/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(output, []byte("NB_SETUP_KEY")) || bytes.Contains(output, []byte("WT_MANAGEMENT_URL")) {
		t.Fatal("NetBird environment overrides reached the subprocess")
	}
}

func TestEnrollmentWaitsForDaemonSocketInsteadOfFailing(t *testing.T) {
	e := testEnroller(t)
	// Unix socket paths are short; t.TempDir can exceed the limit.
	directory, err := os.MkdirTemp("", "nb")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	e.socketPath = filepath.Join(directory, "netbird.sock")
	listening := make(chan struct{})
	listener := make(chan net.Listener, 1)
	go func() {
		defer close(listening)
		time.Sleep(20 * time.Millisecond)
		socket, err := net.Listen("unix", e.socketPath)
		if err != nil {
			t.Error(err)
			return
		}
		listener <- socket
	}()
	t.Cleanup(func() {
		<-listening
		select {
		case socket := <-listener:
			socket.Close()
		default:
		}
	})
	unreachable := 2
	e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		// Check the socket file itself: the listener goroutine closes
		// listening only after net.Listen has already created it, so the
		// channel would race a poll that lands in between.
		if info, err := os.Lstat(e.socketPath); err != nil || info.Mode().Type() != os.ModeSocket {
			t.Fatal("daemon was queried before its control socket existed")
		}
		if args[0] == "debug" {
			return []byte(appliedConfigJSON), nil
		}
		if unreachable > 0 {
			// The socket can exist a moment before the daemon serves it.
			unreachable--
			return nil, errors.New("connection refused")
		}
		return statusJSON("Connected", DefaultManagementURL, true), nil
	}
	if err := e.enroll(t.Context(), testConfig()); err != nil {
		t.Fatal(err)
	}
	if unreachable != 0 {
		t.Fatal("unreachable daemon was not retried")
	}
}

func TestFreshDaemonEnrollsWithoutRedundantDown(t *testing.T) {
	e := testEnroller(t)
	e.readKey = func(context.Context, Config) ([]byte, error) { return []byte(testSetupKey), nil }
	connected := false
	var commands []string
	e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[0])
		switch args[0] {
		case "debug":
			return []byte(appliedConfigJSON), nil
		case "down":
			t.Fatal("a fresh daemon has no client to bring down")
		case "up":
			connected = true
			return nil, nil
		}
		if connected {
			return statusJSON("Connected", DefaultManagementURL, true), nil
		}
		// NetBird 0.79 creates a default-manager config and waits in NeedsLogin.
		return statusJSON("NeedsLogin", "https://api.netbird.io:443", false), nil
	}
	if err := e.enroll(t.Context(), testConfig()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(commands, []string{"status", "up", "status", "debug"}) {
		t.Fatalf("commands = %v", commands)
	}
}

func TestBootReconnectInProgressIsAwaitedWithoutUp(t *testing.T) {
	e := testEnroller(t)
	polls := 0
	var commands []string
	e.run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[0])
		switch args[0] {
		case "debug":
			return []byte(appliedConfigJSON), nil
		case "up", "down":
			t.Fatalf("daemon reconnecting its saved identity received %s", args[0])
		}
		polls++
		if polls < 3 {
			return statusJSON("Connecting", DefaultManagementURL, false), nil
		}
		return statusJSON("Connected", DefaultManagementURL, true), nil
	}
	if err := e.enroll(t.Context(), testConfig()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(commands, []string{"status", "status", "status", "debug"}) {
		t.Fatalf("commands = %v", commands)
	}
}

func TestObserveBacksOffExponentiallyWithinLimit(t *testing.T) {
	e := testEnroller(t)
	e.poll = 2 * time.Millisecond
	var times []time.Time
	e.run = func(context.Context, string, ...string) ([]byte, error) {
		times = append(times, time.Now())
		return statusJSON("Connecting", DefaultManagementURL, false), nil
	}
	started := time.Now()
	status, done, err := e.observe(t.Context(), 100*time.Millisecond, nil, func(daemonStatus) bool { return false })
	if err != nil || done || status.DaemonStatus != "Connecting" {
		t.Fatalf("observe = %v %t %v", status, done, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("observe overran its limit: %v", elapsed)
	}
	// 2+4+8+16+32+64 ms exceeds the limit, so at most seven queries fit;
	// fixed 2 ms polling would need about fifty. Scheduler delay under load
	// only lowers the count.
	if len(times) < 2 || len(times) > 7 {
		t.Fatalf("status queries = %d", len(times))
	}
}

// The pinned client's effective configuration must keep every key the
// settings check reads. Bumping NetBird fails here until the fixture is
// refreshed from the new release's `netbird debug config`.
func TestPinnedClientDebugConfigFixtureSatisfiesServerSettings(t *testing.T) {
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
		t.Fatalf("no debug config fixture for pinned NetBird %s: %v", pin.NetBird.Version, err)
	}
	e := testEnroller(t)
	e.run = func(context.Context, string, ...string) ([]byte, error) { return bytes.Clone(fixture), nil }
	applied, err := e.settingsApplied(t.Context(), DefaultManagementURL)
	if err != nil || !applied {
		t.Fatalf("pinned client fixture rejected: applied=%t error=%v", applied, err)
	}
}
