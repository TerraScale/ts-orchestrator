package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

func TestPrepareActivateWatchdogRestart(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	owner := fmt.Sprint(os.Getuid())
	baked := filepath.Join(dir, "baked")
	if err := os.WriteFile(baked, []byte("baked build"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "identity.key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(private)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	var restarted []string
	invoke := func(args ...string) (string, error) {
		var output bytes.Buffer
		err := run(t.Context(), args, &output, func() time.Time { return now }, func(_ context.Context, unit string) error {
			restarted = append(restarted, unit)
			return nil
		})
		return output.String(), err
	}
	unit := "terrascale-orchestrator-host.service"
	proof := []string{"--proof-file", filepath.Join(dir, "proof.json"), "--proof-key-file", keyFile}
	output, err := invoke(append([]string{"prepare", "--root", root, "--owner", owner, "--unit", unit, "--baked-binary", baked}, proof...)...)
	if err != nil || !strings.Contains(output, "outcome=idle") {
		t.Fatalf("prepare = %q %v", output, err)
	}
	if output, err := invoke("status", "--root", root, "--owner", owner); err != nil || !strings.Contains(output, "pending=none") {
		t.Fatalf("status = %q %v", output, err)
	}
	// Without a staged second release nothing can be activated.
	if _, err := invoke("activate", "--root", root, "--owner", owner, "--release", strings.Repeat("a", 64), "--unit", unit); err == nil {
		t.Fatal("unstaged release activated")
	}
	if _, err := invoke("stage", "--root", root); err == nil {
		t.Fatal("stage without a receipt accepted")
	}
	if _, err := invoke("watchdog", "--root", root, "--owner", owner, "--unit", unit, "--proof-file", "x"); err == nil {
		t.Fatal("half-configured proof accepted")
	}
	if output, err := invoke(append([]string{"watchdog", "--root", root, "--owner", owner, "--unit", unit}, proof...)...); err != nil ||
		output != "" || len(restarted) != 0 {
		t.Fatalf("idle watchdog = %q %v %v", output, err, restarted)
	}
	if _, err := invoke("bogus"); err == nil {
		t.Fatal("unknown command accepted")
	}
}

// captureLog routes the default logger into the returned buffer for one test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	t.Setenv("JOURNAL_STREAM", "")
	var output bytes.Buffer
	logger, err := observability.NewLogger(&output, observability.LogConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := slog.Default()
	observability.ConfigureDefault(logger)
	t.Cleanup(func() { slog.SetDefault(previous) })
	return &output
}

func TestReadKeys(t *testing.T) {
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	rootFile := filepath.Join(dir, "root.pub")
	if err := os.WriteFile(rootFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0o644); err != nil {
		t.Fatal(err)
	}
	if roots, err := readRootKeyring(rootFile); err != nil || len(roots) != 1 {
		t.Fatalf("root keyring = %v %v", roots, err)
	}
	keyFile := filepath.Join(dir, "identity.key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(private)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readIdentityPublicKey(keyFile); err == nil {
		t.Fatal("world-readable identity key accepted")
	}
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if derived, err := readIdentityPublicKey(keyFile); err != nil || !derived.Equal(public) {
		t.Fatalf("derived public key = %v", err)
	}
}

// The image's watchdog takes the unit's key and proof file from the role
// config (TS-553): a fresh proof confirms the activation with no node-local
// file, and every unusable proof or config still rolls back at the deadline.
func TestWatchdogConfirmsOrRollsBackFromTheRoleConfig(t *testing.T) {
	controller, host := selfupdate.ControllerUnit, selfupdate.HostUnit
	for _, tc := range []struct {
		name, unit string
		// config returns the role config, or "" for none, and the file
		// the healthy process writes its proof to.
		config    func(key, defaultProof, dir string) (string, string)
		wrongKey  bool
		confirmed bool
	}{
		{"controller-default-proof", controller, func(key, proof, _ string) (string, string) {
			return `{"version":1,"nats":{"cell":"gru"},"controller":{"response_key_file":"` + key + `","added_later":true},"future":{}}`, proof
		}, false, true},
		{"host-configured-proof", host, func(key, _, dir string) (string, string) {
			proof := filepath.Join(dir, "custom-proof.json")
			return `{"version":1,"host":{"identity_key_file":"` + key + `","self_update_proof_file":"` + proof + `"}}`, proof
		}, false, true},
		{"proof-signed-by-another-key", controller, func(key, proof, _ string) (string, string) {
			return `{"version":1,"controller":{"response_key_file":"` + key + `"}}`, proof
		}, true, false},
		{"key-of-the-other-role", controller, func(key, proof, _ string) (string, string) {
			return `{"version":1,"host":{"identity_key_file":"` + key + `"}}`, proof
		}, false, false},
		{"role-not-configured", host, func(_, proof, _ string) (string, string) { return "", proof }, false, false},
		{"unreadable-config", host, func(_, proof, _ string) (string, string) { return `{"version":1,"host":`, proof }, false, false},
		{"other-release-root", host, func(key, proof, dir string) (string, string) {
			return `{"version":1,"host":{"identity_key_file":"` + key + `","self_update_root":"` + filepath.Join(dir, "elsewhere") + `"}}`, proof
		}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root := filepath.Join(dir, "lib", "terrascale-orchestrator")
			owner := fmt.Sprint(os.Getuid())
			layout := selfupdate.Layout{Root: root, Owner: os.Getuid()}
			defaultProof := selfupdate.DefaultProofFile(root, tc.unit)
			if err := os.MkdirAll(filepath.Dir(defaultProof), 0o700); err != nil {
				t.Fatal(err)
			}
			baked := filepath.Join(dir, "baked")
			if err := os.WriteFile(baked, []byte("baked build"), 0o755); err != nil {
				t.Fatal(err)
			}
			now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
			logs := captureLog(t)
			var restarted []string
			invoke := func(args ...string) (string, error) {
				var output bytes.Buffer
				err := run(t.Context(), args, &output, func() time.Time { return now }, func(_ context.Context, unit string) error {
					restarted = append(restarted, unit)
					return nil
				})
				return output.String(), err
			}
			if _, err := invoke("prepare", "--root", root, "--owner", owner, "--unit", tc.unit, "--baked-binary", baked); err != nil {
				t.Fatal(err)
			}
			previous, err := layout.Current()
			if err != nil {
				t.Fatal(err)
			}
			// Stage the target as `selfupdate stage` leaves it.
			target := []byte("target build")
			sum := sha256.Sum256(target)
			digest := hex.EncodeToString(sum[:])
			if err := os.Mkdir(layout.ReleaseDir(digest), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(layout.BinaryPath(digest), target, 0o555); err != nil {
				t.Fatal(err)
			}
			if _, err := invoke("activate", "--root", root, "--owner", owner, "--release", digest, "--unit", tc.unit, "--proof-window", "1m"); err != nil {
				t.Fatal(err)
			}
			activation, pending, err := layout.Pending()
			if err != nil || !pending {
				t.Fatalf("pending = %v %v", pending, err)
			}
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			keyFile := filepath.Join(dir, "identity.key")
			if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(private)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			config, proofFile := tc.config(keyFile, defaultProof, dir)
			configFile := filepath.Join(dir, "role.json")
			if config != "" {
				if err := os.WriteFile(configFile, []byte(config), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			signer := private
			if tc.wrongKey {
				if _, signer, err = ed25519.GenerateKey(rand.Reader); err != nil {
					t.Fatal(err)
				}
			}
			// The new process proves itself after it is ready.
			now = now.Add(time.Second)
			wire, err := selfupdate.SignVersionProof(selfupdate.VersionProof{
				Schema: selfupdate.ProofSchema, ActivationID: activation.ActivationID, Unit: tc.unit,
				BinarySHA256: digest, ProcessID: int64(os.Getpid()), ObservedAt: now,
			}, signer, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(proofFile, wire, 0o644); err != nil {
				t.Fatal(err)
			}
			watchdog := []string{"watchdog", "--root", root, "--owner", owner, "--unit", tc.unit, "--config", configFile}
			if _, err := invoke(append(watchdog, "--proof-file", proofFile)...); err == nil {
				t.Fatal("--config combined with --proof-file was accepted")
			}
			if _, err := invoke(watchdog...); err != nil {
				t.Fatal(err)
			}
			if tc.confirmed {
				if !strings.Contains(logs.String(), `"outcome":"confirmed"`) {
					t.Fatalf("watchdog log = %q", logs)
				}
				if current, err := layout.Current(); err != nil || current != digest || len(restarted) != 1 || restarted[0] != tc.unit {
					t.Fatalf("confirmed current = %s %v, restarted %v", current, err, restarted)
				}
				return
			}
			// Pending repeats every 15 s, so it is debug and stays out of the info log.
			if strings.Contains(logs.String(), `"outcome":"pending"`) {
				t.Fatalf("watchdog pending logged above debug = %q", logs)
			}
			now = activation.Deadline.Add(time.Second)
			if _, err := invoke(watchdog...); err != nil || !strings.Contains(logs.String(), `"outcome":"rolled-back"`) {
				t.Fatalf("watchdog after the deadline log = %q %v", logs, err)
			}
			if current, err := layout.Current(); err != nil || current != previous || len(restarted) != 2 || restarted[0] != tc.unit || restarted[1] != tc.unit {
				t.Fatalf("rolled back current = %s %v (want %s), restarted %v", current, err, previous, restarted)
			}
			if knownBad, err := layout.KnownBad(); err != nil || !knownBad[digest] {
				t.Fatalf("target not known bad: %v %v", knownBad, err)
			}
		})
	}
}

// The image-baked binary hands prepare and the watchdog to the known-good
// release with the unit's exact arguments, so the root logic moves with
// confirmed releases. It runs a step itself when that release fails it, or
// when it is already the delegate.
func TestRootStepsRunTheKnownGoodRelease(t *testing.T) {
	logs := captureLog(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	owner := fmt.Sprint(os.Getuid())
	layout := selfupdate.Layout{Root: root, Owner: os.Getuid()}
	baked := filepath.Join(dir, "baked")
	if err := os.WriteFile(baked, []byte("baked build"), 0o755); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(dir, "delegate.log")
	t.Setenv("DELEGATE_LOG", logFile)
	t.Setenv(delegatedEnv, "")
	now := time.Now()
	var restarted []string
	invoke := func(args ...string) (string, error) {
		var output bytes.Buffer
		err := run(t.Context(), args, &output, func() time.Time { return now }, func(_ context.Context, unit string) error {
			restarted = append(restarted, unit)
			return nil
		})
		return output.String(), err
	}
	unit := selfupdate.HostUnit
	prepare := []string{"prepare", "--root", root, "--owner", owner, "--unit", unit, "--baked-binary", baked}
	if _, err := invoke(prepare...); err != nil {
		t.Fatal(err)
	}
	// A confirmed release, staged as `selfupdate stage` leaves it.
	script := []byte("#!/bin/sh\nprintf '%s %s\\n' \"$" + delegatedEnv + "\" \"$*\" >> \"$DELEGATE_LOG\"\n" +
		"[ -z \"$DELEGATE_SLEEP\" ] || exec sleep \"$DELEGATE_SLEEP\"\nexit \"${DELEGATE_EXIT:-0}\"\n")
	sum := sha256.Sum256(script)
	digest := hex.EncodeToString(sum[:])
	if err := os.Mkdir(layout.ReleaseDir(digest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.BinaryPath(digest), script, 0o555); err != nil {
		t.Fatal(err)
	}
	knownGood := func() {
		t.Helper()
		link := filepath.Join(root, "known-good")
		if err := os.Remove(link); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Symlink("releases/"+digest, link); err != nil {
			t.Fatal(err)
		}
	}
	calls := func() []string {
		t.Helper()
		data, err := os.ReadFile(logFile)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
	watchdog := []string{"watchdog", "--root", root, "--owner", owner, "--unit", unit, "--config", filepath.Join(dir, "host.json")}
	knownGood()
	for _, step := range [][]string{watchdog, prepare} {
		output, err := invoke(step...)
		if err != nil || strings.Contains(output, "selfupdate "+step[0]+" unit=") {
			t.Fatalf("%s ran in the image-baked binary: %q %v", step[0], output, err)
		}
		if got, want := calls()[len(calls())-1], "1 selfupdate "+strings.Join(step, " "); got != want {
			t.Fatalf("delegated call = %q, want %q", got, want)
		}
	}
	// A release that fails the step leaves it to the image-baked binary.
	t.Setenv("DELEGATE_EXIT", "1")
	if output, err := invoke(watchdog...); err != nil || output != "" || len(calls()) != 3 {
		t.Fatalf("fallback after a failed delegate = %q %v, calls %q", output, err, calls())
	}
	// A release that hangs is stopped, and the image-baked binary runs the
	// step within the watchdog unit's timeout.
	knownGood()
	t.Setenv("DELEGATE_EXIT", "0")
	t.Setenv("DELEGATE_SLEEP", "30")
	// The short deadline still leaves a loaded race run time to start the
	// delegate's shell, which logs its call before it hangs.
	timeout := delegateTimeout
	defer func() { delegateTimeout = timeout }()
	delegateTimeout = 2 * time.Second
	started := time.Now()
	if output, err := invoke(watchdog...); err != nil || output != "" || len(calls()) != 4 || time.Since(started) > 10*time.Second {
		t.Fatalf("fallback after a hung delegate = %q %v in %s, calls %q", output, err, time.Since(started), calls())
	}
	delegateTimeout = timeout
	// The delegate itself runs the step; it never delegates again.
	knownGood()
	t.Setenv(delegatedEnv, "1")
	if output, err := invoke(watchdog...); err != nil || output != "" || len(calls()) != 4 {
		t.Fatalf("delegated run = %q %v, calls %q", output, err, calls())
	}
	// A release whose watchdog succeeds without enforcing a deadline cannot
	// keep an unproven target: the image-baked binary rolls it back and
	// restarts the unit once the grace has passed.
	t.Setenv(delegatedEnv, "")
	t.Setenv("DELEGATE_SLEEP", "")
	target := []byte("unproven build")
	sum = sha256.Sum256(target)
	unproven := hex.EncodeToString(sum[:])
	if err := os.Mkdir(layout.ReleaseDir(unproven), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(layout.BinaryPath(unproven), target, 0o555); err != nil {
		t.Fatal(err)
	}
	if _, err := invoke("activate", "--root", root, "--owner", owner, "--release", unproven, "--unit", unit, "--proof-window", "1m"); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute + selfupdate.OrphanedActivationGrace)
	if _, err := invoke(watchdog...); err != nil || !strings.Contains(logs.String(), `"outcome":"rolled-back"`) || len(calls()) != 5 || len(restarted) != 2 || restarted[0] != unit || restarted[1] != unit {
		t.Fatalf("backstop after a delegate ignored the deadline = %q, calls %q, restarted %v", logs, calls(), restarted)
	}
	if current, err := layout.Current(); err != nil || current == unproven {
		t.Fatalf("unproven target still current: %v", err)
	}
}
