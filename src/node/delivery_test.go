package node

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type testProcess struct {
	calls []struct {
		executable string
		args       []string
	}
	failRestart bool
}

func (p *testProcess) Run(_ context.Context, executable string, args []string) (ProcessResult, error) {
	p.calls = append(p.calls, struct {
		executable string
		args       []string
	}{executable, append([]string(nil), args...)})
	if p.failRestart && len(args) > 0 && args[0] == "restart" {
		return ProcessResult{ExitCode: 1}, nil
	}
	return ProcessResult{}, nil
}

type testDrain struct {
	events      []string
	endCalls    int
	failEndCall int
}

func (d *testDrain) BeginDrain(context.Context, string) error {
	d.events = append(d.events, "begin")
	return nil
}
func (d *testDrain) EndDrain(context.Context, string) error {
	d.events = append(d.events, "end")
	d.endCalls++
	if d.failEndCall != 0 && d.endCalls == d.failEndCall {
		return errors.New("drain end unavailable")
	}
	return nil
}

type hangingDrain struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	calls   int
}

func (d *hangingDrain) BeginDrain(context.Context, string) error { return nil }

func (d *hangingDrain) EndDrain(context.Context, string) error {
	d.mu.Lock()
	d.calls++
	call := d.calls
	d.mu.Unlock()
	if call == 1 {
		close(d.started)
		<-d.release
	}
	return nil
}

func (d *hangingDrain) endCalls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func testArtifact(t *testing.T, component, version string, payload []byte) Artifact {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	return Artifact{
		Component: component, Version: version, URL: "https://release.invalid/a",
		SHA256: hex.EncodeToString(digest[:]), Signature: ed25519.Sign(private, payload), PublicKey: public,
	}
}

func testDelivery(t *testing.T, process ProcessRunner, download ArtifactDownloader, health HealthGate, drain DrainCoordinator) (*Delivery, string, string) {
	t.Helper()
	root := t.TempDir()
	units := t.TempDir()
	delivery, err := NewDelivery(Config{FileSystem: OSFileSystem{}, Downloader: download, Process: process,
		Drain: drain, Health: health, ArtifactRoot: root, UnitDirectory: units})
	if err != nil {
		t.Fatal(err)
	}
	return delivery, root, units
}

func TestDeliverVerifiesInstallsAtomicallyAndUsesFixedSystemctlArguments(t *testing.T) {
	payload := []byte("static terrabase")
	artifact := testArtifact(t, "terrabase", "v1.2.3", payload)
	process := &testProcess{}
	drain := &testDrain{}
	healthCalls := []string{}
	delivery, root, units := testDelivery(t, process,
		DownloadFunc(func(context.Context, Artifact) ([]byte, error) { return payload, nil }),
		HealthFunc(func(_ context.Context, component, version string) error {
			healthCalls = append(healthCalls, component+"/"+version)
			return nil
		}), drain)
	if err := delivery.Deliver(context.Background(), artifact); err != nil {
		t.Fatal(err)
	}
	current, err := CurrentPath(root, artifact.Component)
	if err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(current); err != nil || target != artifact.Version {
		t.Fatalf("current = %q, %v", target, err)
	}
	executable, _ := ArtifactPath(root, artifact)
	if installed, err := os.ReadFile(executable); err != nil || string(installed) != string(payload) {
		t.Fatalf("installed = %q, %v", installed, err)
	}
	unit, err := os.ReadFile(filepath.Join(units, "terrascale-terrabase.service"))
	if err != nil {
		t.Fatal(err)
	}
	unitText := string(unit)
	for _, required := range []string{"ProtectSystem=strict", "NoNewPrivileges=yes", "CapabilityBoundingSet=", "SystemCallFilter=@system-service", "CPUWeight=100", "IOWeight=100", "MemoryMax=1G", "ReadWritePaths=/var/lib/terrascale/terrabase"} {
		if !strings.Contains(unitText, required) {
			t.Errorf("unit lacks %q: %s", required, unitText)
		}
	}
	if len(process.calls) != 2 || process.calls[0].executable != SystemctlPath ||
		!reflect.DeepEqual(process.calls[0].args, []string{"daemon-reload"}) ||
		!reflect.DeepEqual(process.calls[1].args, []string{"restart", "terrascale-terrabase.service"}) {
		t.Fatalf("systemctl calls = %#v", process.calls)
	}
	if !reflect.DeepEqual(drain.events, []string{"begin", "end"}) || !reflect.DeepEqual(healthCalls, []string{"terrabase/v1.2.3"}) {
		t.Fatalf("coordination = %#v / %#v", drain.events, healthCalls)
	}
}

func TestDeliverRejectsTamperedPayloadBeforeFilesystemMutation(t *testing.T) {
	payload := []byte("signed")
	artifact := testArtifact(t, "terrabase", "v1", payload)
	process := &testProcess{}
	delivery, _, _ := testDelivery(t, process,
		DownloadFunc(func(context.Context, Artifact) ([]byte, error) { return []byte("tampered"), nil }),
		HealthFunc(func(context.Context, string, string) error { return nil }),
		&testDrain{})
	if err := delivery.Deliver(context.Background(), artifact); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("tampered artifact error = %v", err)
	}
	if len(process.calls) != 0 {
		t.Fatalf("tampered artifact ran systemctl: %#v", process.calls)
	}
}

func TestDeliverHealthFailureRollsBackPreviousVersion(t *testing.T) {
	oldPayload := []byte("old")
	newPayload := []byte("new")
	old := testArtifact(t, "terrabase", "v1", oldPayload)
	newArtifact := testArtifact(t, "terrabase", "v2", newPayload)
	process := &testProcess{}
	var healthVersions []string
	delivery, root, _ := testDelivery(t, process,
		DownloadFunc(func(_ context.Context, a Artifact) ([]byte, error) {
			if a.Version == old.Version {
				return oldPayload, nil
			}
			return newPayload, nil
		}),
		HealthFunc(func(_ context.Context, _, version string) error {
			healthVersions = append(healthVersions, version)
			if version == newArtifact.Version {
				return errors.New("candidate not ready")
			}
			return nil
		}), &testDrain{})
	if err := delivery.Deliver(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Deliver(context.Background(), newArtifact); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("failed candidate error = %v", err)
	}
	current, _ := CurrentPath(root, "terrabase")
	if target, err := os.Readlink(current); err != nil || target != old.Version {
		t.Fatalf("rollback current = %q, %v", target, err)
	}
	if !reflect.DeepEqual(healthVersions, []string{"v1", "v2", "v1"}) {
		t.Fatalf("health versions = %#v", healthVersions)
	}
}

func TestRollbackRestoresTrustedUnitConfiguration(t *testing.T) {
	old := testArtifact(t, "terrabase", "v1", []byte("old"))
	old.BinaryName = "terrabase-old"
	old.Arguments = []string{"--old"}
	old.MemoryMax = "2G"
	next := testArtifact(t, "terrabase", "v2", []byte("new"))
	next.BinaryName = "terrabase-new"
	next.Arguments = []string{"--new"}
	next.MemoryMax = "3G"
	delivery, root, units := testDelivery(t, &testProcess{}, DownloadFunc(func(_ context.Context, artifact Artifact) ([]byte, error) {
		if artifact.Version == old.Version {
			return []byte("old"), nil
		}
		return []byte("new"), nil
	}), HealthFunc(func(context.Context, string, string) error { return nil }), &testDrain{})
	if err := delivery.Deliver(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	oldUnit, err := os.ReadFile(filepath.Join(units, unitName(old.Component)))
	if err != nil {
		t.Fatal(err)
	}
	if err := delivery.Deliver(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Rollback(context.Background(), old.Component, old.Version); err != nil {
		t.Fatal(err)
	}
	current, _ := CurrentPath(root, old.Component)
	if target, err := os.Readlink(current); err != nil || target != old.Version {
		t.Fatalf("rollback current = %q, %v", target, err)
	}
	gotUnit, err := os.ReadFile(filepath.Join(units, unitName(old.Component)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotUnit, oldUnit) || !strings.Contains(string(gotUnit), `"--old"`) || strings.Contains(string(gotUnit), `"--new"`) {
		t.Fatalf("rollback unit = %q, want old unit %q", gotUnit, oldUnit)
	}
}

func TestRollbackRejectsMissingOrUntrustedArtifactBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(string) error
		state  RecoveryState
	}{
		{name: "missing", mutate: func(path string) error { return os.Remove(path) }, state: RecoveryArtifactMissing},
		{name: "untrusted", mutate: func(path string) error { return os.WriteFile(path, []byte("tampered"), 0755) }, state: RecoveryArtifactUntrusted},
	} {
		t.Run(test.name, func(t *testing.T) {
			old := testArtifact(t, "terrabase", "v1", []byte("old"))
			next := testArtifact(t, "terrabase", "v2", []byte("new"))
			process := &testProcess{}
			drain := &testDrain{}
			delivery, root, _ := testDelivery(t, process, DownloadFunc(func(_ context.Context, artifact Artifact) ([]byte, error) {
				if artifact.Version == old.Version {
					return []byte("old"), nil
				}
				return []byte("new"), nil
			}), HealthFunc(func(context.Context, string, string) error { return nil }), drain)
			if err := delivery.Deliver(context.Background(), old); err != nil {
				t.Fatal(err)
			}
			if err := delivery.Deliver(context.Background(), next); err != nil {
				t.Fatal(err)
			}
			path, err := ArtifactPath(root, old)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.mutate(path); err != nil {
				t.Fatal(err)
			}
			callsBefore := len(process.calls)
			eventsBefore := len(drain.events)
			if err := delivery.Rollback(context.Background(), old.Component, old.Version); err == nil {
				t.Fatal("rollback unexpectedly succeeded")
			} else {
				var recovery *RecoveryError
				if !errors.As(err, &recovery) || recovery.State != test.state {
					t.Fatalf("rollback error = %v, recovery = %#v", err, recovery)
				}
			}
			if len(process.calls) != callsBefore || len(drain.events) != eventsBefore {
				t.Fatalf("pre-mutation guards failed: process=%#v drain=%#v", process.calls, drain.events)
			}
			journal := filepath.Join(root, old.Component, ".delivery-state.json")
			stateBytes, err := os.ReadFile(journal)
			if err != nil {
				t.Fatal(err)
			}
			var state deliveryState
			if err := json.Unmarshal(stateBytes, &state); err != nil {
				t.Fatal(err)
			}
			if state.Phase != "rollback_failed" || state.Recovery != test.state {
				t.Fatalf("persisted recovery = %#v", state)
			}
		})
	}
}

func TestRollbackHealthFailureLeavesTypedRecoveryState(t *testing.T) {
	old := testArtifact(t, "terrabase", "v1", []byte("old"))
	next := testArtifact(t, "terrabase", "v2", []byte("new"))
	healthCalls := 0
	delivery, root, _ := testDelivery(t, &testProcess{}, DownloadFunc(func(_ context.Context, artifact Artifact) ([]byte, error) {
		if artifact.Version == old.Version {
			return []byte("old"), nil
		}
		return []byte("new"), nil
	}), HealthFunc(func(context.Context, string, string) error {
		healthCalls++
		if healthCalls == 3 {
			return errors.New("rollback target is not ready")
		}
		return nil
	}), &testDrain{})
	if err := delivery.Deliver(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Deliver(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Rollback(context.Background(), old.Component, old.Version); err == nil {
		t.Fatal("rollback unexpectedly succeeded")
	} else {
		var recovery *RecoveryError
		if !errors.As(err, &recovery) || recovery.State != RecoveryHealthFailed {
			t.Fatalf("rollback error = %v, recovery = %#v", err, recovery)
		}
	}
	journal := filepath.Join(root, old.Component, ".delivery-state.json")
	contents, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var state deliveryState
	if err := json.Unmarshal(contents, &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != "rollback_failed" || state.Recovery != RecoveryHealthFailed {
		t.Fatalf("rollback recovery state = %#v", state)
	}
}

func TestRollbackInterruptionLeavesTypedRecoveryState(t *testing.T) {
	old := testArtifact(t, "terrabase", "v1", []byte("old"))
	next := testArtifact(t, "terrabase", "v2", []byte("new"))
	healthCalls := 0
	delivery, root, _ := testDelivery(t, &testProcess{}, DownloadFunc(func(_ context.Context, artifact Artifact) ([]byte, error) {
		if artifact.Version == old.Version {
			return []byte("old"), nil
		}
		return []byte("new"), nil
	}), HealthFunc(func(context.Context, string, string) error {
		healthCalls++
		if healthCalls == 3 {
			return context.Canceled
		}
		return nil
	}), &testDrain{})
	if err := delivery.Deliver(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Deliver(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Rollback(context.Background(), old.Component, old.Version); err == nil {
		t.Fatal("rollback unexpectedly succeeded")
	} else {
		var recovery *RecoveryError
		if !errors.As(err, &recovery) || recovery.State != RecoveryInterrupted {
			t.Fatalf("rollback error = %v, recovery = %#v", err, recovery)
		}
	}
	journal := filepath.Join(root, old.Component, ".delivery-state.json")
	contents, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var state deliveryState
	if err := json.Unmarshal(contents, &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != "rollback_failed" || state.Recovery != RecoveryInterrupted {
		t.Fatalf("rollback interruption state = %#v", state)
	}
}

func TestDeliverRetriesDrainEndFromDurableStateAfterRestart(t *testing.T) {
	payload := []byte("static terrabase")
	artifact := testArtifact(t, "terrabase", "v1", payload)
	process := &testProcess{}
	drain := &testDrain{failEndCall: 1}
	healthCalls := 0
	health := HealthFunc(func(context.Context, string, string) error {
		healthCalls++
		return nil
	})
	download := DownloadFunc(func(context.Context, Artifact) ([]byte, error) { return payload, nil })
	delivery, root, units := testDelivery(t, process, download, health, drain)
	if err := delivery.Deliver(context.Background(), artifact); err == nil {
		t.Fatal("delivery unexpectedly succeeded")
	} else {
		var recovery *RecoveryError
		if !errors.As(err, &recovery) || recovery.State != RecoveryDrainFailed {
			t.Fatalf("delivery error = %v, recovery = %#v", err, recovery)
		}
	}

	journal := filepath.Join(root, artifact.Component, ".delivery-state.json")
	contents, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var state deliveryState
	if err := json.Unmarshal(contents, &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != "committed" || state.Recovery != RecoveryDrainFailed || !state.Drained {
		t.Fatalf("durable drain recovery = %#v", state)
	}

	restarted, err := NewDelivery(Config{FileSystem: OSFileSystem{}, Downloader: download, Process: process,
		Drain: drain, Health: health, ArtifactRoot: root, UnitDirectory: units})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Deliver(context.Background(), artifact); err != nil {
		t.Fatalf("retry delivery = %v", err)
	}
	if len(process.calls) != 2 {
		t.Fatalf("retry restarted the unit: %#v", process.calls)
	}
	if healthCalls != 2 || !reflect.DeepEqual(drain.events, []string{"begin", "end", "end"}) {
		t.Fatalf("retry coordination: health=%d drain=%#v", healthCalls, drain.events)
	}
	contents, err = os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	state = deliveryState{}
	if err := json.Unmarshal(contents, &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != "committed" || state.Recovery != RecoveryNone || state.Drained {
		t.Fatalf("completed drain state = %#v", state)
	}
}

func TestRollbackRetriesDrainEndFromDurableStateAfterRestart(t *testing.T) {
	old := testArtifact(t, "terrabase", "v1", []byte("old"))
	next := testArtifact(t, "terrabase", "v2", []byte("new"))
	process := &testProcess{}
	drain := &testDrain{failEndCall: 3}
	download := DownloadFunc(func(_ context.Context, artifact Artifact) ([]byte, error) {
		if artifact.Version == old.Version {
			return []byte("old"), nil
		}
		return []byte("new"), nil
	})
	health := HealthFunc(func(context.Context, string, string) error { return nil })
	delivery, root, units := testDelivery(t, process, download, health, drain)
	if err := delivery.Deliver(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Deliver(context.Background(), next); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Rollback(context.Background(), old.Component, old.Version); err == nil {
		t.Fatal("rollback unexpectedly succeeded")
	} else {
		var recovery *RecoveryError
		if !errors.As(err, &recovery) || recovery.State != RecoveryDrainFailed {
			t.Fatalf("rollback error = %v, recovery = %#v", err, recovery)
		}
	}

	journal := filepath.Join(root, old.Component, ".delivery-state.json")
	contents, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var state deliveryState
	if err := json.Unmarshal(contents, &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != "committed" || state.Recovery != RecoveryDrainFailed || !state.Drained {
		t.Fatalf("durable rollback drain recovery = %#v", state)
	}

	restarted, err := NewDelivery(Config{FileSystem: OSFileSystem{}, Downloader: download, Process: process,
		Drain: drain, Health: health, ArtifactRoot: root, UnitDirectory: units})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Rollback(context.Background(), old.Component, old.Version); err != nil {
		t.Fatalf("retry rollback = %v", err)
	}
	if len(process.calls) != 6 {
		t.Fatalf("retry restarted the unit: %#v", process.calls)
	}
	if !reflect.DeepEqual(drain.events, []string{"begin", "end", "begin", "end", "begin", "end", "end"}) {
		t.Fatalf("retry drain coordination = %#v", drain.events)
	}
	contents, err = os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	state = deliveryState{}
	if err := json.Unmarshal(contents, &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != "committed" || state.Recovery != RecoveryNone || state.Drained {
		t.Fatalf("completed rollback drain state = %#v", state)
	}
}

func TestDeliverAutomaticRollbackRetriesDrainEndAfterRestart(t *testing.T) {
	old := testArtifact(t, "terrabase", "v1", []byte("old"))
	candidate := testArtifact(t, "terrabase", "v2", []byte("new"))
	process := &testProcess{}
	drain := &testDrain{failEndCall: 2}
	download := DownloadFunc(func(_ context.Context, artifact Artifact) ([]byte, error) {
		if artifact.Version == old.Version {
			return []byte("old"), nil
		}
		return []byte("new"), nil
	})
	health := HealthFunc(func(_ context.Context, _, version string) error {
		if version == candidate.Version {
			return errors.New("candidate is not ready")
		}
		return nil
	})
	delivery, root, units := testDelivery(t, process, download, health, drain)
	if err := delivery.Deliver(context.Background(), old); err != nil {
		t.Fatal(err)
	}
	if err := delivery.Deliver(context.Background(), candidate); err == nil {
		t.Fatal("candidate unexpectedly succeeded")
	}

	journal := filepath.Join(root, old.Component, ".delivery-state.json")
	contents, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var state deliveryState
	if err := json.Unmarshal(contents, &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != "rolled_back" || state.Recovery != RecoveryDrainFailed || !state.Drained {
		t.Fatalf("automatic rollback drain recovery = %#v", state)
	}

	restarted, err := NewDelivery(Config{FileSystem: OSFileSystem{}, Downloader: download, Process: process,
		Drain: drain, Health: health, ArtifactRoot: root, UnitDirectory: units})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Deliver(context.Background(), candidate); err == nil {
		t.Fatal("candidate retry unexpectedly succeeded")
	}
	if drain.endCalls < 3 || drain.events[4] != "end" {
		t.Fatalf("automatic rollback did not retry drain end first: calls=%d events=%#v", drain.endCalls, drain.events)
	}
	contents, err = os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	state = deliveryState{}
	if err := json.Unmarshal(contents, &state); err != nil {
		t.Fatal(err)
	}
	if state.Phase != "rolled_back" || state.Recovery != RecoveryNone || state.Drained {
		t.Fatalf("automatic rollback after retry = %#v", state)
	}
}

func TestDeliverBoundsCanceledFailureDrainCleanupAndRetriesAfterRestart(t *testing.T) {
	payload := []byte("static terrabase")
	artifact := testArtifact(t, "terrabase", "v1", payload)
	process := &testProcess{}
	drain := &hangingDrain{started: make(chan struct{}), release: make(chan struct{})}
	defer close(drain.release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	healthCalls := 0
	health := HealthFunc(func(_ context.Context, _, _ string) error {
		healthCalls++
		if healthCalls == 1 {
			cancel()
			return context.Canceled
		}
		return nil
	})
	download := DownloadFunc(func(context.Context, Artifact) ([]byte, error) { return payload, nil })
	root := t.TempDir()
	units := t.TempDir()
	delivery, err := NewDelivery(Config{FileSystem: OSFileSystem{}, Downloader: download, Process: process,
		Drain: drain, Health: health, ArtifactRoot: root, UnitDirectory: units, DrainCleanupTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}

	started := time.Now()
	result := make(chan error, 1)
	go func() { result <- delivery.Deliver(ctx, artifact) }()
	select {
	case <-drain.started:
	case <-time.After(time.Second):
		t.Fatal("EndDrain was not started")
	}
	var deliveryErr error
	select {
	case deliveryErr = <-result:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("delivery did not honor the drain cleanup deadline")
	}
	if time.Since(started) >= 500*time.Millisecond {
		t.Fatalf("delivery cleanup exceeded deadline: %s", time.Since(started))
	}
	var recovery *RecoveryError
	if !errors.As(deliveryErr, &recovery) || recovery.State != RecoveryDrainFailed || !errors.Is(deliveryErr, context.DeadlineExceeded) {
		t.Fatalf("bounded cleanup error = %v, recovery = %#v", deliveryErr, recovery)
	}

	journal := filepath.Join(root, artifact.Component, ".delivery-state.json")
	contents, err := os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	var state deliveryState
	if err := json.Unmarshal(contents, &state); err != nil {
		t.Fatal(err)
	}
	if state.Recovery != RecoveryDrainFailed || !state.Drained {
		t.Fatalf("bounded cleanup recovery state = %#v", state)
	}

	restarted, err := NewDelivery(Config{FileSystem: OSFileSystem{}, Downloader: download, Process: process,
		Drain: drain, Health: health, ArtifactRoot: root, UnitDirectory: units, DrainCleanupTimeout: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Deliver(context.Background(), artifact); err != nil {
		t.Fatalf("retry after bounded cleanup = %v", err)
	}
	if drain.endCalls() != 2 || len(process.calls) != 2 {
		t.Fatalf("retry repeated activation or cleanup: drain=%d process=%#v", drain.endCalls(), process.calls)
	}
	contents, err = os.ReadFile(journal)
	if err != nil {
		t.Fatal(err)
	}
	state = deliveryState{}
	if err := json.Unmarshal(contents, &state); err != nil {
		t.Fatal(err)
	}
	if state.Recovery != RecoveryNone || state.Drained {
		t.Fatalf("retry completion state = %#v", state)
	}
}
