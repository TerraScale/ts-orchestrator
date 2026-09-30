//go:build linux

package host

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/nativerootoci"
)

func TestNativeRootDesiredRequestFailureRevokesSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native-root.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})
	file, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	close(done)
	root := &managedNativeRoot{role: "terrabase", fingerprint: "accepted", path: path,
		file: file, listener: listener, cancel: cancel, done: done}
	now := time.Now()
	agent := &Agent{
		cfg:              AgentConfig{Node: "node", Cell: "gru", ClockCheck: func() error { return nil }},
		session:          session{ExpiresAt: now.Add(2 * time.Minute)},
		sessionSafeUntil: now.Add(time.Minute),
		nativeRoots:      map[string]*managedNativeRoot{"terrabase": root},
		nativeDesired: map[string]nativeRootDesired{"terrabase": {
			fingerprint: "accepted", until: now.Add(time.Minute),
		}},
	}
	// The missing identity key fails before any NATS exchange. Reconcile must
	// still revoke the previously accepted privileged helper.
	if err := agent.reconcile(t.Context(), "terrabase"); err == nil {
		t.Fatal("desired refresh unexpectedly succeeded")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("native root socket remained after failed desired refresh: %v", err)
	}
	if len(agent.nativeRoots) != 0 || len(agent.nativeDesired) != 0 {
		t.Fatal("native root authority remained after failed desired refresh")
	}
}

func TestNativeRootPinExtendsOnlyTheSameValidatedDesired(t *testing.T) {
	now := time.Now()
	agent := &Agent{
		cfg:              AgentConfig{ClockCheck: func() error { return nil }},
		session:          session{ExpiresAt: now.Add(2 * time.Minute)},
		sessionSafeUntil: now.Add(20 * time.Second),
	}
	if err := agent.pinManagedNativeRootDesired("terrabase", "accepted"); err != nil {
		t.Fatal(err)
	}
	renewed := now.Add(50 * time.Second)
	agent.sessionSafeUntil = renewed
	if err := agent.extendManagedNativeRootPin("terrabase", "changed"); err != nil {
		t.Fatal(err)
	}
	if pinned, err := agent.nativeRootDesiredDeadline("terrabase", "accepted"); err != nil || pinned.Equal(renewed) {
		t.Fatalf("a changed desired extended the pin: %v, %v", pinned, err)
	}
	if err := agent.extendManagedNativeRootPin("terrabase", "accepted"); err != nil {
		t.Fatal(err)
	}
	if pinned, err := agent.nativeRootDesiredDeadline("terrabase", "accepted"); err != nil || !pinned.Equal(renewed) {
		t.Fatalf("the re-validated desired did not extend its pin: %v, %v", pinned, err)
	}
	agent.nativeRootMu.Lock()
	delete(agent.nativeDesired, "terrabase")
	agent.nativeRootMu.Unlock()
	if err := agent.extendManagedNativeRootPin("terrabase", "accepted"); err != nil {
		t.Fatal(err)
	}
	if _, err := agent.nativeRootDesiredDeadline("terrabase", "accepted"); err == nil {
		t.Fatal("extension recreated a revoked pin")
	}
}

func TestNativeRootPinExpiryAndPeerRestrictions(t *testing.T) {
	now := time.Now()
	leaseDeadline := now.Add(30 * time.Second)
	root := &managedNativeRoot{role: "terrabase", fingerprint: "accepted"}
	agent := &Agent{
		cfg: AgentConfig{WorkloadIdentity: WorkloadIdentity{UID: 123, GID: 456},
			ClockCheck: func() error { return nil }},
		session:          session{ExpiresAt: now.Add(2 * time.Minute)},
		sessionSafeUntil: leaseDeadline,
		nativeRoots:      map[string]*managedNativeRoot{"terrabase": root},
	}
	if err := agent.pinManagedNativeRootDesired("terrabase", "accepted"); err != nil {
		t.Fatal(err)
	}
	if pinned, err := agent.nativeRootDesiredDeadline("terrabase", "accepted"); err != nil || !pinned.Equal(leaseDeadline) {
		t.Fatalf("valid desired pin = %v, error = %v", pinned, err)
	}
	agent.sessionSafeUntil = now.Add(time.Minute)
	if pinned, err := agent.nativeRootDesiredDeadline("terrabase", "accepted"); err != nil || !pinned.Equal(leaseDeadline) {
		t.Fatalf("session renewal extended desired pin: %v, error = %v", pinned, err)
	}
	agent.nativeDesired["terrabase"] = nativeRootDesired{fingerprint: "accepted", until: now.Add(-time.Second)}
	if _, err := agent.nativeRootDesiredDeadline("terrabase", "accepted"); err == nil {
		t.Fatal("renewed host session extended expired desired pin")
	}
	if _, err := agent.authorizeManagedNativeRoot(t.Context(), nativerootoci.Peer{
		PID: 99, UID: 123, GID: 456,
	}, Desired{Role: "terrabase"}, root); err == nil {
		t.Fatal("expired desired pin authorized native root peer")
	}
	agent.nativeDesired["terrabase"] = nativeRootDesired{fingerprint: "accepted", until: now.Add(time.Minute)}
	if _, err := agent.authorizeManagedNativeRoot(t.Context(), nativerootoci.Peer{
		PID: 99, UID: 124, GID: 456,
	}, Desired{Role: "terrabase"}, root); err == nil {
		t.Fatal("wrong Unix peer UID authorized native root")
	}
	if _, err := agent.authorizeManagedNativeRoot(t.Context(), nativerootoci.Peer{
		PID: 99, UID: 123, GID: 457,
	}, Desired{Role: "terrabase"}, root); err == nil {
		t.Fatal("wrong Unix peer GID authorized native root")
	}
}

func TestNativeRootReplacementClosesOldSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "native-root.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(path)
	})
	file, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	close(done)
	root := &managedNativeRoot{role: "terrabase", fingerprint: "old", path: path,
		file: file, listener: listener, cancel: cancel, done: done}
	agent := &Agent{nativeRoots: map[string]*managedNativeRoot{"terrabase": root}}
	if err := agent.stopManagedNativeRootIfChanged("terrabase", "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("old native root socket remained after replacement: %v", err)
	}
	if len(agent.nativeRoots) != 0 {
		t.Fatal("old native root helper remained active after replacement")
	}
}
